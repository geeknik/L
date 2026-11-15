//! Stateful authorization gate for one authenticated, single-owner session.

use std::collections::{HashMap, HashSet, VecDeque};
use sha2::{Digest, Sha256};
use crate::ast::Act;
use crate::authority::{Claims, Envelope, Integrity, SecurityError, TrustKey, hash_valid, name_valid, verify};
use crate::gate::Gate;
use crate::limits::{MAX_AUDIT_RECORDS, MAX_AUTHORITY_BYTES, MAX_SECURITY_RECORDS};
use crate::parser::parse;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityAudit {
    pub operation: &'static str,
    pub allowed: bool,
    pub code: &'static str,
}

pub struct SecurityGate {
    subject: String,
    trust: HashMap<String, TrustKey>,
    integrity: Integrity,
    last_now: Option<i64>,
    exhausted: bool,
    // None is a retained revocation tombstone, not an unused identifier.
    capabilities: HashMap<String, Option<Claims>>,
    approvals: HashMap<(String, String), Claims>,
    nonces: HashSet<(String, String)>,
    audit: VecDeque<SecurityAudit>,
}

impl SecurityGate {
    pub fn new(subject: String, trust: HashMap<String, TrustKey>, integrity: Integrity) -> Result<Self, SecurityError> {
        if subject.is_empty() || subject.len() > MAX_AUTHORITY_BYTES || trust.len() > MAX_SECURITY_RECORDS {
            return Err(SecurityError::new("AUTH.INVALID"));
        }
        for (issuer, key) in &trust {
            if issuer.is_empty() || issuer.len() > MAX_AUTHORITY_BYTES {
                return Err(SecurityError::new("AUTH.INVALID"));
            }
            key.validate()?;
        }
        Ok(Self { subject, trust, integrity, last_now: None, exhausted: false, capabilities: HashMap::new(),
            approvals: HashMap::new(), nonces: HashSet::new(), audit: VecDeque::new() })
    }
    pub fn integrity(&self) -> Integrity { self.integrity }
    pub fn audit(&self) -> &VecDeque<SecurityAudit> { &self.audit }
    pub fn observe(&mut self, incoming: Integrity) {
        self.integrity = self.integrity.min(incoming);
        self.record("OBSERVE", &Ok::<(), SecurityError>(()));
    }

    fn clock(&mut self, now: i64) -> Result<(), SecurityError> {
        if now < 0 || self.last_now.is_some_and(|previous| now < previous) {
            return Err(SecurityError::new("TIME.INVALID"));
        }
        self.last_now = Some(now);
        Ok(())
    }
    fn record<T>(&mut self, operation: &'static str, result: &Result<T, SecurityError>) {
        if self.audit.len() == MAX_AUDIT_RECORDS { self.audit.pop_front(); }
        self.audit.push_back(SecurityAudit { operation, allowed: result.is_ok(),
            code: result.as_ref().err().map_or("ALLOW", |error| error.code) });
    }
    fn live_capability(&self, id: &str, now: i64) -> Result<&Claims, SecurityError> {
        let grant = self.capabilities.get(id).ok_or(SecurityError::new("AUTH.REQUIRED"))?
            .as_ref().ok_or(SecurityError::new("AUTH.REVOKED"))?;
        if now >= grant.expires_at { return Err(SecurityError::new("AUTH.EXPIRED")); }
        Ok(grant)
    }
    fn same_binding(left: &Claims, right: &Claims) -> bool {
        left.subject == right.subject && left.capability == right.capability
            && left.scope == right.scope && left.tool_principal == right.tool_principal
            && left.tool_hash == right.tool_hash && left.integrity == right.integrity
    }

    pub fn apply(&mut self, envelope: &Envelope, now: i64) -> Result<(), SecurityError> {
        let result = self.apply_inner(envelope, now);
        if result.as_ref().err().is_some_and(|error| error.code == "AUTH.CAPACITY") {
            self.exhausted = true;
        }
        self.record("APPLY", &result);
        result
    }
    fn apply_inner(&mut self, envelope: &Envelope, now: i64) -> Result<(), SecurityError> {
        self.clock(now)?;
        if self.exhausted { return Err(SecurityError::new("AUTH.CAPACITY")); }
        let claims = verify(envelope, &self.trust)?;
        if claims.subject != self.subject { return Err(SecurityError::new("AUTH.MISMATCH")); }
        if now < claims.issued_at || now >= claims.expires_at {
            return Err(SecurityError::new("AUTH.EXPIRED"));
        }
        let nonce = (claims.issuer.clone(), claims.nonce.clone());
        if self.nonces.contains(&nonce) { return Err(SecurityError::new("AUTH.REPLAY")); }
        if self.nonces.len() >= MAX_SECURITY_RECORDS { return Err(SecurityError::new("AUTH.CAPACITY")); }
        match claims.kind.as_str() {
            "grant" => {
                if let Some(entry) = self.capabilities.get(&claims.capability) {
                    return Err(SecurityError::new(if entry.is_none() { "AUTH.REVOKED" } else { "AUTH.REPLAY" }));
                }
                if self.capabilities.len() >= MAX_SECURITY_RECORDS { return Err(SecurityError::new("AUTH.CAPACITY")); }
                self.capabilities.insert(claims.capability.clone(), Some(claims));
            }
            "endorse" | "revoke" => {
                let grant = self.live_capability(&claims.capability, now)?;
                if !Self::same_binding(&claims, grant) { return Err(SecurityError::new("AUTH.MISMATCH")); }
                if claims.kind == "revoke" {
                    if claims.issuer != grant.issuer { return Err(SecurityError::new("AUTH.MISMATCH")); }
                    self.approvals.retain(|(capability, _), _| capability != &claims.capability);
                    self.capabilities.insert(claims.capability.clone(), None);
                } else {
                    if claims.expires_at > grant.expires_at { return Err(SecurityError::new("AUTH.MISMATCH")); }
                    let key = (claims.capability.clone(), claims.action_hash.clone());
                    if !self.approvals.contains_key(&key) && self.approvals.len() >= MAX_SECURITY_RECORDS {
                        return Err(SecurityError::new("AUTH.CAPACITY"));
                    }
                    self.approvals.insert(key, claims);
                }
            }
            _ => return Err(SecurityError::new("AUTH.INVALID")),
        }
        self.nonces.insert(nonce);
        Ok(())
    }

    pub fn execute(&mut self, source: &str, now: i64) -> Result<Act, SecurityError> {
        let result = self.execute_inner(source, now);
        self.record("EXECUTE", &result);
        result
    }
    fn execute_inner(&mut self, source: &str, now: i64) -> Result<Act, SecurityError> {
        self.clock(now)?;
        let mut acts = parse(source).map_err(|_| SecurityError::new("ACT.INVALID"))?;
        if acts.len() != 1 { return Err(SecurityError::new("ACT.INVALID")); }
        let act = acts.remove(0);
        Gate::new().execute(&act, Some(now as u64)).map_err(|_| SecurityError::new("ACT.INVALID"))?;
        match &act {
            Act::Grant(_) | Act::Revoke(_) | Act::Endorse(_) => return Err(SecurityError::new("AUTH.REQUIRED")),
            Act::Assert(a) => {
                Self::reference(&a.evidence)?;
                self.integrity = Integrity::Low;
            }
            Act::Query(a) => {
                Self::reference(&a.evidence)?;
                self.integrity = Integrity::Low;
            }
            Act::Commit(a) => Self::reference(&a.reference)?,
            Act::Direct(direct) => {
                if self.exhausted { return Err(SecurityError::new("AUTH.CAPACITY")); }
                Self::reference(&direct.call.tool)?;
                if !hash_valid(&direct.capability.cap_hash) { return Err(SecurityError::new("ACT.INVALID")); }
                let grant = self.live_capability(&direct.capability.cap_hash, now)?;
                if direct.capability.scope != grant.scope || direct.capability.from_principal.id != grant.issuer
                    || direct.call.tool.principal.id != grant.tool_principal || direct.call.tool.content_hash != grant.tool_hash
                    || direct.capability.exp > grant.expires_at - grant.issued_at {
                    return Err(SecurityError::new("AUTH.MISMATCH"));
                }
                if self.integrity < grant.integrity {
                    let action_hash = format!("{:x}", Sha256::digest(source.as_bytes()));
                    let key = (grant.capability.clone(), action_hash);
                    let approval = self.approvals.get(&key).ok_or(SecurityError::new("INTEGRITY.DENIED"))?;
                    if now >= approval.expires_at || approval.integrity < grant.integrity {
                        return Err(SecurityError::new("INTEGRITY.DENIED"));
                    }
                    self.approvals.remove(&key);
                }
            }
        }
        Ok(act)
    }
    fn reference(reference: &crate::ast::Reference) -> Result<(), SecurityError> {
        if !hash_valid(&reference.content_hash) || !name_valid(&reference.principal.id, ':')
            || reference.principal.id == "anon" { return Err(SecurityError::new("ACT.INVALID")); }
        Ok(())
    }
}
