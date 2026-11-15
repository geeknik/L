//! Gate (reference monitor) in Rust.
//! Implements the four rules: runtime labels, DIRECT integrity,
//! ENDORSE authorization, reference binding + TTL.

use crate::ast::{Act, Capability, Reference, act_type};
use crate::limits::MAX_AUDIT_RECORDS;
use crate::parser::parse;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub enum GateError {
    IntegrityDenied(String),
    AuthorizationUnauthorized(String),
    InvalidReference(String),
    Expired(String),
    CapabilityInvalid(String),
}

impl GateError {
    pub fn new(code: &str, msg: &str) -> Self {
        match code {
            "INTEGRITY.DIRECT.DENIED" => GateError::IntegrityDenied(msg.to_string()),
            "ENDORSE.UNAUTHORIZED" => GateError::AuthorizationUnauthorized(msg.to_string()),
            "REFERENCE.INVALID" => GateError::InvalidReference(msg.to_string()),
            "EXPIRY.INVALID" => GateError::Expired(msg.to_string()),
            "CAPABILITY.INVALID" => GateError::CapabilityInvalid(msg.to_string()),
            _ => GateError::InvalidReference(msg.to_string()),
        }
    }
}

impl std::fmt::Display for GateError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            GateError::IntegrityDenied(m) => write!(f, "INTEGRITY.DIRECT.DENIED: {}", m),
            GateError::AuthorizationUnauthorized(m) => write!(f, "ENDORSE.UNAUTHORIZED: {}", m),
            GateError::InvalidReference(m) => write!(f, "REFERENCE.INVALID: {}", m),
            GateError::Expired(m) => write!(f, "EXPIRY.INVALID: {}", m),
            GateError::CapabilityInvalid(m) => write!(f, "CAPABILITY.INVALID: {}", m),
        }
    }
}

impl GateError {
    pub fn code(&self) -> &'static str {
        match self {
            GateError::IntegrityDenied(_) => "INTEGRITY.DIRECT.DENIED",
            GateError::AuthorizationUnauthorized(_) => "ENDORSE.UNAUTHORIZED",
            GateError::InvalidReference(_) => "REFERENCE.INVALID",
            GateError::Expired(_) => "EXPIRY.INVALID",
            GateError::CapabilityInvalid(_) => "CAPABILITY.INVALID",
        }
    }
}

impl std::error::Error for GateError {}

pub type AuditRecord = (String, u64, String);
pub type ScanResult = Result<(bool, Vec<AuditRecord>), GateError>;

#[derive(Debug, Default)]
pub struct Gate {
    pub audit: Vec<AuditRecord>,
}

impl Gate {
    pub fn new() -> Self {
        Self { audit: Vec::new() }
    }

    /// Validate capability structure: scope and from_principal grammar.
    /// Returns Err(CapabilityInvalid) if the capability's scope or from_principal
    /// is structurally malformed. Mirrors the parser's ASCII identifier rules.
    fn validate_capability_structure(&self, cap: &Capability) -> Result<(), GateError> {
        if cap.cap_hash.is_empty() {
            return Err(GateError::InvalidReference("Capability must have non-empty hash".into()));
        }
        let scope = &cap.scope;
        if scope.is_empty() {
            return Err(GateError::CapabilityInvalid("Capability scope must be non-empty".into()));
        }
        for seg in scope.split('.') {
            if seg.is_empty() {
                return Err(GateError::CapabilityInvalid(format!("Invalid scope segment '{}'", seg)));
            }
            if !seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(GateError::CapabilityInvalid(format!(
                    "Invalid scope segment '{}' (must be ASCII alphanumeric or '_')",
                    seg
                )));
            }
        }
        let pid = &cap.from_principal.id;
        if pid.is_empty() {
            return Err(GateError::CapabilityInvalid("Capability from_principal must be non-empty".into()));
        }
        for seg in pid.split(':') {
            if seg.is_empty() {
                return Err(GateError::CapabilityInvalid(format!("Invalid from_principal segment in '{}'", pid)));
            }
            if !seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(GateError::CapabilityInvalid(format!(
                    "Invalid from_principal segment '{}' (must be ASCII alphanumeric or '_')",
                    seg
                )));
            }
        }
        Ok(())
    }

    fn validate_reference(&self, reference: &Reference) -> Result<(), GateError> {
        if reference.principal.id.is_empty() || reference.content_hash.is_empty() {
            return Err(GateError::InvalidReference("Reference must be (principal, content hash)".into()));
        }
        Ok(())
    }

    pub fn execute(&mut self, act: &Act, now: Option<u64>) -> Result<(), GateError> {
        let now = now.unwrap_or_else(|| SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
        let mut allowed = true;
        let mut first_err: Option<GateError> = None;

        macro_rules! fail_if {
            ($cond:expr, $code:expr, $msg:expr) => {
                if $cond {
                    if first_err.is_none() {
                        first_err = Some(GateError::new($code, $msg));
                    }
                    allowed = false;
                }
            };
        }

        match act {
            Act::Direct(da) => {
                if let Err(e) = self.validate_capability_structure(&da.capability) {
                    if first_err.is_none() { first_err = Some(e); }
                    allowed = false;
                }
                fail_if!(da.capability.integrity_level != "low", "INTEGRITY.DIRECT.DENIED", "Directive integrity 'low' does not meet capability requirement");
                if let Err(e) = self.validate_reference(&da.call.tool) {
                    if first_err.is_none() { first_err = Some(e); }
                    allowed = false;
                }
                fail_if!(da.capability.exp < 1, "EXPIRY.INVALID", format!("Capability TTL must be an integer in 1..=i64::MAX, got {}", da.capability.exp).as_str());
            }
            Act::Endorse(ea) => {
                if let Err(e) = self.validate_reference(&ea.reference) {
                    if first_err.is_none() { first_err = Some(e); }
                    allowed = false;
                }
                fail_if!(ea.signer.id.is_empty(), "REFERENCE.INVALID", "Invalid endorsement signer");
                // Rule 3: signer must be authorized. Mirrors Python gate:
                // allowed pairs [('admin','any'), ('reviewer','top_secret')];
                // authorized if signer.id startswith p OR endswith h for any pair.
                let allowed = [("admin", "any"), ("reviewer", "top_secret")];
                let authorized = allowed.iter().any(|(p, h)| ea.signer.id.starts_with(p) || ea.signer.id.ends_with(h));
                fail_if!(!authorized, "ENDORSE.UNAUTHORIZED", format!("Signer '{}' lacks authority to elevate integrity", ea.signer.id).as_str());
            }
            Act::Assert(a) => {
                if let Err(e) = self.validate_reference(&a.evidence) {
                    if first_err.is_none() { first_err = Some(e); }
                    allowed = false;
                }
            }
            Act::Query(a) => {
                if let Err(e) = self.validate_reference(&a.evidence) {
                    if first_err.is_none() { first_err = Some(e); }
                    allowed = false;
                }
            }
            Act::Commit(a) => {
                if let Err(e) = self.validate_reference(&a.reference) {
                    if first_err.is_none() { first_err = Some(e); }
                    allowed = false;
                }
            }
            Act::Grant(g) => {
                if let Err(e) = self.validate_capability_structure(&g.capability) {
                    if first_err.is_none() { first_err = Some(e); }
                    allowed = false;
                }
                fail_if!(g.capability.exp < 1, "EXPIRY.INVALID", format!("Capability TTL must be an integer in 1..=i64::MAX, got {}", g.capability.exp).as_str());
            }
            Act::Revoke(a) => {
                if let Err(e) = self.validate_capability_structure(&a.capability) {
                    if first_err.is_none() { first_err = Some(e); }
                    allowed = false;
                }
                fail_if!(a.capability.exp < 1, "EXPIRY.INVALID", format!("Capability TTL must be an integer in 1..=i64::MAX, got {}", a.capability.exp).as_str());
            }
        }

        let status = if allowed { "ALLOW" } else { "DENY" };
        self.audit.push((act_type(act).to_string(), now, status.to_string()));
        if self.audit.len() > MAX_AUDIT_RECORDS {
            self.audit.drain(..self.audit.len() - MAX_AUDIT_RECORDS);
        }
        if allowed { Ok(()) } else { Err(first_err.unwrap()) }
    }

    #[allow(dead_code)]
    pub fn scan(&mut self, source: &str) -> ScanResult {
        let acts = parse(source).map_err(|e| GateError::new("REFERENCE.INVALID", &format!("parse error: {}", e)))?;
        let mut all_allowed = true;
        for act in &acts {
            if let Err(_e) = self.execute(act, None) {
                all_allowed = false;
            }
        }
        Ok((all_allowed, self.audit.clone()))
    }
}
