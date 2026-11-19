//! Signed authority statements. Private signing material is separate from gates.

use std::collections::{HashMap, HashSet};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::de::IntoDeserializer;
use serde::{Deserialize, Serialize};
use crate::limits::{MAX_AUTHORITY_BYTES, MAX_SECURITY_RECORDS};

pub const DOMAIN: &[u8] = b"TSD-AUTHORITY-v1\0";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Integrity { #[default] Low, Medium, High, Critical }

fn deserialize_integrity<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Integrity, D::Error> {
    let name = String::deserialize(deserializer)?;
    Integrity::deserialize(name.into_deserializer())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub version: u8,
    pub kind: String,
    pub issuer: String,
    pub subject: String,
    pub capability: String,
    pub scope: String,
    pub tool_principal: String,
    pub tool_hash: String,
    #[serde(deserialize_with = "deserialize_integrity")]
    pub integrity: Integrity,
    pub action_hash: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub nonce: String,
}

#[derive(Clone)]
pub struct Envelope { pub payload: Vec<u8>, pub signature: Vec<u8> }

#[derive(Clone)]
pub struct TrustKey {
    pub public_key: [u8; 32],
    pub kinds: HashSet<String>,
    pub scopes: HashSet<String>,
    pub max_integrity: Integrity,
}

impl TrustKey {
    fn validated_key(&self) -> Result<VerifyingKey, SecurityError> {
        if self.kinds.iter().any(|kind| !matches!(kind.as_str(), "grant" | "endorse" | "revoke"))
            || self.scopes.len() > MAX_SECURITY_RECORDS
            || self.scopes.iter().any(|scope| scope.len() > MAX_AUTHORITY_BYTES || !name_valid(scope, '.')) {
            return Err(invalid());
        }
        strict_point(&self.public_key)
    }
    pub fn validate(&self) -> Result<(), SecurityError> { self.validated_key().map(|_| ()) }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityError { pub code: &'static str }

impl SecurityError { pub const fn new(code: &'static str) -> Self { Self { code } } }
impl std::fmt::Display for SecurityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code)
    }
}
impl std::error::Error for SecurityError {}

pub(crate) fn invalid() -> SecurityError { SecurityError::new("AUTH.INVALID") }

pub(crate) fn hash_valid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub(crate) fn name_valid(value: &str, separator: char) -> bool {
    !value.is_empty() && value.split(separator).all(|part| {
        !part.is_empty() && part.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
    })
}

pub(crate) fn validate_claims(claims: &Claims) -> Result<(), SecurityError> {
    if claims.version != 1 || !matches!(claims.kind.as_str(), "grant" | "endorse" | "revoke")
        || claims.issuer.is_empty() || claims.subject.is_empty()
        || !hash_valid(&claims.capability) || !hash_valid(&claims.tool_hash)
        || !hash_valid(&claims.nonce) || !name_valid(&claims.scope, '.')
        || !name_valid(&claims.tool_principal, ':') || claims.tool_principal == "anon"
        || claims.issued_at < 0 || claims.expires_at <= claims.issued_at
        || (claims.kind == "endorse" && !hash_valid(&claims.action_hash))
        || (claims.kind != "endorse" && !claims.action_hash.is_empty()) {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn signed_bytes(payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(DOMAIN.len() + payload.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(payload);
    message
}

fn strict_point(bytes: &[u8; 32]) -> Result<VerifyingKey, SecurityError> {
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| invalid())?;
    let point = key.to_edwards();
    if key.is_weak() || !point.is_torsion_free() || point.compress().to_bytes() != *bytes {
        return Err(invalid());
    }
    Ok(key)
}

fn decode_claims(payload: &[u8]) -> Result<Claims, SecurityError> {
    // Derived struct deserialization also accepts sequences. The wire contract
    // admits only objects, and typed decoding still checks all fields.
    if payload.len() > MAX_AUTHORITY_BYTES
        || payload.iter().copied().find(|b| !b.is_ascii_whitespace()) != Some(b'{') {
        return Err(invalid());
    }
    let claims = serde_json::from_slice(payload).map_err(|_| invalid())?;
    validate_claims(&claims)?;
    Ok(claims)
}

pub fn verify(envelope: &Envelope, trust: &HashMap<String, TrustKey>) -> Result<Claims, SecurityError> {
    if envelope.signature.len() != 64 { return Err(invalid()); }
    // Decode only for key lookup/schema checks. No decoded claim is trusted until
    // strict verification of the exact received bytes succeeds.
    let claims = decode_claims(&envelope.payload)?;
    let policy = trust.get(&claims.issuer).ok_or_else(invalid)?;
    let key = policy.validated_key()?;
    // Validate R with the library's point operations too. This rejects mixed
    // order/noncanonical encodings consistently with libsodium's point check.
    let r: [u8; 32] = envelope.signature[..32].try_into().map_err(|_| invalid())?;
    strict_point(&r)?;
    let signature = Signature::from_slice(&envelope.signature).map_err(|_| invalid())?;
    key.verify_strict(&signed_bytes(&envelope.payload), &signature).map_err(|_| invalid())?;
    if !policy.kinds.contains(&claims.kind) || !policy.scopes.contains(&claims.scope)
        || claims.integrity > policy.max_integrity { return Err(invalid()); }
    Ok(claims)
}

/// A local issuer. The host supplies and protects its signing key; no built-in
/// key or model-supplied identity is authorized by this type.
pub struct Authority { issuer: String, key: SigningKey }

impl Authority {
    pub fn new(issuer: String, secret: &[u8; 32]) -> Result<Self, SecurityError> {
        if issuer.is_empty() || issuer.len() > MAX_AUTHORITY_BYTES { return Err(invalid()); }
        Ok(Self { issuer, key: SigningKey::from_bytes(secret) })
    }
    pub fn public_key(&self) -> [u8; 32] { self.key.verifying_key().to_bytes() }
    pub fn issue(&self, claims: &Claims) -> Result<Envelope, SecurityError> {
        validate_claims(claims)?;
        if claims.issuer != self.issuer { return Err(invalid()); }
        let payload = serde_json::to_vec(claims).map_err(|_| invalid())?;
        if payload.len() > MAX_AUTHORITY_BYTES { return Err(invalid()); }
        let signature = self.key.sign(&signed_bytes(&payload)).to_bytes().to_vec();
        Ok(Envelope { payload, signature })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn claims_require_an_object_with_string_integrity() {
        // I7: Schema rejection is independent of signing or installing authority.
        let fixture: Value = serde_json::from_str(include_str!("../../conformance/security_vectors.json")).unwrap();
        let payload = fixture["grant"]["payload_utf8"].as_str().unwrap();
        let claims = decode_claims(payload.as_bytes()).unwrap();

        let positional = serde_json::json!([
            claims.version, claims.kind, claims.issuer, claims.subject, claims.capability,
            claims.scope, claims.tool_principal, claims.tool_hash, claims.integrity,
            claims.action_hash, claims.issued_at, claims.expires_at, claims.nonce,
        ]);
        assert!(decode_claims(positional.to_string().as_bytes()).is_err());
        let tagged = payload.replace("\"integrity\":\"high\"", "\"integrity\":{\"high\":null}");
        assert!(decode_claims(tagged.as_bytes()).is_err());
        let negative_zero = payload.replace("\"issued_at\":100", "\"issued_at\":-0");
        assert!(decode_claims(negative_zero.as_bytes()).is_err());
        let zero = payload.replace("\"issued_at\":100", "\"issued_at\":0");
        assert_eq!(decode_claims(zero.as_bytes()).unwrap().issued_at, 0);
    }
}
