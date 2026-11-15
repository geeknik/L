//! Security decisions use signed authority, not the structural Gate's ALLOW.
use std::collections::HashMap;
use std::io::Read;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use tsd_rust::authority::{Authority, Claims, DOMAIN, Envelope, Integrity, SecurityError, TrustKey};
use tsd_rust::limits::{MAX_AUDIT_RECORDS, MAX_AUTHORITY_BYTES, MAX_SECURITY_RECORDS};
use tsd_rust::security::SecurityGate;

fn ephemeral_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    // Tests run on the local Unix lab; production key custody is host-owned.
    std::fs::File::open("/dev/urandom").unwrap().read_exact(&mut seed).unwrap();
    seed
}
fn policy(public_key: [u8; 32]) -> TrustKey {
    TrustKey { public_key, kinds: ["grant", "endorse", "revoke"].into_iter().map(str::to_string).collect(),
        scopes: ["fs.read"].into_iter().map(str::to_string).collect(), max_integrity: Integrity::Critical }
}
fn setup(initial: Integrity) -> (Authority, SecurityGate) {
    let authority = Authority::new("issuer".into(), &ephemeral_seed()).unwrap();
    let trust = HashMap::from([("issuer".into(), policy(authority.public_key()))]);
    (authority, SecurityGate::new("session:alice".into(), trust, initial).unwrap())
}
fn source() -> String {
    format!("DIRECT cap:{} (scope=fs.read, exp=60, from=issuer) call tool:(srv:files, sha256:{}) {{path: \"/logs\"}}", "a".repeat(64), "b".repeat(64))
}
fn claims(kind: &str, nonce: usize) -> Claims {
    Claims { version: 1, kind: kind.into(), issuer: "issuer".into(), subject: "session:alice".into(),
        capability: "a".repeat(64), scope: "fs.read".into(), tool_principal: "srv:files".into(),
        tool_hash: "b".repeat(64), integrity: Integrity::High,
        action_hash: if kind == "endorse" { format!("{:x}", Sha256::digest(source().as_bytes())) } else { String::new() },
        issued_at: 100, expires_at: 200, nonce: format!("{nonce:064x}") }
}
fn code<T>(result: Result<T, SecurityError>, expected: &str) {
    assert_eq!(result.err().expect("operation must deny").code, expected);
}
fn sign_raw(seed: &[u8; 32], payload: Vec<u8>) -> Envelope {
    let mut message = DOMAIN.to_vec(); message.extend_from_slice(&payload);
    Envelope { signature: SigningKey::from_bytes(seed).sign(&message).to_bytes().to_vec(), payload }
}
fn hex(value: &str) -> Vec<u8> {
    (0..value.len()).step_by(2).map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap()).collect()
}

#[test]
fn signed_lifecycle_requires_one_use_exact_action_approval() {
    let (authority, mut gate) = setup(Integrity::Low);
    code(gate.execute(&source(), 110), "AUTH.REQUIRED");
    let grant = authority.issue(&claims("grant", 1)).unwrap();
    gate.apply(&grant, 110).unwrap();
    code(gate.apply(&grant, 110), "AUTH.REPLAY");
    code(gate.execute(&source(), 110), "INTEGRITY.DENIED");
    gate.apply(&authority.issue(&claims("endorse", 2)).unwrap(), 110).unwrap();
    code(gate.execute(&source().replace("/logs", "/other"), 110), "INTEGRITY.DENIED");
    code(gate.execute(&(source() + " "), 110), "INTEGRITY.DENIED");
    gate.execute(&source(), 110).unwrap();
    assert_eq!(gate.integrity(), Integrity::Low);
    code(gate.execute(&source(), 110), "INTEGRITY.DENIED");
    gate.apply(&authority.issue(&claims("revoke", 3)).unwrap(), 110).unwrap();
    code(gate.execute(&source(), 110), "AUTH.REVOKED");
    code(gate.apply(&authority.issue(&claims("grant", 4)).unwrap(), 110), "AUTH.REVOKED");
}

#[test]
fn schema_signature_and_trust_are_fail_closed() {
    let seed = ephemeral_seed();
    let key = SigningKey::from_bytes(&seed);
    let trust = HashMap::from([("issuer".into(), policy(key.verifying_key().to_bytes()))]);
    let encoded = serde_json::to_string(&claims("grant", 1)).unwrap();
    for payload in [
        encoded.replacen("\"version\":1", "\"version\":true", 1),
        encoded.replacen("\"version\":1", "\"version\":1,\"version\":1", 1),
        encoded.replacen("\"version\":1", "\"version\":1,\"unknown\":0", 1),
        encoded.replacen("\"issued_at\":100", "\"issued_at\":100.0", 1),
        encoded.replacen("\"issued_at\":100", "\"issued_at\":-1", 1),
        encoded.replacen("\"expires_at\":200", "\"expires_at\":9223372036854775808", 1),
    ] {
        let mut gate = SecurityGate::new("session:alice".into(), trust.clone(), Integrity::Low).unwrap();
        code(gate.apply(&sign_raw(&seed, payload.into_bytes()), 110), "AUTH.INVALID");
        code(gate.execute(&source(), 110), "AUTH.REQUIRED");
    }
    let mut envelope = sign_raw(&seed, encoded.into_bytes());
    envelope.signature[0] ^= 1;
    let mut gate = SecurityGate::new("session:alice".into(), trust, Integrity::Low).unwrap();
    code(gate.apply(&envelope, 110), "AUTH.INVALID");
    let (_, mut unknown) = setup(Integrity::Low);
    code(unknown.apply(&envelope, 110), "AUTH.INVALID");
    let mut no_keys = SecurityGate::new("session:alice".into(), HashMap::new(), Integrity::Low).unwrap();
    code(no_keys.apply(&sign_raw(&seed, serde_json::to_vec(&claims("grant", 1)).unwrap()), 110), "AUTH.INVALID");
}

#[test]
fn exact_scope_role_and_integrity_ceiling_are_enforced() {
    let authority = Authority::new("issuer".into(), &ephemeral_seed()).unwrap();
    for mut policy in [policy(authority.public_key()), policy(authority.public_key()), policy(authority.public_key())].into_iter().enumerate() {
        match policy.0 { 0 => policy.1.scopes.clear(), 1 => policy.1.kinds.clear(), _ => policy.1.max_integrity = Integrity::Low }
        let mut gate = SecurityGate::new("session:alice".into(), HashMap::from([("issuer".into(), policy.1)]), Integrity::Low).unwrap();
        code(gate.apply(&authority.issue(&claims("grant", 1)).unwrap(), 110), "AUTH.INVALID");
    }
}

#[test]
fn timestamps_and_session_binding_are_enforced() {
    let (authority, mut gate) = setup(Integrity::High);
    let envelope = authority.issue(&claims("grant", 1)).unwrap();
    code(gate.apply(&envelope, 99), "AUTH.EXPIRED");
    gate.apply(&envelope, 100).unwrap();
    gate.execute(&source(), 199).unwrap();
    code(gate.execute(&source(), 198), "TIME.INVALID");
    code(gate.execute(&source(), 200), "AUTH.EXPIRED");
    code(gate.execute(&source(), -1), "TIME.INVALID");
    let mut statement = claims("grant", 2); statement.subject = "session:bob".into();
    // Use matching trust so rejection is specifically the session binding.
    let trust = HashMap::from([("issuer".into(), policy(authority.public_key()))]);
    let mut wrong = SecurityGate::new("session:alice".into(), trust, Integrity::High).unwrap();
    code(wrong.apply(&authority.issue(&statement).unwrap(), 110), "AUTH.MISMATCH");
}

#[test]
fn tool_capability_and_ttl_must_match_signed_grant() {
    let (authority, mut gate) = setup(Integrity::High);
    gate.apply(&authority.issue(&claims("grant", 1)).unwrap(), 110).unwrap();
    for altered in [source().replace("fs.read", "fs.write"), source().replace("from=issuer", "from=other"),
        source().replace("srv:files", "srv:other"), source().replace(&"b".repeat(64), &"c".repeat(64)),
        source().replace("exp=60", "exp=101")] {
        code(gate.execute(&altered, 110), "AUTH.MISMATCH");
    }
    code(gate.execute(&source().replace(&"a".repeat(64), &"c".repeat(64)), 110), "AUTH.REQUIRED");
    gate.execute(&source(), 110).unwrap();
}

#[test]
fn revoke_requires_grant_issuer_and_clears_approvals() {
    let authority = Authority::new("issuer".into(), &ephemeral_seed()).unwrap();
    let other = Authority::new("other".into(), &ephemeral_seed()).unwrap();
    let trust = HashMap::from([("issuer".into(), policy(authority.public_key())), ("other".into(), policy(other.public_key()))]);
    let mut gate = SecurityGate::new("session:alice".into(), trust, Integrity::Low).unwrap();
    gate.apply(&authority.issue(&claims("grant", 1)).unwrap(), 110).unwrap();
    let mut approve = claims("endorse", 2); approve.issuer = "other".into();
    gate.apply(&other.issue(&approve).unwrap(), 110).unwrap();
    let mut revoke = claims("revoke", 3); revoke.issuer = "other".into();
    code(gate.apply(&other.issue(&revoke).unwrap(), 110), "AUTH.MISMATCH");
    gate.apply(&authority.issue(&claims("revoke", 4)).unwrap(), 110).unwrap();
    code(gate.execute(&source(), 110), "AUTH.REVOKED");
}

#[test]
fn observe_matches_shared_lattice_and_assert_lowers_trust() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!("../../conformance/label_vectors.json")).unwrap();
    let levels = [Integrity::Low, Integrity::Medium, Integrity::High, Integrity::Critical];
    for (i, initial) in levels.iter().enumerate() {
        for (j, input) in levels.iter().enumerate() {
            let (_, mut gate) = setup(*initial); gate.observe(*input);
            assert_eq!(serde_json::to_value(gate.integrity()).unwrap(), vectors["expected"][i][j]);
        }
    }
    let (_, mut gate) = setup(Integrity::Critical);
    let source = format!("ASSERT ev:(user:g, sha256:{}) data:<untrusted>", "b".repeat(64));
    gate.execute(&source, 110).unwrap();
    assert_eq!(gate.integrity(), Integrity::Low);
    gate.observe(Integrity::Critical);
    assert_eq!(gate.integrity(), Integrity::Low);
}

#[test]
fn structural_allow_cannot_install_authority() {
    let (_, mut gate) = setup(Integrity::Critical);
    for act in ["GRANT", "REVOKE"] {
        let source = format!("{} cap:{} (scope=fs.read, exp=60, from=issuer)", act, "a".repeat(64));
        code(gate.execute(&source, 110), "AUTH.REQUIRED");
    }
    code(gate.execute(&format!("ENDORSE (user:g, sha256:{}) by:admin", "b".repeat(64)), 110), "AUTH.REQUIRED");
    code(gate.execute(&(source() + "\n" + &source()), 110), "ACT.INVALID");
    code(gate.execute("COMMIT (sha256:aaaaaaaa)", 110), "ACT.INVALID");
    code(gate.execute(&source(), 110), "AUTH.REQUIRED");
}

#[test]
fn capacities_and_audit_are_bounded_without_payload_retention() {
    let (authority, mut gate) = setup(Integrity::Low);
    gate.apply(&authority.issue(&claims("grant", 0)).unwrap(), 110).unwrap();
    for nonce in 1..MAX_SECURITY_RECORDS {
        gate.apply(&authority.issue(&claims("endorse", nonce)).unwrap(), 110).unwrap();
    }
    code(gate.apply(&authority.issue(&claims("revoke", MAX_SECURITY_RECORDS)).unwrap(), 110), "AUTH.CAPACITY");
    let envelope = Envelope { payload: vec![b'x'; MAX_AUTHORITY_BYTES + 1], signature: vec![0; 64] };
    code(gate.apply(&envelope, 110), "AUTH.CAPACITY");
    assert_eq!(gate.audit().len(), MAX_AUDIT_RECORDS);
    assert!(!format!("{:?}", gate.audit()).contains("/logs"));
    code(gate.execute(&source(), 110), "AUTH.CAPACITY");
    gate.observe(Integrity::Critical);
    code(gate.execute(&source(), 110), "AUTH.CAPACITY");
    gate.execute(&format!("COMMIT (user:g, sha256:{})", "b".repeat(64)), 110).unwrap();
}

#[test]
fn shared_python_signed_vectors_verify_in_rust() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!("../../conformance/security_vectors.json")).unwrap();
    let key: [u8; 32] = hex(fixture["public_key_hex"].as_str().unwrap()).try_into().unwrap();
    let trust = HashMap::from([(fixture["issuer"].as_str().unwrap().to_string(), policy(key))]);
    let mut gate = SecurityGate::new(fixture["subject"].as_str().unwrap().into(), trust, Integrity::Low).unwrap();
    let envelope = |kind: &str| Envelope { payload: fixture[kind]["payload_utf8"].as_str().unwrap().as_bytes().to_vec(),
        signature: hex(fixture[kind]["signature_hex"].as_str().unwrap()) };
    let source = fixture["source"].as_str().unwrap();
    let now = fixture["now"].as_i64().unwrap();
    gate.apply(&envelope("grant"), now).unwrap();
    code(gate.execute(source, now), "INTEGRITY.DENIED");
    gate.apply(&envelope("endorse"), now).unwrap();
    gate.execute(source, now).unwrap();
    code(gate.execute(source, now), "INTEGRITY.DENIED");
    gate.apply(&envelope("revoke"), now).unwrap();
    code(gate.execute(source, now), "AUTH.REVOKED");
}

#[test]
fn weak_public_key_and_invalid_unicode_claims_are_rejected() {
    let mut identity = [0u8; 32]; identity[0] = 1;
    let trust = HashMap::from([("issuer".into(), policy(identity))]);
    code(SecurityGate::new("session:alice".into(), trust.clone(), Integrity::Low), "AUTH.INVALID");
    let mut signature = vec![0u8; 64]; signature[0] = 1;
    let envelope = Envelope { payload: serde_json::to_vec(&claims("grant", 1)).unwrap(), signature };
    code(tsd_rust::authority::verify(&envelope, &trust), "AUTH.INVALID");

    let seed = ephemeral_seed();
    let key = SigningKey::from_bytes(&seed);
    let trust = HashMap::from([("issuer".into(), policy(key.verifying_key().to_bytes()))]);
    let mut gate = SecurityGate::new("session:alice".into(), trust, Integrity::Low).unwrap();
    let payload = serde_json::to_string(&claims("grant", 1)).unwrap().replace("session:alice", "\\ud800");
    code(gate.apply(&sign_raw(&seed, payload.into_bytes()), 110), "AUTH.INVALID");
}

#[test]
fn approval_expiry_and_metadata_fail_without_consuming_valid_authority() {
    let (authority, mut gate) = setup(Integrity::Low);
    gate.apply(&authority.issue(&claims("grant", 1)).unwrap(), 110).unwrap();
    let mut approval = claims("endorse", 2); approval.expires_at = 120;
    gate.apply(&authority.issue(&approval).unwrap(), 110).unwrap();
    code(gate.execute(&source(), 120), "INTEGRITY.DENIED");
    let mut wrong = claims("endorse", 3); wrong.tool_hash = "c".repeat(64);
    code(gate.apply(&authority.issue(&wrong).unwrap(), 120), "AUTH.MISMATCH");
    wrong.tool_hash = "b".repeat(64); wrong.expires_at = 201;
    code(gate.apply(&authority.issue(&wrong).unwrap(), 120), "AUTH.MISMATCH");
    wrong.expires_at = 200;
    gate.apply(&authority.issue(&wrong).unwrap(), 120).unwrap();
    gate.execute(&source(), 120).unwrap();
}
