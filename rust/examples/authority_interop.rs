//! Public-only interoperability fixture. Generates an ephemeral test key from
//! the Unix lab's OS random source; never prints or persists private key bytes.
use std::io::Read;
use tsd_rust::authority::{Authority, Claims};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let template: serde_json::Value = serde_json::from_str(include_str!("../../conformance/security_vectors.json"))?;
    let issuer = template["issuer"].as_str().ok_or("fixture issuer missing")?;
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut seed)?;
    let authority = Authority::new(issuer.to_string(), &seed)?;
    // The signing key owns its copy; do not include this seed in fixture output.
    seed.fill(0);
    let mut fixture = serde_json::json!({
        "description": "EPHEMERAL PUBLIC TEST ONLY; do not trust this key in deployment",
        "public_key_hex": hex(&authority.public_key()),
        "issuer": issuer,
        "subject": template["subject"],
        "source": template["source"],
        "now": template["now"],
    });
    for kind in ["grant", "endorse", "revoke"] {
        let payload = template[kind]["payload_utf8"].as_str().ok_or("fixture payload missing")?;
        let claims: Claims = serde_json::from_str(payload)?;
        let envelope = authority.issue(&claims)?;
        fixture[kind] = serde_json::json!({
            "payload_utf8": String::from_utf8(envelope.payload)?,
            "signature_hex": hex(&envelope.signature),
        });
    }
    println!("{}", serde_json::to_string(&fixture)?);
    Ok(())
}
