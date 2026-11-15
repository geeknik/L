use serde_json::{Value, json};
use tsd_rust::{ast::*, limits::*, wire};
fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn vectors() -> Value {
    serde_json::from_str(include_str!("../../conformance/wire_vectors.json")).unwrap()
}
#[test]
fn shared_vectors() {
    let v = vectors();
    for case in v["accept"].as_array().unwrap() {
        let b = unhex(case["hex"].as_str().unwrap());
        let p = case["projection"].as_str().unwrap();
        assert_eq!(wire::project(&b).unwrap(), p);
        assert_eq!(wire::unproject(p).unwrap(), b);
        assert_eq!(wire::encode(&wire::decode(&b).unwrap()).unwrap(), b);
    }
    for case in v["reject"].as_array().unwrap() {
        assert_eq!(
            wire::decode(&unhex(case["hex"].as_str().unwrap())).unwrap_err(),
            wire::WireError
        );
    }
}
#[test]
fn truncation_and_noncanonical_mutations() {
    for case in vectors()["accept"].as_array().unwrap() {
        let b = unhex(case["hex"].as_str().unwrap());
        for n in 0..b.len() {
            assert!(wire::decode(&b[..n]).is_err());
        }
        let mut trailing = b.clone();
        trailing.push(0);
        assert!(wire::decode(&trailing).is_err());
        let p = case["projection"].as_str().unwrap();
        assert!(wire::unproject(p.trim_end()).is_err());
        assert!(wire::unproject(&format!(" {p}")).is_err());
        assert!(wire::unproject(&p.replacen('1', "1.0", 1)).is_err());
    }
    for hex in [
        "8219000180",
        "821a0000000180",
        "821b000000000000000180",
        "82019800",
        "82014100",
        "8201c080",
        "8201f90000",
        "820120",
        "82011c",
        "82011bffffffffffffffff",
        "82017b7fffffffffffffff",
        "82019b7fffffffffffffff",
    ] {
        assert!(wire::decode(&unhex(hex)).is_err(), "{hex}");
    }
}
#[test]
fn schema_refuses_unknown_and_invalid_fields() {
    let v = vectors();
    let mut base: Value =
        serde_json::from_str(v["accept"][3]["projection"].as_str().unwrap()).unwrap();
    let cases = [
        json!(true),
        json!(-1),
        json!(9223372036854775808u64),
        json!("1"),
    ];
    for bad in cases {
        base[1][0][1][2] = bad;
        assert!(wire::unproject(&(base.to_string() + "\n")).is_err());
    }
    for bad in [
        json!([["x", ["int", 1]], ["x", ["int", 2]]]),
        json!([["z", ["int", 1]], ["a", ["int", 2]]]),
        json!([["", ["str", ""]]]),
        json!([["x", ["bool", true]]]),
    ] {
        let mut model: Value =
            serde_json::from_str(v["accept"][3]["projection"].as_str().unwrap()).unwrap();
        model[1][0][3] = bad;
        assert!(wire::unproject(&(model.to_string() + "\n")).is_err());
    }
    for p in [
        "[1,[]] \n",
        "[1,[]]\n\n",
        "[true,[]]\n",
        "[1,{},0]\n",
        "[1,[[\"COMMIT\",[[\"\",\"00\"],\"ab\"]]]]\n",
    ] {
        assert!(wire::unproject(p).is_err());
    }
}
#[test]
fn hostile_bounds_and_direct_ast() {
    assert!(wire::decode(&vec![0; MAX_WIRE_BYTES + 1]).is_err());
    assert!(wire::unproject(&" ".repeat(MAX_WIRE_BYTES + 1)).is_err());
    let deep = "[".repeat(MAX_WIRE_DEPTH + 2) + "0" + &"]".repeat(MAX_WIRE_DEPTH + 2) + "\n";
    assert!(wire::unproject(&deep).is_err());
    let mut binary = vec![0x81; MAX_WIRE_DEPTH + 2];
    binary.push(0);
    assert!(wire::decode(&binary).is_err());
    let many = "[".to_owned() + &vec!["0"; MAX_WIRE_NODES + 1].join(",") + "]\n";
    assert!(wire::unproject(&many).is_err());
    let p = Principal {
        id: "user:g".into(),
        hash: "00".into(),
    };
    let act = Act::Assert(AssertAct {
        evidence: Reference {
            principal: p,
            content_hash: "ab".into(),
        },
        data: Payload {
            content: "x".repeat(MAX_WIRE_BYTES),
            is_opaque: true,
        },
    });
    assert!(wire::encode(std::slice::from_ref(&act)).is_err());
    assert!(wire::encode(&vec![act; MAX_ACTS + 1]).is_err());
}

#[test]
fn exact_byte_boundaries_and_integer_widths() {
    let mut acts = wire::decode(&unhex(vectors()["accept"][1]["hex"].as_str().unwrap())).unwrap();
    if let Act::Assert(a) = &mut acts[0] {
        a.data.content.clear();
    }
    let overhead = wire::encode(&acts).unwrap().len();
    if let Act::Assert(a) = &mut acts[0] {
        a.data.content = "x".repeat(MAX_WIRE_BYTES - overhead - 2);
    }
    // Even a fitting binary refuses if its JSON projection exceeds the bound.
    assert!(wire::encode(&acts).is_err());
    if let Act::Assert(a) = &mut acts[0] {
        a.data.content.push('x');
    }
    assert!(wire::encode(&acts).is_err());
    if let Act::Assert(a) = &mut acts[0] {
        a.data.content.clear();
    }
    let projection_overhead = wire::project(&wire::encode(&acts).unwrap()).unwrap().len();
    if let Act::Assert(a) = &mut acts[0] {
        a.data.content = "x".repeat(MAX_WIRE_BYTES - projection_overhead);
    }
    let projection = wire::project(&wire::encode(&acts).unwrap()).unwrap();
    assert_eq!(projection.len(), MAX_WIRE_BYTES);
    assert!(wire::unproject(&projection).is_ok());
    for n in [
        0,
        23,
        24,
        255,
        256,
        65535,
        65536,
        u32::MAX as i64,
        u32::MAX as i64 + 1,
        i64::MAX,
    ] {
        let mut model: Value =
            serde_json::from_str(vectors()["accept"][3]["projection"].as_str().unwrap()).unwrap();
        model[1][0][1][2] = json!(n);
        model[1][0][3][0][1][1] = json!(n);
        let projection = model.to_string() + "\n";
        assert_eq!(
            wire::project(&wire::unproject(&projection).unwrap()).unwrap(),
            projection
        );
    }
}

#[test]
fn binary_acceptance_requires_bounded_projection() {
    let mut acts = wire::decode(&unhex(vectors()["accept"][1]["hex"].as_str().unwrap())).unwrap();
    if let Act::Assert(a) = &mut acts[0] {
        a.data.content.clear();
    }
    let mut raw = wire::encode(&acts).unwrap();
    // Replace the empty payload text and final opaque=true with a long control
    // payload. The CBOR fits, but each NUL expands to six projection bytes.
    raw.truncate(raw.len() - 2);
    let count = MAX_WIRE_BYTES / 6;
    raw.push(0x79);
    raw.extend_from_slice(&(count as u16).to_be_bytes());
    raw.extend(std::iter::repeat_n(0, count));
    raw.push(0xf5);
    assert!(raw.len() < MAX_WIRE_BYTES);
    assert!(wire::decode(&raw).is_err());
    assert!(wire::project(&raw).is_err());
    if let Act::Assert(a) = &mut acts[0] {
        a.data.content = "\0".repeat(count);
    }
    assert!(wire::encode(&acts).is_err());
}
