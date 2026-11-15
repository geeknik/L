//! TSD CLI - Rust binary entry point.
//! Reads an L program file, parses it, runs every act through the gate,
//! and reports validation result.
//!
//! `--emit` retains the legacy per-act result format. `--emit-ast` exposes
//! every AST field and gate decision to the differential test oracle.

use std::env;
use std::fs;
use std::io::Read;
use std::process;

use tsd_rust::{Gate, act_type, parse, ParamValue, Act, Principal, Reference, Capability};
use tsd_rust::limits::MAX_SOURCE_BYTES;

fn main() {
    let args: Vec<String> = env::args().collect();
    let ast_mode = args.get(1).is_some_and(|arg| arg == "--emit-ast");
    let (emit_mode, path) = if args.len() >= 2 && (args[1] == "--emit" || ast_mode) {
        if args.len() < 3 {
            eprintln!("Usage: tsd-rust [--emit|--emit-ast] <file>");
            process::exit(1);
        }
        (true, args[2].clone())
    } else if args.len() >= 2 {
        (false, args[1].clone())
    } else {
        eprintln!("Usage: tsd-rust [--emit|--emit-ast] <file>");
        process::exit(1);
    };

    let bytes = match fs::File::open(&path).and_then(|file| {
        let mut bytes = Vec::new();
        file.take(MAX_SOURCE_BYTES as u64 + 1).read_to_end(&mut bytes)?;
        Ok(bytes)
    }) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error reading {}: {}", path, e);
            process::exit(1);
        }
    };
    if bytes.len() > MAX_SOURCE_BYTES {
        if ast_mode {
            println!("[\"PARSE_ERROR\"]");
            return;
        }
        eprintln!("Source exceeds byte limit");
        process::exit(1);
    }
    let source = match String::from_utf8(bytes) {
        Ok(source) => source,
        Err(_) => {
            eprintln!("Source is not valid UTF-8");
            process::exit(1);
        }
    };

    if ast_mode {
        println!("{}", emit_ast(&source));
        return;
    }
    if emit_mode {
        match emit(&source) {
            Ok(out) => { print!("{}", out); }
            Err(e) => {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        }
        return;
    }

    match run(&source) {
        Ok((valid, acts)) => {
            println!("File: {}", path);
            println!("Valid: {}", valid);
            println!("Acts parsed: {}", acts);
            if valid {
                println!("VALIDATION PASSED");
            } else {
                println!("VALIDATION FAILED");
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

/// Test-oracle JSON encoding; this is not the language's wire codec.
fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if c <= '\u{1f}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn principal_json(p: &Principal) -> String {
    format!("[{},{}]", json_string(&p.id), json_string(&p.hash))
}

fn reference_json(r: &Reference) -> String {
    format!("[{},{}]", principal_json(&r.principal), json_string(&r.content_hash))
}

fn capability_json(c: &Capability) -> String {
    format!("[{},{},{},{},{}]", json_string(&c.cap_hash), json_string(&c.scope),
            c.exp, principal_json(&c.from_principal), json_string(&c.integrity_level))
}

fn act_json(act: &Act) -> String {
    match act {
        Act::Assert(a) => format!("[\"ASSERT\",{},[{},{}]]", reference_json(&a.evidence), json_string(&a.data.content), a.data.is_opaque),
        Act::Query(a) => format!("[\"QUERY\",{},[{},{}]]", reference_json(&a.evidence), json_string(&a.data.content), a.data.is_opaque),
        Act::Direct(a) => {
            let mut keys: Vec<_> = a.call.params.keys().collect();
            keys.sort();
            let params: Vec<_> = keys.into_iter().map(|key| {
                let value = match &a.call.params[key] {
                    ParamValue::Str(v) => format!("[\"str\",{}]", json_string(v)),
                    ParamValue::Int(v) => format!("[\"int\",{}]", v),
                };
                format!("[{},{}]", json_string(key), value)
            }).collect();
            format!("[\"DIRECT\",{},{},[{}]]", capability_json(&a.capability), reference_json(&a.call.tool), params.join(","))
        }
        Act::Commit(a) => format!("[\"COMMIT\",{}]", reference_json(&a.reference)),
        Act::Grant(a) => format!("[\"GRANT\",{}]", capability_json(&a.capability)),
        Act::Revoke(a) => format!("[\"REVOKE\",{}]", capability_json(&a.capability)),
        Act::Endorse(a) => format!("[\"ENDORSE\",{},{}]", reference_json(&a.reference), principal_json(&a.signer)),
    }
}

fn emit_ast(source: &str) -> String {
    let acts = match parse(source) {
        Ok(acts) => acts,
        Err(_) => return "[\"PARSE_ERROR\"]".into(),
    };
    let mut gate = Gate::new();
    let records: Vec<_> = acts.iter().map(|act| {
        let decision = match gate.execute(act, None) {
            Ok(()) => "[\"ALLOW\"]".into(),
            Err(e) => format!("[\"DENY\",{}]", json_string(e.code())),
        };
        format!("[{},{}]", act_json(act), decision)
    }).collect();
    format!("[\"OK\",[{}]]", records.join(","))
}

fn run(source: &str) -> Result<(bool, usize), Box<dyn std::error::Error>> {
    let acts = parse(source)?;
    let mut gate = Gate::new();
    let mut all_allowed = true;
    for act in &acts {
        if let Err(_e) = gate.execute(act, None) {
            all_allowed = false;
        }
    }
    Ok((all_allowed, acts.len()))
}

/// Emit per-act results in stable format for differential fuzzing.
fn emit(source: &str) -> Result<String, Box<dyn std::error::Error>> {
    let acts = parse(source)?;
    let mut gate = Gate::new();
    let mut out = format!("ACTS={}\n", acts.len());
    for act in &acts {
        match gate.execute(act, None) {
            Ok(()) => out.push_str(&format!("{} ALLOW\n", act_type(act))),
            Err(e) => out.push_str(&format!("{} DENY {}\n", act_type(act), e.code())),
        }
        // Canonical param dump: key=value, sorted, value encoded as s:<str> or i:<int>.
        // Backslash and newline are escaped inside string values so a multiline
        // string and separate key=value lines never collide.
        if let Act::Direct(d) = act {
            let mut keys: Vec<&String> = d.call.params.keys().collect();
            keys.sort();
            for k in keys {
                match &d.call.params[k] {
                    ParamValue::Str(v) => {
                        let escaped: String = v.chars().flat_map(|c| match c {
                            '\\' => "\\\\".chars().collect::<Vec<_>>(),
                            '\n' => "\\n".chars().collect::<Vec<_>>(),
                            _ => vec![c],
                        }).collect();
                        out.push_str(&format!("P {} s:{}\n", k, escaped));
                    }
                    ParamValue::Int(v) => out.push_str(&format!("P {} i:{}\n", k, v)),
                }
            }
        }
    }
    Ok(out)
}
