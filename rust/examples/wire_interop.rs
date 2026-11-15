//! Bounded local cross-language codec probe. Never executes decoded acts.
use serde::Deserialize;
use serde_json::json;
use std::io::{self, BufRead, Write};
use tsd_rust::{limits::MAX_WIRE_BYTES, wire};

#[derive(Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
enum Command {
    #[serde(rename = "decode")]
    Decode { hex: String },
    #[serde(rename = "encode")]
    Encode { projection: String },
}
fn process(line: &[u8]) -> Result<serde_json::Value, wire::WireError> {
    let cmd: Command = serde_json::from_slice(line).map_err(|_| wire::WireError)?;
    match cmd {
        Command::Decode { hex } => {
            if hex.len() > MAX_WIRE_BYTES * 2 || !hex.len().is_multiple_of(2) {
                return Err(wire::WireError);
            }
            let data: Result<Vec<u8>, _> = hex
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    let s = std::str::from_utf8(pair).map_err(|_| wire::WireError)?;
                    u8::from_str_radix(s, 16).map_err(|_| wire::WireError)
                })
                .collect();
            Ok(json!({"projection": wire::project(&data?)?}))
        }
        Command::Encode { projection } => {
            let bytes = wire::unproject(&projection)?;
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            Ok(json!({"hex": hex}))
        }
    }
}
fn main() {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut output = io::stdout().lock();
    loop {
        // JSON escaping can expand a projection by six bytes per scalar.
        let mut line = Vec::new();
        let mut oversized = false;
        loop {
            let buf = match input.fill_buf() {
                Ok(b) => b,
                Err(_) => return,
            };
            if buf.is_empty() {
                break;
            }
            let count = buf
                .iter()
                .position(|b| *b == b'\n')
                .map_or(buf.len(), |i| i + 1);
            let ended = buf[count - 1] == b'\n';
            if line.len().saturating_add(count) <= MAX_WIRE_BYTES * 6 {
                line.extend_from_slice(&buf[..count]);
            } else {
                oversized = true;
            }
            input.consume(count);
            if ended {
                break;
            }
        }
        if line.is_empty() && !oversized {
            break;
        }
        let result = if oversized {
            Err(wire::WireError)
        } else {
            process(&line)
        };
        let response = match result {
            Ok(value) => value,
            Err(_) => json!({"error":"WIRE.INVALID"}),
        };
        if writeln!(output, "{response}").is_err() || output.flush().is_err() {
            return;
        }
    }
}
