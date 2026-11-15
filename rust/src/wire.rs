//! Closed deterministic CBOR transport. Decoding never authorizes execution.
use crate::ast::*;
use crate::limits::{MAX_ACTS, MAX_WIRE_BYTES, MAX_WIRE_DEPTH, MAX_WIRE_NODES};
use serde_json::{Value, json};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireError;
impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WIRE.INVALID")
    }
}
impl std::error::Error for WireError {}
type Result<T> = std::result::Result<T, WireError>;

fn array(v: &Value, len: usize) -> Result<&[Value]> {
    let a = v.as_array().ok_or(WireError)?;
    if a.len() != len {
        return Err(WireError);
    }
    Ok(a)
}
fn text(v: &Value) -> Result<&str> {
    v.as_str().ok_or(WireError)
}
fn uint(v: &Value) -> Result<i64> {
    v.as_u64()
        .filter(|n| *n <= i64::MAX as u64)
        .map(|n| n as i64)
        .ok_or(WireError)
}
fn segment(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
fn segmented(s: &str, sep: char) -> bool {
    s.split(sep).all(segment)
}
fn hash(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn principal(v: &Value) -> Result<Principal> {
    let a = array(v, 2)?;
    let (id, h) = (text(&a[0])?, text(&a[1])?);
    if !segmented(id, ':') || !hash(h) {
        return Err(WireError);
    }
    Ok(Principal {
        id: id.into(),
        hash: h.into(),
    })
}
fn reference(v: &Value) -> Result<Reference> {
    let a = array(v, 2)?;
    let h = text(&a[1])?;
    if !hash(h) {
        return Err(WireError);
    }
    Ok(Reference {
        principal: principal(&a[0])?,
        content_hash: h.into(),
    })
}
fn capability(v: &Value) -> Result<Capability> {
    let a = array(v, 5)?;
    let (h, scope, integrity) = (text(&a[0])?, text(&a[1])?, text(&a[4])?);
    if !hash(h)
        || !segmented(scope, '.')
        || !matches!(integrity, "low" | "medium" | "high" | "critical")
    {
        return Err(WireError);
    }
    Ok(Capability {
        cap_hash: h.into(),
        scope: scope.into(),
        exp: uint(&a[2])?,
        from_principal: principal(&a[3])?,
        integrity_level: integrity.into(),
    })
}
fn payload(v: &Value) -> Result<Payload> {
    let a = array(v, 2)?;
    Ok(Payload {
        content: text(&a[0])?.into(),
        is_opaque: a[1].as_bool().ok_or(WireError)?,
    })
}
fn params(v: &Value) -> Result<HashMap<String, ParamValue>> {
    let mut out = HashMap::new();
    let mut previous: Option<&str> = None;
    for entry in v.as_array().ok_or(WireError)? {
        let a = array(entry, 2)?;
        let key = text(&a[0])?;
        if !segment(key) || previous.is_some_and(|p| p >= key) {
            return Err(WireError);
        }
        previous = Some(key);
        let val = array(&a[1], 2)?;
        let value = match text(&val[0])? {
            "str" => ParamValue::Str(text(&val[1])?.into()),
            "int" => ParamValue::Int(uint(&val[1])?),
            _ => return Err(WireError),
        };
        out.insert(key.into(), value);
    }
    Ok(out)
}
fn from_model(v: &Value) -> Result<Vec<Act>> {
    let root = array(v, 2)?;
    if uint(&root[0])? != 1 {
        return Err(WireError);
    }
    let records = root[1].as_array().ok_or(WireError)?;
    if records.len() > MAX_ACTS {
        return Err(WireError);
    }
    let mut acts = Vec::new();
    for record in records {
        let a = record.as_array().ok_or(WireError)?;
        let kind = text(a.first().ok_or(WireError)?)?;
        let act = match kind {
            "ASSERT" | "QUERY" => {
                let a = array(record, 3)?;
                let (evidence, data) = (reference(&a[1])?, payload(&a[2])?);
                if kind == "ASSERT" {
                    Act::Assert(AssertAct { evidence, data })
                } else {
                    Act::Query(QueryAct { evidence, data })
                }
            }
            "DIRECT" => {
                let a = array(record, 4)?;
                Act::Direct(DirectAct {
                    capability: capability(&a[1])?,
                    call: ToolCall {
                        tool: reference(&a[2])?,
                        params: params(&a[3])?,
                    },
                })
            }
            "COMMIT" => Act::Commit(CommitAct {
                reference: reference(&array(record, 2)?[1])?,
            }),
            "GRANT" => Act::Grant(GrantAct {
                capability: capability(&array(record, 2)?[1])?,
            }),
            "REVOKE" => Act::Revoke(RevokeAct {
                capability: capability(&array(record, 2)?[1])?,
            }),
            "ENDORSE" => {
                let a = array(record, 3)?;
                Act::Endorse(EndorseAct {
                    reference: reference(&a[1])?,
                    signer: principal(&a[2])?,
                })
            }
            _ => return Err(WireError),
        };
        acts.push(act);
    }
    Ok(acts)
}

// Preflight before cloning any caller-owned strings/maps into the transport model.
struct Budget {
    bytes: usize,
    entries: usize,
}
impl Budget {
    fn nodes(&mut self, count: usize) -> Result<()> {
        self.entries = self.entries.checked_add(count).ok_or(WireError)?;
        if self.entries > MAX_WIRE_NODES {
            return Err(WireError);
        }
        Ok(())
    }
    fn string(&mut self, s: &str) -> Result<()> {
        self.bytes = self.bytes.checked_add(s.len()).ok_or(WireError)?;
        self.nodes(1)?;
        if self.bytes > MAX_WIRE_BYTES {
            return Err(WireError);
        }
        Ok(())
    }
    fn principal(&mut self, p: &Principal) -> Result<()> {
        self.nodes(1)?;
        self.string(&p.id)?;
        self.string(&p.hash)
    }
    fn reference(&mut self, r: &Reference) -> Result<()> {
        self.nodes(1)?;
        self.principal(&r.principal)?;
        self.string(&r.content_hash)
    }
    fn capability(&mut self, c: &Capability) -> Result<()> {
        self.nodes(2)?; // capability array and expiration integer
        self.string(&c.cap_hash)?;
        self.string(&c.scope)?;
        self.principal(&c.from_principal)?;
        self.string(&c.integrity_level)
    }
}
fn to_model(acts: &[Act]) -> Result<Value> {
    if acts.len() > MAX_ACTS {
        return Err(WireError);
    }
    let mut b = Budget {
        bytes: 0,
        entries: 0,
    };
    b.nodes(3)?; // root array, version, acts array
    for act in acts {
        b.nodes(2)?; // act array and kind
        match act {
            Act::Assert(a) => {
                b.reference(&a.evidence)?;
                b.nodes(2)?; // payload array and opaque boolean
                b.string(&a.data.content)?;
            }
            Act::Query(a) => {
                b.reference(&a.evidence)?;
                b.nodes(2)?; // payload array and opaque boolean
                b.string(&a.data.content)?;
            }
            Act::Direct(a) => {
                b.capability(&a.capability)?;
                b.reference(&a.call.tool)?;
                if a.call.params.len() > MAX_WIRE_NODES {
                    return Err(WireError);
                }
                b.nodes(1)?; // parameter array
                for (k, v) in &a.call.params {
                    b.nodes(3)?; // entry array, tagged value array, type tag
                    b.string(k)?;
                    match v {
                        ParamValue::Str(s) => b.string(s)?,
                        ParamValue::Int(_) => b.nodes(1)?,
                    }
                }
            }
            Act::Commit(a) => b.reference(&a.reference)?,
            Act::Grant(a) => b.capability(&a.capability)?,
            Act::Revoke(a) => b.capability(&a.capability)?,
            Act::Endorse(a) => {
                b.reference(&a.reference)?;
                b.principal(&a.signer)?;
            }
        }
    }
    fn p(p: &Principal) -> Value {
        json!([p.id, p.hash])
    }
    fn r(r: &Reference) -> Value {
        json!([p(&r.principal), r.content_hash])
    }
    fn c(c: &Capability) -> Value {
        json!([
            c.cap_hash,
            c.scope,
            c.exp,
            p(&c.from_principal),
            c.integrity_level
        ])
    }
    fn d(d: &Payload) -> Value {
        json!([d.content, d.is_opaque])
    }
    let records: Vec<Value> = acts
        .iter()
        .map(|act| match act {
            Act::Assert(a) => json!(["ASSERT", r(&a.evidence), d(&a.data)]),
            Act::Query(a) => json!(["QUERY", r(&a.evidence), d(&a.data)]),
            Act::Direct(a) => {
                let mut pairs: Vec<_> = a.call.params.iter().collect();
                pairs.sort_by_key(|(k, _)| *k);
                let pairs: Vec<Value> = pairs
                    .into_iter()
                    .map(|(k, v)| {
                        json!([
                            k,
                            match v {
                                ParamValue::Str(s) => json!(["str", s]),
                                ParamValue::Int(n) => json!(["int", n]),
                            }
                        ])
                    })
                    .collect();
                json!(["DIRECT", c(&a.capability), r(&a.call.tool), pairs])
            }
            Act::Commit(a) => json!(["COMMIT", r(&a.reference)]),
            Act::Grant(a) => json!(["GRANT", c(&a.capability)]),
            Act::Revoke(a) => json!(["REVOKE", c(&a.capability)]),
            Act::Endorse(a) => json!(["ENDORSE", r(&a.reference), p(&a.signer)]),
        })
        .collect();
    Ok(json!([1, records]))
}

fn header(out: &mut Vec<u8>, major: u8, n: u64) {
    if n < 24 {
        out.push((major << 5) | n as u8);
    } else if n <= u8::MAX as u64 {
        out.extend_from_slice(&[(major << 5) | 24, n as u8]);
    } else if n <= u16::MAX as u64 {
        out.push((major << 5) | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= u32::MAX as u64 {
        out.push((major << 5) | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push((major << 5) | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}
fn write(v: &Value, out: &mut Vec<u8>, depth: usize, nodes: &mut usize) -> Result<()> {
    *nodes += 1;
    if depth > MAX_WIRE_DEPTH || *nodes > MAX_WIRE_NODES {
        return Err(WireError);
    }
    match v {
        Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Value::Number(_) => header(out, 0, uint(v)? as u64),
        Value::String(s) => {
            if s.len() > MAX_WIRE_BYTES.saturating_sub(out.len()) {
                return Err(WireError);
            }
            header(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(a) => {
            if a.len() > MAX_WIRE_NODES.saturating_sub(*nodes) {
                return Err(WireError);
            }
            header(out, 4, a.len() as u64);
            for item in a {
                write(item, out, depth + 1, nodes)?;
            }
        }
        _ => return Err(WireError),
    }
    if out.len() > MAX_WIRE_BYTES {
        return Err(WireError);
    }
    Ok(())
}
fn binary(v: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write(v, &mut out, 0, &mut 0)?;
    Ok(out)
}
struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
    nodes: usize,
}
impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        let end = self.pos.checked_add(n).ok_or(WireError)?;
        let data = self.input.get(self.pos..end).ok_or(WireError)?;
        self.pos = end;
        Ok(data)
    }
    fn value(&mut self, depth: usize) -> Result<Value> {
        self.nodes += 1;
        if depth > MAX_WIRE_DEPTH || self.nodes > MAX_WIRE_NODES {
            return Err(WireError);
        }
        let first = self.take(1)?[0];
        if first == 0xf4 || first == 0xf5 {
            return Ok(Value::Bool(first == 0xf5));
        }
        let (major, ai) = (first >> 5, first & 31);
        if !matches!(major, 0 | 3 | 4) {
            return Err(WireError);
        }
        let (n, min) = match ai {
            0..=23 => (ai as u64, 0),
            24 => (self.take(1)?[0] as u64, 24),
            25 => {
                let b = self.take(2)?;
                (u16::from_be_bytes([b[0], b[1]]) as u64, 256)
            }
            26 => {
                let b = self.take(4)?;
                (u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64, 65536)
            }
            27 => {
                let b = self.take(8)?;
                (
                    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
                    4294967296,
                )
            }
            _ => return Err(WireError),
        };
        if n < min || n > i64::MAX as u64 {
            return Err(WireError);
        }
        if major == 0 {
            return Ok(json!(n));
        }
        let len = usize::try_from(n).map_err(|_| WireError)?;
        if len > self.input.len().saturating_sub(self.pos) {
            return Err(WireError);
        }
        if major == 3 {
            return Ok(Value::String(
                std::str::from_utf8(self.take(len)?)
                    .map_err(|_| WireError)?
                    .into(),
            ));
        }
        if len > MAX_WIRE_NODES.saturating_sub(self.nodes) {
            return Err(WireError);
        }
        let mut items = Vec::new();
        for _ in 0..len {
            items.push(self.value(depth + 1)?);
        }
        Ok(Value::Array(items))
    }
}
fn read(input: &[u8]) -> Result<Value> {
    if input.len() > MAX_WIRE_BYTES {
        return Err(WireError);
    }
    let mut reader = Reader {
        input,
        pos: 0,
        nodes: 0,
    };
    let value = reader.value(0)?;
    if reader.pos != input.len() {
        return Err(WireError);
    }
    Ok(value)
}
// Count exact compact JSON bytes before allocating escaped output. The final
// LF is included so every accepted binary has a bounded lossless projection.
fn projection_size(v: &Value, used: &mut usize) -> Result<()> {
    let own = match v {
        Value::String(s) => {
            2 + s
                .bytes()
                .map(|b| match b {
                    b'"' | b'\\' | b'\x08' | b'\x0c' | b'\n' | b'\r' | b'\t' => 2,
                    0..=31 => 6,
                    _ => 1,
                })
                .sum::<usize>()
        }
        Value::Number(_) => uint(v)?.to_string().len(),
        Value::Bool(true) => 4,
        Value::Bool(false) => 5,
        Value::Array(a) => 2 + a.len().saturating_sub(1),
        _ => return Err(WireError),
    };
    *used = used.checked_add(own).ok_or(WireError)?;
    if *used > MAX_WIRE_BYTES {
        return Err(WireError);
    }
    if let Value::Array(a) = v {
        for item in a {
            projection_size(item, used)?;
        }
    }
    Ok(())
}
pub fn encode(acts: &[Act]) -> Result<Vec<u8>> {
    let model = to_model(acts)?;
    let bytes = binary(&model)?;
    projection_size(&model, &mut 1)?;
    from_model(&model)?;
    Ok(bytes)
}
pub fn decode(input: &[u8]) -> Result<Vec<Act>> {
    let model = read(input)?;
    projection_size(&model, &mut 1)?;
    from_model(&model)
}
pub fn project(input: &[u8]) -> Result<String> {
    let model = read(input)?;
    projection_size(&model, &mut 1)?;
    from_model(&model)?;
    let mut s = serde_json::to_string(&model).map_err(|_| WireError)?;
    s.push('\n');
    if s.len() > MAX_WIRE_BYTES {
        return Err(WireError);
    }
    Ok(s)
}
// Bound JSON traversal before serde allocates the tree. Syntax is still checked
// by serde; this scanner only counts values and nesting outside quoted strings.
fn projection_budget(input: &str) -> Result<()> {
    let mut depth = 0usize;
    let mut nodes = 0usize;
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch.is_ascii_whitespace() || ch == ',' || ch == ':' {
            continue;
        }
        if ch == ']' || ch == '}' {
            depth = depth.checked_sub(1).ok_or(WireError)?;
            continue;
        }
        nodes += 1;
        if nodes > MAX_WIRE_NODES || depth > MAX_WIRE_DEPTH {
            return Err(WireError);
        }
        if ch == '[' || ch == '{' {
            depth += 1;
        } else if ch == '"' {
            while let Some(c) = chars.next() {
                if c == '\\' {
                    chars.next();
                } else if c == '"' {
                    break;
                }
            }
        } else {
            while chars.peek().is_some_and(|c| {
                !c.is_ascii_whitespace() && !matches!(c, ',' | ':' | ']' | '}' | '[' | '{' | '"')
            }) {
                chars.next();
            }
        }
    }
    Ok(())
}
pub fn unproject(input: &str) -> Result<Vec<u8>> {
    if input.len() > MAX_WIRE_BYTES {
        return Err(WireError);
    }
    projection_budget(input)?;
    let model: Value = serde_json::from_str(input).map_err(|_| WireError)?;
    let bytes = binary(&model)?;
    projection_size(&model, &mut 1)?;
    from_model(&model)?;
    if project(&bytes)? != input {
        return Err(WireError);
    }
    Ok(bytes)
}
