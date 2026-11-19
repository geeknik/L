//! Tokenizer + recursive-descent parser for L (Rust).
//! Mirrors lang/parser.py. Token kinds ordered most-specific-first.

use crate::ast::{Act, AssertAct, QueryAct, DirectAct, CommitAct, GrantAct, RevokeAct, EndorseAct,
    Principal, Reference, Capability, ToolCall, Payload, ParamValue};
use crate::limits::{MAX_SOURCE_BYTES, MAX_TOKENS, MAX_ACTS};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    ACT, NUMBER, HASH, IDENT, STRING, OPAQUE,
    LPAREN, RPAREN, LBRACE, RBRACE, COLON, COMMA, EQUALS, DOT, UNKNOWN, EOF,
}

impl Kind {
    pub fn as_str(&self) -> &'static str { match self {
        Kind::ACT => "ACT", Kind::NUMBER => "NUMBER", Kind::HASH => "HASH",
        Kind::IDENT => "IDENT", Kind::STRING => "STRING", Kind::OPAQUE => "OPAQUE",
        Kind::LPAREN => "LPAREN", Kind::RPAREN => "RPAREN", Kind::LBRACE => "LBRACE", Kind::RBRACE => "RBRACE",
        Kind::COLON => "COLON", Kind::COMMA => "COMMA", Kind::EQUALS => "EQUALS", Kind::DOT => "DOT",
        Kind::UNKNOWN => "UNKNOWN", Kind::EOF => "EOF",
    }}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token { pub kind: Kind, pub value: String }

fn is_hex(c: char) -> bool { c.is_ascii_digit() || matches!(c, 'a'..='f' | 'A'..='F') }

/// Tokenize source into Vec<Token>, ignoring whitespace/comments.
/// Rejects unterminated `<opaque>` blocks and `"..."` strings.
pub fn tokenize(src: &str) -> Result<Vec<Token>, ParseError> {
    if src.len() > MAX_SOURCE_BYTES {
        return Err(ParseError { pos: 0, msg: "source exceeds byte limit".into() });
    }
    let chars: Vec<char> = src.chars().collect();
    let mut toks: Vec<Token> = Vec::new();
    let mut i = 0usize;
    let n = chars.len();

    while i < n {
        let c = chars[i];
        if matches!(c, ' ' | '\t' | '\n' | '\r' | '\u{000b}' | '\u{000c}') { i += 1; continue; }
        if c == '#' { while i < n && chars[i] != '\n' { i += 1; } continue; }
        if toks.len() >= MAX_TOKENS {
            return Err(ParseError { pos: i, msg: "source exceeds token limit".into() });
        }

        let kind: Kind;
        let value: String;

        if c.is_ascii_alphabetic() || c == '_' || c.is_ascii_digit() {
            let mut word = String::new();
            let mut hex_mode = c.is_ascii_digit();
            while i < n {
                let ch = chars[i];
                if hex_mode {
                    if is_hex(ch) { word.push(ch); i += 1; }
                    else if ch.is_ascii_alphabetic() || ch == '_' { hex_mode = false; word.push(ch); i += 1; }
                    else { break; }
                } else {
                    if ch.is_ascii_alphanumeric() || ch == '_' { word.push(ch); i += 1; }
                    else { break; }
                }
            }
            value = word.clone();
            let kw = matches!(word.as_str(),
                "ASSERT"|"QUERY"|"DIRECT"|"COMMIT"|"GRANT"|"REVOKE"|"ENDORSE");
            kind = if kw { Kind::ACT }
                else if word.len() >= 8 && word.chars().all(is_hex) { Kind::HASH }
                else if word.chars().all(|c| c.is_ascii_digit()) { Kind::NUMBER }
                else { Kind::IDENT };
        }
        else if c == '<' {
            let start = i;
            let mut inner = String::new();
            i += 1;
            while i < n && chars[i] != '>' { inner.push(chars[i]); i += 1; }
            if i >= n {
                return Err(ParseError { pos: start, msg: "unterminated opaque payload".into() });
            }
            i += 1;
            kind = Kind::OPAQUE; value = inner;
        }
        else if c == '"' {
            let start = i;
            let mut inner = String::new();
            i += 1;
            while i < n {
                if chars[i] == '"' {
                    if i + 1 < n && chars[i + 1] == '"' {
                        inner.push('"');
                        i += 2;
                        continue;
                    }
                    break;
                }
                inner.push(chars[i]);
                i += 1;
            }
            if i >= n {
                return Err(ParseError { pos: start, msg: "unterminated string".into() });
            }
            i += 1;
            kind = Kind::STRING; value = inner;
        }
        else {
            i += 1;
            match c {
                '(' => { kind = Kind::LPAREN; value = "(".into(); }
                ')' => { kind = Kind::RPAREN; value = ")".into(); }
                '{' => { kind = Kind::LBRACE; value = "{".into(); }
                '}' => { kind = Kind::RBRACE; value = "}".into(); }
                ':' => { kind = Kind::COLON; value = ":".into(); }
                ',' => { kind = Kind::COMMA; value = ",".into(); }
                '=' => { kind = Kind::EQUALS; value = "=".into(); }
                '.' => { kind = Kind::DOT; value = ".".into(); }
                _ => { kind = Kind::UNKNOWN; value = c.to_string(); }
            }
        }
        toks.push(Token { kind, value });
    }

    toks.push(Token { kind: Kind::EOF, value: String::new() });
    Ok(toks)
}

#[derive(Debug)]
pub struct ParseError { pub pos: usize, pub msg: String }
impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "ParseError at {}: {}", self.pos, self.msg)
    }
}
impl std::error::Error for ParseError {}

pub struct Parser { toks: Vec<Token>, i: usize }

impl Parser {
    pub fn new(toks: Vec<Token>) -> Self { Self { toks, i: 0 } }

    fn peek(&self) -> &Token { self.toks.get(self.i.min(self.toks.len()-1)).unwrap() }
    fn peek_kind(&self) -> Kind { self.peek().kind.clone() }
    fn next(&mut self) -> Token { let t = self.peek().clone(); self.i += 1; t }

    fn expect(&mut self, kind: Kind, what: &str) -> Result<Token, ParseError> {
        let t = self.next();
        if t.kind != kind {
            return Err(ParseError { pos: self.i-1, msg: format!("expected {} ({}), got {} ({})", what, kind.as_str(), t.kind.as_str(), t.value) });
        }
        Ok(t)
    }

    fn expect_lit(&mut self, kind: Kind, literal: &str, what: &str) -> Result<Token, ParseError> {
        let t = self.next();
        if t.kind != kind || t.value != literal {
            return Err(ParseError { pos: self.i-1, msg: format!("expected {} ('{}'), got {} ({})", what, literal, t.kind.as_str(), t.value) });
        }
        Ok(t)
    }

    fn parse_program(&mut self) -> Result<Vec<Act>, ParseError> {
        let mut acts = Vec::new();
        while self.peek_kind() != Kind::EOF {
            if acts.len() >= MAX_ACTS {
                return Err(ParseError { pos: self.i, msg: "program exceeds act limit".into() });
            }
            acts.push(self.parse_act()?);
        }
        Ok(acts)
    }

    fn parse_act(&mut self) -> Result<Act, ParseError> {
        let tok = self.expect(Kind::ACT, "act keyword")?;
        match tok.value.as_str() {
            "ASSERT" => {
                self.expect_lit(Kind::IDENT, "ev", "'ev'")?;
                self.expect(Kind::COLON, "':'")?;
                let ev = self.parse_ref()?;
                let data = self.parse_payload()?;
                Ok(Act::Assert(AssertAct{evidence: ev, data}))
            }
            "QUERY" => {
                self.expect_lit(Kind::IDENT, "ev", "'ev'")?;
                self.expect(Kind::COLON, "':'")?;
                let ev = self.parse_ref()?;
                let data = self.parse_payload()?;
                Ok(Act::Query(QueryAct{evidence: ev, data}))
            }
            "DIRECT" => {
                self.expect_lit(Kind::IDENT, "cap", "'cap'")?;
                self.expect(Kind::COLON, "':'")?;
                let cap_tok = self.next();
                if cap_tok.kind != Kind::HASH {
                    return Err(ParseError{pos:self.i-1, msg:format!("expected capability hash, got {}", cap_tok.kind.as_str())});
                }
                self.expect(Kind::LPAREN, "'('")?;
                let spec = self.parse_cap_spec()?;
                self.expect(Kind::RPAREN, "')'")?;
                self.expect_lit(Kind::IDENT, "call", "'call'")?;
                self.expect_lit(Kind::IDENT, "tool", "'tool'")?;
                self.expect(Kind::COLON, "':'")?;
                let tool = self.parse_ref()?;
                let params = self.parse_params()?;
                let cap = Capability { cap_hash: cap_tok.value, scope: spec.0, exp: spec.1, from_principal: spec.2, integrity_level: "low".into() };
                Ok(Act::Direct(DirectAct{capability: cap, call: ToolCall{tool, params}}))
            }
            "COMMIT" => {
                let r = self.parse_ref()?;
                Ok(Act::Commit(CommitAct{reference: r}))
            }
            "GRANT" | "REVOKE" => {
                self.expect_lit(Kind::IDENT, "cap", "'cap'")?;
                self.expect(Kind::COLON, "':'")?;
                let cap_tok = self.next();
                if cap_tok.kind != Kind::HASH {
                    return Err(ParseError{pos:self.i-1, msg:format!("expected capability hash, got {}", cap_tok.kind.as_str())});
                }
                self.expect(Kind::LPAREN, "'('")?;
                let spec = self.parse_cap_spec()?;
                self.expect(Kind::RPAREN, "')'")?;
                let cap = Capability { cap_hash: cap_tok.value, scope: spec.0, exp: spec.1, from_principal: spec.2, integrity_level: "low".into() };
                if tok.value == "GRANT" { Ok(Act::Grant(GrantAct{capability: cap})) }
                else { Ok(Act::Revoke(RevokeAct{capability: cap})) }
            }
            "ENDORSE" => {
                let r = self.parse_ref()?;
                self.expect_lit(Kind::IDENT, "by", "'by'")?;
                self.expect(Kind::COLON, "':'")?;
                let signer = self.parse_principal(false)?;
                Ok(Act::Endorse(EndorseAct{reference: r, signer}))
            }
            other => Err(ParseError{pos:self.i-1, msg:format!("unknown act {}", other)}),
        }
    }

    fn parse_payload(&mut self) -> Result<Payload, ParseError> {
        self.expect_lit(Kind::IDENT, "data", "'data'")?;
        self.expect(Kind::COLON, "':'")?;
        let t = self.next();
        match t.kind {
            Kind::OPAQUE => Ok(Payload{content: t.value, is_opaque: true}),
            Kind::STRING => Ok(Payload{content: t.value, is_opaque: false}),
            _ => Err(ParseError{pos:self.i-1, msg:format!("expected payload, got {}", t.kind.as_str())}),
        }
    }

    fn parse_principal(&mut self, preserve_hash: bool) -> Result<Principal, ParseError> {
        let mut parts = vec![self.expect(Kind::IDENT, "principal identifier")?];
        while self.peek_kind() == Kind::COLON {
            self.next();
            let segment = self.next();
            if !matches!(segment.kind, Kind::IDENT | Kind::NUMBER | Kind::HASH) {
                return Err(ParseError { pos: self.i - 1, msg: "expected non-empty principal segment".into() });
            }
            parts.push(segment);
        }
        let hash = if preserve_hash && parts.len() == 2 && parts[1].kind == Kind::HASH {
            parts[1].value.clone()
        } else {
            "00".repeat(32)
        };
        let id = parts.iter().map(|part| part.value.as_str()).collect::<Vec<_>>().join(":");
        Ok(Principal { id, hash })
    }

    fn parse_ref(&mut self) -> Result<Reference, ParseError> {
        self.expect(Kind::LPAREN, "'('")?;
        // Match the complete shorthand before treating sha256 as anonymous.
        if matches!(
            self.toks.get(self.i..self.i + 4),
            Some([
                Token { kind: Kind::IDENT, value },
                Token { kind: Kind::COLON, .. },
                Token { kind: Kind::HASH, .. },
                Token { kind: Kind::RPAREN, .. },
            ]) if value == "sha256"
        ) {
            self.next();
            self.expect(Kind::COLON, "':'")?;
            let h = self.expect(Kind::HASH, "sha256 hex hash")?.value;
            self.expect(Kind::RPAREN, "')'")?;
            return Ok(Reference{principal: Principal{id:"anon".into(), hash:"00".repeat(32)}, content_hash: h});
        }
        let principal = self.parse_principal(true)?;
        self.expect(Kind::COMMA, "','")?;
        self.expect_lit(Kind::IDENT, "sha256", "'sha256'")?;
        self.expect(Kind::COLON, "':'")?;
        let content_hash = self.expect(Kind::HASH, "content hash")?.value;
        self.expect(Kind::RPAREN, "')'")?;
        Ok(Reference{principal, content_hash})
    }

    /// Parse (scope=..., exp=..., from=...) -> (scope, exp, from_principal)
    /// Enforce exactly scope, exp, from — one each, all required, no unknown keys.
    fn parse_cap_spec(&mut self) -> Result<(String, i64, Principal), ParseError> {
        let mut scope: Option<String> = None;
        let mut exp: Option<i64> = None;
        let mut from_principal: Option<Principal> = None;
        let mut seen = std::collections::HashSet::new();
        loop {
            let key = self.expect(Kind::IDENT, "capability key")?;
            if !seen.insert(key.value.clone()) {
                return Err(ParseError { pos: self.i-1, msg: format!("duplicate capability key '{}'", key.value) });
            }
            self.expect(Kind::EQUALS, "'='")?;
            let val = self.next();
            match key.value.as_str() {
                "scope" => {
                    if val.kind != Kind::IDENT || val.value.is_empty() {
                        return Err(ParseError { pos: self.i-1, msg: format!("invalid scope value '{}'", val.value) });
                    }
                    let mut s = val.value.clone();
                    while self.peek_kind() == Kind::DOT {
                        self.next();
                        let seg = self.next();
                        if seg.kind != Kind::IDENT || seg.value.is_empty() {
                            return Err(ParseError { pos: self.i-1, msg: format!("invalid scope segment '{}'", seg.value) });
                        }
                        s.push('.'); s.push_str(&seg.value);
                    }
                    scope = Some(s);
                }
                "exp" => {
                    if !matches!(val.kind, Kind::NUMBER | Kind::HASH)
                        || !val.value.chars().all(|c| c.is_ascii_digit())
                    {
                        return Err(ParseError { pos: self.i-1, msg: format!("invalid TTL number '{}'", val.value) });
                    }
                    let parsed: i64 = match val.value.parse() {
                        Ok(v) => v,
                        Err(_) => return Err(ParseError { pos: self.i-1, msg: format!("TTL {} out of range 0..=i64::MAX", val.value) }),
                    };
                    if parsed < 0 {
                        return Err(ParseError { pos: self.i-1, msg: format!("TTL {} out of range 0..=i64::MAX", parsed) });
                    }
                    exp = Some(parsed);
                }
                "from" => {
                    if val.kind != Kind::IDENT || val.value.is_empty() {
                        return Err(ParseError { pos: self.i-1, msg: format!("invalid from value '{}'", val.value) });
                    }
                    let mut parts = vec![val.value.clone()];
                    while self.peek_kind() == Kind::COLON {
                        self.next();
                        let seg = self.next();
                        if (seg.kind != Kind::IDENT && seg.kind != Kind::NUMBER && seg.kind != Kind::HASH) || seg.value.is_empty() {
                                                return Err(ParseError { pos: self.i-1, msg: format!("invalid from segment '{}'", seg.value) });
                                            }
                        parts.push(seg.value.clone());
                    }
                    from_principal = Some(Principal{id: parts.join(":"), hash:"00".repeat(32)});
                }
                _ => {
                    return Err(ParseError { pos: self.i-1, msg: format!("unknown capability key '{}'", key.value) });
                }
            }
            if self.peek_kind() == Kind::COMMA { self.next(); continue; }
            break;
        }
        let scope = scope.ok_or_else(|| ParseError { pos: self.i-1, msg: "missing capability key 'scope'".into() })?;
        let exp = exp.ok_or_else(|| ParseError { pos: self.i-1, msg: "missing capability key 'exp'".into() })?;
        let from_principal = from_principal.ok_or_else(|| ParseError { pos: self.i-1, msg: "missing capability key 'from'".into() })?;
        Ok((scope, exp, from_principal))
    }

    fn parse_params(&mut self) -> Result<std::collections::HashMap<String, ParamValue>, ParseError> {
        self.expect(Kind::LBRACE, "'{'")?;
        let mut params = std::collections::HashMap::new();
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        while self.peek_kind() != Kind::RBRACE && self.peek_kind() != Kind::EOF {
            let key = self.expect(Kind::IDENT, "param key")?.value;
            if !seen.insert(key.clone()) {
                return Err(ParseError {
                    pos: self.i - 1,
                    msg: format!("duplicate param key '{}'", key),
                });
            }
            self.expect(Kind::COLON, "':'")?;
            let val = self.next();
            match val.kind {
                Kind::STRING => {
                    params.insert(key, ParamValue::Str(val.value));
                }
                Kind::NUMBER => {
                    let n: i64 = val.value.parse().map_err(|_| ParseError {
                        pos: self.i - 1,
                        msg: format!("invalid number '{}'", val.value),
                    })?;
                    if !(0..=9223372036854775807).contains(&n) {
                        return Err(ParseError {
                            pos: self.i - 1,
                            msg: format!("number {} out of range 0..=i64::MAX", n),
                        });
                    }
                    params.insert(key, ParamValue::Int(n));
                }
                Kind::IDENT => {
                    params.insert(key, ParamValue::Str(val.value));
                }
                Kind::HASH => {
                    // Accept HASH numeric values (all ASCII digits, 8+ chars) as integers,
                    // matching the TTL lexical rule and Python behavior.
                    if val.value.chars().all(|c| c.is_ascii_digit()) {
                        let n: i64 = val.value.parse().map_err(|_| ParseError {
                            pos: self.i - 1,
                            msg: format!("invalid number '{}'", val.value),
                        })?;
                        if !(0..=9223372036854775807).contains(&n) {
                            return Err(ParseError {
                                pos: self.i - 1,
                                msg: format!("number {} out of range 0..=i64::MAX", n),
                            });
                        }
                        params.insert(key, ParamValue::Int(n));
                    } else {
                        return Err(ParseError {
                            pos: self.i - 1,
                            msg: format!("invalid param value '{}'", val.value),
                        });
                    }
                }
                Kind::OPAQUE => {
                    return Err(ParseError {
                        pos: self.i - 1,
                        msg: "opaque values not allowed in params".into(),
                    });
                }
                _ => {
                    return Err(ParseError {
                        pos: self.i - 1,
                        msg: format!("unsupported param value kind '{}'", val.kind.as_str()),
                    });
                }
            }
            // Require either comma or closing brace; no silent skip.
            if self.peek_kind() == Kind::COMMA {
                self.next();
            } else if self.peek_kind() != Kind::RBRACE {
                return Err(ParseError {
                    pos: self.i - 1,
                    msg: format!(
                        "expected ',' or '}}' after param value, got {}",
                        self.peek_kind().as_str()
                    ),
                });
            }
        }
        self.expect(Kind::RBRACE, "'}'")?;
        Ok(params)
    }
}

/// Public entry point.
pub fn parse(src: &str) -> Result<Vec<Act>, ParseError> {
    let toks = tokenize(src)?;
    let mut p = Parser::new(toks);
    p.parse_program()
}
