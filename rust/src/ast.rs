//! L: A Trust-Typed Language for Agents — core AST (Rust).
//! Mirrors lang/ast.py. All types are plain structs with Debug/Clone/PartialEq.

#[derive(Debug, Clone, PartialEq)]
pub struct Principal {
    pub id: String,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Reference {
    pub principal: Principal,
    pub content_hash: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Capability {
    pub cap_hash: String,
    pub scope: String,
    pub exp: i64,
    pub from_principal: Principal,
    pub integrity_level: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Payload {
    pub content: String,
    pub is_opaque: bool,
}

/// A tool-call parameter value. The type contract is shared with the Python
/// reference implementation: textual values are strings, numeric values are
/// integers (both NUMBER tokens and decimal-only HASH tokens), bounded to
/// 0..=i64::MAX. Unsupported token kinds are rejected at parse time.
#[derive(Debug, Clone, PartialEq)]
pub enum ParamValue {
    Str(String),
    Int(i64),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    pub tool: Reference,
    pub params: std::collections::HashMap<String, ParamValue>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Act {
    Assert(AssertAct),
    Query(QueryAct),
    Direct(DirectAct),
    Commit(CommitAct),
    Grant(GrantAct),
    Revoke(RevokeAct),
    Endorse(EndorseAct),
}

#[derive(Debug, Clone, PartialEq)]
pub struct AssertAct { pub evidence: Reference, pub data: Payload }
#[derive(Debug, Clone, PartialEq)]
pub struct QueryAct { pub evidence: Reference, pub data: Payload }
#[derive(Debug, Clone, PartialEq)]
pub struct DirectAct { pub capability: Capability, pub call: ToolCall }
#[derive(Debug, Clone, PartialEq)]
pub struct CommitAct { pub reference: Reference }
#[derive(Debug, Clone, PartialEq)]
pub struct GrantAct { pub capability: Capability }
#[derive(Debug, Clone, PartialEq)]
pub struct RevokeAct { pub capability: Capability }
#[derive(Debug, Clone, PartialEq)]
pub struct EndorseAct { pub reference: Reference, pub signer: Principal }

pub fn act_type(act: &Act) -> &'static str {
    match act {
        Act::Assert(_) => "ASSERT",
        Act::Query(_) => "QUERY",
        Act::Direct(_) => "DIRECT",
        Act::Commit(_) => "COMMIT",
        Act::Grant(_) => "GRANT",
        Act::Revoke(_) => "REVOKE",
        Act::Endorse(_) => "ENDORSE",
    }
}