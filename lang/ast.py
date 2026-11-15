"""L: A Trust-Typed Language for Agents — core AST."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    id: str          # short principal id, e.g. "user:g" or "srv:9c1e"
    hash: str        # full sha256 hex of the principal identity

    def __repr__(self) -> str:
        return f"{self.id}"


@dataclass(frozen=True)
class Reference:
    """A (principal, content hash) pair."""
    principal: Principal
    content_hash: str  # sha256 hex

    def __repr__(self) -> str:
        return f"(princ:{self.principal.id}, sha256:{self.content_hash[:8]})"


@dataclass(frozen=True)
class Capability:
    cap_hash: str        # sha256 hex of capability token
    scope: str           # e.g. "fs.read"
    exp: int             # seconds until expiry
    from_principal: Principal
    integrity_level: str = "low"

    def __repr__(self) -> str:
        return f"cap:{self.cap_hash[:8]}(scope={self.scope}, exp={self.exp}s, from={self.from_principal})"


@dataclass(frozen=True)
class Payload:
    content: str
    is_opaque: bool = True

    def __repr__(self) -> str:
        if self.is_opaque:
            return f"<opaque:{self.content}>"
        return f'"{self.content}"'


@dataclass(frozen=True)
class ToolCall:
    tool: Reference
    params: dict[str, str | int]

    def __repr__(self) -> str:
        params_str = ', '.join(f"{k}={v}" for k, v in self.params.items())
        return f"call tool:{self.tool} {{ {params_str} }}"


class Act:
    act_type: str = ""


@dataclass(frozen=True)
class AssertAct(Act):
    evidence: Reference
    data: Payload

    act_type = "ASSERT"

    def __repr__(self) -> str:
        return f"ASSERT  ev:{self.evidence} data:{self.data}"


@dataclass(frozen=True)
class QueryAct(Act):
    evidence: Reference
    data: Payload

    act_type = "QUERY"

    def __repr__(self) -> str:
        return f"QUERY  ev:{self.evidence} data:{self.data}"


@dataclass(frozen=True)
class DirectAct(Act):
    capability: Capability
    call: ToolCall

    act_type = "DIRECT"

    def __repr__(self) -> str:
        return f"DIRECT  {self.capability}\n        {self.call}"


@dataclass(frozen=True)
class CommitAct(Act):
    reference: Reference

    act_type = "COMMIT"

    def __repr__(self) -> str:
        return f"COMMIT ref:{self.reference}"


@dataclass(frozen=True)
class GrantAct(Act):
    capability: Capability

    act_type = "GRANT"

    def __repr__(self) -> str:
        return f"GRANT  {self.capability}"


@dataclass(frozen=True)
class RevokeAct(Act):
    capability: Capability

    act_type = "REVOKE"

    def __repr__(self) -> str:
        return f"REVOKE {self.capability}"


@dataclass(frozen=True)
class EndorseAct(Act):
    reference: Reference
    signer: Principal

    act_type = "ENDORSE"

    def __repr__(self) -> str:
        return f"ENDORSE ref:{self.reference} by:{self.signer}"


ACT_TYPES = (AssertAct, QueryAct, DirectAct, CommitAct, GrantAct, RevokeAct, EndorseAct)
ACT_TYPE_NAMES = [a.act_type for a in ACT_TYPES]
