"""L: A Trust-Typed Language for Agents — tokenizer + recursive-descent parser.

Concrete v1.0 syntax (a faithful, simplified subset of DESIGN.md):

    ASSERT ev:(user:g, sha256:0011223344556677889900112233445566778899001122334455667788990011) data:<opaque, non-promotable>
    QUERY  ev:(srv:abcdef00, sha256:0011223344556677889900112233445566778899001122334455667788990011) data:<opaque, some data>
    DIRECT cap:(user:g, sha256:0011223344556677889900112233445566778899001122334455667788990011) (scope=fs.read, exp=60, from=user:g)
           call tool:(srv:abcdef00, sha256:0011223344556677889900112233445566778899001122334455667788990011) {path: "/logs"}
    COMMIT (srv:abcdef00, sha256:0011223344556677889900112233445566778899001122334455667788990011)
    GRANT  cap:(user:g, sha256:0011223344556677889900112233445566778899001122334455667788990011) (scope=fs.read, exp=60, from=user:g)
    REVOKE cap:(user:g, sha256:0011223344556677889900112233445566778899001122334455667788990011) (scope=fs.read, exp=60, from=user:g)
    ENDORSE (srv:abcdef00, sha256:0011223344556677889900112233445566778899001122334455667788990011) by:user:g
"""

import re
from typing import TypedDict
from lang.limits import MAX_SOURCE_BYTES, MAX_TOKENS, MAX_ACTS

from lang.ast import (
    Act, AssertAct, QueryAct, DirectAct, CommitAct, GrantAct, RevokeAct, EndorseAct,
    Principal, Reference, Capability, Payload, ToolCall,
)


class Token(TypedDict):
    kind: str
    value: str


class CapabilitySpec(TypedDict):
    scope: str
    exp: int
    from_principal: Principal


class ParseError(RuntimeError):
    def __init__(self, msg: str, pos: int) -> None:
        self.msg = msg
        self.pos = pos
        super().__init__(f"ParseError at {pos}: {msg}")


# ── Tokenizer ──────────────────────────────────────────────────────────────

_TOKEN_RE = re.compile(r"""
    (?P<WS>\s+)
  | (?P<COMMENT>\#[^\n]*)
  | (?P<ACT>ASSERT|QUERY|DIRECT|COMMIT|GRANT|REVOKE|ENDORSE)
  | (?P<HASH>[0-9a-fA-F]{8,})
  | (?P<NUMBER>\d+)
  | (?P<IDENT>[a-zA-Z_][a-zA-Z0-9_]*)
  | (?P<STRING>"[^"]*")
  | (?P<OPAQUE><[^>]*>)
  | (?P<LPAREN>\()
  | (?P<RPAREN>\))
  | (?P<LBRACE>\{)
  | (?P<RBRACE>\})
  | (?P<COLON>:)
  | (?P<COMMA>,)
  | (?P<EQUALS>=)
  | (?P<DOT>\.)
  | (?P<UNKNOWN>.)
""", re.VERBOSE)


# ── Helper to scan a word, classify as ACT/HASH/NUMBER/IDENT.
HEX = set('0123456789abcdefABCDEF')

def _is_digit(c: str) -> bool:
    return '0' <= c <= '9'

def _is_alpha(c: str) -> bool:
    return ('a' <= c <= 'z') or ('A' <= c <= 'Z') or c == '_'

def _is_alnum(c: str) -> bool:
    return _is_digit(c) or ('a' <= c <= 'z') or ('A' <= c <= 'Z') or c == '_'

def _scan_word(src: str, i: int) -> tuple[str, int, str]:
    n = len(src)
    # Determine if first char is digit -> hex_mode to scan hex digits until non-hex.
    hex_mode = _is_digit(src[i])
    word = ''
    while i < n:
        ch = src[i]
        if hex_mode:
            if ch in HEX:
                word += ch
                i += 1
            elif _is_alpha(ch):
                hex_mode = False
                word += ch
                i += 1
            else:
                break
        else:
            if _is_alnum(ch):
                word += ch
                i += 1
            else:
                break
    # Classify
    if word in ('ASSERT', 'QUERY', 'DIRECT', 'COMMIT', 'GRANT', 'REVOKE', 'ENDORSE'):
        kind = 'ACT'
    elif len(word) >= 8 and all(c in HEX for c in word):
        kind = 'HASH'
    elif word and all(_is_digit(c) for c in word):
        kind = 'NUMBER'
    else:
        kind = 'IDENT'
    return word, i, kind


def tokenize(src: str) -> list[Token]:
    if len(src) > MAX_SOURCE_BYTES:
        raise ParseError('source exceeds byte limit', 0)
    try:
        source_bytes = len(src.encode('utf-8'))
    except UnicodeEncodeError as error:
        raise ParseError('source is not valid UTF-8', 0) from error
    if source_bytes > MAX_SOURCE_BYTES:
        raise ParseError('source exceeds byte limit', 0)
    out: list[Token] = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c in ' \t\n\r\v\f':
            i += 1
            continue
        if c == '#':
            while i < n and src[i] != '\n':
                i += 1
            continue
        if len(out) >= MAX_TOKENS:
            raise ParseError('source exceeds token limit', i)
        if _is_alnum(c) or c == '_':
            word, i, kind = _scan_word(src, i)
            out.append({'kind': kind, 'value': word})
            continue
        if c == '<':
            start = i
            i += 1
            inner = ''
            while i < n and src[i] != '>':
                inner += src[i]
                i += 1
            if i >= n:
                raise ParseError('unterminated opaque payload', start)
            i += 1  # consume '>'
            out.append({'kind': 'OPAQUE', 'value': inner})
            continue
        if c == '"':
            start = i
            i += 1
            inner = ''
            while i < n:
                if src[i] == '"':
                    if i + 1 < n and src[i + 1] == '"':
                        inner += '"'
                        i += 2
                        continue
                    break
                inner += src[i]
                i += 1
            if i >= n:
                raise ParseError('unterminated string', start)
            i += 1  # consume closing quote
            out.append({'kind': 'STRING', 'value': inner})
            continue
        SINGLE = {
            '(': 'LPAREN', ')': 'RPAREN', '{': 'LBRACE', '}': 'RBRACE',
            ':': 'COLON', ',': 'COMMA', '=': 'EQUALS', '.': 'DOT',
        }
        if c in SINGLE:
            out.append({'kind': SINGLE[c], 'value': c})
            i += 1
            continue
        out.append({'kind': 'UNKNOWN', 'value': c})
        i += 1
    out.append({'kind': 'EOF', 'value': ''})
    return out


# ── Parser ─────────────────────────────────────────────────────────────────

class _Parser:
    def __init__(self, toks: list[Token]) -> None:
        self.t = toks
        self.i = 0

    # ── helpers ──────────────────────────────────────────────────────────
    def peek(self, k: int = 0) -> Token:
        return self.t[min(self.i + k, len(self.t) - 1)]

    def next(self) -> Token:
        tok = self.t[self.i]
        self.i += 1
        return tok

    def expect(self, kind: str, what: str) -> Token:
        tok = self.next()
        if tok['kind'] != kind:
            raise ParseError(f"expected {what} ({kind}), got {tok['kind']} ({tok['value']})", self.i - 1)
        return tok

    def expect_lit(self, kind: str, literal: str, what: str) -> Token:
        """Expect a token of `kind` whose value is exactly `literal`."""
        tok = self.next()
        if tok['kind'] != kind or tok['value'] != literal:
            raise ParseError(
                f"expected {what} ('{literal}'), got {tok['kind']} ({tok['value']})",
                self.i - 1,
            )
        return tok

    # ── program ───────────────────────────────────────────────────────────
    def parse_program(self) -> list[Act]:
        acts: list[Act] = []
        while self.peek()['kind'] != 'EOF':
            tok = self.peek()
            if tok['kind'] == 'COMMENT':
                self.next()
                continue
            if len(acts) >= MAX_ACTS:
                raise ParseError('program exceeds act limit', self.i)
            acts.append(self.parse_act())
        return acts

    # ── act dispatch ──────────────────────────────────────────────────────
    def parse_act(self) -> Act:
        kind = self.expect('ACT', 'act keyword')['value']
        if kind == 'ASSERT':
            return self.parse_assert()
        if kind == 'QUERY':
            return self.parse_query()
        if kind == 'DIRECT':
            return self.parse_direct()
        if kind == 'COMMIT':
            return self.parse_commit()
        if kind == 'GRANT':
            return self.parse_grant()
        if kind == 'REVOKE':
            return self.parse_revoke()
        if kind == 'ENDORSE':
            return self.parse_endorse()
        raise ParseError(f"unknown act {kind}", self.i - 1)

    # ── references / principals ───────────────────────────────────────────
    def _parse_principal(self, preserve_hash: bool = False) -> Principal:
        parts = [self.expect('IDENT', 'principal identifier')]
        while self.peek()['kind'] == 'COLON':
            self.next()
            segment = self.next()
            if segment['kind'] not in ('IDENT', 'NUMBER', 'HASH'):
                raise ParseError('expected non-empty principal segment', self.i - 1)
            parts.append(segment)
        principal_hash = '00' * 32
        if preserve_hash and len(parts) == 2 and parts[1]['kind'] == 'HASH':
            principal_hash = parts[1]['value']
        return Principal(id=':'.join(part['value'] for part in parts), hash=principal_hash)

    def parse_ref(self) -> Reference:
        self.expect('LPAREN', "'('")
        tok = self.peek()
        # Match the complete shorthand before treating sha256 as anonymous.
        if (tok['kind'] == 'IDENT' and tok['value'] == 'sha256'
                and self.peek(1)['kind'] == 'COLON'
                and self.peek(2)['kind'] == 'HASH'
                and self.peek(3)['kind'] == 'RPAREN'):
            self.next()
            self.expect('COLON', "':' in sha256:<hash>")
            content_hash = self.expect('HASH', 'sha256 hex hash')['value']
            self.expect('RPAREN', "')'")
            return Reference(principal=Principal(id='anon', hash='00' * 32), content_hash=content_hash)
        principal = self._parse_principal(preserve_hash=True)
        self.expect('COMMA', "','")
        self.expect_lit('IDENT', 'sha256', "'sha256'")
        self.expect('COLON', "':'")
        content_hash = self.expect('HASH', 'content hash')['value']
        self.expect('RPAREN', "')'")
        return Reference(principal=principal, content_hash=content_hash)

    # ── ASSERT / QUERY ────────────────────────────────────────────────────
    def _parse_payload(self) -> Payload:
        self.expect_lit('IDENT', 'data', "'data'")
        self.expect('COLON', "':'")
        payload_tok = self.peek()
        if payload_tok['kind'] == 'OPAQUE':
            self.next()
            return Payload(content=payload_tok['value'], is_opaque=True)
        elif payload_tok['kind'] == 'STRING':
            self.next()
            return Payload(content=payload_tok['value'], is_opaque=False)
        raise ParseError(f"expected payload, got {payload_tok}", self.i - 1)

    def parse_assert(self) -> AssertAct:
        self.expect_lit('IDENT', 'ev', "'ev'")
        self.expect('COLON', "':'")
        ev = self.parse_ref()
        payload = self._parse_payload()
        return AssertAct(evidence=ev, data=payload)

    def parse_query(self) -> QueryAct:
        self.expect_lit('IDENT', 'ev', "'ev'")
        self.expect('COLON', "':'")
        ev = self.parse_ref()
        payload = self._parse_payload()
        return QueryAct(evidence=ev, data=payload)

    # ── DIRECT ────────────────────────────────────────────────────────────
    def parse_direct(self) -> DirectAct:
        self.expect_lit('IDENT', 'cap', "'cap'")
        self.expect('COLON', "':'")
        cap_tok = self.next()
        if cap_tok['kind'] != 'HASH':
            raise ParseError(f"expected capability hash, got {cap_tok['kind']}", self.i - 1)
        self.expect('LPAREN', "'('")
        scope_val = self._parse_cap_spec()
        self.expect('RPAREN', "')'")
        self.expect_lit('IDENT', 'call', "'call'")
        self.expect_lit('IDENT', 'tool', "'tool'")
        self.expect('COLON', "':'")
        tool = self.parse_ref()
        params = self._parse_params()
        cap = Capability(
            cap_hash=cap_tok['value'],
            scope=scope_val['scope'],
            exp=scope_val['exp'],
            from_principal=scope_val['from_principal'],
            integrity_level='low',
        )
        return DirectAct(capability=cap, call=ToolCall(tool=tool, params=params))

    def _parse_bounded_int(self, val: str, pos: int, context: str = "number") -> int:
        """Parse a non-negative decimal integer bounded to 0..=i64::MAX.

        Rules (matching Rust's i64 parse):
        - Must contain only ASCII digits (caller guarantees this).
        - Leading zeros are stripped; all-zero input becomes "0".
        - Significant length > 19 digits -> out of range.
        - Significant length == 19 digits -> lexicographic compare against i64::MAX.
        - Raises ParseError with descriptive message, never raw ValueError.
        """
        # Strip leading zeros, keep at least one digit.
        stripped = val.lstrip('0')
        if not stripped:
            stripped = '0'
        max_str = '9223372036854775807'
        if len(stripped) > len(max_str):
            raise ParseError(f"{context} {val} out of range 0..=i64::MAX", pos)
        if len(stripped) == len(max_str) and stripped > max_str:
            raise ParseError(f"{context} {val} out of range 0..=i64::MAX", pos)
        return int(stripped)

    def _parse_cap_spec(self) -> CapabilitySpec:
        # scope=fs.read, exp=60, from=user:g
        # Enforce exactly scope, exp, from — one each, all required, no unknown keys.
        seen = set()
        scope = None
        exp = None  # will fail if absent
        from_principal = None  # will fail if absent
        while True:
            key_tok = self.expect('IDENT', 'capability key')
            k = key_tok['value']
            if k in seen:
                raise ParseError(f"duplicate capability key '{k}'", self.i - 1)
            seen.add(k)
            self.expect('EQUALS', "'='")
            val_tok = self.next()
            if k == 'scope':
                # scope must be a non-empty sequence of identifier segments
                # separated by single dots. No quotes, opaque, empty, or trailing dot.
                if val_tok['kind'] != 'IDENT' or not val_tok['value']:
                    raise ParseError(f"invalid scope value '{val_tok['value']}'", self.i - 1)
                scope = val_tok['value']
                while self.peek()['kind'] == 'DOT':
                    self.next()  # consume '.'
                    seg = self.next()
                    if seg['kind'] != 'IDENT' or not seg['value']:
                        raise ParseError(f"invalid scope segment '{seg['value']}'", self.i - 1)
                    scope += '.' + seg['value']
            elif k == 'exp':
                if val_tok['kind'] not in ('NUMBER', 'HASH') or not all(c in '0123456789' for c in val_tok['value']):
                    raise ParseError(f"invalid TTL number '{val_tok['value']}'", self.i - 1)
                exp_val = self._parse_bounded_int(val_tok['value'], self.i - 1, context="TTL")
                exp = exp_val
            elif k == 'from':
                # from must be a principal: non-empty type, optionally ':'-separated
                # non-empty segments. No quotes, opaque, empty, or trailing colon.
                if val_tok['kind'] != 'IDENT' or not val_tok['value']:
                    raise ParseError(f"invalid from value '{val_tok['value']}'", self.i - 1)
                from_id = val_tok['value']
                while self.peek()['kind'] == 'COLON':
                    self.next()  # consume ':'
                    seg = self.next()
                    if seg['kind'] not in ('IDENT', 'NUMBER', 'HASH') or not seg['value']:
                        raise ParseError(f"invalid from segment '{seg['value']}'", self.i - 1)
                    from_id += ':' + seg['value']
                from_principal = Principal(id=from_id, hash='00' * 32)
            else:
                raise ParseError(f"unknown capability key '{k}'", self.i - 1)
            if self.peek()['kind'] == 'COMMA':
                self.next()
                continue
            break
        # All three required keys must be present
        if scope is None:
            raise ParseError("missing capability key 'scope'", self.i - 1)
        if exp is None:
            raise ParseError("missing capability key 'exp'", self.i - 1)
        if from_principal is None:
            raise ParseError("missing capability key 'from'", self.i - 1)
        return {'scope': scope, 'exp': exp, 'from_principal': from_principal}

    def _parse_params(self) -> dict[str, str | int]:
        self.expect('LBRACE', "'{'")
        params: dict[str, str | int] = {}
        while self.peek()['kind'] != 'RBRACE':
            key = self.expect('IDENT', 'param key')['value']
            if key in params:
                raise ParseError(f"duplicate param key '{key}'", self.i - 1)
            self.expect('COLON', "':'")
            val_tok = self.next()
            if val_tok['kind'] == 'STRING':
                params[key] = val_tok['value']
            elif val_tok['kind'] == 'NUMBER':
                n = self._parse_bounded_int(val_tok['value'], self.i - 1)
                params[key] = n
            elif val_tok['kind'] == 'IDENT':
                params[key] = val_tok['value']
            elif val_tok['kind'] == 'HASH':
                # Accept HASH numeric values (all ASCII digits, 8+ chars) as integers,
                # matching the TTL lexical rule. Silently rejecting them would lose arguments.
                if all(c in '0123456789' for c in val_tok['value']):
                    n = self._parse_bounded_int(val_tok['value'], self.i - 1)
                    params[key] = n
                else:
                    raise ParseError(f"invalid param value '{val_tok['value']}'", self.i - 1)
            elif val_tok['kind'] == 'OPAQUE':
                raise ParseError(f"opaque values not allowed in params", self.i - 1)
            else:
                raise ParseError(f"unsupported param value kind '{val_tok['kind']}'", self.i - 1)
            # Require either comma or closing brace; no silent skip.
            if self.peek()['kind'] == 'COMMA':
                self.next()
            elif self.peek()['kind'] != 'RBRACE':
                raise ParseError(
                    f"expected ',' or '}}' after param value, got {self.peek()['kind']}", self.i - 1
                )
        self.expect('RBRACE', "'}'")
        return params

    # ── COMMIT / GRANT / REVOKE / ENDORSE ─────────────────────────────────
    def parse_commit(self) -> CommitAct:
        return CommitAct(reference=self.parse_ref())

    def parse_grant(self) -> GrantAct:
        self.expect_lit('IDENT', 'cap', "'cap'")
        self.expect('COLON', "':'")
        cap_tok = self.next()
        if cap_tok['kind'] != 'HASH':
            raise ParseError(f"expected capability hash, got {cap_tok['kind']}", self.i - 1)
        self.expect('LPAREN', "'('")
        spec = self._parse_cap_spec()
        self.expect('RPAREN', "')'")
        cap = Capability(
            cap_hash=cap_tok['value'],
            scope=spec['scope'],
            exp=spec['exp'],
            from_principal=spec['from_principal'],
            integrity_level='low',
        )
        return GrantAct(capability=cap)

    def parse_revoke(self) -> RevokeAct:
        self.expect_lit('IDENT', 'cap', "'cap'")
        self.expect('COLON', "':'")
        cap_tok = self.next()
        if cap_tok['kind'] != 'HASH':
            raise ParseError(f"expected capability hash, got {cap_tok['kind']}", self.i - 1)
        self.expect('LPAREN', "'('")
        spec = self._parse_cap_spec()
        self.expect('RPAREN', "')'")
        cap = Capability(
            cap_hash=cap_tok['value'],
            scope=spec['scope'],
            exp=spec['exp'],
            from_principal=spec['from_principal'],
            integrity_level='low',
        )
        return RevokeAct(capability=cap)

    def parse_endorse(self) -> EndorseAct:
        ref = self.parse_ref()
        self.expect_lit('IDENT', 'by', "'by'")
        self.expect('COLON', "':'")
        return EndorseAct(reference=ref, signer=self._parse_principal())


def parse(src: str) -> list[Act]:
    toks = tokenize(src)
    p = _Parser(toks)
    return p.parse_program()
