# L: A Trust-Typed Language for Agents — CALCULUS.md

L is a minimal trust-typed language with a formally specified core calculus. The following defines the syntax, label lattice, operational semantics, and the four enforcement rules that constitute the design's central constraint.

**Implementation status (2026-11-15).** The structural Gate remains a scanner.
The separate SecurityGate implements signed capabilities, one-use exact-action
endorsement, revocation, expiry and conservative session integrity in Python and
Rust. Its normative contract is [spec/security-gate.md](spec/security-gate.md).
These are local runtime semantics, not an end-to-end security proof or a 1.0
release. The remaining design obligations are in [spec/MILESTONE.md](spec/MILESTONE.md).

## Syntax

L consists of seven core acts, each with explicit syntax and label structure:

```text
ASSERT ev:(<principal-id>, sha256:<hash>) data:<opaque | string>
DIRECT cap:<hash> (scope:<dotted>, exp=<seconds>, from:<principal>) call tool:<reference> {key: value}
COMMIT <reference>
GRANT  <capability-spec>
REVOKE <capability-spec>
ENDORSE <reference> by:<principal-id>
QUERY  ev:(<principal-id>, sha256:<hash>) data:<opaque | string>
```

### Reference Format

Every reference is `(<type>:<id>, sha256:<content-hash>)` where:
- `<type>`: `user:<g>`, `srv:<hex>`, `admin`
- `<content-hash>`: 256-bit hex string (lowercase)
- `<id>`: principal identifier (e.g., `user:g`, `srv:9c1e`)

### Capability Spec

`cap:<hash> (scope=<dotted>, exp=<seconds>, from=<principal>)`

- `scope`: dotted domain of authority (e.g., `fs.read`, `net.api.call`)
- `exp`: TTL in seconds (>0)
- `from`: principal issuing the directive

### Parameter Value Grammar and Type Contract

A `DIRECT` act carries a tool-call parameter map `{key: value}` passed to the target tool. The shared parameter-value contract is:

- **Textual values**: quoted strings or bare identifiers — represented as strings (`s:<str>`).
- Source strings preserve backslashes and whitespace literally; double an embedded
  quotation mark (`"a""b"` represents `a"b`). See `spec/source-strings.md`.
- **Numeric values**: integer tokens (and decimal-only digit strings classified as `HASH` by the tokenizer) — represented as integers (`i:<int>`), bounded to `0..=i64::MAX` (mirrors the TTL numeric range).
- **Unsupported value kinds** (e.g., `<opaque>` payloads used as tool arguments) — **rejected at parse time** with `ParseError`. They are never silently dropped, because a dropped argument would let the gate approve a directive whose arguments differ from the supplied program.

Parameter keys must be unique, even when repeated values are identical. Entries must be separated by commas. Empty maps and a single trailing comma after the final entry are permitted; missing separators and duplicate keys reject the entire program.

Numeric values in TTLs and tool arguments use a shared bounded-decimal parse: ASCII digits only, leading zeros stripped (all-zero input becomes `0`), significant-digit length capped at 19 and compared lexicographically against `9223372036854775807` before conversion, then converted to int. Python must not use unbounded `int()` directly on arbitrarily long digit strings (its conversion safeguard raises `ValueError` past ~4,300 digits); it must route through this bounded helper. Oversized significant values raise `ParseError`, never raw `ValueError`. All-zero numeric input parses as `0` (TTL `0` is then gate-denied via `EXPIRY.INVALID`).

The Python and Rust implementations share this contract. Both preserve every unique key and its typed value; neither may skip or coerce unknown token kinds. Canonical comparison sorts keys independently of input order.

### Principal Binding

Every reference binds a principal to a content hash. A content hash binds bytes; it does not establish authority. Authority requires a verified statement under an explicitly trusted key.

## Labels

Every term carries three labels (per `lang/labels.py`):

1. **Provenance**: `tuple` of principals in the chain of custody
2. **Integrity**: `low` < `medium` < `high` < `critical`
3. **Confidentiality**: `public` < `restricted` < `secret` < `top_secret`

### Label Lattice

```python
def join(self, other: Label) -> Label:
    return Label(
        provenance=tuple(sorted(set(self.provenance) | set(other.provenance))),
        integrity=min((self.integrity, other.integrity), key=INTEGRITY_ORDER.index),
        confidentiality=_max_of(CONFIDENTIALITY_ORDER, self.confidentiality, other.confidentiality),
    )
```

**Contract (I3).** Combining influences takes the lowest integrity and highest
confidentiality. Provenance is the union. No combination of inputs elevates
integrity. Authorized endorsement is a separate exact-action permission,
never an ordinary join and never a session-wide trust upgrade. The shared
`conformance/label_vectors.json` pins all integrity pairs. Structural Rust
validation always uses low; its security runtime applies this same minimum
when observing influencing inputs.

### Default Label

For anything a model emits after reading untrusted data:
```python
LOW = Label(provenance=('untrusted',), integrity='low', confidentiality='public')
```

## Operational Semantics

The security contract separates the scanner from the authorization runtime.
`gate/monitor.py` and `rust/src/gate.rs` perform structural validation only.
`gate/security.py` and `rust/src/security.rs` are the stateful authorization APIs.

### Rule 1: Runtime influence

An authenticated host supplies the session subject, initial integrity and every
influencing input through `observe`. Integrity combines by minimum. ASSERT and
QUERY lower session integrity to low. The model cannot supply trusted labels.
This is conservative session taint, not inferred per-value dataflow. Correct
host observation remains an integration obligation.

### Rule 2: DIRECT

A DIRECT requires a live signed capability matching subject, cap hash, scope,
issuer and tool principal/hash. Its runtime integrity must meet the grant's
required integrity, or an exact-action approval under Rule 3 must exist.
The model's capability fields never determine trusted required integrity.

### Rule 3: ENDORSE

Signed `apply` installs one-use approvals of the exact UTF-8 DIRECT source hash,
subject, capability and expiry. Only a provisioned key with endorse authority
for the exact scope may issue one. Names resembling administrators carry no
authority. Success consumes the approval without raising session integrity.
Model-written ENDORSE, GRANT and REVOKE refuse at the security boundary.

### Rule 4: References and expiry

Security references require named principals and full lowercase SHA-256 hashes.
The signed grant binds the tool identity and content hash. TTL syntax remains
an integer in `1..=i64::MAX`; security execution additionally bounds it by the
signed lifetime and enforces absolute expiry using the host's monotonic clock.
Rollback, replay and revoked capabilities refuse. Nonprivileged surface acts
have no issuance metadata; full transcript expiry remains a design obligation.

## Evidence and limits of the claim

- Shared principal and label vectors pin grammar and all integrity joins.
- Full-AST differential fuzzing compares every field and structural decision;
  crashes, timeouts and malformed subprocess output are test failures.
- Signed vectors and adversarial tests cover authority verification and state
  transitions in both languages, including one-use and changed-action refusal.
- Parser, traversal, signed payload, security-state and audit bounds come from
  `spec/limits.md`; generated constants are checked for drift.
- No mechanized non-interference proof exists. Tests do not establish one.

The intended property is: a low-integrity session cannot authorize an action
requiring higher integrity without explicit authority for that exact action.
It depends on trusted host identity, clock, key provisioning, input observation,
and execution of only the returned validated act. It does not imply that a
signed tool is safe or that omitted host observations can be detected.

## Remaining 1.0 obligations

The MCP proxy is a structural scaffold. The local Python reference host enforces
the security API on registered callbacks, with confidentiality recipient checks,
provenance accumulation and trusted input observation. It is not a production
model/MCP adapter. Fresh random session subjects prevent reuse of old evidence
after reconstruction; underlying gate state is still process-local. Key custody,
rotation and resumable sessions require deployment integration. Canonical binary
wire encoding and lossless projection are implemented under `spec/wire.md`;
decoding does not authorize anything or change exact-source approvals. Real agent utility
has not been measured and no threshold has been approved. Licensing and formal
proof claims remain unresolved.

See [spec/MILESTONE.md](spec/MILESTONE.md) for release acceptance criteria.
