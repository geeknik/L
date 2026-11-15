# Structural gate boundary

This contract covers structural validation of direct AST callers. It does not
add capability issuance, revocation, cryptographic authentication, endorsement
effects, label-lattice changes, or elapsed-time expiry enforcement.

## I4 / I7: references

Every reference-bearing act (`ASSERT`, `QUERY`, `DIRECT`, `COMMIT`, `ENDORSE`)
must contain a reference with a principal whose identifier is a non-empty
string and a content hash that is a non-empty string. Python additionally
checks the `Reference` and `Principal` container types; Rust enforces those
types statically. Invalid references return `REFERENCE.INVALID` and audit
`DENY`. This phase does not tighten hash length or lexical grammar.

An endorsement signer must likewise be a `Principal` with a non-empty string
identifier before the existing authority rule is evaluated. Malformed signers
return `REFERENCE.INVALID`; valid but unauthorized signers retain
`ENDORSE.UNAUTHORIZED`.

## I7: capability and call containers

`DIRECT`, `GRANT`, and `REVOKE` require a `Capability`. A missing or wrong
capability container returns `CAPABILITY.INVALID`. Its hash is validated first
(`REFERENCE.INVALID`), then scope and issuer structure (`CAPABILITY.INVALID`).
The issuer must be a `Principal` before its identifier is accessed. Existing
scope/issuer grammar and TTL checks remain unchanged. `DIRECT` requires a
`ToolCall` container (`REFERENCE.INVALID`) before accessing the tool reference.

DIRECT validation order is capability structure, integrity requirement, tool
reference, TTL. A malformed integrity requirement refuses with
`INTEGRITY.DIRECT.DENIED`. GRANT/REVOKE validate capability structure then TTL.
Both implementations return the first error in this order.

## I1 / I7: runtime labels and audit finalization

Each execution owns its audit entry, even when a trusted label-assignment
callback reenters the gate. A callback exception or non-`Label` result returns
`LABEL.INVALID` with a fixed message and audit `DENY`; exception text is not
copied into that record. Other unexpected execution failures return
`GATE.INTERNAL` with a fixed message and audit `DENY`. No failure may return
an allowed act or leave its own entry at `ENTER`. Explicit `now=0` remains zero.

Gate audit collections retain only the newest `MAX_AUDIT_RECORDS` entries,
using the generated constant from `spec/limits.md`. Python denial entries
store the error code and fixed text, never the exception message containing
caller-supplied principal, scope, or payload text. Rust audit entries contain
only the act type, timestamp, and decision.

These callback error codes are Python-specific because Rust has no callback
label assigner. Unsupported Python acts return `ACT.UNSUPPORTED` and `DENY`.

Reject vectors live in `tests/test_gate.py` and `rust/tests/gate_tests.rs` and
identify I4/I7 or I1/I7 in their test documentation.
