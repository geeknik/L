# Differential AST comparison v1

This is a test-oracle format, not the language wire encoding. It preserves
the parsed meaning of every AST field and the gate decision. It does not
claim a canonical language codec or prove non-interference.

`tsd-rust --emit-ast FILE` emits one compact JSON array. Successful parsing
returns `["OK", [[ACT, DECISION], ...]]`. Expected parse rejection returns
`["PARSE_ERROR"]` with exit status zero. File errors, panics, timeouts and
other process failures are infrastructure failures, never parse rejection.
The Python oracle catches only `ParseError`; unexpected exceptions fail the run.
The Rust CLI reads at most `MAX_SOURCE_BYTES + 1` bytes from a file before
decoding. Oversized source is an expected rejection (`PARSE_ERROR` in AST mode,
nonzero exit in normal/legacy modes). File-open/read and UTF-8 decoding errors
remain process failures and are never reported as a successful comparison.

Record layouts (array order is significant):

- Principal: `[id, hash]`
- Reference: `[principal, content_hash]`
- Capability: `[cap_hash, scope, exp, from_principal, integrity_level]`
- Payload: `[content, is_opaque]`
- Parameters: sorted `[key, ["str", value]]` or `[key, ["int", value]]` entries
- ASSERT / QUERY: `[kind, evidence, payload]`
- DIRECT: `["DIRECT", capability, tool_reference, parameters]`
- COMMIT: `["COMMIT", reference]`
- GRANT / REVOKE: `[kind, capability]`
- ENDORSE: `["ENDORSE", reference, signer]`
- Decision: `["ALLOW"]` or `["DENY", error_code]`

Strings use JSON escaping; Unicode text, backslashes, control characters and
newlines are preserved. Parameters are ordered by key. Comparison uses parsed
JSON values, so JSON serialization spelling is not itself a semantic mismatch.
The legacy `--emit` output remains unchanged.

The CLI fuzzer builds the Rust binary with `cargo build --locked` before
comparison. Runs print a deterministic seed (default zero), replay fixed
accept/reject cases and optional UTF-8 program files supplied with `--replay`,
then generate seeded programs and malformed mutations. Both expected parser
rejections compare equal; rejection versus acceptance differs. A crash or
unexpected exception fails the command even if both implementations fail.

Coverage relates to I5 (one parse) and I7 (fail closed). Agreement is evidence
of parity over tested inputs, not evidence that shared behavior satisfies the
language specification. Independent expected accept/reject vectors remain
necessary.
