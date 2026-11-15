# Shared resource limits

These limits bound structural validation at every public entry point (I6).
They are not a deadline, rate limit, or substitute for host process isolation.
The table is authoritative; run `python3 scripts/generate_limits.py` after
changes and `python3 scripts/generate_limits.py --check` in verification.
Generated Python and Rust modules must never be edited by hand.

| Constant | Value | Meaning |
| --- | ---: | --- |
| MAX_SOURCE_BYTES | 65536 | UTF-8 bytes per L program, before token allocation |
| MAX_TOKENS | 8192 | Tokens excluding EOF per L program |
| MAX_ACTS | 1024 | Acts per L program |
| MAX_LINE_BYTES | 65536 | JSON-RPC frame bytes excluding terminating LF |
| MAX_ARG_DEPTH | 16 | Argument nesting; root is depth zero |
| MAX_ARG_NODES | 1024 | All visited argument values including root and repeated aliases |
| MAX_ARG_STRING_BYTES | 65536 | Aggregate UTF-8 bytes in argument string values |
| MAX_AUDIT_RECORDS | 1024 | Most recent decision records retained per audit store |
| MAX_AUTHORITY_BYTES | 8192 | Signed authority payload bytes before decoding |
| MAX_SECURITY_RECORDS | 1024 | Entries in each security state map/set; overflow denies |
| MAX_WIRE_BYTES | 65536 | Canonical binary or projection bytes before decoding |
| MAX_WIRE_DEPTH | 16 | Wire container depth; root is zero |
| MAX_WIRE_NODES | 8192 | Wire values visited including containers |
| MAX_PROCESS_SECONDS | 30 | Maximum subprocess adapter wall-clock deadline |
| MAX_BENCH_MEMORY_BYTES | 1073741824 | Isolated benchmark worker virtual address-space ceiling |

Inputs exactly at a limit remain eligible for normal validation. Exceeding
a limit refuses the input. Audit overflow evicts the oldest decision, never
changes the decision, and never retains payloads. The host must consume an
external audit sink if durable complete history is required.
