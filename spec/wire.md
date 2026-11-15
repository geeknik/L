# Canonical L wire and lossless projection, version 1

This transport serializes typed L programs, not gate decisions or authority.
Decoding never authorizes execution and never applies model GRANT/ENDORSE/REVOKE.
The existing exact-source signed approval contract is unchanged; adapters must
not substitute projected text or decoded ASTs for approved source bytes.

## Data model

The root is `[1, acts]`, where acts is an array of at most MAX_ACTS records.
Records use the full AST layouts in ast-comparison.md, excluding decisions.
Every record has exactly its documented arity; unknown kinds/extra fields refuse.
Parameters are ascending ASCII key order with no duplicate keys. Each key is
nonempty ASCII alphanumeric/underscore. Values are tagged str or int; integers
are in 0..=i64::MAX, booleans never stand in for integers. Capability exp has
the same numeric domain (zero remains a structural gate refusal).

Principals have nonempty ASCII colon-separated alphanumeric/underscore IDs and
nonempty ASCII hexadecimal hashes. References and capability hashes likewise
require nonempty ASCII hexadecimal strings (structural format; SecurityGate
separately requires full lowercase hashes and rejects anon). Scope uses nonempty
ASCII dot-separated alphanumeric/underscore segments. Integrity is exactly low,
medium, high or critical. Payload content is a Unicode scalar string and opaque
is an actual boolean. All schema strings are preserved byte-for-byte; no Unicode
normalization or implicit name defaults. Empty programs are representable, not
successful authorization.

## Deterministic binary profile

Use RFC 8949 core deterministic CBOR, restricted to definite-length arrays,
UTF-8 text strings, unsigned integers (at most i64::MAX), and false/true.
Use shortest integer and length encodings. Refuse maps, byte strings, negative
integers, floats, null, tags, indefinite lengths, reserved additional information,
invalid UTF-8, truncation, trailing bytes and non-shortest encodings. No decoder
fallback or normalization is permitted. This small closed subset needs no new
runtime dependency and is not a general-purpose CBOR library.

Before allocation, enforce MAX_WIRE_BYTES; during traversal enforce
MAX_WIRE_DEPTH and MAX_WIRE_NODES (including repeated visits on encoding).
Declared array/string lengths cannot cause allocations beyond the remaining
input or node budget. Cyclic direct-caller structures refuse within these bounds.
Encoders also enforce these limits before returning bytes.

## Projection

The human-auditable projection is compact UTF-8 JSON of that same array model,
followed by exactly one LF: no insignificant whitespace, Unicode emitted as
UTF-8, standard JSON escapes for quotes, backslashes and controls, lowercase
hexadecimal in necessary control escapes. No ASCII escaping of Unicode scalars.
It is an AST projection, distinct from the ergonomic L source syntax.
Projection import validates schema and exact canonical spelling; e.g. alternate
number syntax, extra whitespace, unknown fields and noncanonical escapes refuse.
`unproject(project(binary)) == binary` and `decode(encode(acts)) == acts`.
Binary encode and decode must also reject a program whose canonical projection
would exceed MAX_WIRE_BYTES (measure escaped length before allocation). Thus
every accepted binary has an available lossless projection within the same bound.
Opaque payloads remain data, including text resembling acts or projection syntax.

Errors are fixed WIRE.INVALID without raw bytes. Shared vectors and adversarial
mutation tests exercise both implementations. RFC reference:
https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1
