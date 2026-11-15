# Security gate contract (implementation target)

This is the local trusted-runtime contract for the DESIGN.md gate. The old
`Gate` remains a structural checker for scanners. It is not an authorization
decision. Hosts must use `SecurityGate` for operations affecting resources.
No model text, parser field, matching name, or legacy Gate ALLOW authenticates
an identity. A successful security decision is not tool execution.

## Trust boundary

The host constructs one gate per authenticated session with its subject ID,
initial integrity (default low), and an explicit map of trusted Ed25519 public
keys. Each trusted key has exact allowed scopes, allowed statement kinds, and
a maximum integrity level. There are no built-in keys, wildcard scopes, or
privileged names. The host supplies current epoch seconds from a trusted clock;
the gate refuses time rollback. Private signing keys stay outside the gate.
`observe(level)` is a trusted host operation for every influencing input and
can only lower the session's integrity. Model-supplied labels are never used.

## Signed statements

Our authority issues Ed25519 signatures using established libraries, never
custom curve/signature code. Sign the exact UTF-8 payload bytes prefixed by
`TSD-AUTHORITY-v1\0`. The envelope contains payload bytes and a 64-byte signature;
the transport representation is separate from the L canonical wire format.
Do not normalize a payload before checking its signature.

The payload is a JSON object with exactly these fields (duplicates rejected):

| Field | Contract |
| --- | --- |
| version | integer 1, not boolean |
| kind | grant, endorse, or revoke |
| issuer | exact trusted key ID / principal |
| subject | exact authenticated session subject |
| capability | 64 lowercase hexadecimal characters |
| scope | nonempty ASCII dot-separated alphanumeric/underscore segments |
| tool_principal | nonempty ASCII colon-separated alphanumeric/underscore segments |
| tool_hash | 64 lowercase hexadecimal characters |
| integrity | low, medium, high, or critical |
| action_hash | SHA-256 of exact UTF-8 single-DIRECT source for endorse; empty otherwise |
| issued_at | integer epoch seconds, 0..=i64::MAX |
| expires_at | integer epoch seconds, issued_at < expires_at <= i64::MAX |
| nonce | 64 lowercase hexadecimal characters, unique per issuer/session |

All statement kinds must be signed, scope-authorized, within the key's integrity
ceiling, and satisfy issued_at <= now < expires_at. Statement metadata must
match the live capability for endorsement/revocation. Only the grant issuer
may revoke its grant. Endorsers need a separately authorized endorse role.
Unknown fields/types, signature failure, replay, missing trust, and unknown
capabilities deny with fixed errors and sanitized bounded audit records.

## State transitions and execution

`apply(envelope, now)` verifies everything before mutation. Grant installs a
capability bound to subject, scope, tool principal/hash, required integrity,
issuer and absolute expiry. Duplicate/revoked IDs cannot be re-granted in the
same session. Endorse installs a one-use approval bound to that capability,
exact action hash, subject, integrity and expiry. Revoke removes the grant and
all its approvals, retaining a tombstone. Evidence nonces cannot be replayed.

`execute(source, now)` accepts exactly one parsed act and first runs structural
validation. Model GRANT/REVOKE/ENDORSE refuse: only signed `apply` can change
authority state. ASSERT/QUERY/COMMIT record a structural, non-privileged decision;
ASSERT/QUERY lower session integrity to low. DIRECT requires a live grant.
Its cap hash/scope/issuer and tool principal/hash must match the grant. Its TTL
must not exceed the signed grant lifetime; the signed absolute expiry always
wins. Required integrity comes from the grant, never the model's capability.
If session integrity is too low, an unexpired approval of the exact source and
capability with sufficient integrity is required and consumed on success.
An endorsement never raises session integrity or authorizes altered arguments.

Gate state is per process/session and single-owner (hosts serialize calls).
Security state collections are bounded by MAX_SECURITY_RECORDS. Capacity
exhaustion latches the session closed: further APPLY and privileged DIRECT
operations refuse AUTH.CAPACITY. This prevents an exhausted replay store from
blocking revocation while leaving old grants usable. Nonprivileged observations
and acts may continue; a host must end the exhausted session, not clear its state.
Replay/revocation protection survives for the session lifetime, not a restart.
Persistent deployment must supply durable state before claiming restart-safe
revocation/replay protection. No production release until host integration,
key custody/rotation, durable-state policy and real utility evaluation are tested.

## Verification and dependencies

Tests must cover forged signatures/unknown keys, schema ambiguity, exact scope
and tool binding, expiry/rollback, grant/endorse/revoke lifecycle, replay,
altered payloads, low-input propagation, one-use approvals, capacity refusal,
sanitized audits, and cross-language signed-statement compatibility.
See dependencies.md and limits.md. No safety claim follows from ordinary
structural fuzz agreement alone. This contract does not claim a mechanized proof.
