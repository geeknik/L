# Local reference host contract

This host is an executable reference integration, not an MCP transport or an
agent benchmark. It demonstrates I1/I3/I4/I7/I8 at actual callback execution.

The host creates a fresh unpredictable session subject at construction, supplies
its own trusted clock, and never resumes a previous session. Grants must bind
that new subject. Restart therefore invalidates old-session evidence; it does
not implement persistent revocation across resumable sessions. Trusted keys and
immutable tool registrations are supplied by the operator, never model output.

A registered tool has a named principal, exact definition bytes, SHA-256 hash
computed by the host, recipient clearance and a trusted callback. Definitions
and registrations are bounded by shared source/security limits. No duplicate
principal/hash binding or dynamic model-selected callback is allowed.

One serialized run receives bounded labeled inputs and a model adapter. The
host validates the complete input batch before passing any bytes to the model,
checks its configured recipient clearance, accumulates provenance and maximum
confidentiality, and lowers session integrity for all inputs before model work.
Labels are trusted host metadata; adapters must wrap untyped external inputs
at low integrity. Model text never sets these labels. Input payloads are not
retained in audit/state; only bounded label metadata persists.

The adapter returns one source act. SecurityGate authorizes that exact source.
Only a returned DIRECT can invoke a registered callback. The tool identity/hash
must match the registry and the session confidentiality must flow to the tool's
clearance. The callback receives a copy of the validated arguments, never raw
source. Denials cause zero callback executions. Tool result text is bounded,
treated as low integrity, and assigned the maximum of session confidentiality
and the tool's trusted output confidentiality (default: its clearance). Its
provenance includes the tool principal. Validate provenance capacity and output
recipient clearance before dispatch; do not invoke a tool whose declared output
cannot flow to the model. Tool adapters must conservatively label their outputs.
Non-DIRECT acts have no callback side effects. All external errors are fixed.

A nonblocking lock serializes apply, observation, authorization and dispatch.
Same-thread reentry refuses with HOST.REENTRANT; concurrent operations refuse
with HOST.BUSY instead of waiting or growing a queue. The caller may retry an
operation explicitly after the active one finishes. A consumed approval is not restored after tool failure (retry
needs new authority); a tool error may have partial effects and is never retried
automatically. Callbacks/model adapters are trusted local code and must provide
their own I/O deadlines; Python threads cannot safely cancel arbitrary code.

Tests cover valid exact callback arguments, missing grant, taint/approval/revoke,
changed definition, confidentiality refusal before disclosure, low tool output,
reentrancy, bounded inputs and failures, and fresh-session replay refusal.
No secret key enters the host. A local demo may use an ephemeral authority.
