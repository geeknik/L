# Project-owned local deployment

This profile supplies our own POSIX stdio host and offline authority tooling.
It builds on LocalHost, ToolProcess and the existing Ed25519/SecretBox APIs;
it introduces no cryptography, network listener, dependency or implicit trust.

## Boundaries and failure model

The operator owns the host configuration and installed tool executables. The
model controls only JSON requests and proposed L source. The host receives only
public verification keys, never signing seeds, encrypted key blobs or wrapping
keys. The offline authority is a separate executable, accessible only to the
operator. Deploy it under a different OS identity from model/tool processes;
mode bits alone do not isolate processes sharing the authority's UID. Root and
compromised trusted adapters remain outside this isolation claim.

The transport is one private inherited stdin/stdout pipe pair per host process,
not JSON-RPC or MCP. The trusted launcher controls who receives those descriptors.
No model-provided path, command, trust map, label or clock selects host behavior.
Fresh startup creates a fresh subject; restart never resumes old authorization.
Retiring a compromised signer means provisioning a new trust configuration and
restarting, so old statements cannot regain authority. No automatic endorsement,
retry after partial effects, or transcript replay interface is supplied.

## Framing

One strict UTF-8 JSON object per LF-terminated frame, bounded by MAX_LINE_BYTES
excluding LF, MAX_ARG_DEPTH and MAX_ARG_NODES. Duplicate keys, lone surrogates,
non-object roots, noninteger numbers and integers outside signed i64 refuse.
Every read and write has a monotonic deadline at most MAX_PROCESS_SECONDS;
partial EOF, overlong frames and stalled peers terminate the session with a
fixed sanitized error where possible. No recovery skips arbitrary input bytes.
Schema/authorization errors on a complete frame return a fixed error and may
continue. Responses obey the same size bound. No raw requests are logged.
The read deadline includes idle time between requests. A trusted launcher waiting
for model work or offline human review may send complete `info` requests before
that deadline; these neither extend grant expiry nor change authorization.
Serialize requests through one writer and consume every response.

## Host configuration and protocol

The configuration is an operator-owned regular file, mode 0600, in a private
0700 directory, with no symlink components or hard links. Read through checked
descriptors and reject oversized files before decoding. Its exact schema is:

```
{"version":1,"model_clearance":"public","input_confidentiality":"public",
 "trusted_keys":{"issuer":{"public_key":"<64 lowercase hex>",
   "kinds":["grant","endorse","revoke"],"scopes":["files.read"],
   "max_integrity":"high"}},
 "tools":[{"principal":"srv:files","definition":"read interface v1",
   "argv":["/absolute/operator-installed/adapter"],"timeout":30,
   "clearance":"public","output_confidentiality":"public"}]}
```

Reject extra/missing fields, duplicate roles/scopes and invalid types; all
collections and strings use existing shared bounds. Bind tool definitions to
the canonical entire tool configuration (including argv, timeout and clearances),
not just its description. Configuration is never read from the model stream.
Initial integrity is always low. Every supplied input is low integrity with
operator-configured confidentiality; clients cannot override either label.
The proposed source receives those same labels even when `inputs` is empty.

Requests have exactly one of these schemas:

- `{"op":"info"}`: return version, fresh subject and registered principal/hash
  pairs. No paths, executable argv or secret material are returned.
- `{"op":"apply","payload":"<base64>","signature":"<base64>"}`: verify and
  apply an existing signed statement; this endpoint cannot sign anything.
- `{"op":"execute","source":"<one L act>","inputs":["untrusted text"]}`:
  taint all inputs, authorize exact source, and dispatch only through LocalHost.
  Return status and result text (or null). No client-selectable shell command.
- `{"op":"close"}`: acknowledge and terminate the fresh session.

There is no unsigned grant, approve, reset, reload or label-setting operation.
Complete malformed requests get `{"status":"DENY","error":"Invalid request"}`;
authorization/tool failures get `{"status":"DENY","error":"Operation denied"}`.
No supplied payload, path, claim or exception text appears in errors.

## Authority custody

Store the encrypted authority blob and random 32-byte wrapping key in separate
private directories. Existing files never overwrite implicitly. Creation uses
exclusive no-follow files, mode 0600, complete writes and fsync; failed creation
must not leave a usable partial key pair or delete a pre-existing file. Loading
requires owner/mode/regular-file/single-link checks, bounded reads and no symlink
path traversal. This is OS-protected local custody, not an HSM or defense against
compromise of the operator UID. Python does not guarantee memory zeroization.

The offline CLI supports init, public-key inspection and signing one explicit
claims object. It uses Authority.sign's existing strict schema and domain.
Signing outputs only base64 payload/signature; initialization/public output only
the public key. Seeds and wrapping bytes never appear in argv, environment,
stdout, stderr or logs. New signer rotation creates a new pair at new paths,
then the operator replaces trusted public configuration and restarts the host.
Backup/restore copies only encrypted blobs; wrapping keys require separate custody.

Verification must include real-process grant/endorse/revoke/file effects,
restart refusal of old evidence, malformed/oversized/stalled framing, zero
effects on denial, private-file attacks, failed initialization, and payload-free
errors. Existing benchmark evidence remains historical when executable code
changes; freeze and measure the new candidate before claiming release readiness.
