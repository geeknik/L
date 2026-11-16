# Operating the project-owned host

This is the operator workflow for [the local deployment profile](owned-host.md).
The host is a private POSIX stdio process with fixed tool commands. It does not
need an external hosting service, model provider, key service, or network listener.
The offline authority CLI and host CLI are separate processes. Keep the signing
identity under a different OS account from model/tool processes in deployment.

## Verify the local lifecycle

From the checkout root:

```bash
uv sync --locked
uv run --locked python demos/owned_host.py
uv run --locked python -m unittest tests.test_owned_host
```

The demonstration creates separate temporary 0700 directories for ciphertext,
wrapping material, and host configuration. It invokes the real authority CLI to
initialize, inspect, and sign; the real host CLI dispatches a fixed local file
writer through ToolProcess. It checks all of these before returning success:

- An unsigned request produces no file.
- A signed low-integrity grant permits the fixed fixture action.
- A signed revocation prevents another effect under that capability.
- A separate high-integrity grant refuses until an exact-source endorsement is
  signed; the endorsement permits one effect and cannot be reused.
- A restarted host has a new subject and refuses the previous grant.

The program prints only boolean checks. It removes temporary keys, configuration,
and effects on normal completion and emits a fixed error with nonzero status on
failure. This is a local integration test using one UID, not evidence of OS-account
isolation, production security, model utility, or human approval cost. Fixture
signing approves only the fixed demonstration; never turn it into an automatic
signing service for arbitrary model proposals.

## Provision authority custody

Choose two separate, pre-existing absolute directories owned by the offline
operator account, each mode 0700. Neither path may traverse symbolic links or
contain `..`. Keep the wrapping directory outside the ciphertext backup location.
Set shell variables `TSD_KEY_STORE` and `TSD_WRAPPING_KEY` to distinct new absolute
file paths in those directories; these variables contain paths, never key bytes.
Then, in the installed project environment:

```bash
python -m cli.authority init \
  --key-store "${TSD_KEY_STORE:?Set an absolute ciphertext path}" \
  --wrapping-key "${TSD_WRAPPING_KEY:?Set a separate absolute wrapping-key path}"
python -m cli.authority public \
  --key-store "$TSD_KEY_STORE" --wrapping-key "$TSD_WRAPPING_KEY"
```

Both commands return only `{"public_key":"<lowercase hex>"}`. Initialization
refuses existing destinations; it never replaces an identity. Files must remain
owner-only mode 0600, regular, single-link files. Keep both unavailable to the
host/model/tool account. The host configuration needs only the public key.

## Provision and launch the host

Create a mode-0600 configuration in a separate mode-0700 directory owned by the
host account. Use exactly the schema in [owned-host.md](owned-host.md), replacing
its illustrative public key, scopes, tool principal, and absolute adapter argv
with the reviewed local policy. Keep configuration and installed adapters outside
model-writable directories. The entire tool configuration determines its hash;
changing argv, timeout, description, or clearances requires new authorization.

Set `TSD_HOST_CONFIG` to that absolute configuration path. The trusted launcher
starts:

```bash
python -m cli.host --config "${TSD_HOST_CONFIG:?Set the protected config path}"
```

The launcher supplies one private stdin/stdout pipe pair. Requests and responses
are LF-terminated JSON objects; close the session with `{"op":"close"}`. Send
`{"op":"info"}` first and retain its fresh `subject` and each tool's principal/hash
for explicit operator review. Never take these bindings from an untrusted model
summary. All supplied inputs, including empty input batches, retain the configured
confidentiality and low integrity. There is no client label override.
The host closes an idle connection after MAX_PROCESS_SECONDS (currently 30).
While waiting for model work or human review, the launcher must send and consume
harmless `info` exchanges before that deadline. Use one serialized writer; never
interleave heartbeat bytes with another request. Heartbeats do not renew grants
or approvals. A transport failure after execution leaves the outcome uncertain;
inspect the effect before any new operator-authorized attempt.

## Sign reviewed evidence offline

Prepare exactly one JSON claims object with these existing authority fields:

```json
{"version":1,"kind":"grant","issuer":"operator","subject":"<fresh host subject>","capability":"<64 lowercase hex>","scope":"files.read","tool_principal":"srv:files","tool_hash":"<exact info hash>","integrity":"high","action_hash":"","issued_at":0,"expires_at":1,"nonce":"<fresh 64 lowercase hex>"}
```

This is a schema illustration, not a usable grant: replace bindings and timestamps
with the actual reviewed session/tool and a short current validity interval.
Choose distinct cryptographically random capability and statement nonce values.
`issuer` must match the configured trusted key. Review scope and required integrity
before signing. Low-integrity grants explicitly permit low-integrity action; they
must never be used to sidestep an operation that requires endorsement.

Set `TSD_CLAIMS_FILE` to the reviewed local claims file, containing one JSON object
and a final LF. Run under the offline authority account:

```bash
python -m cli.authority sign \
  --key-store "$TSD_KEY_STORE" --wrapping-key "$TSD_WRAPPING_KEY" \
  < "${TSD_CLAIMS_FILE:?Set the reviewed claims file}"
```

EOF is required after that one frame. The command returns only base64 `payload`
and `signature`. Transfer this signed envelope to the trusted launcher and send
`{"op":"apply","payload":"...","signature":"..."}`. Send execute requests using
the exact proposed L source and untrusted input strings, as specified in the
protocol. Do not transfer signing seeds or wrapping bytes to the launcher.

For an endorsement, review the exact UTF-8 L source bytes, hash them with SHA-256,
and sign `kind:"endorse"` with that hash in `action_hash`, the matching grant's
bindings, and a new nonce. Reformatting the source changes the hash. Endorsements
are one-use. For revocation, sign `kind:"revoke"`, matching grant bindings, an empty
`action_hash`, and a new nonce; deliver it through apply. Never automatically retry
an operation after a tool failure: an effect may already have happened.

## Recovery and limits

Back up encrypted authority blobs; protect wrapping keys separately. Restoring
both restores signing identity only. Host sessions and replay state are never
restored. Restart always requires evidence bound to a fresh subject. To rotate a
signer, initialize new custody paths, replace trusted public configuration, and
restart the host. Old evidence cannot authorize the new session.

Mode bits do not isolate processes sharing one UID. This custody profile is not
an HSM and does not protect against operator-account or root compromise. Python
does not promise secret-memory zeroization. ToolProcess bounds communication and
kills its process group; it is not an OS sandbox, and detached descendants require
OS containment. The operator is responsible for the reviewed adapter's own input
validation, filesystem permissions, and side effects. Forced termination or
filesystem failure can leave temporary or incomplete local artifacts requiring
operator cleanup. The owned-host candidate's paired utility evidence is retained
in `../release-evidence/utility-owned-host-2026-11-15/`. It describes that exact
implementation; later executable changes require a fresh frozen measurement.
