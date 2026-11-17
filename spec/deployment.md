# Deployment and release preparation

## Supported integration profile

Use our `tsd-host` service and `tsd-authority` offline operator tool, described in
[owned-host.md](owned-host.md), for the supported local POSIX deployment. This
profile owns its transport, protected configuration and encrypted key custody;
no external host or secret-manager product is required. The model receives only
the private pipe endpoints, not authority files or operator configuration.
See [the operator workflow](owned-host-operations.md) for provisioning, explicit
signing, rotation and recovery, and [verification](OWNED-HOST-VERIFICATION.md)
for the tested lifecycle and its limits.

The Python LocalHost library also supports trusted, fixed model/tool adapters. POSIX
process adapters provide bounded JSON I/O and deadlines; they are not an OS
sandbox. The Rust library supplies equivalent core authority/security/wire logic,
not a Rust LocalHost or provider daemon. The MCP proxy remains structural only.

```bash
uv sync --locked
uv run --locked python scripts/verify.py
uv run --locked python -m demos.security_demo
uv build
uv run --locked python scripts/check_artifacts.py
```

The wheel installs `lang`, `gate`, `proxy`, and `cli` and exposes `tsd-host`,
`tsd-authority`, `tsd-scan` and `tsd-proxy`.
Do not use the scanner or scaffold ALLOW result for real execution.

## Authority and host wiring

1. Create an Authority in a separate trusted authority process. Persist only
   `export_encrypted(wrapping_key)` ciphertext; keep the cryptographically random
   32-byte wrapping key in separate protected custody. The owned authority CLI
   implements this with separate operator-owned 0700 directories and checked
   0600 files. It requires an OS identity isolated from model/tool processes.
   See authority-lifecycle.md and owned-host.md.
2. Provision explicit TrustKey entries with exact roles, scopes and ceilings.
   Register each tool with immutable definition bytes, actual principal, callback,
   recipient clearance and conservative output confidentiality.
3. Construct LocalHost with model clearance and a trusted epoch clock. Its random
   `subject` identifies this fresh session; have the authority sign grants for it.
4. Send every influencing input as trusted LabeledInput metadata. Unknown external
   text is low integrity. Never trust labels from model output or remote content.
5. For subprocess transport, use fixed absolute argv with ModelProcess/ToolProcess.
   Programs receive only the documented input/argument JSON. They load any provider
   credentials through their own trusted secret-manager integration; the transport
   deliberately does not inherit the caller's credentials or environment.
6. Call host.run with inputs and the model adapter. Required endorsements bind the
   exact proposed L source hash. Never automatically approve arbitrary proposed
   actions. Tool dispatch happens only after signed authorization and flow checks.
7. Replace compromised signer policy with rotate_trust. The subject changes and
   all grants/approvals must be freshly issued. Taint and secrecy do not reset.
   Persisted old statements cannot resume the retired session.

Authority key storage is not authorization-state persistence. This profile never
resumes sessions after restart. The primitive SecurityGate is single-owner and
in-memory; callers bypassing LocalHost must enforce these same boundaries.
Direct Python callbacks remain responsible for deadlines. Process adapters kill
their process group on failure/completion, but detached groups require OS-level
containment. No automatic retry follows partial tool effects.

## Final release gates

MIT is selected. The current final candidate uses `1.0.0` in both manifests.
The earlier explicit RC used Python `1.0.0rc1` and Rust `1.0.0-rc.1`.
Use `--channel rc` for the RC preflight; the default `final` channel accepts
only final versions. Mixed channels or RC numbers are rejected.
The operator approved the sandbox policy and utility criteria in utility-run.md.
Commit the complete protocol before starting paired baseline/gated tasks, and
independently inspect retained traces. No fabricated results may substitute for
these measurements. This assistant is the agent; separate provider credentials
are not needed for the isolated benchmark profile.

Before freezing the experiment, set candidate package versions and refresh locks,
verify all software/artifact/advisory checks, and commit the reviewed source.
Record that commit as adapter_revision. The preflight requires it to exist and
requires runtime, adapter, benchmark code and dependency manifests to remain
unchanged since measurement. Later documentation/protocol commits are permitted;
changes to executable code or measured manifests/scripts require new measurements.
The retained owned-host run certifies its recorded 1.0.0 candidate, not the later
RC metadata/tooling revision. Do not rewrite its protocol or traces to relabel it.
Choose the intended release channel before the last measurement:

- For RC publication, freeze and measure the RC source and use `--channel rc`.
- For final 1.0 publication, first set both manifests to `1.0.0`, refresh both
  lockfiles, complete code changes and verification, and commit that source.
  Freeze the protocol against that commit, run and retain the paired experiment,
  then use the default final preflight. An RC measurement cannot certify a later
  final-version bump under the exact-source rule.

Do not run an extra RC experiment merely as a prerequisite to the final one.
The historical measurements remain separate evidence for their own revisions.
Merely setting a candidate version does not authorize publication.
Run `python scripts/release_check.py --results <measured-results.json> --trace-root <directory>` under the
project environment. A zero exit is a technical preflight, not permission to
publish. Confirm distribution contents, license, source revision and destination
before a maintainer publishes or tags. No release has been published by this work.

The license preflight checks matching Python/Rust SPDX identifiers (MIT,
Apache-2.0 or LicenseRef-Proprietary) and a nonempty LICENSE. Maintainers must
review the actual license text and rights; this presence check is not legal review.
