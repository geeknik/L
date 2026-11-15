# Deployment and release preparation

## Supported integration profile

Use the Python LocalHost library with trusted, fixed model/tool adapters. POSIX
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

The wheel installs `lang`, `gate`, `proxy`, and `cli` and exposes `tsd-scan` and
`tsd-proxy`. These names are existing public modules, not a new privileged API.
Do not use the scanner or scaffold ALLOW result for real execution.

## Authority and host wiring

1. Create an Authority in a separate trusted authority process. Persist only
   `export_encrypted(wrapping_key)` ciphertext; keep the cryptographically random
   32-byte wrapping key in a separate secret manager. See authority-lifecycle.md.
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

Choose a repository license and add its exact LICENSE/SPDX metadata. Freeze an
approved real-agent experiment (utility-experiment.md), configure a real model,
run paired baseline/gated tasks, and independently inspect retained traces.
The checked-in proposal is unapproved and contains no fabricated results.

Before freezing the experiment, set candidate package versions and refresh locks,
verify all software/artifact/advisory checks, and commit the reviewed source.
Record that commit as adapter_revision. The preflight requires it to exist and
requires runtime, adapter, benchmark code and dependency manifests to remain
unchanged since measurement. Later documentation/protocol commits are permitted;
changed executable code requires new measurements. Merely setting a candidate
version does not authorize publication. No version bump has been made here.
Run `python scripts/release_check.py --results <measured-results.json>` under the
project environment. A zero exit is a technical preflight, not permission to
publish. Confirm distribution contents, license, source revision and destination
before a maintainer publishes or tags. No release has been published by this work.

The license preflight checks matching Python/Rust SPDX identifiers (MIT,
Apache-2.0 or LicenseRef-Proprietary) and a nonempty LICENSE. Maintainers must
review the actual license text and rights; this presence check is not legal review.
