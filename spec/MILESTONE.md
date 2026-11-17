# 1.0 acceptance ledger

The operator selected the DESIGN.md security gate, including trusted authority,
endorsement, revocation and taint semantics. Passing structural tests alone does
not satisfy 1.0. MIT is selected; no release or formal proof is implied.

## Implemented locally; verify with scripts/verify.py

- Shared bounded parser and principal grammar, complete-AST differential oracle.
- Minimum-integrity joins and conservative trusted-host session observations.
- Explicit trusted Ed25519 keys, signed exact-scope grants, tool/hash binding.
- Exact-action one-use endorsement, expiry, replay refusal and revocation.
- Fail-stop capacity exhaustion; bounded sanitized audits and proxy traversal.
- Python/Rust signed fixtures, adversarial regressions, strict mypy/Clippy and CI entry point.
- Local Python host: callback execution, model/tool clearance checks, provenance,
  fresh unresumable sessions, and bounded nonblocking concurrency.
- Canonical CBOR and lossless JSON AST projection in Python and Rust, shared
  vectors, strict schema/size/depth checks and mutation parity tests.
- POSIX model/tool subprocess adapters: bounded multiplexed I/O, deadlines,
  same-group descendant cleanup and actual signed file-effect regression.
- Encrypted authority export/restore and atomic trust rotation into fresh
  subjects while preserving input taint, confidentiality and provenance.
- Project-owned private stdio service, strict protected tool configuration and
  offline authority CLI with separate encrypted-blob/wrapping-key custody.
  Runtime keys remain public-only; unsigned requests cannot change authority.
- Wheel/sdist builds, explicit package contents and isolated installation checks.
- Approved frozen utility protocol, strict paired-evidence checker and final
  release preflight that refuses missing license/revision/real measurements.
- Live assistant dogfood through an actual gated file adapter: one benign task,
  two reads/one write, six refused negative probes. This exposed and fixed source
  quoted-string representation in both parsers. See DOGFOOD-2026-11-15.md; this
  exploratory exercise is not a paired standard-benchmark utility measurement.
- CI action commit pins, tested Rust toolchain pin and dependency advisory gates.
- Completed owned-host real-assistant paired AgentDojo evaluation: 94/97 successes in each
  arm, zero harmful paired regressions, one-sided 95% upper bound 3.04 percentage
  points (approved maximum 5). All 194 traces and six ordinary failures are
  retained in `release-evidence/utility-owned-host-2026-11-15/`. This closes the
  approved sandbox utility criterion for the recorded owned-host candidate.
  The earlier run remains historical; later code changes require new measurement.

The [RC hardening review](RC-HARDENING-2026-11-16.md) records the latest
feature-to-test mapping, corrected defects and candidate-evidence boundary.

## Release and deployment obligations

The supported local host, offline custody and candidate-bound utility measurement
are implemented and verified. An external hosting or key-storage service is not
a missing implementation dependency. Before publication, run final clean release
preflight, review the retained evidence/artifacts and select the publication
destination with maintainer approval. No tag, push or publication is implied.

Both package manifests and locks now use `1.0.0`. Candidate source
`6336916d5a3e02fae00081e71936787db747ec53` passed software/artifact checks and
runtime, Rust and benchmark dependency audits before protocol freeze. The fresh
paired run in `release-evidence/utility-final-2026-11-16/` stopped after an
agent-reported launch-path transcription error: 51 traced arms completed, one
launch failed, and 142 arms were not started. It is incomplete and ineligible;
see the [incident](../release-evidence/utility-final-2026-11-16/INCIDENT.md).
A fresh full run requires an explicit restart decision under the frozen no-retry
policy. The older 94/97 result does not certify this candidate. The default final release preflight
must pass before publication. See [deployment.md](deployment.md).

The following are deployment responsibilities and explicit profile limits:

1. **Actual deployment:** the current assistant now uses a real local tool adapter
   in the exploratory dogfood profile. Broader deployment must ensure all relevant
   inputs and tool effects use the trusted host; the surrounding platform tools
   are not intercepted. A separate provider API is not needed for this dogfood
   profile. Our private stdio host and offline authority now supply the local
   deployment; their end-to-end CLI verification and local boundary review pass
   (see OWNED-HOST-VERIFICATION.md). Installation-specific OS identity isolation
   remains the deployer's responsibility, not a property inferred from unit tests.
   The standard-benchmark adapter is isolated with Bubblewrap.
2. **Authority lifecycle:** use the implemented custody/rotation and fresh-session
   recovery semantics; obtain subject/tool bindings from the trusted launcher.
   Encrypted backup/restore and trust rotation are implemented. The operator must
   use the owned custody tooling under an isolated operator identity, with a
   separate wrapping-key directory. LocalHost deliberately
   never resumes a retired subject; resumable sessions are outside this profile.
3. **Deployment information flow:** verify trusted labels assigned by actual
   provider/tool adapters. The local host now checks confidentiality and propagates
   provenance, but cannot infer hidden inputs inside a misconfigured adapter.
4. **Transcript transport integration:** the canonical codec is implemented and
   grants no authority. Current approvals still bind exact L source bytes; do not
   silently substitute projected AST text. Nonprivileged transcript expiry needs
   a host envelope if transcripts are persisted/replayed; the current host only
   processes freshly generated acts and does not expose replay ingestion.
5. **Release assurance:** MIT selected; repeat dependency advisory checks at
   release and retain a tracked source/release process. Internal security review
   is recorded; no external certification or mechanized proof exists. Do not
   advertise formal non-interference.

Every closure needs a test or retained experiment result, not a prose assertion.
The local authority protocol is owned here; its primitives are supplied by vetted
libraries. It does not claim interoperability with unimplemented standards.
