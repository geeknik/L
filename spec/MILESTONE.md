# 1.0 acceptance ledger

The operator selected the DESIGN.md security gate, including trusted authority,
endorsement, revocation and taint semantics. Passing structural tests alone does
not satisfy 1.0. No release, license or formal proof is implied.

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
- Wheel/sdist builds, explicit package contents and isolated installation checks.
- Frozen utility-protocol proposal, strict paired-evidence checker and final
  release preflight that refuses missing license/revision/real measurements.
- Live assistant dogfood through an actual gated file adapter: one benign task,
  two reads/one write, six refused negative probes. This exposed and fixed source
  quoted-string representation in both parsers. See DOGFOOD-2026-11-15.md; this
  exploratory exercise is not a paired standard-benchmark utility measurement.
- CI action commit pins, tested Rust toolchain pin and dependency advisory gates.

## Release obligations still open

1. **Actual deployment:** the current assistant now uses a real local tool adapter
   in the exploratory dogfood profile. Broader deployment must ensure all relevant
   inputs and tool effects use the trusted host; the surrounding platform tools
   are not intercepted. A separate provider API is not needed for this dogfood
   profile. The standard-benchmark adapter and full deployment boundary review
   remain to be completed.
2. **Authority lifecycle:** secure key custody and rotation; authenticated subject
   provisioning; durable session/replay/revocation semantics and recovery tests.
   Encrypted backup/restore and trust rotation are implemented. The operator must
   provision secure storage and a separate wrapping key. LocalHost deliberately
   never resumes a retired subject; resumable sessions are outside this profile.
3. **Deployment information flow:** verify trusted labels assigned by actual
   provider/tool adapters. The local host now checks confidentiality and propagates
   provenance, but cannot infer hidden inputs inside a misconfigured adapter.
4. **Transcript transport integration:** the canonical codec is implemented and
   grants no authority. Current approvals still bind exact L source bytes; do not
   silently substitute projected AST text. Nonprivileged transcript expiry needs
   a host envelope if transcripts are persisted/replayed; the current host only
   processes freshly generated acts and does not expose replay ingestion.
5. **Utility experiment:** select a standard agent benchmark, freeze benign task
   criteria and acceptable loss threshold before running gated/ungated comparison.
   Synthetic throughput is not evidence for this requirement.
6. **Release assurance:** select repository license, repeat dependency advisory
   checks at release, independent security review, tracked source/release process.
   No mechanized proof exists; do not advertise formal non-interference.

Every closure needs a test or retained experiment result, not a prose assertion.
The local authority protocol is owned here; its primitives are supplied by vetted
libraries. It does not claim interoperability with unimplemented standards.
