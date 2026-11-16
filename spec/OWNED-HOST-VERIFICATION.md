# Owned host verification — 2026-11-15

The local POSIX deployment now supplies its own stdio host, protected tool
configuration, offline authority CLI and encrypted local custody. It needs no
external host or key-service integration. Vetted Ed25519/SecretBox primitives
and existing dependencies are unchanged.

## Verified

- `uv run --locked python scripts/verify.py` — exit 0: 379 Python tests,
  95 Rust tests, strict mypy on 27 files, Clippy all targets with warnings denied,
  conformance 10/10, exploit/security demos, 500 generated differential programs
  plus 9 replay cases, synthetic checks, wheel/sdist and isolated installation.
- `uv run --isolated --python 3.12 --locked python -W error::ResourceWarning
  -m unittest discover -s tests` — 379 passed.
- `uv run --locked python demos/owned_host.py` — real offline CLI initialization,
  public-key recovery and signing; private host pipes; authorized file effects;
  unsigned/revoked/unendorsed/reused endorsement/previous-session refusals;
  temporary state removed.
- `uv tool run pip-audit==2.10.1 --require-hashes --disable-pip
  -r /tmp/tsd-owned-runtime-audit.txt` — no known vulnerabilities in the runtime
  requirements exported from `uv.lock` with no development packages.
- The same advisory command against `benchmarks/agentdojo-requirements.lock`
  — no known vulnerabilities in the pinned benchmark environment.
- `cargo audit --file rust/Cargo.lock` — no advisories for 39 dependencies.

Transport tests include strict JSON/UTF-8, duplicate fields, size/depth/node
bounds, exact frame limits, partial EOF, stalled peers, fixed errors and restored
descriptor modes. Custody tests include permissions, ownership, symbolic/hard
links, FIFOs, tampered ciphertext, wrong wrapping keys, short/failed writes,
failed fsync and collision-safe rollback. A huge integer process timeout now
refuses with PROCESS.INVALID instead of leaking OverflowError.

Two implementation agents separately reviewed each other's host/custody/transport
boundaries; the coordinating agent inspected final source and ran full checks.
This is internal review, not external certification or a mechanized proof.

## Evidence limits

The CLI lifecycle uses temporary fixtures under one UID. Deployment must keep the
offline signing account separate from model/tool processes and protect reviewed
configuration and adapters. ToolProcess bounds I/O and process-group lifetime;
it is not an OS sandbox. Root, the signing account and trusted adapter compromise
are outside this local isolation claim. No real deployment identities were
created and no long-lived production keys were provisioned by the demonstration.

The benchmark exercises HostSession in its gated arm and applies equal framing
bounds to both arms. The fresh candidate-bound run completed all 97 pairs once:
94/97 successes in each arm, zero harmful regressions and a one-sided 95% upper
bound of 3.04118 percentage points (approved maximum 5). The six normal failed
arms are retained; no infrastructure errors or retries occurred. See
`../release-evidence/utility-owned-host-2026-11-15/README.md`. This measures the
approved sandbox policy, not production endorsement costs or attack resistance.
Later executable changes require fresh evidence. No release, tag, push or
publication is implied.
