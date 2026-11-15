# Release preparation — 2026-11-15

Status: implementation preparation verified; final 1.0 release blocked by the
outstanding decisions and measured deployment evidence below. No release, tag,
push, license selection or version bump was performed.

## Changed this phase

- `lang/wire.py`, `rust/src/wire.rs`, `rust/src/lib.rs`,
  `rust/examples/wire_interop.rs`: deterministic bounded binary AST transport and
  lossless canonical JSON projection. `conformance/wire_vectors.json`,
  `tests/test_wire.py`, `rust/tests/wire_tests.rs`: shared vectors, boundary and
  mutation regressions. Projection size and concrete Python act types are checked.
- `gate/keystore.py`, `gate/authority.py`, `gate/host.py`,
  `tests/test_keystore.py`: authenticated encrypted authority restore and atomic
  fresh-subject trust rotation preserving taint, secrecy and provenance.
- `gate/process.py`, `tests/test_process.py`: fixed POSIX subprocess adapters,
  bounded multiplexed I/O, deadlines, process-group cleanup and actual authorized
  tool effects. This is not an OS sandbox or a configured model provider.
- `pyproject.toml`, `uv.lock`, `scripts/check_artifacts.py`,
  `tests/test_artifacts.py`: explicit wheel/sdist packaging and isolated installed
  CLI/runtime verification. Version remains 0.1.0.
- `benchmarks/utility_protocol.json`, `benchmarks/utility_report.py`,
  `tests/test_utility_report.py`, `scripts/release_check.py`,
  `tests/test_release_check.py`: unapproved experiment proposal, strict paired
  evidence checks, conservative regression bound, release blockers and measured
  source revision binding. License metadata checks do not replace legal review.
- `scripts/verify.py`, shared limits and their Python/Rust generated constants:
  verification wiring, wire/process resource budgets, strict module resolution.
- README, DESIGN, CALCULUS, local AGENTS and the wire, authority-lifecycle,
  process-adapter, deployment, dependencies, utility-experiment and milestone
  specifications document the implemented behavior and remaining limitations.

## Verified

- `uv run --locked python scripts/verify.py` — passed on Python 3.15.2:
  312 Python tests, 93 Rust tests, strict mypy (18 files), Clippy all targets with
  warnings denied, conformance 10/10, exploit/security demos, 500 generated fuzz
  cases plus 9 replays, synthetic microbenchmark and isolated artifact installation.
- `uv run --isolated --python 3.12 --locked python scripts/verify.py` — passed
  before the last two release-preflight tests (310 Python, 93 Rust).
  The final release/utility tests were rerun under Python 3.12: 8/8 passed.
- `uv tool run pip-audit -r /tmp/tsd-runtime-requirements.txt` — no known
  vulnerabilities in the exported locked runtime environment.
- `uv tool run pip-audit -r /tmp/tsd-build-requirements.txt` — no known
  vulnerabilities in resolved Hatchling 1.33.0 build dependencies.
- `cargo audit --file rust/Cargo.lock` — no advisories reported for 39 dependencies.
- `uv run --locked python scripts/release_check.py` — expected exit 1:
  missing final version, license, approved protocol, real paired evidence and
  tracked source commit. This is a release blocker, not a successful preflight.

These are local checks, not hosted CI results, a production deployment, an
external security certification or a real-agent utility experiment. Temporary
audit/verification logs are local artifacts, not committed release evidence.

## Required to finish

1. Select the repository license, deployment/model integration and utility
   acceptance thresholds. The questions presented to the operator remain open.
2. Provision actual model/tool adapters and secure authority/wrapping-key custody;
   validate labels and confidentiality at those deployment boundaries.
3. Review and commit the candidate implementation, freeze the benchmark protocol,
   run real paired tasks and independently review retained traces. A results JSON
   checker cannot establish the authenticity of measurements.
4. Complete the release review and final preflight against the measured source,
   with consistent version/license metadata and a clean tracked tree.

See `MILESTONE.md` and `deployment.md` for the detailed acceptance boundaries.
