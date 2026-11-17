# RC hardening review — 2026-11-16

This internal review follows the RC preparation commit `abfbcaf` and verifies
hardening commit `c0144fe`. It checks the supported local POSIX profile against
DESIGN.md and the current security, host, custody and release contracts.
It is not an exhaustive security proof or fresh utility measurement.

## Feature coverage

| 1.0 requirement | Implementation and regression coverage |
| --- | --- |
| Trusted signed authority | `gate/authority.py`, `gate/security.py`, Rust counterparts; forged signatures, unknown keys, roles, scopes and subject bindings in `tests/test_security_gate.py` and `rust/tests/security_tests.rs` |
| Exact one-use endorsement | Python/Rust security tests plus actual callback refusal in `tests/test_host.py` |
| Revocation and replay refusal | Issuer checks, approval removal, tombstones, nonce retention and regrant refusal in the security tests |
| Runtime taint and confidentiality | Trusted observations, minimum-integrity propagation and clearance checks before disclosure/dispatch in `tests/test_host.py` |
| Owned deployment and custody | `gate/service.py`, `gate/local_protocol.py`, `gate/custody.py`, offline/host CLIs; 33 protocol, custody, service and lifecycle tests |
| Bounded language and transport | Shared parser/codec limits, conformance, complete-AST differential tests and framing/deadline regressions |
| Release evidence enforcement | Explicit RC/final version checks, frozen source/protocol binding, retained trace verification and negative metadata tests |

The reviewed required features are implemented for this profile. General MCP
forwarding, durable resumable sessions, formal proof and production human-approval
cost measurements remain outside the documented implementation claim. The MCP
structural probe is not the enforcing host. No new authorization bypass was
established by this review.

## Defects fixed

- Protocol/results reads previously blocked indefinitely on a FIFO. They now
  use nonblocking, no-follow opens and validate the opened regular file before
  bounded reading. A real subprocess regression failed by timeout before the fix.
- A huge integer utility threshold raised uncaught OverflowError. Range rejection
  now precedes float conversion. Both threshold fields failed before the fix.
- Python retained full revoked grant claims despite the contract requiring
  removal; Rust already removed them. Python now drops the claims and approvals,
  retaining tombstones/nonces. The regression proves replay, regrant and execution
  remain denied. This is retention correction, not a demonstrated bypass.

## Verification

- `uv sync --locked` — passed.
- `uv run --locked python scripts/verify.py` — passed: 384 Python tests, 95 Rust
  tests, strict mypy on 27 files, Clippy with warnings denied, 10 conformance
  cases, exploit/security demos, 500 differential cases plus 9 replays, synthetic
  checks and isolated artifact installation.
- Focused host/custody/protocol/lifecycle tests — 33 passed.
- Focused security/host tests — 37 passed; Rust security tests — 12 passed.
- Retained owned-host utility report — still validates its original 97 pairs,
  94 successes per arm and 3.04118-point upper confidence bound.
- `git diff --check` — passed.

## Remaining release gate

Running release_check with `--channel rc` and the retained owned-host results
at clean `c0144fe` refuses: `Utility evidence does not match the release implementation`.
This is expected: metadata, release tooling and runtime changed since measurement.
Freeze the final candidate source and protocol, run fresh paired tasks under the
approved policy, retain all failures and traces, then rerun clean preflight.
Do not relabel historical traces or relax the source-binding check.
The successful local tests do not substitute for that experiment or final
maintainer release approval. Source pushes are not versioned releases.
