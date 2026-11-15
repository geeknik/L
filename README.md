# L: A Trust-Typed Language for Agents

L is a seven-act language with Python and Rust parsers, structural scanners,
and a separate stateful security gate. **1.0 is not released.** No formal
non-interference guarantee is claimed.

## Status (2026-11-15)

The security API (`gate/security.py`, `rust/src/security.rs`) verifies our own
signed authority statements using established Ed25519 libraries. It enforces
trusted capability lookup, exact scope/tool binding, absolute expiry,
revocation, replay refusal, session integrity that only decreases, and one-use
endorsement of the exact action bytes. Trust keys and input labels come from
the host, never from model text. See [the contract](spec/security-gate.md).

The existing `Gate`, CLI scanner and MCP proxy remain **structural tools**.
Their ALLOW result is not permission to execute a tool. The proxy has no upstream
transport or authority integration. Model-written GRANT/REVOKE/ENDORSE cannot
mutate SecurityGate authority; its signed `apply` API is the only state-changing
entry point.

Other completed hardening includes shared parser/traversal/audit bounds,
sanitized diagnostics, minimum-integrity label joins, shared principal vectors,
full-AST differential comparison, and fail-closed verification runners.

`gate/host.py` is a local reference integration: it checks model/tool recipient
clearance, accumulates provenance and taint, binds registered tool definitions,
and dispatches only validated arguments. It creates fresh unresumable sessions;
old grants cannot authorize a new session. Trusted adapters supply I/O deadlines.

`gate/process.py` supplies bounded POSIX subprocess adapters with enforced
deadlines and fixed schemas. `gate/keystore.py` supports encrypted authority-key
backup/restore; `LocalHost.rotate_trust` retires old authority without clearing
taint. `lang/wire.py` and `rust/src/wire.rs` implement canonical CBOR and lossless
JSON AST projection. See [deployment instructions](spec/deployment.md).

The assistant has used the gate interactively for real temporary file operations.
[Dogfood results](spec/DOGFOOD-2026-11-15.md) record the successful task, refused
probes, and a source-string defect found and fixed during integration. Run
`uv run --locked python -m demos.dogfood_host` for the bounded JSON-line interface;
its [contract](spec/dogfood.md) distinguishes this exercise from the required
standard-benchmark utility experiment.

The approved paired AgentDojo experiment is complete: baseline and gated runs
each passed 93/97 tasks, with zero harmful paired regressions. The computed
one-sided 95% upper bound is 3.04 percentage points, below the approved 5-point
threshold. All 194 arms and the four tasks failed by both arms are retained in
[the evidence](release-evidence/utility-2026-11-15/README.md). This measures
low-integrity sandbox autonomy, not production endorsement costs or security
against malicious agents.

Still required before 1.0: production provider/transport integration, tested key
custody provisioning and release review. The sandbox utility criterion is met.
See [the milestone checklist](spec/MILESTONE.md). Core SecurityGate state remains
process-local; restarting it with an old subject would discard replay protection.

## Enforcement boundary

1. The host assigns initial integrity and calls `observe` for inputs. Combining
   influences takes the minimum integrity; model text cannot raise it.
2. A DIRECT requires an unexpired signed grant for the exact subject, scope,
   tool principal and content hash. Its required integrity is trusted metadata.
3. Insufficient integrity requires a signed endorsement of the exact UTF-8
   DIRECT source. That approval is consumed on success, never a session upgrade.
4. Signed statements reject unknown keys, forged signatures, duplicate/unknown
   fields, invalid time, replay and changed bindings. Capacity exhaustion blocks
   further privileged operations. Audits retain only bounded sanitized metadata.

## Language Syntax

### Core Acts

All acts are capitalized keywords; fields are separated by whitespace.

```text
ASSERT ev:(<principal-id>, sha256:<hash>) data:<opaque | string>
DIRECT cap:<hash> (scope:<dotted>, exp=<seconds>, from:<principal>) call tool:<reference> {key: value}
COMMIT <reference>
GRANT  <capability-spec>
REVOKE <capability-spec>
ENDORSE <reference> by:<principal-id>
QUERY  ev:(<principal-id>, sha256:<hash>) data:<opaque | string>
```

### Reference Format

`(<type>:<id>, sha256:<content-hash>)`

- Type: `user:<g>`, `srv:<hex>`, `admin`
- Content hash: full 256-bit hex

### Principal Binding

Every reference binds a principal to a content hash. A hash binds content; it is not proof of authority. Authority comes from a
verified signature under an explicitly trusted key.

### Integrity Levels

`low < medium < high < critical`

`Label.join()` takes the minimum integrity, maximum confidentiality, and union
of provenance. SecurityGate tracks session integrity conservatively; it cannot
infer inputs the host failed to report.

### Capability Spec

`cap:<hash> (scope=fs.read, exp=60, from=user:g)`

- Scope: dotted domain of authority, e.g. `fs.read`, `net.api.call`
- Expiry: positive integer TTL. The structural checker validates syntax only.
  SecurityGate also enforces the signed absolute deadline and grant lifetime.
- From: principal issuing the directive

## Verification

Run from the repository root with Python 3.12+ and Rust installed:

```bash
uv sync --locked
uv run --locked python scripts/verify.py
```

The single runner checks generated limits, Rust tests and Clippy (all targets,
warnings denied), strict Python typing, tests with ResourceWarnings treated as errors,
conformance, exploit contracts, deterministic differential fuzzing, and the
synthetic microbenchmark. `.github/workflows/verify.yml` runs the same command.
A local pass is not evidence that hosted CI has run.

For targeted work:

```bash
uv run --locked python -m unittest tests.test_security_gate
cargo test --locked --manifest-path rust/Cargo.toml --test security_tests
uv run --locked python conformance/diff_fuzz.py 500 --seed 0
uv run --locked python -m cli.tsd_scanner demos/full_demo.tsd
uv run --locked python -m demos.security_demo
uv run --locked python scripts/check_artifacts.py
```

The differential oracle compares complete ASTs and structural decisions,
distinguishes crashes from parse refusal, and builds the Rust binary before
comparison. Shared signed vectors exercise both security implementations;
ordinary parser fuzzing is not a proof of the stateful security system.

## Synthetic Benchmark (smoke / microbenchmark, NOT the utility experiment)

The benchmark suite runs 5 fixed synthetic task patterns and reports
parse/gate latency:

```bash
cd tsd && PYTHONPATH=. python3 benchmarks/run_benchmark.py
```

It runs 5 scripts (endorsement, file access, log analysis, network access,
revocation) and reports per-task parse/gate latency, acts per task, pass
rate, and acts/sec throughput (averages are per task, not per act).
Parse and gate timings are measured separately. Empty programs do not pass.
This is **not** DESIGN.md's utility experiment: no agent runs, no real tool
executes, and no task outcome is measured against an ungated baseline. Throughput
numbers are machine/load dependent; use a fresh run instead of a release claim.

## Structural scanner and proxy

The CLI exits 0 for structural acceptance, 1 for validation failure and 2 for
I/O or unexpected failure. It bounds input before parsing. The MCP scaffold
validates line-delimited JSON-RPC, frame sizes, duplicate keys, IDs, finite
numbers and params; recursively inspects bounded string arguments; and preserves
notification silence. Both sandbox and gate audit buffers are bounded and do
not retain raw program excerpts. See [limits](spec/limits.md) and
[proxy boundary](spec/proxy-boundary.md).

## Error Codes

- `INTEGRITY.DIRECT.DENIED`
- `ENDORSE.UNAUTHORIZED`
- `REFERENCE.INVALID`
- `EXPIRY.INVALID`

## File Structure

| Path | Purpose |
| --- | --- |
| `spec/` | Security contract, shared limits, grammar and milestone criteria |
| `lang/`, `gate/` | Python parser, labels, structural gate, authority and security gate |
| `gate/host.py` | Local enforcing host with registered callbacks and information-flow checks |
| `rust/` | Rust counterparts and integration tests |
| `proxy/`, `cli/` | Structural MCP scaffold and scanner |
| `conformance/`, `tests/` | Shared vectors, differential oracle and regressions |
| `benchmarks/`, `demos/` | Synthetic measurements and local negative fixtures |
| `scripts/` | Limits generator and verification entry point |

## Exploit Demos

Two demo programs demonstrate that the gate blocks common agent-based
attacks:

- **TSD-1** (`demos/exploit_tsd_1.tsd`) — content-swap exploit: references
  by principal without binding to an exact content hash. Rejected at
  parse time (ungrammatical) and at gate time (`REFERENCE.INVALID`).
- **TSD-4** (`demos/exploit_tsd_4.tsd`) — missing/invalid expiry: acts with
  non-positive TTL. Rejected at gate time (`EXPIRY.INVALID`).

Run the exploit demo runner to verify all attacks are blocked:

```bash
cd tsd && PYTHONPATH=. python3 demos/run_exploits.py
```

The runner exits 0 only when every exploit is blocked by an expected defense
(parse-time rejection for TSD-1; for TSD-4, successful parsing of exactly
the expected number of acts, each DENIED with the expected error code in
order); unexpected parses, act counts, codes, or exceptions exit 1.

## One-Page Calculus

The formal core is specified in `CALCULUS.md`:

- Core syntax and reference format
- Label lattice (provenance, integrity, confidentiality)
- Operational semantics of the four rules
- Soundness sketch (intended, NOT established — no proof exists for the
  current implementation)
- Cross-references to the reference implementation

The proof artifacts (Python + Rust implementations, conformance suite,
differential fuzzer) live in this repository and are described, with their
limits, in `CALCULUS.md`.

## Roadmap

1.0 means the DESIGN.md security gate, not a relabeled structural scanner.
The remaining acceptance criteria are tracked in [spec/MILESTONE.md](spec/MILESTONE.md).
`uv run --locked python scripts/release_check.py --results PATH --trace-root DIR` checks final
version/license/source/evidence prerequisites before running all software checks.
It currently refuses release until the approved real-agent experiment is complete.
The project is MIT licensed (see LICENSE); package version 1.0.0 is a release
candidate until preflight passes. No tag, publication or formal guarantee is implied.
