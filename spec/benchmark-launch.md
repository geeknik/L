# Manifest-based benchmark launch contract

This coordination layer prevents solver agents from reconstructing long launch
commands. It does not change the sandbox, task population, policy, request budget,
utility evaluator, or release criteria. It does not authorize a new experiment.
The incomplete 2026-11-16 run remains historical evidence and is never resumed.

## Trust and preparation

The trusted coordinator prepares a new private directory using an explicit pinned
benchmark checkout, frozen protocol, protocol commit and destination. Preparation
validates the protocol/source Git binding and the pinned checkout without starting
a benchmark worker. Existing destinations refuse; failures leave an unusable
partial directory for inspection, never an apparently complete manifest.

Use strict UTF-8 JSON, reject duplicate/unknown fields, bound each metadata file
by MAX_WIRE_BYTES, and require regular non-symlink files. The task list is bounded
by MAX_SECURITY_RECORDS and must contain unique IDs with integer seeds. The
protocol must be approved; its settings provide the frozen elapsed deadline and
kill grace. Both must be actual positive integers, elapsed at most
MAX_SECURITY_RECORDS seconds and grace at most MAX_PROCESS_SECONDS. These are
validation bounds, not permission to change the approved 600-second deadline or
five-second grace. Worker resource limits remain in run_agentdojo.py.

The manifest records version, absolute project/checkout/protocol/destination
paths, protocol commit and SHA-256. Its schema admits no executable, arbitrary
argv, shell fragment, or per-arm path overrides. All generated Python wrappers pin the
manifest SHA-256 and invoke the same reviewed Python launcher with literal
arguments; no shell commands are constructed. The pinned interpreter path must
be safe for a shebang (no whitespace or control characters). The solver receives only its short wrapper path
and task/arm identity; it must not reconstruct paths or launch arguments.

Tokens are four decimal digits followed by `b` or `g`, identifying the frozen
zero-based task index and baseline/gated arm. Task identity, seed, request budget,
trace directory and command argv are derived from that token and the frozen
protocol. Unknown/out-of-range tokens refuse before spawning. A solver that
invokes a wrong valid token is not silently credited: the coordinator must verify
returned task/arm identity and launch records against its assignment.

This is trusted local coordination, not a security boundary against the operator
UID modifying scripts, source or state. Keep these files outside model/tool sandbox
mounts except the worker's own trace destination. Source remains frozen throughout
the run. Hash/identity checks establish binding, not honest agent execution.

## Launch lifecycle and failure

A valid arm must atomically claim its attempt before validating arm-specific
resources or spawning. A duplicate claim refuses without rewriting the original
record or rerunning the worker. Neither errors nor timeouts release the claim.
Malformed manifests/tokens have no trustworthy arm identity: return a fixed error
without inventing an arm record. The coordinator still records that orchestration
failure in its global ledger; absence of a claim is not permission to retry.

Each claimed attempt retains payload-free, atomically replaced lifecycle metadata:

- `claimed`: the arm is reserved, with no process launched yet.
- `setup_refused`: a required path or binding failed validation.
- `process_started`: Popen returned a PID; this does not prove task initialization.
- `task_finished`: the process exited zero and exactly one bounded terminal trace
  matches the manifest/protocol, task, seed, arm and terminal finish metadata.
  Keep the upstream success boolean; false is a normal task failure, not an error.
- `infrastructure_failure`: spawn failure, timeout, abnormal exit, missing/invalid
  trace, or trace-reported error. Record fixed reason codes, never exception text.

A crash may leave `claimed` or `process_started`. Reconciliation must treat that
as unresolved infrastructure state, not success or permission to rerun. Do not
log raw commands, prompts, tool data, stdout/stderr, or signed evidence.

Launch the existing isolated worker using a fixed argv list with inherited stdin
and stdout; do not shell-evaluate the manifest. Bound elapsed time, terminate the
process group, apply the frozen grace, kill if needed, and reap the child. Cleanup
must also run after exceptions. A timeout remains an infrastructure failure even
if partial output or a trace exists. No implicit retries or automatic approvals.
External errors are fixed; worker JSON responses remain its existing interface.

A matching terminal trace is a lifecycle classification, not release acceptance.
The complete utility-report validator and independent review must still verify
all paired results and retained traces. No partial run satisfies the release gate.

## Verification before any new freeze

Use mocked processes or harmless local fixture workers, never benchmark tasks, to
cover valid argv and paths (including spaces), unknown/malformed tokens, manifest
mutation, changed protocol, missing directories, duplicate/concurrent claims,
spawn failures, nonzero exit, missing/wrong traces, ordinary failed tasks, timeouts,
cleanup and sanitized records. Verify no worker starts on setup rejection.

A fresh full experiment requires operator authorization and passing checks.
Freeze the revised prompt and launcher/source before it
begins; retain the failed run separately and preserve the original acceptance
thresholds, task population and authority policy.


## Coordinator usage

After a new source/protocol freeze, set `AGENTDOJO_DIR` to the pinned benchmark
checkout, `PROTOCOL_COMMIT` to the exact freeze commit, and `LAUNCH_DIR` to a new
absolute destination whose parent exists. Choose a short destination path. Run:

```bash
uv run --locked python -m benchmarks.launch_arm prepare \
  --checkout "$AGENTDOJO_DIR" \
  --protocol benchmarks/utility_protocol.json \
  --protocol-commit "$PROTOCOL_COMMIT" \
  --destination "$LAUNCH_DIR"
```

Preparation prints the manifest digest. Retain the manifest and digest with the
new experiment's provenance. It creates `arms/0000b`, `arms/0000g`, and subsequent
index wrappers, separate `traces/<token>/` directories and an `attempts/` store.
Preparation does not start a task. Give each fresh agent its one absolute wrapper
path; it invokes that executable once with `tty=true` and no extra arguments.
Do not hand agents the prepare command or ask them to reconstruct run arguments.

After each arm, independently check `attempts/<token>/status.json` against the
assignment and returned trace. Wait for the terminal lifecycle state, not merely
a model's completion message. Retain each status record and content-addressed
trace. Do not infer success from process exit, delete claims, reuse a destination,
or restart incomplete attempts. Missing status or a refusal before claim remains
an orchestration failure to record in the coordinator ledger.

The launcher validates lifecycle bindings. Full release acceptance still requires
all frozen pairs, full trace validation, independent provenance review, and clean
release preflight. An existing historical protocol cannot authorize measurement
of a changed launcher or prompt.
