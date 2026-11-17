# Real-agent utility release evidence

The checked-in `benchmarks/utility_protocol.json` is approved and frozen at commit
`541cb181412b222d228adaa0d4f46a2c4db7206e`, binding adapter revision
`4edf0e14162cef0ec9d8637780fcd9fcbca87452`. It is a protocol, not a measurement.
The paired run uses all 97 registered AgentDojo v1.2.2 tasks and the isolated
policy described in utility-run.md. All 194 arms completed and passed the frozen
utility criterion; retained results and traces are in
`release-evidence/utility-owned-host-2026-11-15/`: 94/97 successes in each arm,
zero harmful paired regressions, and a one-sided 95% upper bound of 3.04 percentage
points against the approved 5-point maximum. The earlier
`release-evidence/utility-2026-11-15/` run is separate historical evidence and is
not pooled with this run. Broader release obligations remain in
[MILESTONE.md](MILESTONE.md). Upstream source:
https://github.com/ethz-spylab/agentdojo/tree/089ed468cf3ed0322acc66b0211f26d9d90dbf60

Before any release experiment, the operator must select/approve the benchmark
revision and exact task IDs, model/version/settings, maximum step budget,
paired seeds, maximum utility loss, minimum acceptable baseline success rate,
and the fixed signing/endorsement policy. Freeze that JSON and record its SHA-256.
The adapter_revision must identify an existing commit of this repository. Release
preflight compares lang, gate, proxy, cli, rust, scripts, benchmarks (except the
protocol JSON), pyproject.toml and uv.lock against that commit. Changes to those
measured files require fresh evidence; documentation/protocol-only commits do not.
Do not choose tasks, tune authority, alter prompts or change the acceptance
criterion after examining results. Approval does not authorize uncontrolled
third-party tool effects; use the benchmark's isolated environments.

Run each frozen task/seed once with the baseline and once with the security gate.
Use the benchmark's own task success check and retain trace SHA-256 digests and
the adapter revision. Every influencing input must pass trusted labeling; every
gated tool call must pass LocalHost. Document all grant/endorsement decisions and
their policy; do not auto-approve arbitrary actions just to recover utility.

The report checker requires every frozen task/seed exactly once, exact protocol
hash, real-model metadata, trace hashes, no errors or security violations, and
actual boolean success outcomes. Missing, duplicated, unexpected or simulated
runs fail. A results producer remains trusted evidence: a JSON checker cannot
prove traces were genuinely measured. Independent trace review is required.

## Retained artifacts and freeze binding

Results contain exactly `protocol_sha256`, `protocol_commit`, `kind`, and `runs`.
`protocol_commit` is a lowercase 40-character Git commit ID containing the exact
approved bytes at `benchmarks/utility_protocol.json`. Release preflight requires
that commit to be an ancestor of HEAD and the adapter revision to be an ancestor
of (or equal to) that commit. The existing measured-source comparison still
applies. This establishes version binding, not trustworthy real-world timing:
Git histories and producer-generated traces can be fabricated. The operator must
retain independent approval/predeclaration evidence and review experiment
provenance; neither commit ancestry nor hashes authenticate a measurement.

Protocol and result metadata must also be regular non-symlink files, bounded by
MAX_WIRE_BYTES. Open them without blocking on FIFOs and validate the opened
descriptor before reading. Invalid numeric thresholds produce validation errors,
including integers too large to convert to floating point.

Both report CLI and release preflight require explicit `--trace-root`. Each arm's
trace is a regular non-symlink file named `<trace_sha256>.json` directly within
that directory. Read at most MAX_WIRE_BYTES per file, recompute SHA-256 over exact
bytes, then strictly validate the JSON. Missing, substituted, oversized or
malformed artifacts refuse. The arithmetic-only `evaluate` helper does not
establish artifact validity and cannot suffice for release preflight.

Each trace has exactly these fields: `version` (integer 1), `protocol_sha256`,
`adapter_revision`, `id`, `seed`, `arm` (`baseline` or `gated`), `success`
(boolean), `error` (null for acceptable evidence), `security_violations` (integer
zero for acceptable evidence), and `events`. Header fields must match the frozen
protocol and the corresponding run/arm. An arm cannot borrow another run's trace.
`events` has 1..MAX_SECURITY_RECORDS entries with exactly `step` (sequential
zero-based integer), `operation` (nonempty fixed diagnostic name), `status`
(`ALLOW`, `DENY`, or `ERROR`), `input_sha256`, and `output_sha256` (lowercase
64-character digests). The final event operation is `finish`. Event count is
distinct from the model step budget: one model step may emit several decisions.
Events retain no raw prompts, results, keys or signed statements. The adapter
remains responsible for honest event generation and sanitized operation names.

Report baseline/gated task success fractions and paired observed loss. Also bound
the harmful paired regression probability (baseline success, gated failure) by
the one-sided 95% exact binomial Clopper-Pearson upper confidence limit. Require
that conservative upper bound <= the frozen loss threshold; improvements do not
cancel regressions for this confidence test. Too few samples yield inconclusive
release evidence, not a pass. The binomial confidence interpretation requires
independent Bernoulli sampling from the prespecified task population; a fixed
convenience task set does not establish population-level coverage. Trials must
justify this sampling model and independence (repeated seeds
on the same task may be correlated); do not treat an inflated repetition count
as new independent evidence. Use unique task IDs for the release confidence set.

The baseline must meet its frozen minimum success fraction. Otherwise an agent
that fails everything could make the gate appear harmless. This experiment is
distinct from throughput, parser fuzzing, deterministic adapter fixtures and the
synthetic microbenchmark. None of those closes this release requirement.
