# Real-agent utility release evidence

The checked-in `benchmarks/utility_protocol.json` is a proposal, NOT an approved
protocol or a measurement. AgentDojo is a suitable standard tool-use benchmark;
the referenced upstream revision was resolved read-only. No upstream code or
tasks have been executed in this work. Source:
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
