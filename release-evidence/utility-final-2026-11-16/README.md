# Incomplete final-candidate utility run

This run is **ineligible for release acceptance**. It stopped after an agent
reported mistyping the supplied launch path for `slack/user_task_9`, gated arm.
The launcher refused before producing a task trace. No retry was attempted.

- Implementation: `6336916d5a3e02fae00081e71936787db747ec53`.
- Protocol freeze: `b6c4b3fb034a8b8d75f25a844c0c1275cba1851c`.
- 51 completed terminal traces, all reporting task success.
- One launch infrastructure failure, with no trace; 142 arms never started.
- Only 25 complete pairs and one unpaired baseline exist. No full-population
  success rate or confidence-bound acceptance is inferred from this subset.

`progress.json` retains every planned arm and the failed launch. `traces/`
retains all 51 completed content-addressed traces. `protocol.json` is unchanged.
`verification.json` records software checks separately from utility status.
No `results.json` or passing `report.json` exists for this incomplete experiment.
See [INCIDENT.md](INCIDENT.md) for the failure and evidence limitations.
Historical experiments remain separate; no outcomes are substituted or pooled.
