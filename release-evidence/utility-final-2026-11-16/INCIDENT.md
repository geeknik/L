# Final utility run infrastructure incident

The run stopped at `slack/user_task_9`, gated arm (index 25).
Agent: `/root/final_utility_coordinator/eval025_gated`.

The coordinator supplied this trace directory in the exact launch command:
`/home/geeknik/dev/tsd/release-evidence/utility-final-2026-11-16/025_gated`.
The agent reported launching with `/home/geeknik/devtsd/...` instead, omitting
`/` between `dev` and `tsd`. The launcher refused with exit code 2 before task
execution. No gated trace was produced. The agent did not retry.
The incorrect path is recorded from the agent's report; the coordinator did not
inspect its full task transcript or infer a benchmark result from that report.

The already-running baseline arm completed normally with success=true. The final
ledger contains 51 completed, hashed terminal traces (all success=true), one
infrastructure-failed launch without a trace, and 142 unstarted arms. This is
25 complete pairs and one unpaired baseline, not a completed utility experiment.
There are no retries, substitutions, or excluded failures. `progress.json`
retains the failure as `LAUNCH.PATH` and marks the run stopped. No `results.json`
or passing `report.json` was fabricated for this incomplete run.

Frozen implementation `6336916d5a3e02fae00081e71936787db747ec53`, protocol commit
`b6c4b3fb034a8b8d75f25a844c0c1275cba1851c`, and protocol SHA-256
`4e7f21fc0d72d836c946ebdf7b9e5dcd3f5ad9a0cbfe0afedf5f2e08f3c74903` were not
changed during coordination. The incident is an agent launch-command error,
not a measured gate utility regression. The retained run is ineligible for
release acceptance under the frozen no-infrastructure-error contract.
