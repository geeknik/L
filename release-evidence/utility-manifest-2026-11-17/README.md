# Incomplete manifest-launcher utility run

This experiment is **ineligible for release acceptance**. It stopped after the
correct baseline wrapper invocation for `banking/user_task_10` returned
`gRPC code-mode session closed`. No retry was attempted. See [INCIDENT.md](INCIDENT.md).

- Candidate: `292a54009c2bac4863d8ca186146d1a369f447f8`.
- Protocol freeze: `fc8a2aec1a8cddd0683c5a96940b65b94fbf90d3`.
- Protocol SHA-256: `0090af41eddbce24c81d5357c6639ba544f604aded1f15a183768b57bb57f8ce`.
- Manifest SHA-256: `5dee443eede5d50fe71436b08834b18c38c72d00dc6871fb7f4e1848790750bd`.
- 21 completed terminal traces, all reporting task success.
- One pre-claim infrastructure failure, with no observed attempt status or trace.
- 172 arms unstarted; ten complete pairs and one unpaired gated result.

`protocol.json` and `manifest.json` preserve the exact frozen bytes. `progress.json`
retains all 194 planned arms and the unique fresh-context agent identity for each
launched assignment. `attempts/` retains the 21 observed terminal lifecycle records;
`traces/` retains their content-addressed terminal traces. Lifecycle histories and
trace identities, seeds, arms, protocol/source bindings and digests were checked.
No status record was fabricated for the pre-claim platform failure.

`verification.json` records fresh software verification independently of utility.
No `results.json` or passing `report.json` exists: partial results cannot satisfy
the frozen criterion. No full-population success rate or confidence bound is
inferred from this subset. Prior experiments remain separate and untouched.

Solvers received the frozen prompt and only their assigned wrapper/task/arm, each
in a fresh non-inherited context using the inherited model. No model override,
retry, outcome substitution, policy tuning, or task exclusion occurred. Traces
contain hashed events, not task payloads. Identity and hash checks establish
binding, not independent proof of model isolation or producer honesty.
