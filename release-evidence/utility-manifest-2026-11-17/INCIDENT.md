# Manifest-run platform incident

The experiment stopped on an infrastructure failure at index 10,
`banking/user_task_10`, baseline arm. The solver invoked the exact supplied
wrapper `/tmp/l17/arms/0010b` once with `tty=true`. Its tool returned
`gRPC code-mode session closed`, without a worker response or session ID.
The solver did not retry. This is not a wrapper-path transcription error.

## Evidence and timeline

- Protocol freeze: `fc8a2aec1a8cddd0683c5a96940b65b94fbf90d3`.
- Candidate: `292a54009c2bac4863d8ca186146d1a369f447f8`.
- Manifest SHA-256: `5dee443eede5d50fe71436b08834b18c38c72d00dc6871fb7f4e1848790750bd`.
- 2026-11-17 15:18:38.895 UTC: solver invoked `/tmp/l17/arms/0010b`,
  with `tty=true` and `max_output_tokens=20000`.
- 2026-11-17 15:19:57.468 UTC: tool reported
  `gRPC code-mode session closed`.
- The root independently checked those two records in the retained local
  solver transcript. Raw transcripts and account metadata are not copied here.
- Both root and coordinator also observed their functions runtime being replaced
  during unrelated read-only polling or ledger work around this interval.
- Reconciliation found no `0010b` attempt directory/status or terminal trace.
  Absence of those artifacts does not establish what happened inside the tool
  service; the deeper platform cause is unknown.

The paired gated arm had already started. No new arms were launched after the
failure report. It completed normally with success=true, and its terminal trace is retained.
It cannot replace or authorize retrying the failed baseline arm. The final ledger
contains 21 completed arms, one infrastructure failure and 172 unstarted arms: ten
complete pairs and one unpaired gated result.

## Disposition

The run is ineligible for release acceptance: its fixed 194-arm population is
incomplete. Completed task outcomes remain retained without substitution,
exclusion, pooling, or retry. An orchestration failure before a claim is still
an infrastructure failure, not permission to launch that arm again.

The launcher prevented duplicate claims within its process boundary, but cannot
make the external execution service available or prove whether a failed tool
request reached that boundary. No evidence demonstrates a gate or launcher
logic defect in this event. Successful task traces are not a complete utility
result or security proof.

Before task execution, an initial preparation command used an abbreviated Git
commit and was refused before creating a launch directory or claim. Preparation
with the required full 40-character commit succeeded. That preparation diagnostic
was not a task attempt and is separate from this platform incident.
