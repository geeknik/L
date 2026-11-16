# Frozen AgentDojo adapter

This adapter is experimental, not release evidence by itself. No real tasks may
run until the operator approves the frozen utility protocol. Catalog mode emits
only registered suite/task IDs. Task mode requires an approved protocol and an
isolating launcher; the TSD_BENCH_SANDBOX=1 environment flag is an interlock, not
a sandbox. The launcher must deny network and external filesystem effects.

Each process loads one fresh v1.2.2 suite environment, invokes init_environment
once, then deep-copies the initial state for evaluation. It never invokes task
ground_truth, suite.check, or run_task_with_pipeline. The latter retries tasks
implicitly; this adapter does not. Seed controls Python's local random source,
not any unavailable model sampling control. Each task/arm needs a fresh model
context with no access to evaluator/solution code or the other arm's trace.

The initial JSON line contains prompt and tool names. Subsequent requests are
exact objects: {op:"schema",tool:name}, {op:"call",tool:name,args:object}, or
{op:"finish",answer:string}. Every request, including denial, consumes one of
the frozen max_steps. Finish is terminal and invokes utility_from_traces once,
falling back to utility only if it returns None. Budget exhaustion and EOF without
finish are retained utility failures, success=false with error=null unless an
infrastructure failure already occurred. They never invoke an evaluator, retry,
or request another model answer. The host appends one internal finish/DENY event
after the last model request (so a 30-request budget permits 31 trace events).
Its input hash covers `TSD-BENCH-budget_exhausted-v1` or
`TSD-BENCH-abandoned-v1`, respectively, without LF. Its output hash covers the
canonical object {success:false,reason:"budget_exhausted"} or
{success:false,reason:"abandoned"}. This event is terminal accounting, not an
additional model request. These completed failures exit normally; infrastructure
failures remain explicitly ineligible evidence. Every JSON line, argument depth and visited node
count obey shared byte/depth/node limits. Duplicate keys, nonfinite numbers,
unknown request fields and unknown top-level tool parameters refuse. Transport
JSON cannot construct executable FunctionCall instances.

Both arms use identical argument validation and tool-result formatting. Gated
calls encode the canonical JSON argument object as one L string parameter,
using L's doubled-quote syntax. The registered callback decodes that data and
calls only its fixed AgentDojo tool. Definitions bind canonical tool name,
description and parameter schema to the registration hash. Only the upstream
in-memory tool module allowlist is registered; no operating-system or network
tool is exposed. The isolating launcher is still required defense in depth.

The gated worker applies signed grants and executes through the owned
`HostSession` controller. Both arms validate the same execute request and result
against the owned JSON framing bounds; rich nested arguments, including finite
floats, remain data inside the L string. The worker uses the controller's trusted,
payload-free internal error code to distinguish infrastructure failures from
ordinary denial. This diagnostic is never included in host protocol responses.
This controller integration requires a fresh frozen revision and paired run;
previously retained measurements describe only their recorded adapter revision.

The approved policy grants low-integrity authority for every registered sandbox
tool, scoped to bench.<tool_name>, a fresh host session and exact tool definition.
No automatic endorsements are issued. Inputs and results remain low integrity.
This measures utility of low-risk sandbox autonomy, not the cost of approving
high-privilege actions. It must not be presented as evidence for arbitrary
privileged tool execution, malicious-task security or real external side effects.

Events contain only sequential step, operation (schema/call/finish), status
(ALLOW/DENY/ERROR), and SHA-256 hashes of request/response bytes. No raw task,
tool result, prompt, signing seed or wrapping key is written. Invalid JSON is a
call DENY event. Finish returns success and events. With approved protocol
context it also writes a bounded content-addressed JSON trace containing
version=1, protocol_sha256, adapter_revision, id, seed, arm, success, error,
security_violations=0 and events. Unexpected adapter errors set error to a fixed
code; ordinary request/tool refusals remain visible DENY events. This zero count
does not constitute an independent security measurement. File creation is
exclusive with mode 0600 and no symlink following; existing artifacts never
overwrite. The protocol hash and adapter revision bind the trace to reviewed
configuration. The release producer must independently review/verify traces.
Input hashes cover the exact received line (including its LF when present).
Output hashes cover the canonical response object before adding events and the
trace digest, excluding LF; this avoids a self-referential finish hash. Upstream
tool/evaluator console output is discarded, never mixed into the protocol.

Tests use an injected fake backend and do not import AgentDojo or execute real
tasks. They exercise real LocalHost dispatch, exact rich argument preservation,
schema and transport rejection, terminal budget behavior, sanitized failures,
evaluator invocation counts and artifact custody. I1/I3/I4/I6/I7/I8 remain in
force; this adapter creates no authority through model-provided labels.
