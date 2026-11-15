# Bounded local subprocess adapters

This is a POSIX reference deployment transport for LocalHost, not an OS sandbox.
Executables are trusted, operator-installed adapter programs. Model output cannot
select argv, environment, executable, working directory or tool registrations.
Programs must not bypass the host to execute model-suggested actions themselves.
Use a separate OS sandbox when a tool's own code is not trusted.

Each call starts one process with fixed argv, no shell, a fresh process group,
closed inherited descriptors and an explicit minimal environment (PATH only).
The executable path must be absolute. The host sends one UTF-8 JSON object then
closes stdin. Model adapters receive exactly `{"inputs":[text,...]}` and return
exactly `{"source":"one L act"}`. Tool adapters receive exactly
`{"arguments":{"key":typed_value,...}}` and return exactly `{"result":"text"}`.
No authority/private/wrapping keys, trust labels or session secrets are sent.

Input, stdout and stderr are independently limited to MAX_SOURCE_BYTES. I/O
must be multiplexed to avoid deadlock when a child writes before reading stdin.
After the configured positive deadline (at most MAX_PROCESS_SECONDS), malformed
output, size overflow or process failure, kill the process group, reap the child,
close pipes and return a fixed HostError. Do not retry automatically or include
stdout/stderr/argv in errors. Successful process completion also terminates
remaining descendants in the group; detached/session-escaping descendants are
outside this transport's containment claim and require an OS sandbox.

Output must be one strict object with exactly the expected string field. Reject
duplicate keys, non-finite constants, invalid UTF-8, unknown fields, extra JSON,
and nonzero exit codes. Empty result text is allowed. Model source is subsequently
parsed and authorized by LocalHost/SecurityGate; transport success is not ALLOW.

Tests use local deterministic child programs, not a real agent benchmark. Cover
blocked stdin, flooded stdout/stderr, premature exit, timeout, malformed protocol,
normal round trips and a real LocalHost signed callback path.
