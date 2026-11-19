# Proxy boundary and audit contract

The proxy remains a structural probe until connected to a trusted runtime.
I6: all public string extraction is bounded by MAX_SOURCE_BYTES; argument
string values cumulatively obey MAX_ARG_STRING_BYTES (UTF-8), and containers
obey the shared depth/node limits. Non-JSON Python values and invalid Unicode
are refused, not silently skipped. Unknown policy refuses every request.

I7: invalid programs never become success under deny policy. Diagnostics
and retained audit records contain only act types, decisions, and fixed
error codes. No raw source, payload excerpt, or exception message is retained.
Both sandbox and gate histories retain at most MAX_AUDIT_RECORDS entries.
Explicit allow/log policies are diagnostic modes, not security enforcement.

The stdio scaffold expects pipe-compatible stdin and stdout. Regular-file
redirection is unsupported. If the transport cannot initialize, the CLI exits
with status 1 and a fixed diagnostic on stderr before processing requests.
