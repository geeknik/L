#!/usr/bin/env python3
"""MCP Proxy for L: A Trust-Typed Language for Agents.

Structural MCP scaffold that inspects embedded L programs. It neither forwards
upstream requests nor authorizes real tool execution; use SecurityGate in a host.

Usage:
    python3 -m proxy.mcp_proxy --upstream stdio --policy deny
    python3 -m proxy.mcp_proxy --upstream "ws://localhost:8080/mcp" --policy log
"""

import sys
import os
import json
import math
import asyncio
import argparse
import logging
from typing import Optional, Dict, Any, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + '/..')

from lang.parser import parse
from gate.monitor import Gate, GateError
from lang.limits import (MAX_LINE_BYTES, MAX_ARG_DEPTH, MAX_ARG_NODES,
                         MAX_ARG_STRING_BYTES, MAX_AUDIT_RECORDS, MAX_SOURCE_BYTES)

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('mcp_proxy')

def _reject_duplicate_keys(pairs: List[tuple[str, Any]]) -> dict[str, Any]:
    """object_pairs_hook that rejects duplicate keys at any nesting level.

    json.loads decodes escape sequences before deduplication, so escaped-equivalent
    keys such as "code" and "co\\u0064e" both become "code" and are correctly caught
    as duplicates. Duplicate keys are rejected (not last-value-wins) so no
    earlier argument value disappears before nested traversal and gate validation.
    Raises ValueError, which is caught by the surrounding parse-error handler
    and surfaced as a sanitized -32700 Parse error with id: null.
    """
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate key in JSON object: {key!r}')
        result[key] = value
    return result


def _is_valid_jsonrpc_id(value: Any) -> bool:
    """Return True if value is a valid JSON-RPC 2.0 request identifier.

    JSON-RPC 2.0 allows: String, Number, or Null. Booleans are NOT valid
    (Python bool is a subclass of int). Containers (dict, list) are NOT
    valid. Non-finite floats (inf, nan from Python's lenient json parser,
    e.g. 1e999 or NaN literals) are rejected: they are not JSON numbers
    and cannot be echoed back as valid JSON.

    Fractional floats (e.g. 3.5) are permitted per the spec's "Number" type
    (which says numbers SHOULD NOT have fractional parts, not MUST NOT).
    """
    if value is None:
        return True  # id: null is legal (and distinct from an absent id)
    if isinstance(value, bool):
        return False
    if isinstance(value, str):
        return True
    if isinstance(value, int):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    return False  # dict, list, anything else


def _reject_json_constant(literal: str) -> float:
    """Reject Python's nonstandard JSON constants NaN, Infinity, -Infinity.

    These literals are outside RFC 8259's JSON grammar. Raising here makes
    json.loads fail, which is routed through the sanitized -32700 Parse error
    handler. The literal text is never surfaced in error responses.
    """
    raise ValueError(f'Invalid JSON constant: {literal}')


def _parse_float_checked(s: str) -> float:
    """Parse a JSON float and reject results that are not finite.

    Numbers like 1e999 are valid JSON numeric syntax but overflow to
    infinity in binary floating point; rejecting them keeps every decoded
    float within the finite numeric range (RFC 8259 §6).
    """
    value = float(s)
    if not math.isfinite(value):
        raise ValueError(f'Non-finite numeric literal: {s}')
    return value


class ExtractionError(Exception):
    """Raised when L program extraction fails (e.g., unterminated fence)."""
    pass


class ParamsError(Exception):
    """Raised when JSON-RPC request params are malformed or missing required fields."""
    pass


class LProgramExtractor:
    """Extract L programs from MCP tool call arguments."""

    @staticmethod
    def extract(text: str) -> List[str]:
        """Find and return L programs embedded in text.

        Looks for code fences with 'tsd' or 'l' language tag, or
        bare acts starting with ASSERT/QUERY/DIRECT/COMMIT/GRANT/REVOKE/ENDORSE.

        - Opening fence: `` ```tsd ```` or `` ```l ```` starts a recognized block.
        - Closing fence: `` ``` `` (plain three backticks) closes any active block,
          even without a language tag.
        - Non-L fences (```python etc.) are preserved as content while in a block.
        - Blank lines are guarded against in the bare-act heuristic.
        - Unterminated recognized blocks raise ExtractionError (fail closed).
        """
        if not isinstance(text, str) or len(text) > MAX_SOURCE_BYTES:
            raise ExtractionError('Program text exceeds size limit')
        try:
            if len(text.encode('utf-8')) > MAX_SOURCE_BYTES:
                raise ExtractionError('Program text exceeds size limit')
        except UnicodeEncodeError:
            raise ExtractionError('Invalid Unicode program text') from None
        programs = []
        lines = text.split('\n')
        in_block = False
        block_lines = []

        for line in lines:
            stripped = line.strip()

            # Guard against blank lines in the act-keyword heuristic
            if not stripped:
                if in_block:
                    block_lines.append(line)  # preserve original line (could be empty or spaces)
                continue

            # ── Fence detection ──
            if stripped.startswith('```'):
                tag_part = stripped[3:].strip().lower()
                if tag_part in ('tsd', 'l'):
                    # Recognized opening fence (```tsd / ```l): toggle in_block,
                    # do NOT append this line to block_lines.
                    in_block = not in_block
                    if not in_block and block_lines:
                        programs.append('\n'.join(block_lines))
                        block_lines = []
                elif not tag_part:
                    # Plain `` ``` `` closing fence: end the active block
                    if in_block:
                        in_block = False
                        if block_lines:
                            programs.append('\n'.join(block_lines))
                            block_lines = []
                else:
                    # Non-L fence (```python etc.): preserve as content while in block
                    if in_block:
                        block_lines.append(line)  # preserve original line
                # In all fence cases, skip the normal in_block / act handling below
                continue

            # ── In-block content ──
            if in_block:
                block_lines.append(line)  # preserve original line
                continue

            # ── Bare act lines (no fence) ──
            first_word = stripped.split()[0]
            if first_word in ('ASSERT', 'QUERY', 'DIRECT', 'COMMIT', 'GRANT', 'REVOKE', 'ENDORSE'):
                programs.append(stripped)

        # Unterminated recognized block: fail closed with explicit error.
        if in_block:
            raise ExtractionError(
                f"Unterminated recognized fence (```tsd/```l) without closing fence"
            )
        return programs


class TSDSandbox:
    """Sandbox that wraps the L parser + gate."""

    VALID_POLICIES = ('deny', 'allow', 'log')

    def __init__(self, policy: str = 'deny'):
        # Fail closed at construction: an unrecognized policy must never
        # reach the enforcement branch, where the old code would treat it
        # as implicit allow.
        if policy not in self.VALID_POLICIES:
            raise ValueError("invalid policy: must be 'deny', 'allow', or 'log'")
        self.gate = Gate()
        self.policy = policy  # 'deny', 'allow', 'log'
        self.audit_log: List[Dict[str, Any]] = []

    def check(self, program: str) -> tuple[bool, List[Dict[str, Any]]]:
        """Run program through parser + gate.

        Returns (allowed_all, details_per_act).
        """
        try:
            acts = parse(program)
        except Exception:
            detail = {'error': 'PARSE.INVALID', 'allowed': False}
            self.audit_log.append(detail)
            del self.audit_log[:-MAX_AUDIT_RECORDS]
            return False, [detail]

        results = []
        allowed_all = True

        for act in acts:
            try:
                self.gate.execute(act)
                detail = {'act': act.act_type, 'allowed': True}
                results.append(detail)
            except GateError as e:
                allowed_all = False
                detail = {'act': act.act_type, 'allowed': False, 'error': e.code}
                results.append(detail)
            except Exception:
                allowed_all = False
                results.append({'act': act.act_type, 'allowed': False, 'error': 'GATE.INTERNAL'})

        for r in results:
            self.audit_log.append(r)
        del self.audit_log[:-MAX_AUDIT_RECORDS]

        return allowed_all, results


class MCPProxy:
    """MCP protocol proxy with L gate enforcement."""

    def __init__(self, upstream_url: str, policy: str = 'deny'):
        self.upstream_url = upstream_url
        self.sandbox = TSDSandbox(policy)

    def _validate_params(self, method: str, params: Any) -> None:
        """Validate JSON-RPC request params for the given method.

        Raises ParamsError on malformed input. Enforces:
          - params must be a dict; any other type is rejected.
          - For tools/call: 'name' must be a non-empty string; 'arguments', when supplied,
            must be an object (dict).
        """
        if not isinstance(params, dict):
            raise ParamsError('Invalid params: must be an object')
        if method == 'tools/call':
            name = params.get('name')
            if not isinstance(name, str) or not name:
                raise ParamsError('Invalid params: missing or invalid tool name')
            # Distinguish an absent 'arguments' key from an explicit null value:
            # absent is accepted (defaults to {}); explicit null must be rejected.
            if 'arguments' in params and not isinstance(params['arguments'], dict):
                raise ParamsError('Invalid params: arguments must be an object')

    def _collect_strings(self, value: Any, depth: int = 0,
                        visited: Optional[set[int]] = None) -> List[str]:
        """Collect all string values from a nested dict/list structure.

        Depth-bounded recursive traversal with explicit depth and node limits.
        Raises ParamsError on excessive depth, node count, or cyclic references.

        Cycle detection tracks containers on the current traversal path only,
        so shared acyclic containers (e.g. the same dict referenced from two
        sibling keys) are accepted. Each visit counts toward the node limit.
        """
        if visited is None:
            visited = set()

        strings = []
        nodes_visited = 0
        string_bytes = 0

        def _walk(obj: Any, current_depth: int) -> None:
            nonlocal nodes_visited, string_bytes
            nodes_visited += 1
            if nodes_visited > MAX_ARG_NODES:
                raise ParamsError(f'Arguments exceed node limit ({MAX_ARG_NODES})')

            if current_depth > MAX_ARG_DEPTH:
                raise ParamsError(f'Arguments exceed depth limit ({MAX_ARG_DEPTH})')

            if isinstance(obj, str):
                if len(obj) > MAX_ARG_STRING_BYTES - string_bytes:
                    raise ParamsError('Argument strings exceed size limit')
                try:
                    string_bytes += len(obj.encode('utf-8'))
                except UnicodeEncodeError:
                    raise ParamsError('Invalid Unicode argument') from None
                if string_bytes > MAX_ARG_STRING_BYTES:
                    raise ParamsError('Argument strings exceed size limit')
                strings.append(obj)
            elif isinstance(obj, dict):
                # Track containers on the current traversal path only.
                # Removing in finally means a shared acyclic container visited
                # through another branch is not mistaken for a cycle.
                obj_id = id(obj)
                if obj_id in visited:
                    raise ParamsError('Cyclic reference in arguments')
                visited.add(obj_id)
                try:
                    for k, v in obj.items():
                        if not isinstance(k, str):
                            raise ParamsError('Non-string key in arguments object')
                        _walk(v, current_depth + 1)
                finally:
                    visited.discard(obj_id)
            elif isinstance(obj, list):
                obj_id = id(obj)
                if obj_id in visited:
                    raise ParamsError('Cyclic reference in arguments')
                visited.add(obj_id)
                try:
                    for item in obj:
                        _walk(item, current_depth + 1)
                finally:
                    visited.discard(obj_id)
            elif isinstance(obj, float) and not math.isfinite(obj):
                # Non‑finite floats are not JSON numbers; reject as invalid arguments.
                raise ParamsError('Non-finite numeric argument')
            elif obj is not None and not isinstance(obj, (int, float, bool)):
                raise ParamsError('Unsupported argument type')

        _walk(value, depth)
        return strings

    def _check_arguments_for_programs(self, arguments: Dict[str, Any]) -> None:
        """Traverse all string values in arguments and run L program extraction + gate checks.

        Raises RuntimeError (under deny) or logs (under log policy) for denied programs.
        Raises ParamsError for malformed structures (depth, cycles, non-string keys).
        """
        strings = self._collect_strings(arguments)
        for value in strings:
            programs = LProgramExtractor.extract(value)
            for prog in programs:
                allowed, details = self.sandbox.check(prog)
                log.info(f"L program check: allowed={allowed} acts={len(details)}")
                if not allowed:
                    if self.sandbox.policy == 'deny':
                        raise RuntimeError(f"L gate denied: {details}")
                    elif self.sandbox.policy == 'log':
                        # Fixed message + safe metadata only. Never log
                        # the program text or exception details, which
                        # may carry payload content.
                        denied = sum(1 for d in details if not d.get('allowed', True))
                        log.warning(
                            f"L gate would deny (log only): "
                            f"acts={len(details)} denied={denied}"
                        )
                    elif self.sandbox.policy == 'allow':
                        # Explicit pass-through. Reachable only for the
                        # exact validated value, not for typos or None.
                        pass
                    else:
                        # Defensive: the policy was mutated after
                        # construction to an unknown value. Fail closed
                        # instead of behaving like allow.
                        log.error("L gate: unknown policy; failing closed")
                        raise RuntimeError("L gate denied: unknown policy")

    def handle_request(self, method: str, params: Dict[str, Any], req_id: Any = None) -> Dict[str, Any]:
        """Process an MCP request, checking for L programs.

        The response envelope uses the incoming request ID, not a locally
        generated one. Callers must pass the ID from the incoming JSON-RPC
        request, or None for notifications (which must not receive responses).
        """

        # Reject malformed params instead of silently replacing them with {}.
        if self.sandbox.policy not in TSDSandbox.VALID_POLICIES:
            raise RuntimeError('L gate denied: unknown policy')
        self._validate_params(method, params)

        # Check tool calls for embedded L programs
        if method == 'tools/call':
            arguments = params.get('arguments', {})
            # Traverse all nesting levels: dict values and list elements.
            # Strings inside nested structures must reach extraction and
            # gate validation just like top-level strings.
            self._check_arguments_for_programs(arguments)

        # Forward to upstream (placeholder - actual implementation depends on transport)
        return {
            'jsonrpc': '2.0',
            'id': req_id,
            'result': {'content': [{'type': 'text', 'text': 'Structural validation completed; upstream transport is not implemented'}]}
        }

    async def run_stdio(self) -> None:
        """Run proxy over stdio (for local subprocess upstream)."""
        log.info("Starting MCP proxy over stdio")

        # For stdio, we'd spawn the upstream process and pipe
        # This is a skeleton - full implementation needs async subprocess
        # Use a bounded line limit so oversized frames raise a controlled
        # ValueError instead of an uncaught crash or unbounded memory use.
        reader = asyncio.StreamReader(limit=MAX_LINE_BYTES)
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin)

        writer_transport, writer_protocol = await asyncio.get_event_loop().connect_write_pipe(
            asyncio.streams.FlowControlMixin, sys.stdout)
        writer = asyncio.StreamWriter(writer_transport, writer_protocol, None, asyncio.get_event_loop())

        while True:
            try:
                line = await reader.readuntil(b'\n')
            except asyncio.IncompleteReadError as e:
                # EOF: process any trailing partial line, then stop.
                line = e.partial
                if not line:
                    break
            except asyncio.LimitOverrunError:
                # Oversized frame: readuntil leaves the buffer intact, so
                # discard exactly through the terminating newline, one byte
                # at a time (bounded memory), keeping framing in sync.
                while True:
                    ch = await reader.read(1)
                    if not ch:
                        break
                    if ch == b'\n':
                        break
                # Fixed, sanitized error; never include payload text.
                await self._send_error(writer, None, -32600, 'Input too large')
                continue

            # ── Stage 1: decoding / parsing ──
            try:
                raw = line.decode('utf-8').strip()
            except UnicodeDecodeError:
                # Invalid UTF-8: fixed, sanitized error; never leak payload bytes.
                await self._send_error(writer, None, -32700, 'Parse error')
                continue

            if not raw:
                continue

            try:
                req = json.loads(raw, object_pairs_hook=_reject_duplicate_keys,
                                 parse_constant=_reject_json_constant,
                                 parse_float=_parse_float_checked)
            except Exception:
                # Fixed public message; never surface parser details.
                await self._send_error(writer, None, -32700, 'Parse error')
                continue

            # ── Stage 2: request validation ──
            if not isinstance(req, dict):
                # Invalid Request with no echoable id.
                await self._send_error(writer, None, -32600, 'Invalid Request')
                continue

            # Distinguish an absent id (notification) from id: null using
            # key presence, not truthiness — id 0 and id null are both valid
            # request identifiers.
            has_id = 'id' in req
            supplied_id = req.get('id')
            # A supplied id is usable in error responses only when it is a
            # valid JSON-RPC id. Invalid ids (bool, container, non-finite)
            # are never echoed back — the response uses id: null.
            supplied_id_ok = _is_valid_jsonrpc_id(supplied_id) if has_id else True
            req_id = supplied_id if has_id and supplied_id_ok else None

            # Envelope: exact jsonrpc version "2.0" and a usable id.
            version_ok = req.get('jsonrpc') == '2.0'
            envelope_ok = version_ok and supplied_id_ok
            if not envelope_ok:
                # Invalid objects without IDs are still invalid requests —
                # JSON-RPC 2.0 requires a valid envelope even when id is absent.
                await self._send_error(writer, req_id, -32600, 'Invalid Request')
                continue

            method = req.get('method')
            if not isinstance(method, str):
                await self._send_error(writer, req_id, -32600, 'Invalid Request')
                continue

            # ── Stage 3: dispatch ──
            try:
                # Absent params default to {}; any other non-dict value is
                # rejected inside handle_request (never silently replaced).
                params = req.get('params', {})
                result = self.handle_request(method, params, req_id=req_id)
                # Notifications (no id key) must not receive a response.
                if has_id:
                    writer.write((json.dumps(result) + '\n').encode())
                    await writer.drain()
            except ParamsError:
                # Fixed parameter-validation error; preserve the request ID.
                # Notifications never receive a response, even on failure.
                if has_id:
                    await self._send_error(writer, req_id, -32602, 'Invalid params')
            except Exception:
                # Fixed public message; do NOT leak internal exception text or
                # any payload content from the rejected program.
                # Notifications never receive a response, even on dispatch failure.
                if has_id:
                    await self._send_error(writer, req_id, -32603, 'Internal error')

    @staticmethod
    async def _send_error(writer: asyncio.StreamWriter, req_id: Any, code: int, message: str) -> None:
        """Write a sanitized JSON-RPC error response."""
        err = {
            'jsonrpc': '2.0',
            'id': req_id,
            'error': {'code': code, 'message': message},
        }
        writer.write((json.dumps(err) + '\n').encode())
        await writer.drain()


def main() -> None:
    parser = argparse.ArgumentParser(description='MCP Proxy with L gate enforcement')
    parser.add_argument('--upstream', required=True, help='Upstream MCP endpoint (stdio|ws://...)')
    parser.add_argument('--policy', choices=['deny', 'allow', 'log'], default='deny',
                        help='Action when gate denies: deny=block, allow=pass, log=warn')
    args = parser.parse_args()

    proxy = MCPProxy(args.upstream, args.policy)

    if args.upstream == 'stdio':
        asyncio.run(proxy.run_stdio())
    else:
        log.error(f"Transport '{args.upstream}' not implemented yet")
        sys.exit(1)


if __name__ == '__main__':
    main()
