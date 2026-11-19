"""Subprocess-level tests for the stdio proxy transport error handling.

These tests exercise the actual MCPProxy.run_stdio() loop through a real
subprocess with piped stdin/stdout, as required by the acceptance criteria.

Covers:
- Malformed JSON as first line does not terminate the process
- JSON null as first line does not terminate the process
- Valid request after malformed input is processed
- A malformed line never inherits an earlier request's ID
- ID round-trip (numeric incl. 0, string) and notification handling
- Oversized input lines are rejected with a sanitized error, process stays alive
- Malformed params (null/bool/number/string) are rejected, never silently replaced
- tools/call requires a non-empty string name and object arguments
- Valid request after rejected params still succeeds
- Invalid UTF-8 bytes are rejected with a sanitized Parse error (raw bytes)
- Test helper: stdio transport subprocess streams are always drained/closed,
  with a bounded deadline (no resource warnings, no hangs)
"""

import gc
import sys
import os
import json
import subprocess
import tempfile
import threading
import time
import unittest
import warnings

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + '/..')
from proxy.mcp_proxy import MAX_LINE_BYTES

PROXY_MODULE = 'proxy.mcp_proxy'


class TestStdioTransportErrors(unittest.TestCase):
    """Run the real stdio loop and assert process stays alive across bad input."""

    def test_regular_file_stdio_fails_with_fixed_diagnostic(self):
        # I7: Unsupported transport fails before handling requests.
        cmd = [sys.executable, '-m', PROXY_MODULE, '--upstream', 'stdio']
        request = b'{"jsonrpc":"2.0","method":"tools/list","id":1}\n'
        for stream in ('stdin', 'stdout'):
            with self.subTest(stream=stream), tempfile.TemporaryFile() as file:
                if stream == 'stdin':
                    file.write(request)
                    file.seek(0)
                    result = subprocess.run(cmd, stdin=file, capture_output=True, timeout=15)
                    self.assertEqual(result.stdout, b'')
                else:
                    result = subprocess.run(cmd, input=request, stdout=file,
                                            stderr=subprocess.PIPE, timeout=15)
                    file.seek(0)
                    self.assertEqual(file.read(), b'')
                self.assertEqual(result.returncode, 1)
                self.assertIn(b'Could not initialize stdio transport', result.stderr)
                self.assertNotIn(b'Traceback', result.stderr)

    @staticmethod
    def _run(lines, policy='deny'):
        """Send lines to a fresh proxy subprocess, return (responses, stderr, rc).

        Args:
            lines: list of raw lines fed via stdin (str or bytes).
            policy: one of 'deny' | 'log' | 'stdout' — passed through to the
                subprocess --policy flag.
        """
        # Normalize bytes lines to str (all test content is ASCII)
        str_lines = [
            ln.decode('utf-8') if isinstance(ln, bytes) else ln
            for ln in lines
        ]
        proc = subprocess.run(
            [sys.executable, '-m', PROXY_MODULE, '--upstream', 'stdio', '--policy', policy],
            input='\n'.join(str_lines) + '\n',
            capture_output=True,
            text=True,
            timeout=15,
        )
        responses = []
        for ln in proc.stdout.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                responses.append(json.loads(ln))
            except json.JSONDecodeError:
                responses.append({'raw': ln})
        return responses, proc.stderr, proc.returncode

    @staticmethod
    def _run_writes(writes, timeout=10, cmd=None):
        """Send raw byte chunks through separate writes to a fresh child.

        One deadline covers the entire operation (writes + reads + exit).
        The deadline starts before stdin writes, so a child that never reads
        stdin cannot block past the timeout — the supervising thread kills
        the child when the deadline expires.

        Drains stdout and stderr concurrently (threaded) so a child that
        fills stderr cannot deadlock the parent while it waits for stdout EOF.

        On expiry the child is killed and reaped; every pipe is closed before
        returning or raising TimeoutError.

        Args:
            writes: list of bytes chunks, fed via separate writes with a small
                delay between them (preserves chunked-input framing semantics).
            timeout: overall deadline in seconds for the full operation.
            cmd: optional subprocess argv; defaults to the stdio MCP proxy.

        Returns:
            (responses, stderr_bytes, returncode)

        Raises:
            TimeoutError: if the child does not exit within `timeout` seconds.
        """
        if cmd is None:
            cmd = [sys.executable, '-m', PROXY_MODULE, '--upstream', 'stdio', '--policy', 'deny']
        deadline = time.monotonic() + timeout

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        drained = {}
        exit_event = threading.Event()

        def _drain(stream, name):
            try:
                data = stream.read()
            except Exception:
                data = b''
            finally:
                try:
                    stream.close()
                except Exception:
                    pass
            drained[name] = data
            exit_event.set()

        out_thr = threading.Thread(target=_drain, args=(proc.stdout, 'stdout'), daemon=True)
        err_thr = threading.Thread(target=_drain, args=(proc.stderr, 'stderr'), daemon=True)
        out_thr.start()
        err_thr.start()

        # ── Feed stdin concurrently so the deadline can cut it short. ─────
        stdin_done = threading.Event()

        def _stdin_feeder():
            try:
                for w in writes:
                    proc.stdin.write(w)
                    proc.stdin.flush()
                    time.sleep(0.05)
                proc.stdin.close()
            except BrokenPipeError:
                pass
            finally:
                try:
                    proc.stdin.close()
                except BrokenPipeError:
                    pass
                finally:
                    stdin_done.set()

        stdin_thr = threading.Thread(target=_stdin_feeder, daemon=True)
        stdin_thr.start()

        # ── Wait for deadline or completion. ─────────────────────────────
        timed_out = False
        try:
            # Join all threads, recomputing the deadline before each join so
            # the total wait is bounded by `timeout`, not 3x it.
            out_thr.join(max(0, deadline - time.monotonic()))
            err_thr.join(max(0, deadline - time.monotonic()))
            stdin_thr.join(max(0, deadline - time.monotonic()))
            rc = proc.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            try:
                proc.wait()
            except Exception:
                pass

        # Ensure threads have observed EOF / released stream handles.
        out_thr.join(1.0)
        err_thr.join(1.0)
        stdin_thr.join(1.0)

        if timed_out:
            raise TimeoutError(f'proxy did not exit within {timeout}s')

        out_b = drained.get('stdout') or b''
        err_b = drained.get('stderr') or b''

        responses = []
        for ln in out_b.decode(errors='replace').splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                responses.append(json.loads(ln))
            except json.JSONDecodeError:
                responses.append({'raw': ln})

        return responses, err_b, rc

    def test_malformed_json_then_valid(self):
        """Malformed JSON as first line must not kill the process; next line works."""
        valid = json.dumps({'jsonrpc': '2.0', 'id': 7, 'method': 'initialize', 'params': {}})
        responses, stderr, rc = self._run(['this is not json', valid])
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 2, f"Expected 2 responses, got {responses}")
        first, second = responses
        self.assertIn('error', first, f"First response must be an error: {first}")
        self.assertIsNone(first['id'], f"Malformed line must have id=null, not inherit: {first}")
        self.assertIn('result', second, f"Valid request must succeed: {second}")
        # Request ID is preserved, not proxy-generated.
        self.assertEqual(second['id'], 7, f"Valid request must preserve its id 7: {second}")

    def test_json_null_then_valid(self):
        """JSON null as first line must not crash; next line works and id is not inherited."""
        valid = json.dumps({'jsonrpc': '2.0', 'id': 42, 'method': 'initialize', 'params': {}})
        responses, stderr, rc = self._run(['null', valid])
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 2, f"Expected 2 responses, got {responses}")
        first, second = responses
        self.assertIn('error', first)
        self.assertIsNone(first['id'], f"null line must have id=null: {first}")
        self.assertIn('result', second)
        self.assertEqual(second['id'], 42, f"Valid request must preserve its id 42: {second}")

    def test_valid_then_malformed_does_not_inherit_id(self):
        """A malformed line after a valid request must not inherit the earlier request's id."""
        valid = json.dumps({'jsonrpc': '2.0', 'id': 99, 'method': 'initialize', 'params': {}})
        responses, stderr, rc = self._run([valid, '{broken'])
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 2)
        first, second = responses
        self.assertIn('result', first)
        self.assertEqual(first['id'], 99, f"Success response must preserve id 99: {first}")
        self.assertIn('error', second)
        self.assertIsNone(second['id'], f"Malformed line must not inherit id 99: {second}")

    def test_non_object_json_rejected(self):
        """A JSON array (non-object) must be rejected, not crash the process."""
        responses, stderr, rc = self._run(['[1, 2, 3]'])
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 1)
        self.assertIn('error', responses[0])
        self.assertIsNone(responses[0]['id'])

    def test_oversized_line_rejected(self):
        """A line exceeding MAX_LINE_BYTES bytes is rejected with a sanitized error."""
        # Build a line with content bytes = MAX_LINE_BYTES + 1 (just over the limit).
        # Use a single character for speed.
        content_len = MAX_LINE_BYTES + 1
        oversized = 'x' * content_len + '\n'
        self.assertEqual(len(oversized), content_len + 1)

        valid = json.dumps({'jsonrpc': '2.0', 'id': 5, 'method': 'initialize', 'params': {}})
        responses, stderr, rc = self._run([oversized, valid])
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        # Expect exactly 2 responses: one error for oversized, then success.
        self.assertEqual(len(responses), 2, f"Expected 2 responses, got {responses}")
        first, second = responses
        # First must be the size-limit error.
        self.assertIn('error', first, f"First response must be an error: {first}")
        self.assertIsNone(first['id'], f"Oversized line must have id null: {first}")
        self.assertEqual(first['error']['message'], 'Input too large',
                         f"Error message must be sanitized: {first}")
        # Second must be success.
        self.assertIn('result', second, f"Valid request after oversized must succeed: {second}")
        self.assertEqual(second['id'], 5, f"Valid request must preserve its id 5: {second}")

    def test_id_round_trip_preserved(self):
        """Numeric (incl. 0) and string IDs round-trip unchanged."""
        lines = [
            json.dumps({'jsonrpc': '2.0', 'id': 0, 'method': 'initialize', 'params': {}}),
            json.dumps({'jsonrpc': '2.0', 'id': 42, 'method': 'initialize', 'params': {}}),
            json.dumps({'jsonrpc': '2.0', 'id': 'client-7', 'method': 'initialize', 'params': {}}),
        ]
        responses, stderr, rc = self._run(lines)
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 3)
        self.assertEqual(responses[0]['id'], 0, f"id 0 must round-trip: {responses[0]}")
        self.assertEqual(responses[1]['id'], 42, f"id 42 must round-trip: {responses[1]}")
        self.assertEqual(responses[2]['id'], 'client-7', f"string id must round-trip: {responses[2]}")

    def test_notification_emits_no_response(self):
        """A valid notification (no id key) must not receive a response, and
        a subsequent request still succeeds with its own id."""
        notif = json.dumps({'jsonrpc': '2.0', 'method': 'notifications/initialized', 'params': {}})
        req = json.dumps({'jsonrpc': '2.0', 'id': 5, 'method': 'initialize', 'params': {}})
        responses, stderr, rc = self._run([notif, req])
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        # Notification produces no response; only the request does.
        self.assertEqual(len(responses), 1, f"Notification must emit no response: {responses}")
        self.assertIn('result', responses[0])
        self.assertEqual(responses[0]['id'], 5, f"Request after notification must preserve id 5: {responses[0]}")

    def test_notification_dispatch_failure_no_response(self):
        """A notification whose dispatch fails must still emit no response.

        Uses tools/call with an unterminated L fence, which raises
        ExtractionError during handle_request — the notification must not
        produce an error response.
        """
        # Unterminated tsd fence -> ExtractionError in handle_request
        unterminated = '```tsd\nCOMMIT (user:abc)'
        notif = json.dumps({
            'jsonrpc': '2.0',
            'method': 'tools/call',
            'params': {'name': 'run_l', 'arguments': {'code': unterminated}},
        })
        req = json.dumps({'jsonrpc': '2.0', 'id': 5, 'method': 'initialize', 'params': {}})
        responses, stderr, rc = self._run([notif, req])
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        # Notification emits no response even when dispatch raises.
        self.assertEqual(len(responses), 1,
                         f"Notification must emit no response even on failure: {responses}")
        self.assertEqual(responses[0]['id'], 5)

    def test_malformed_json_still_sanitized_id_null(self):
        """Malformed JSON must still produce a sanitized error with id: null."""
        responses, stderr, rc = self._run(['{broken'])
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 1)
        self.assertIn('error', responses[0])
        self.assertIsNone(responses[0]['id'])
        self.assertEqual(responses[0]['error']['message'], 'Parse error',
                         f"Error message must be sanitized: {responses[0]}")

    def test_error_response_is_sanitized(self):
        """A rejected program's synthetic payload marker must never leak into the
        external error response under deny, and a later valid request succeeds."""
        marker = 'SYNTHETIC_PAYLOAD_MARKER_9f3a'
        bad_program = '```tsd\nCOMMIT (user:' + marker + ')\n```'
        bad_req = json.dumps({
            'jsonrpc': '2.0',
            'id': 5,
            'method': 'tools/call',
            'params': {'name': 'run_l', 'arguments': {'code': bad_program}},
        })
        good_req = json.dumps({'jsonrpc': '2.0', 'id': 6, 'method': 'initialize', 'params': {}})

        responses, stderr, rc = self._run([bad_req, good_req], policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 2)

        first, second = responses
        self.assertIn('error', first)
        error_blob = json.dumps(first)
        self.assertNotIn(marker, error_blob,
                         f"Synthetic marker leaked into error response: {error_blob}")
        self.assertNotIn(marker, stderr, f"Synthetic marker leaked into stderr: {stderr}")
        self.assertEqual(first['error']['message'], 'Internal error',
                         f"Error message must be sanitized: {first}")
        self.assertIn('result', second)

    def test_log_policy_does_not_leak_stderr(self):
        """Under --policy log, the marker must never appear in stderr while
        requests continue to succeed (process stays alive)."""
        marker = 'SYNTHETIC_PAYLOAD_MARKER_9f3a'
        bad_program = '```tsd\nCOMMIT (user:' + marker + ')\n```'
        bad_req = json.dumps({
            'jsonrpc': '2.0',
            'id': 5,
            'method': 'tools/call',
            'params': {'name': 'run_l', 'arguments': {'code': bad_program}},
        })
        good_req = json.dumps({'jsonrpc': '2.0', 'id': 6, 'method': 'initialize', 'params': {}})

        responses, stderr, rc = self._run([bad_req, good_req], policy='log')
        self.assertEqual(rc, 0, f"Proxy must not crash under log policy; stderr={stderr}")
        self.assertEqual(len(responses), 2)
        self.assertNotIn(marker, stderr,
                         f"Synthetic marker leaked into stderr under log: {stderr}")
        self.assertNotIn(marker, json.dumps(responses),
                         f"Synthetic marker leaked into responses under log")
        # Requests continue processing under log policy.
        self.assertIn('result', responses[1], f"Valid request after log-denied program must succeed: {responses[1]}")

    def test_oversized_at_limit_accepted(self):
        """Frame with content length exactly MAX_LINE_BYTES is NOT rejected as oversized."""
        at_limit = (b'x' * MAX_LINE_BYTES + b'\n')
        valid = (json.dumps({'jsonrpc': '2.0', 'id': 6, 'method': 'initialize', 'params': {}}) + '\n').encode()
        responses, stderr, rc = self._run([at_limit, valid], policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 2)
        first, second = responses
        self.assertIn('error', first)
        self.assertEqual(first['error']['message'], 'Parse error', f"Error message must be sanitized: {first}")
        self.assertIn('result', second)
        self.assertEqual(second['id'], 6)

    def test_oversized_frame_split_writes(self):
        """Oversized frame delivered across multiple writes preserves framing."""
        oversize = b'x' * (MAX_LINE_BYTES + 1) + b'\n'
        chunk1 = oversize[:len(oversize)//2]
        chunk2 = oversize[len(oversize)//2:]
        valid_line = (json.dumps({'jsonrpc': '2.0', 'id': 6, 'method': 'initialize', 'params': {}}) + '\n').encode()
        responses, stderr, rc = self._run_writes([chunk1, chunk2, valid_line])
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 2)
        error_resp, valid_resp = responses
        self.assertIn('error', error_resp)
        self.assertEqual(error_resp['error']['message'], 'Input too large')
        self.assertIsNone(error_resp['id'])
        self.assertIn('result', valid_resp)
        self.assertEqual(valid_resp['id'], 6)

    def test_oversized_at_eof(self):
        """Oversized frame ending at EOF is rejected with sanitized error."""
        oversize = b'x' * (MAX_LINE_BYTES + 1) + b'\n'
        responses, stderr, rc = self._run([oversize], policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 1)
        self.assertIn('error', responses[0])
        self.assertEqual(responses[0]['error']['message'], 'Input too large')
        self.assertIsNone(responses[0]['id'])
        self.assertNotIn('Traceback', stderr)
        self.assertNotIn('ValueError', stderr)

    def test_invalid_utf8_rejected(self):
        """Invalid UTF-8 bytes are rejected with a Parse error (id: null),
        never silently rewritten and accepted by the gate.

        These tests exercise real subprocess delivery of raw bytes (not
        text-mode approximation) so that errors='replace' bypass is prevented.
        """
        # Case 1: invalid byte 0xFF inside a payload string
        payload_ff = (
            b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
            b'"arguments":{"code":"ASSERT ev:(user:aabbccdd, sha256:00112233'
            b'44556677889900112233445566778899001122334455667788990011) '
            b'data:LEAK_FF\xfftext"}}}'
            + b'\n'
        )
        responses, stderr, rc = self._run_writes([payload_ff])
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        # Find the Parse error response
        error_resp = None
        for r in responses:
            if r.get('error', {}).get('message') == 'Parse error' and r.get('id') is None:
                error_resp = r
                break
        self.assertIsNotNone(error_resp, f"No Parse error with id=null found in {responses}")
        # Marker must not leak into error response or stderr
        self.assertNotIn(b'LEAK_FF', json.dumps(error_resp).encode(),
                         f"Marker leaked into error response: {error_resp}")
        self.assertNotIn(b'LEAK_FF', stderr, f"Marker leaked into stderr: {stderr}")

        # Case 2: truncated multibyte sequence
        payload_trunc = (
            b'{"jsonrpc":"2.0","id":2,"method":"initialize",'
            b'"params":{"x":"\xe2\x82"}}\n'
        )
        responses2, stderr2, rc2 = self._run_writes([payload_trunc])
        self.assertEqual(rc2, 0)
        error_resp2 = None
        for r in responses2:
            if r.get('error', {}).get('message') == 'Parse error' and r.get('id') is None:
                error_resp2 = r
                break
        self.assertIsNotNone(error_resp2, f"No Parse error found in {responses2}")
        self.assertNotIn(b'\xe2\x82', stderr2, f"Payload bytes leaked into stderr: {stderr2}")

        # Case 3: valid Unicode still accepted
        payload_ok = (
            b'{"jsonrpc":"2.0","id":3,"method":"initialize",'
            b'"params":{"note":"caf\xc3\xa9 japonais"}}\n'
        )
        responses3, stderr3, rc3 = self._run_writes([payload_ok])
        self.assertEqual(rc3, 0)
        self.assertEqual(len(responses3), 1)
        self.assertIn('result', responses3[0], f"Valid Unicode should succeed: {responses3[0]}")
        self.assertEqual(responses3[0]['id'], 3, f"Valid Unicode must preserve id: {responses3[0]}")

    def test_non_finite_numeric_values_rejected(self):
        """Non‑finite numeric literals in tool arguments must be rejected.

        JSON (RFC 8259) does not define NaN, Infinity, or -Infinity literals;
        Python's json module accepts them by default. The proxy adds a
        parse_constant hook to reject these constants and a parse_float hook
        to reject numbers that overflow to infinity (e.g., 1e999). The
        traversal also rejects non‑finite floats for direct callers.
        """
        # NaN literal
        responses, stderr, rc = self._run(
            ['{"jsonrpc":"2.0","id":1,"method":"tools/call",'
             '"params":{"name":"run_l","arguments":{"code":NaN}}}'],
            policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 1)
        self.assertIn('error', responses[0])
        self.assertIsNone(responses[0]['id'])
        self.assertEqual(responses[0]['error']['code'], -32700)

        # Infinity literal
        responses, stderr, rc = self._run(
            ['{"jsonrpc":"2.0","id":2,"method":"tools/call",'
             '"params":{"name":"run_l","arguments":{"code":Infinity}}}'],
            policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 1)
        self.assertIn('error', responses[0])
        self.assertIsNone(responses[0]['id'])
        self.assertEqual(responses[0]['error']['code'], -32700)

        # -Infinity literal
        responses, stderr, rc = self._run(
            ['{"jsonrpc":"2.0","id":3,"method":"tools/call",'
             '"params":{"name":"run_l","arguments":{"code":-Infinity}}}'],
            policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 1)
        self.assertIn('error', responses[0])
        self.assertIsNone(responses[0]['id'])
        self.assertEqual(responses[0]['error']['code'], -32700)

        # 1e999 overflows to infinity in binary float
        responses, stderr, rc = self._run(
            ['{"jsonrpc":"2.0","id":4,"method":"tools/call",'
             '"params":{"name":"run_l","arguments":{"code":1e999}}}'],
            policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 1)
        self.assertIn('error', responses[0])
        self.assertIsNone(responses[0]['id'])
        self.assertEqual(responses[0]['error']['code'], -32700)

        # Non‑finite floats nested inside objects/arrays
        responses, stderr, rc = self._run(
            ['{"jsonrpc":"2.0","id":5,"method":"tools/call",'
             '"params":{"name":"run_l","arguments":{"outer":{"code":NaN}}}}'],
            policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 1)
        self.assertIn('error', responses[0])
        self.assertIsNone(responses[0]['id'])
        self.assertEqual(responses[0]['error']['code'], -32700)

        # Array containing non‑finite
        responses, stderr, rc = self._run(
            ['{"jsonrpc":"2.0","id":6,"method":"tools/call",'
             '"params":{"name":"run_l","arguments":{"code":[1, 2, NaN]}}}'],
            policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 1)
        self.assertIn('error', responses[0])
        self.assertIsNone(responses[0]['id'])
        self.assertEqual(responses[0]['error']['code'], -32700)

        # Ordinary finite numbers must still succeed
        responses, stderr, rc = self._run(
            ['{"jsonrpc":"2.0","id":7,"method":"tools/call",'
             '"params":{"name":"run_l","arguments":{"code":42}}}'],
            policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 1)
        self.assertIn('result', responses[0])
        self.assertEqual(responses[0]['id'], 7)

        # Float with decimal (finite) must succeed
        responses, stderr, rc = self._run(
            ['{"jsonrpc":"2.0","id":8,"method":"tools/call",'
             '"params":{"name":"run_l","arguments":{"code":3.14}}}'],
            policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 1)
        self.assertIn('result', responses[0])
        self.assertEqual(responses[0]['id'], 8)

        # Negative finite float must succeed
        responses, stderr, rc = self._run(
            ['{"jsonrpc":"2.0","id":9,"method":"tools/call",'
             '"params":{"name":"run_l","arguments":{"code":-0.001}}}'],
            policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 1)
        self.assertIn('result', responses[0])
        self.assertEqual(responses[0]['id'], 9)

    def test_malformed_params_rejected_not_replaced(self):
        """Non-object params (null/bool/number/string) must be rejected with
        id preserved, never silently replaced with {} and treated as success."""
        cases = [None, True, 7, 'bad']
        for idx, params in enumerate(cases, start=1):
            req = json.dumps({'jsonrpc': '2.0', 'id': idx, 'method': 'tools/call',
                              'params': params})
            responses, stderr, rc = self._run([req], policy='deny')
            self.assertEqual(rc, 0, f"Proxy must not crash for params={params!r}; stderr={stderr}")
            self.assertEqual(len(responses), 1, f"params={params!r}: {responses}")
            resp = responses[0]
            self.assertIn('error', resp, f"params={params!r} must be rejected, got: {resp}")
            self.assertNotIn('result', resp, f"params={params!r} must not succeed: {resp}")
            self.assertEqual(resp['error']['message'], 'Invalid params',
                             f"params={params!r} error must be sanitized: {resp}")
            self.assertEqual(resp['id'], idx, f"params={params!r} must preserve id: {resp}")

    def test_tools_call_missing_or_invalid_name_rejected(self):
        """tools/call requires a non-empty string 'name'."""
        bad_params = [
            {},                                # no name
            {'name': ''},                      # empty name
            {'name': 7},                       # non-string name
            {'name': None},                    # null name
            {'name': ['run_l']},               # list name
        ]
        for idx, params in enumerate(bad_params, start=1):
            req = json.dumps({'jsonrpc': '2.0', 'id': idx, 'method': 'tools/call',
                              'params': params})
            responses, stderr, rc = self._run([req], policy='deny')
            self.assertEqual(rc, 0, f"Proxy must not crash for {params!r}; stderr={stderr}")
            self.assertEqual(len(responses), 1)
            resp = responses[0]
            self.assertIn('error', resp, f"{params!r} must be rejected: {resp}")
            self.assertNotIn('result', resp, f"{params!r} must not succeed: {resp}")
            self.assertEqual(resp['error']['message'], 'Invalid params')
            self.assertEqual(resp['id'], idx)

    def test_tools_call_arguments_omitted_or_empty_accepted(self):
        """Omitted 'arguments' and empty object arguments remain accepted and
        reach gate validation."""
        valid_programs = [
            {'name': 'run_l'},                                       # omitted arguments
            {'name': 'run_l', 'arguments': {}},                      # empty object
        ]
        for idx, params in enumerate(valid_programs, start=1):
            req = json.dumps({'jsonrpc': '2.0', 'id': 10 + idx, 'method': 'tools/call',
                              'params': params})
            responses, stderr, rc = self._run([req], policy='deny')
            self.assertEqual(rc, 0, f"Proxy must not crash for {params!r}; stderr={stderr}")
            self.assertEqual(len(responses), 1, f"{params!r}: {responses}")
            # Gate validation runs on the empty arguments (no L program) → forwarded success.
            self.assertIn('result', responses[0],
                          f"{params!r} must be accepted and forwarded: {responses[0]}")
            self.assertEqual(responses[0]['id'], 10 + idx)

    def test_tools_call_non_object_arguments_rejected(self):
        """tools/call 'arguments', when supplied, must be an object."""
        bad_params = [
            {'name': 'run_l', 'arguments': 'not-an-object'},
            {'name': 'run_l', 'arguments': 7},
            {'name': 'run_l', 'arguments': [1, 2]},
            {'name': 'run_l', 'arguments': True},
            {'name': 'run_l', 'arguments': None},  # explicit null != absent
        ]
        for idx, params in enumerate(bad_params, start=1):
            req = json.dumps({'jsonrpc': '2.0', 'id': idx, 'method': 'tools/call',
                              'params': params})
            responses, stderr, rc = self._run([req], policy='deny')
            self.assertEqual(rc, 0, f"Proxy must not crash for {params!r}; stderr={stderr}")
            self.assertEqual(len(responses), 1)
            resp = responses[0]
            self.assertIn('error', resp, f"{params!r} must be rejected: {resp}")
            self.assertNotIn('result', resp, f"{params!r} must not succeed: {resp}")
            self.assertEqual(resp['error']['message'], 'Invalid params')
            self.assertEqual(resp['id'], idx)

    def test_valid_tools_call_reaches_gate(self):
        """A well-formed tools/call still reaches gate validation (not blocked
        by parameter validation)."""
        req = json.dumps({
            'jsonrpc': '2.0', 'id': 11, 'method': 'tools/call',
            'params': {'name': 'run_l', 'arguments': {'code': 'ASSERT ev:(user:aabbccdd, sha256:0011223344556677889900112233445566778899001122334455667788990011) data:<x>'}},
        })
        responses, stderr, rc = self._run([req], policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 1)
        # Gate validates the program; a valid program succeeds via forwarding.
        self.assertIn('result', responses[0], f"Valid tools/call must reach gate and succeed: {responses[0]}")

    def test_valid_request_after_rejected_params_succeeds(self):
        """A rejected params request must not stop subsequent processing."""
        bad = json.dumps({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': None})
        good = json.dumps({'jsonrpc': '2.0', 'id': 3, 'method': 'initialize', 'params': {}})
        responses, stderr, rc = self._run([bad, good], policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 2, f"Expected 2 responses, got {responses}")
        first, second = responses
        self.assertIn('error', first)
        self.assertEqual(first['error']['message'], 'Invalid params')
        self.assertEqual(first['id'], 2)
        self.assertIn('result', second, f"Valid request after rejection must succeed: {second}")
        self.assertEqual(second['id'], 3)

    def test_rejected_params_no_payload_leak(self):
        """Payload content in rejected params must not appear in response or stderr."""
        marker = 'PARAMS_LEAK_MARKER_c4d1'
        bad = json.dumps({
            'jsonrpc': '2.0', 'id': 9, 'method': 'tools/call',
            'params': {'name': 'run_l', 'arguments': {'code': marker}},
        })
        good = json.dumps({'jsonrpc': '2.0', 'id': 10, 'method': 'initialize', 'params': {}})
        responses, stderr, rc = self._run([bad, good], policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        blob = json.dumps(responses)
        self.assertNotIn(marker, blob, f"Marker leaked into responses: {blob}")
        self.assertNotIn(marker, stderr, f"Marker leaked into stderr: {stderr}")
        self.assertIn('result', responses[1])

    def test_repeated_calls_no_resource_warnings(self):
        """Repeated _run_writes calls must not emit unclosed-stream ResourceWarnings."""
        chunks = [b'{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}\n']
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            rcs = []
            for _ in range(3):
                responses, err, rc = self._run_writes(chunks)
                rcs.append(rc)
            gc.collect()
        self.assertEqual(rcs, [0, 0, 0])
        rw = [w for w in caught if issubclass(w.category, ResourceWarning)]
        self.assertEqual(
            len(rw),
            0,
            f"Unclosed-stream ResourceWarnings emitted: {rw}",
        )

    def test_stalled_child_bounded_failure(self):
        """A deliberately stalled child must cause a bounded test failure (TimeoutError)."""
        stalled_cmd = [sys.executable, '-c', 'import time; time.sleep(60)']
        with self.assertRaises(TimeoutError):
            self._run_writes([], timeout=2, cmd=stalled_cmd)

    def test_substantial_stderr_completes_without_deadlock(self):
        """A child producing substantial stderr completes without deadlock."""
        nl = chr(10)
        script = (
            "import sys, json" + nl +
            "sys.stderr.write('E' * 200000)" + nl +
            "sys.stderr.flush()" + nl +
            "print(json.dumps({'jsonrpc': '2.0', 'id': 0, 'result': {'ok': True}}), file=sys.stdout)" + nl +
            "sys.stdout.flush()" + nl
        )
        cmd = [sys.executable, '-c', script]
        responses, err, rc = self._run_writes([b'x\n'], timeout=10, cmd=cmd)
        self.assertEqual(rc, 0)
        self.assertEqual(len(responses), 1)
        self.assertIn('result', responses[0])
        self.assertGreater(len(err), 100000)

    def test_broken_pipe_path_reaps_child(self):
        """A child that exits before stdin is written must not hang (broken pipe)."""
        cmd = [sys.executable, '-c', 'pass']
        responses, err, rc = self._run_writes(
            [b'{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}\n'],
            timeout=10,
            cmd=cmd,
        )
        self.assertIsNotNone(rc)
        self.assertEqual(len(responses), 0)

    def test_non_reading_child_large_input_bounded_deadline(self):
        """A child that never reads stdin cannot block past the timeout.

        Sends input larger than the OS pipe buffer (~64 KiB) so the write
        blocks, then asserts the deadline still fires promptly (not 3x it).
        """
        payload = (
            b'{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}\n'
            + b'x' * (2 * 1024 * 1024)
            + b'\n'
        )
        start = time.monotonic()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always', ResourceWarning)
            with self.assertRaises(TimeoutError):
                self._run_writes([payload], timeout=0.2,
                                 cmd=[sys.executable, '-c', 'import time; time.sleep(1)'])
            gc.collect()
        self.assertEqual(
            [str(w.message) for w in caught if issubclass(w.category, ResourceWarning)],
            [],
            'Timeout cleanup must close stdin as well as stdout and stderr',
        )
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 1.0,
                        f"Deadline must fire promptly, not after full child sleep: {elapsed:.2f}s")

    def test_duplicate_json_keys_rejected(self):
        """Duplicate JSON keys at any level must be rejected, not last-value-wins.

        json.loads silently keeps the last value for duplicate keys, so earlier
        values disappear before nested traversal and gate validation. The
        object_pairs_hook rejects duplicates (including escaped-equivalent keys
        like "code" vs "co\\u0064e") and routes through sanitized parse-error
        handling with id: null.
        """
        # Duplicate at arguments level: invalid program overwritten by ordinary text
        dup_args = (
            '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{'
            '"name":"run_l","arguments":{"code":"```tsd\\nCOMMIT (user:g)\\n```","code":"ordinary text"}}}'
        )
        responses, stderr, rc = self._run([dup_args], policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 1)
        self.assertIn('error', responses[0])
        self.assertIsNone(responses[0]['id'], f"Duplicate keys must yield id null: {responses[0]}")
        self.assertEqual(responses[0]['error']['code'], -32700)
        self.assertEqual(responses[0]['error']['message'], 'Parse error')

        # Duplicate at params level
        dup_params = (
            '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{'
            '"name":"run_l","name":"run_l","arguments":{}}}'
        )
        responses, stderr, rc = self._run([dup_params], policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertIn('error', responses[0])
        self.assertIsNone(responses[0]['id'])
        self.assertEqual(responses[0]['error']['code'], -32700)

        # Duplicate at request level
        dup_req = (
            '{"jsonrpc":"2.0","id":3,"method":"tools/call","method":"tools/call",'
            '"params":{"name":"run_l","arguments":{}}}'
        )
        responses, stderr, rc = self._run([dup_req], policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertIn('error', responses[0])
        self.assertIsNone(responses[0]['id'])
        self.assertEqual(responses[0]['error']['code'], -32700)

        # Duplicate inside nested object
        dup_nested = (
            '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{'
            '"name":"run_l","arguments":{"outer":{"code":"```tsd\\nCOMMIT (user:g)\\n```","code":"ordinary text"}}}}'
        )
        responses, stderr, rc = self._run([dup_nested], policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertIn('error', responses[0])
        self.assertIsNone(responses[0]['id'])
        self.assertEqual(responses[0]['error']['code'], -32700)

        # Identical duplicate values still rejected
        dup_identical = (
            '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{'
            '"name":"run_l","arguments":{"code":"same","code":"same"}}}'
        )
        responses, stderr, rc = self._run([dup_identical], policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertIn('error', responses[0])
        self.assertIsNone(responses[0]['id'])
        self.assertEqual(responses[0]['error']['code'], -32700)

        # Escaped-equivalent keys ("code" vs "co\\u0064e") rejected
        dup_escaped = (
            '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{'
            '"name":"run_l","arguments":{"code":"ordinary text","co\\u0064e":"another"}}}'
        )
        responses, stderr, rc = self._run([dup_escaped], policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertIn('error', responses[0])
        self.assertIsNone(responses[0]['id'])
        self.assertEqual(responses[0]['error']['code'], -32700)

    def test_duplicate_key_rejection_preserves_processing(self):
        """After a duplicate-key rejection, valid requests still process correctly."""
        dup = (
            '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{'
            '"name":"run_l","arguments":{"code":"same","code":"same"}}}'
        )
        valid1 = json.dumps({'jsonrpc': '2.0', 'id': 2, 'method': 'initialize', 'params': {}})
        valid2 = json.dumps({'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
                             'params': {'name': 'run_l', 'arguments': {'code': 'plain text'}}})
        responses, stderr, rc = self._run([dup, valid1, valid2], policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 3, f"Expected 3 responses, got {responses}")
        # First: duplicate-key rejection with id null
        self.assertIn('error', responses[0])
        self.assertIsNone(responses[0]['id'])
        self.assertEqual(responses[0]['error']['code'], -32700)
        # Second and third: valid requests processed with preserved IDs
        self.assertIn('result', responses[1])
        self.assertEqual(responses[1]['id'], 2)
        self.assertIn('result', responses[2])
        self.assertEqual(responses[2]['id'], 3)

    def test_jsonrpc_envelope_validation(self):
        """Envelope validation: version "2.0", valid IDs, notification silence.

        JSON-RPC 2.0 requires the exact version string "2.0" and request ids
        restricted to string, number, or null. Booleans and containers are
        invalid; the error response uses id: null (never echoing invalid id
        contents) and carries sanitized code -32600.
        """
        # Boolean id is invalid; rejected before dispatch with -32600, id null.
        responses, stderr, rc = self._run(
            ['{"jsonrpc":"2.0","id":true,"method":"initialize","params":{}}'], policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 1)
        self.assertIn('error', responses[0])
        self.assertIsNone(responses[0]['id'])
        self.assertEqual(responses[0]['error']['code'], -32600)
        self.assertEqual(responses[0]['error']['message'], 'Invalid Request')

        # Object-valued id is invalid; rejected with -32600, id null.
        responses, stderr, rc = self._run(
            ['{"jsonrpc":"2.0","id":{"nested":"value"},"method":"initialize","params":{}}'],
            policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 1)
        self.assertIn('error', responses[0])
        self.assertIsNone(responses[0]['id'])
        self.assertEqual(responses[0]['error']['code'], -32600)

        # Array-valued id is invalid; rejected with -32600, id null.
        responses, stderr, rc = self._run(
            ['{"jsonrpc":"2.0","id":[1,2,3],"method":"initialize","params":{}}'],
            policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 1)
        self.assertIn('error', responses[0])
        self.assertIsNone(responses[0]['id'])
        self.assertEqual(responses[0]['error']['code'], -32600)

        # Missing jsonrpc version is invalid; rejected with -32600, id echoed
        # only because the supplied id (1) is valid.
        responses, stderr, rc = self._run(
            ['{"id":1,"method":"initialize","params":{}}'], policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 1)
        self.assertIn('error', responses[0])
        self.assertEqual(responses[0]['error']['code'], -32600)
        self.assertEqual(responses[0]['id'], 1)

        # Bogus jsonrpc version is invalid; rejected with -32600, id echoed.
        responses, stderr, rc = self._run(
            ['{"jsonrpc":"bogus","id":1,"method":"initialize","params":{}}'], policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 1)
        self.assertIn('error', responses[0])
        self.assertEqual(responses[0]['error']['code'], -32600)
        self.assertEqual(responses[0]['id'], 1)

        # Valid ids are preserved: 0, string, and null must all succeed.
        for rid, line in [
            (0, '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}'),
            ('abc123', '{"jsonrpc":"2.0","id":"abc123","method":"initialize","params":{}}'),
            (None, '{"jsonrpc":"2.0","id":null,"method":"initialize","params":{}}'),
        ]:
            responses, stderr, rc = self._run([line], policy='deny')
            self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
            self.assertEqual(len(responses), 1)
            self.assertIn('result', responses[0])
            self.assertEqual(responses[0]['id'], rid)

        # Valid notification (absent id) stays silent.
        responses, stderr, rc = self._run(
            ['{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'],
            policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(responses, [])

        # After an envelope rejection, the next valid request processes correctly.
        mix = [
            '{"jsonrpc":"bogus","id":7,"method":"initialize","params":{}}',
            '{"jsonrpc":"2.0","id":8,"method":"initialize","params":{}}',
        ]
        responses, stderr, rc = self._run(mix, policy='deny')
        self.assertEqual(rc, 0, f"Proxy must not crash; stderr={stderr}")
        self.assertEqual(len(responses), 2)
        self.assertIn('error', responses[0])
        self.assertEqual(responses[0]['error']['code'], -32600)
        self.assertEqual(responses[0]['id'], 7)
        self.assertIn('result', responses[1])
        self.assertEqual(responses[1]['id'], 8)


if __name__ == '__main__':
    unittest.main(verbosity=2)
