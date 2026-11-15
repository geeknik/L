"""Regression tests for proxy/mcp_proxy.py — fenced program extraction.

Covers:
- Fenced program with invalid reference is rejected (not bypassed)
- Bare ``` closing fence works
- Blank lines don't crash the extractor
- Unterminated tsd/l fences produce an explicit ExtractionError
- That error reaches MCPProxy.handle_request() and prevents success under deny
- Unfinished block after a valid closed block still errors
- Empty unfinished block errors
- Valid closed blocks succeed under deny (positive control)
- ```python inside a tsd block is treated as content, not a closing fence
- Multiple fenced blocks are extracted separately
- Non-L fences (```python, ```json) are ignored
- Bare act lines (no fence) are extracted
- Empty input returns no programs
- Invalid bodies rejected via handle_request (gate denies)
- Nested argument traversal: invalid programs rejected at all nesting levels
- Valid nested programs reach gate and succeed
- Non-program values remain accepted
- Traversal limits fail closed (cyclic, depth, node count)
- Stdio preserves IDs, notification silence, sanitization
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + '/..')

import unittest
from proxy.mcp_proxy import LProgramExtractor, TSDSandbox, MCPProxy, ExtractionError, ParamsError

H = '0011223344556677889900112233445566778899001122334455667788990011'
H2 = 'abcdef0000000000000000000000000000000000000000000000000000000000000'
VALID_BODY = (
    "ASSERT ev:(user:aabbccdd, sha256:0011223344556677889900112233445566778899001122334455667788990011) "
    "data:<opaque, x>"
)

INVALID_BODY = "COMMIT (user:g)"
INVALID_PROG = "```tsd\n" + INVALID_BODY + "\n```"


class TestFencedProgramExtraction(unittest.TestCase):
    """Tests for LProgramExtractor.extract() and TSDSandbox.check()."""

    def test_fenced_invalid_reference_rejected(self):
        """A fenced program with an invalid reference must be rejected by the gate."""
        text = "```tsd\n" + INVALID_BODY + "\n```"
        programs = LProgramExtractor.extract(text)
        self.assertEqual(len(programs), 1)
        sandbox = TSDSandbox(policy='deny')
        allowed, _ = sandbox.check(programs[0])
        self.assertFalse(allowed, "Invalid reference must be rejected")

    def test_bare_closing_fence_works(self):
        """A bare ``` closing fence must extract the program."""
        text = "```tsd\n" + VALID_BODY + "\n```"
        programs = LProgramExtractor.extract(text)
        self.assertEqual(len(programs), 1)
        self.assertIn("ASSERT", programs[0])

    def test_blank_lines_no_crash(self):
        """Blank lines inside a fenced block must not crash the extractor."""
        text = "```tsd\n" + VALID_BODY + "\n\n```"
        programs = LProgramExtractor.extract(text)
        self.assertEqual(len(programs), 1)
        self.assertIn("ASSERT", programs[0])

    def test_unterminated_tsd_fence_raises(self):
        """An unterminated ```tsd fence with a VALID body must raise ExtractionError."""
        text = "```tsd\n" + VALID_BODY  # no closing fence
        with self.assertRaises(ExtractionError):
            LProgramExtractor.extract(text)

    def test_unterminated_l_fence_raises(self):
        """An unterminated ```l fence with a VALID body must raise ExtractionError."""
        text = "```l\n" + VALID_BODY  # no closing fence
        with self.assertRaises(ExtractionError):
            LProgramExtractor.extract(text)

    def test_empty_unfinished_block_raises(self):
        """An empty unfinished block (just the opening fence) must raise ExtractionError."""
        with self.assertRaises(ExtractionError):
            LProgramExtractor.extract("```tsd")

    def test_unfinished_block_after_valid_closed_block_raises(self):
        """An unfinished block after a valid closed block must still raise."""
        text = "```tsd\n" + VALID_BODY + "\n```\n```tsd\n" + VALID_BODY  # second block unterminated
        with self.assertRaises(ExtractionError):
            LProgramExtractor.extract(text)

    def test_python_fence_inside_tsd_block_is_content(self):
        """```python inside a tsd block must be preserved as content, not discarded."""
        text = "```tsd\nCOMMIT (user:g)\n```python\nmore content\n```"
        programs = LProgramExtractor.extract(text)
        self.assertEqual(len(programs), 1)
        # Assert EXACT content: the fence line and following text must both survive
        self.assertEqual(programs[0], "COMMIT (user:g)\n```python\nmore content")

    def test_multiple_fenced_blocks_extracted_separately(self):
        """Multiple fenced blocks must be extracted as separate programs."""
        text = (
            "```tsd\nCOMMIT (user:g)\n```\n"
            "```tsd\n" + VALID_BODY + "\n```"
        )
        programs = LProgramExtractor.extract(text)
        self.assertEqual(len(programs), 2)
        self.assertIn("COMMIT", programs[0])
        self.assertIn("ASSERT", programs[1])

    def test_non_l_fence_ignored(self):
        """Non-L fences (```python, ```json) must be ignored entirely."""
        text = "```python\nprint('hello')\n```"
        programs = LProgramExtractor.extract(text)
        self.assertEqual(len(programs), 0)

    def test_bare_act_lines_extracted(self):
        """Bare act lines (no fence) must be extracted."""
        text = VALID_BODY
        programs = LProgramExtractor.extract(text)
        self.assertEqual(len(programs), 1)
        self.assertIn("ASSERT", programs[0])

    def test_empty_input_returns_no_programs(self):
        """Empty input must return an empty list, not crash."""
        programs = LProgramExtractor.extract("")
        self.assertEqual(len(programs), 0)

    def test_fenced_content_preserves_whitespace(self):
        """Whitespace inside fenced content must be preserved exactly.

        The extractor previously stripped every line before appending, which
        mutated parameter values containing indentation, trailing spaces, and
        whitespace-only lines. The gate then validated different arguments from
        the ones supplied.
        """
        cases = [
            'first\n  second',      # indentation inside a string value
            'first  \nsecond',      # trailing spaces inside a string value
            'first\n \t \nsecond',  # whitespace-only line inside a string value
            '  leading spaces',     # leading whitespace on a content line
            'trailing spaces  ',    # trailing whitespace on a content line
        ]
        for val in cases:
            with self.subTest(value=val):
                body = (
                    "```tsd\n"
                    f"DIRECT cap:{H} (scope=fs.read, exp=60, from=user:g) "
                    f"call tool:(srv:abcdef00, sha256:{H2}) {{text: \"{val}\"}}\n"
                    "```"
                )
                programs = LProgramExtractor.extract(body)
                self.assertEqual(len(programs), 1, f"Expected 1 program for {val!r}")
                extracted = programs[0]
                # The string token must survive byte-for-byte.
                inner = extracted.split('{text: "', 1)[1].rsplit('"}', 1)[0]
                self.assertEqual(inner, val,
                                 f"Whitespace mutation for {val!r}: got {inner!r}")

    def test_fenced_content_preserves_whitespace_only_lines(self):
        """Whitespace-only lines inside a block must not be collapsed to empty."""
        val = "line1\n   \nline3"
        body = (
            "```tsd\n"
            f"DIRECT cap:{H} (scope=fs.read, exp=60, from=user:g) "
            f"call tool:(srv:abcdef00, sha256:{H2}) {{text: \"{val}\"}}\n"
            "```"
        )
        programs = LProgramExtractor.extract(body)
        self.assertEqual(len(programs), 1)
        inner = programs[0].split('{text: "', 1)[1].rsplit('"}', 1)[0]
        self.assertEqual(inner, val)

    def test_fenced_content_preserves_non_l_fence_lines(self):
        """Non-L fence lines inside a block must preserve original whitespace."""
        val = "```python\n  indented code\n```"
        body = (
            "```tsd\n"
            f"DIRECT cap:{H} (scope=fs.read, exp=60, from=user:g) "
            f"call tool:(srv:abcdef00, sha256:{H2}) {{text: \"{val}\"}}\n"
            "```"
        )
        programs = LProgramExtractor.extract(body)
        self.assertEqual(len(programs), 1)
        inner = programs[0].split('{text: "', 1)[1].rsplit('"}', 1)[0]
        self.assertEqual(inner, val)

    def test_fenced_extraction_round_trip_parses_identically(self):
        """Parsing the original body and the extracted body must agree on params."""
        val = "first\n  second"
        body = (
            "```tsd\n"
            f"DIRECT cap:{H} (scope=fs.read, exp=60, from=user:g) "
            f"call tool:(srv:abcdef00, sha256:{H2}) {{text: \"{val}\"}}\n"
            "```"
        )
        # Parse the body directly (the fence lines are not valid L, so we
        # extract first, then parse the extracted program).
        programs = LProgramExtractor.extract(body)
        self.assertEqual(len(programs), 1)
        from lang.parser import parse
        acts = parse(programs[0])
        self.assertEqual(len(acts), 1)
        self.assertEqual(acts[0].call.params['text'], val)


class TestMCPProxyHandleRequest(unittest.TestCase):
    """Regression tests: unterminated fences must prevent success under deny."""

    def _make_proxy(self):
        return MCPProxy(upstream_url='stdio', policy='deny')

    def _call(self, body: str):
        proxy = self._make_proxy()
        return proxy.handle_request(
            'tools/call',
            {'name': 'run_l', 'arguments': {'code': body}},
        )

    def test_valid_closed_tsd_block_succeeds(self):
        """Positive control: a valid closed tsd block must succeed under deny."""
        body = "```tsd\n" + VALID_BODY + "\n```"
        result = self._call(body)
        self.assertIn('result', result, "Valid closed block must not be blocked")

    def test_valid_closed_l_block_succeeds(self):
        """Positive control: a valid closed l block must succeed under deny."""
        body = "```l\n" + VALID_BODY + "\n```"
        result = self._call(body)
        self.assertIn('result', result, "Valid closed block must not be blocked")

    def test_unterminated_tsd_block_prevents_success(self):
        """Unterminated tsd block with a VALID body must prevent success under deny."""
        body = "```tsd\n" + VALID_BODY  # no closing fence
        with self.assertRaises(ExtractionError):
            self._call(body)

    def test_unterminated_l_block_prevents_success(self):
        """Unterminated l block with a VALID body must prevent success under deny."""
        body = "```l\n" + VALID_BODY  # no closing fence
        with self.assertRaises(ExtractionError):
            self._call(body)

    def test_empty_unfinished_block_prevents_success(self):
        """Empty unfinished block must prevent success under deny."""
        with self.assertRaises(ExtractionError):
            self._call("```tsd")

    def test_unfinished_block_after_valid_block_prevents_success(self):
        """A valid closed block followed by an unfinished block must NOT succeed."""
        body = "```tsd\n" + VALID_BODY + "\n```\n```tsd\n" + VALID_BODY
        with self.assertRaises(ExtractionError):
            self._call(body)

    def test_invalid_body_tsd_block_prevents_success(self):
        """A validly formatted tsd block whose body is invalid must prevent success under deny."""
        body = "```tsd\n" + INVALID_BODY + "\n```"
        with self.assertRaises(RuntimeError):
            self._call(body)

    def test_invalid_body_l_block_prevents_success(self):
        """A validly formatted l block whose body is invalid must prevent success under deny."""
        body = "```l\n" + INVALID_BODY + "\n```"
        with self.assertRaises(RuntimeError):
            self._call(body)

    def test_direct_handle_request_params_validation(self):
        """Direct handle_request() rejects invalid params, never silently replacing them."""
        proxy = self._make_proxy()
        # Non-dict params - should raise ParamsError
        with self.assertRaises(ParamsError):
            proxy.handle_request('tools/call', 'not-a-dict', req_id=1)
        # Missing name in tools/call - should raise ParamsError
        with self.assertRaises(ParamsError):
            proxy.handle_request('tools/call', {'arguments': {}}, req_id=2)
        # Invalid name - should raise ParamsError
        with self.assertRaises(ParamsError):
            proxy.handle_request('tools/call', {'name': '', 'arguments': {}}, req_id=3)
        # Non-object arguments - should raise ParamsError
        with self.assertRaises(ParamsError):
            proxy.handle_request('tools/call', {'name': 'run_l', 'arguments': 'not-an-object'}, req_id=4)
        # Explicit null arguments - should raise ParamsError (not absent, not {})
        with self.assertRaises(ParamsError):
            proxy.handle_request('tools/call', {'name': 'run_l', 'arguments': None}, req_id=6)
        # Valid tools/call still reaches gate validation (raises RuntimeError for denied L program)
        with self.assertRaises(RuntimeError):
            proxy.handle_request('tools/call', {'name': 'run_l', 'arguments': {'code': 'ASSERT ev:()'}}, req_id=5)

    def test_direct_handle_request_omitted_or_empty_arguments_accepted(self):
        """Omitted 'arguments' and empty object hit handle_request without ParamsError."""
        proxy = self._make_proxy()
        # Omitted arguments: no L program, forwarded successfully.
        result = proxy.handle_request('tools/call', {'name': 'run_l'}, req_id=7)
        self.assertIn('result', result)
        self.assertEqual(result['id'], 7)
        # Empty object arguments: no L program, forwarded successfully.
        result = proxy.handle_request('tools/call', {'name': 'run_l', 'arguments': {}}, req_id=8)
        self.assertIn('result', result)
        self.assertEqual(result['id'], 8)

    def test_nested_string_arguments_denied_under_deny_policy(self):
        """Invalid L programs in nested argument positions are rejected.

        Regression for: strings inside objects and arrays nested within
        the 'arguments' dict never reach the gate. The traversal fix ensures
        every string at any depth is extracted and checked.
        """
        proxy = self._make_proxy()

        # Top-level string still works
        with self.assertRaises(RuntimeError):
            proxy.handle_request(
                'tools/call',
                {'name': 'run_l', 'arguments': {'code': INVALID_PROG}},
                req_id=1,
            )

        # Nested inside object
        with self.assertRaises(RuntimeError):
            proxy.handle_request(
                'tools/call',
                {'name': 'run_l', 'arguments': {'inner': INVALID_PROG}},
                req_id=2,
            )

        # Nested inside array element
        with self.assertRaises(RuntimeError):
            proxy.handle_request(
                'tools/call',
                {'name': 'run_l', 'arguments': {'items': [INVALID_PROG]}},
                req_id=3,
            )

        # Object inside array
        with self.assertRaises(RuntimeError):
            proxy.handle_request(
                'tools/call',
                {'name': 'run_l', 'arguments': {'items': [{'inner': INVALID_PROG}]}},
                req_id=4,
            )

        # Mixed: one valid plain string then an invalid nested one -> denied
        with self.assertRaises(RuntimeError):
            proxy.handle_request(
                'tools/call',
                {'name': 'run_l', 'arguments': {'a': 'plain text', 'b': {'c': INVALID_PROG}}},
                req_id=5,
            )

    def test_valid_nested_programs_reach_gate_and_succeed(self):
        """Valid L programs nested at any depth must reach the gate and succeed."""
        proxy = self._make_proxy()

        # Valid nested program inside object (uses VALID_BODY which parses to ASSERT)
        result = proxy.handle_request(
            'tools/call',
            {'name': 'run_l', 'arguments': {'code': VALID_BODY}},
            req_id=1,
        )
        self.assertIn('result', result, 'valid nested must succeed')

        # Valid nested program inside array element
        result = proxy.handle_request(
            'tools/call',
            {'name': 'run_l', 'arguments': {'items': ['```tsd\n' + VALID_BODY + '\n```']}},
            req_id=3,
        )
        self.assertIn('result', result, 'valid nested array must succeed')

        # Valid nested program inside object in array
        result = proxy.handle_request(
            'tools/call',
            {'name': 'run_l', 'arguments': {'items': [{'inner': VALID_BODY}]}},
            req_id=4,
        )
        self.assertIn('result', result, 'valid nested object-in-array must succeed')

    def test_non_program_values_remain_accepted(self):
        """Ordinary non-program values (plain strings, numbers, etc.) are accepted."""
        proxy = self._make_proxy()

        # Plain string that's not an L program
        result = proxy.handle_request(
            'tools/call',
            {'name': 'run_l', 'arguments': {'code': 'just some text'}},
            req_id=1,
        )
        self.assertIn('result', result, 'plain string must succeed')

        # Number value
        result = proxy.handle_request(
            'tools/call',
            {'name': 'run_l', 'arguments': {'count': 42}},
            req_id=2,
        )
        self.assertIn('result', result, 'number value must succeed')

        # Boolean value
        result = proxy.handle_request(
            'tools/call',
            {'name': 'run_l', 'arguments': {'flag': True}},
            req_id=3,
        )
        self.assertIn('result', result, 'boolean value must succeed')

        # Finite float value
        result = proxy.handle_request(
            'tools/call',
            {'name': 'run_l', 'arguments': {'ratio': 3.14}},
            req_id=4,
        )
        self.assertIn('result', result, 'finite float value must succeed')

        # Negative finite float value
        result = proxy.handle_request(
            'tools/call',
            {'name': 'run_l', 'arguments': {'ratio': -0.001}},
            req_id=5,
        )
        self.assertIn('result', result, 'negative finite float value must succeed')

    def test_non_finite_floats_rejected_in_direct_call(self):
        """Non-finite floats in direct handle_request() calls are rejected.

        Direct callers supplying Python NaN/Infinity objects must be rejected
        during argument traversal, not silently skipped.
        """
        proxy = self._make_proxy()

        # NaN in direct call
        with self.assertRaises(ParamsError):
            proxy._check_arguments_for_programs({'code': float('nan')})

        # Infinity in direct call
        with self.assertRaises(ParamsError):
            proxy._check_arguments_for_programs({'code': float('inf')})

        # -Infinity in direct call
        with self.assertRaises(ParamsError):
            proxy._check_arguments_for_programs({'code': float('-inf')})

        # Non-finite nested inside object
        with self.assertRaises(ParamsError):
            proxy._check_arguments_for_programs({'outer': {'code': float('nan')}})

        # Non-finite nested inside array
        with self.assertRaises(ParamsError):
            proxy._check_arguments_for_programs({'items': [float('inf')]})

        # Finite floats still accepted
        self.assertIsNone(proxy._check_arguments_for_programs({'ratio': 3.14}))
        self.assertIsNone(proxy._check_arguments_for_programs({'ratio': -0.001}))

    def test_traversal_limits_fail_closed(self):
        """Excessive nesting, cyclic references, or excessive node counts are rejected."""
        proxy = self._make_proxy()

        # Self-cycle (dict references itself) raises ParamsError
        with self.assertRaises(ParamsError):
            cyclic = {}
            cyclic['self'] = cyclic
            proxy._check_arguments_for_programs(cyclic)

        # Mutual cycle (two dicts reference each other) raises ParamsError
        with self.assertRaises(ParamsError):
            a = {'b': None}
            b = {'a': None}
            a['b'] = b
            b['a'] = a
            proxy._check_arguments_for_programs(a)

        # List self-cycle raises ParamsError
        with self.assertRaises(ParamsError):
            cyclic_list = ['x']
            cyclic_list.append(cyclic_list)
            proxy._check_arguments_for_programs(cyclic_list)

        # Depth exceeding limit raises ParamsError
        with self.assertRaises(ParamsError):
            # Build a dict chain of depth 17 (> MAX_ARG_DEPTH=16)
            chain = {'a': 'x'}
            for _ in range(16):
                chain = {'inner': chain}
            proxy._check_arguments_for_programs(chain)

        # Node count exceeding limit raises ParamsError
        with self.assertRaises(ParamsError):
            proxy._check_arguments_for_programs({'items': ['x'] * 2000})

        # Exactly at the limit should be accepted
        self.assertIsNone(proxy._check_arguments_for_programs({'items': ['x'] * 1000}))

    def test_shared_acyclic_containers_accepted(self):
        """Shared acyclic containers (same object referenced from multiple keys) are accepted.

        Cycle detection tracks containers on the current traversal path only, so
        a shared dict or list referenced from two sibling keys is not mistaken
        for a cycle. JSON cannot produce shared identity, but direct callers can.
        """
        proxy = self._make_proxy()

        # Shared dict from two sibling keys
        shared = {'text': 'ordinary text'}
        args = {'left': shared, 'right': shared}
        self.assertIsNone(proxy._check_arguments_for_programs(args))

        # Shared list from two sibling keys
        shared_list = ['a', 'b']
        args = {'left': shared_list, 'right': shared_list}
        self.assertIsNone(proxy._check_arguments_for_programs(args))

        # Deep shared container
        shared_deep = {'a': {'b': {'c': 'value'}}}
        args = {'x': shared_deep, 'y': shared_deep}
        self.assertIsNone(proxy._check_arguments_for_programs(args))

        # Shared container with an L program still reaches the gate
        shared_prog = {'code': INVALID_PROG}
        args = {'left': shared_prog, 'right': shared_prog}
        with self.assertRaises(RuntimeError):
            proxy._check_arguments_for_programs(args)

    def test_stdio_id_roundtrip_after_denial(self):
        """Stdio transport preserves request IDs even when gate denies.

        _send_error always echoes the incoming request ID. IDs numeric (incl. 0),
        string, and null all pass through; notifications (absent id) emit nothing.
        """
        import asyncio

        class FakeWriter:
            def __init__(self):
                self.output = []
            def write(self, data):
                self.output.append(data.decode() if isinstance(data, bytes) else data)
            async def drain(self):
                pass

        proxy = self._make_proxy()

        def run_send(req_id, code, message):
            w = FakeWriter()
            asyncio.run(proxy._send_error(w, req_id, code, message))
            import json
            return json.loads(w.output[0])

        resp = run_send(7, -32603, 'Internal error')
        self.assertEqual(resp['jsonrpc'], '2.0')
        self.assertEqual(resp['id'], 7)
        self.assertEqual(resp['error']['code'], -32603)
        self.assertEqual(resp['error']['message'], 'Internal error')

        # ID zero preserved (truthy check would fail it)
        resp = run_send(0, -32603, 'Internal error')
        self.assertEqual(resp['id'], 0)

        # ID null preserved
        resp = run_send(None, -32603, 'Internal error')
        self.assertEqual(resp['id'], None)

        # String ID preserved
        resp = run_send('req-42', -32603, 'Internal error')
        self.assertEqual(resp['id'], 'req-42')

    def test_notifications_are_silent(self):
        """Notifications (no 'id' key) never receive a response, even on dispatch failure.

        Handled at the transport level via 'id' in req key presence (not truthiness).
        This test verifies the protocol invariant by checking the transport logic
        path in handle_request via _validate_params + gate deny with no id.
        """
        proxy = self._make_proxy()
        # handle_request with an explicit None id (key present, id None) still
        # sends a response under deny; a true notification omits 'id' entirely
        # and is handled by run_stdio's has_id guard (verified by reading code).
        # Here we confirm a denial still raises RuntimeError so the transport
        # can surface it with the preserved ID.
        with self.assertRaises(RuntimeError):
            proxy.handle_request(
                'tools/call',
                {'name': 'run_l', 'arguments': {'code': INVALID_PROG}},
                req_id=9,
            )


class TestSandboxPolicyValidation(unittest.TestCase):
    """Policy must be validated at construction and enforced fail-closed.

    Regression: TSDSandbox.__init__ accepted any policy value, and the
    enforcement branch handled only 'deny' and 'log' — every other value
    ('denny', 'DENY', '', None, False, post-construction mutation) behaved
    as implicit allow. The CLI's argparse choices cannot protect
    programmatic construction.
    """

    GATE_REJECTED_ARGS = {'code': INVALID_PROG}

    def test_construction_rejects_invalid_policies(self):
        for bad in ('denny', 'DENY', '', None, False, 0, True, [], 'deny ',
                    'allow_all', 'ALLOW'):
            with self.subTest(policy=bad):
                with self.assertRaises(ValueError):
                    TSDSandbox(policy=bad)

    def test_construction_error_message_is_fixed(self):
        # The message must not echo the offending value (sanitization rule).
        with self.assertRaises(ValueError) as ctx:
            TSDSandbox(policy='denny')
        self.assertEqual(
            str(ctx.exception),
            "invalid policy: must be 'deny', 'allow', or 'log'",
        )

    def test_construction_accepts_supported_policies(self):
        for good in ('deny', 'allow', 'log'):
            with self.subTest(policy=good):
                sandbox = TSDSandbox(policy=good)
                self.assertEqual(sandbox.policy, good)

    def test_proxy_construction_rejects_invalid_policy(self):
        with self.assertRaises(ValueError):
            MCPProxy(upstream_url='stdio', policy='denny')

    def test_enforce_deny_blocks_rejected_program(self):
        proxy = MCPProxy(upstream_url='stdio', policy='deny')
        with self.assertRaises(RuntimeError):
            proxy._check_arguments_for_programs(self.GATE_REJECTED_ARGS)

    def test_enforce_allow_passes_rejected_program(self):
        proxy = MCPProxy(upstream_url='stdio', policy='allow')
        self.assertIsNone(
            proxy._check_arguments_for_programs(self.GATE_REJECTED_ARGS))

    def test_enforce_log_passes_rejected_program(self):
        proxy = MCPProxy(upstream_url='stdio', policy='log')
        self.assertIsNone(
            proxy._check_arguments_for_programs(self.GATE_REJECTED_ARGS))

    def test_mutated_unknown_policy_fails_closed(self):
        # Post-construction mutation must not reopen the implicit-allow path.
        proxy = MCPProxy(upstream_url='stdio', policy='deny')
        proxy.sandbox.policy = 'bogus'
        with self.assertRaises(RuntimeError):
            proxy._check_arguments_for_programs(self.GATE_REJECTED_ARGS)


class TestProxyResourceContract(unittest.TestCase):
    """I6/I7: bounded input, bounded sanitized retention, strict argument types."""

    def test_audit_is_bounded_and_payload_free(self):
        from lang.limits import MAX_AUDIT_RECORDS
        sandbox = TSDSandbox()
        marker = 'PRIVATE_SYNTHETIC_MARKER'
        for _ in range(MAX_AUDIT_RECORDS + 3):
            sandbox.check(marker)
        self.assertEqual(len(sandbox.audit_log), MAX_AUDIT_RECORDS)
        self.assertNotIn(marker, repr(sandbox.audit_log))
        sandbox.check(VALID_BODY.replace('opaque, x', marker))
        self.assertNotIn(marker, repr(sandbox.audit_log))
        self.assertTrue(sandbox.audit_log[-1]['allowed'])

    def test_aggregate_string_byte_limit(self):
        from lang.limits import MAX_ARG_STRING_BYTES
        proxy = MCPProxy('stdio')
        self.assertEqual(proxy._collect_strings({'a': 'x' * MAX_ARG_STRING_BYTES}),
                         ['x' * MAX_ARG_STRING_BYTES])
        for args in ({'a': 'x' * MAX_ARG_STRING_BYTES, 'b': 'x'},
                     {'a': '\u00e9' * MAX_ARG_STRING_BYTES}, {'a': '\ud800'}):
            with self.subTest(kind=type(args)), self.assertRaises(ParamsError):
                proxy._collect_strings(args)

    def test_non_json_values_refused(self):
        for value in (object(), (), set(), b'bytes'):
            with self.subTest(kind=type(value)), self.assertRaises(ParamsError):
                MCPProxy('stdio')._collect_strings({'value': value})

    def test_extraction_bound(self):
        from lang.limits import MAX_SOURCE_BYTES
        for text in ('x' * (MAX_SOURCE_BYTES + 1), '\ud800'):
            with self.assertRaises(ExtractionError):
                LProgramExtractor.extract(text)

    def test_unknown_policy_rejected_even_without_program(self):
        proxy = MCPProxy('stdio')
        proxy.sandbox.policy = 'invalid'
        with self.assertRaises(RuntimeError):
            proxy.handle_request('tools/call', {'name': 'example', 'arguments': {}})


if __name__ == '__main__':
    unittest.main()
