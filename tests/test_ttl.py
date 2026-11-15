"""Regression tests for TTL syntax validation (gap 3 fix).

The structural Gate validates TTL syntax, not absolute expiration.
SecurityGate separately enforces signed issuance and deadline metadata.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + '/..')

import unittest
from lang.parser import parse
from gate.monitor import Gate, GateError

H = '0011223344556677889900112233445566778899001122334455667788990011'
H2 = 'abcdef0000000000000000000000000000000000000000000000000000000000000'


class TestTTLValidation(unittest.TestCase):
    """Verify TTL positivity is enforced (syntax), elapsed time is not."""

    def test_positive_ttl_accepted(self):
        """Positive TTL should be accepted by the gate."""
        g = Gate()
        src = f"DIRECT cap:{H} (scope=fs.read, exp=60, from=user:g) call tool:(srv:abcdef00, sha256:{H2}) {{path: \"/logs\"}}"
        acts = parse(src)
        g.execute(acts[0])
        self.assertTrue(any(a['status'] == 'ALLOW' for a in g.audit))

    def test_zero_ttl_rejected(self):
        """Zero TTL should be rejected (syntax check)."""
        g = Gate()
        src = f"DIRECT cap:{H} (scope=fs.read, exp=0, from=user:g) call tool:(srv:abcdef00, sha256:{H2}) {{path: \"/logs\"}}"
        acts = parse(src)
        with self.assertRaises(GateError) as ctx:
            g.execute(acts[0])
        self.assertEqual(ctx.exception.code, 'EXPIRY.INVALID')

    def test_grant_positive_ttl_accepted(self):
        """GRANT with positive TTL should be accepted."""
        g = Gate()
        src = f"GRANT  cap:{H} (scope=fs.read, exp=60, from=user:g)"
        acts = parse(src)
        g.execute(acts[0])

    def test_revoke_positive_ttl_accepted(self):
        """REVOKE with positive TTL should be accepted."""
        g = Gate()
        src = f"REVOKE cap:{H} (scope=fs.read, exp=60, from=user:g)"
        acts = parse(src)
        g.execute(acts[0])

    def test_elapsed_time_not_enforced(self):
        """Structural TTL validation does not enforce elapsed time.

        A one-second capability is still accepted arbitrarily later — this
        documents the scanner boundary. SecurityGate's signed deadlines are
        covered separately in test_security_gate.
        """
        g = Gate()
        src = f"DIRECT cap:{H} (scope=fs.read, exp=1, from=user:g) call tool:(srv:abcdef00, sha256:{H2}) {{path: \"/logs\"}}"
        acts = parse(src)
        # First check with an explicit timestamp.
        g.execute(acts[0], now=1)
        # Second check with now=1000000 (simulating arbitrary later time)
        g.execute(acts[0], now=1000000)
        # Assert each audit entry's timestamp and status explicitly
        self.assertEqual(len(g.audit), 2)
        for entry in g.audit:
            self.assertEqual(entry['status'], 'ALLOW',
                             f"Audit entry must be ALLOW, got {entry}")
        self.assertEqual(g.audit[0]['now'], 1,
                         "First audit entry must have now=1")
        self.assertEqual(g.audit[1]['now'], 1000000,
                         "Second audit entry must have now=1000000")


class TestTTLTypeAndRangeAtGate(unittest.TestCase):
    """Gate-side TTL type and range validation for directly constructed ASTs.

    The parser enforces bounded decimal parse, but direct AST callers can bypass
    it. Gate must enforce: type is int (not bool), 1 <= ttl <= i64::MAX.
    """

    H = '0011223344556677889900112233445566778899001122334455667788990011'
    H2 = 'abcdef0000000000000000000000000000000000000000000000000000000000000'

    def _make_direct(self, ttl):
        from lang.ast import Capability, DirectAct, ToolCall, Reference, Principal, Payload
        cap = Capability(
            cap_hash=self.H,
            scope='fs.read',
            exp=ttl,
            from_principal=Principal(id='user:g', hash=''),
            integrity_level='low',
        )
        call = ToolCall(
            tool=Reference(principal=Principal(id='srv:abcdef00', hash=''), content_hash=self.H2),
            params={'path': '/logs'},
        )
        return DirectAct(capability=cap, call=call)

    def _make_grant(self, ttl):
        from lang.ast import Capability, GrantAct, Reference, Principal
        cap = Capability(
            cap_hash=self.H,
            scope='fs.read',
            exp=ttl,
            from_principal=Principal(id='user:g', hash=''),
            integrity_level='low',
        )
        return GrantAct(capability=cap)

    def _make_revoke(self, ttl):
        from lang.ast import Capability, RevokeAct, Reference, Principal
        cap = Capability(
            cap_hash=self.H,
            scope='fs.read',
            exp=ttl,
            from_principal=Principal(id='user:g', hash=''),
            integrity_level='low',
        )
        return RevokeAct(capability=cap)

    def _assert_denied(self, act):
        g = Gate()
        with self.assertRaises(GateError) as ctx:
            g.execute(act)
        self.assertEqual(ctx.exception.code, 'EXPIRY.INVALID', f"Expected EXPIRY.INVALID for {act.capability.exp!r}")
        # Verify audit has DENY
        self.assertTrue(any(a['status'] == 'DENY' and a.get('error', '').startswith('EXPIRY.INVALID') for a in g.audit))

    def test_bool_true_rejected(self):
        for make in (self._make_direct, self._make_grant, self._make_revoke):
            with self.subTest(act_type=make.__name__):
                self._assert_denied(make(True))

    def test_bool_false_rejected(self):
        for make in (self._make_direct, self._make_grant, self._make_revoke):
            with self.subTest(act_type=make.__name__):
                self._assert_denied(make(False))

    def test_float_rejected(self):
        for make in (self._make_direct, self._make_grant, self._make_revoke):
            with self.subTest(act_type=make.__name__):
                self._assert_denied(make(0.5))

    def test_nan_rejected(self):
        for make in (self._make_direct, self._make_grant, self._make_revoke):
            with self.subTest(act_type=make.__name__):
                self._assert_denied(make(float('nan')))

    def test_positive_infinity_rejected(self):
        for make in (self._make_direct, self._make_grant, self._make_revoke):
            with self.subTest(act_type=make.__name__):
                self._assert_denied(make(float('inf')))

    def test_negative_infinity_rejected(self):
        for make in (self._make_direct, self._make_grant, self._make_revoke):
            with self.subTest(act_type=make.__name__):
                self._assert_denied(make(float('-inf')))

    def test_oversized_int_rejected(self):
        oversized = 9223372036854775808  # i64::MAX + 1
        for make in (self._make_direct, self._make_grant, self._make_revoke):
            with self.subTest(act_type=make.__name__):
                self._assert_denied(make(oversized))

    def test_negative_int_rejected(self):
        for make in (self._make_direct, self._make_grant, self._make_revoke):
            with self.subTest(act_type=make.__name__):
                self._assert_denied(make(-1))

    def test_zero_rejected(self):
        for make in (self._make_direct, self._make_grant, self._make_revoke):
            with self.subTest(act_type=make.__name__):
                self._assert_denied(make(0))

    def test_string_rejected(self):
        for make in (self._make_direct, self._make_grant, self._make_revoke):
            with self.subTest(act_type=make.__name__):
                self._assert_denied(make("60"))

    def test_none_rejected(self):
        for make in (self._make_direct, self._make_grant, self._make_revoke):
            with self.subTest(act_type=make.__name__):
                self._assert_denied(make(None))

    def test_boundary_accepted(self):
        """i64::MAX should be accepted."""
        for make in (self._make_direct, self._make_grant, self._make_revoke):
            with self.subTest(act_type=make.__name__):
                g = Gate()
                g.execute(make(9223372036854775807))
                self.assertTrue(any(a['status'] == 'ALLOW' for a in g.audit))

    def test_one_accepted(self):
        """1 should be accepted."""
        for make in (self._make_direct, self._make_grant, self._make_revoke):
            with self.subTest(act_type=make.__name__):
                g = Gate()
                g.execute(make(1))
                self.assertTrue(any(a['status'] == 'ALLOW' for a in g.audit))


if __name__ == '__main__':
    unittest.main(verbosity=2)
