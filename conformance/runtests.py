#!/usr/bin/env python3
"""Conformance suite for L: A Trust-Typed Language for Agents v1.0.

Run via: PYTHONPATH=. python3 -m conformance.runtests

Exit code: 0 iff every test passes; 1 otherwise. A conformance runner that
exits 0 on failure is not a release gate.

This suite verifies:
- All 7 act types parse and gate correctly
- Label lattice operations
- Expiry enforcement
- Integrity/DIRECT authorization
- ENDORSE authorization (admin/reviewer rules)
- Short/long principal hash formats
- Capability scope parsing with dotted parts
- Reference (principal, content hash) structure
- Expired program denial
- Unauthorized ENDORSE denial
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + '/..')

from lang.parser import parse
from gate.monitor import Gate, GateError
from lang.ast import (
    DirectAct, Principal, Reference, Capability, ToolCall,
)
from lang.labels import Label, LOW

H = '0011223344556677889900112233445566778899001122334455667788990011'
H2 = 'abcdef00000000000000000000000000000000000000000000000000000000000'

PROGS = {
    'ASSERT_LOW': 'ASSERT ev:(user:g, sha256:' + H + ') data:<opaque, sample>',
    'ASSERT_HIGH': 'ASSERT ev:(user:g, sha256:' + H + ') data:<opaque, sample>',
    'QUERY_SIMPLE': 'QUERY ev:(user:a, sha256:' + H + ') data:<some data>',
    'DIRECT_ALLOW': (
        'DIRECT cap:' + H + ' (scope=fs.read, exp=60, from=user:g) '
        'call tool:(srv:abcdef00, sha256:' + H2 + ') {path: "/logs"}'
    ),
    'COMMIT_SIMPLE': 'COMMIT (user:g, sha256:' + H + ')',
    'GRANT_SIMPLE': 'GRANT cap:' + H + ' (scope=fs.read, exp=60, from=user:g)',
    'REVOKE_SIMPLE': 'REVOKE cap:' + H + ' (scope=fs.read, exp=60, from=user:g)',
    'ENDORSE_ADMIN': 'ENDORSE (srv:abcdef00, sha256:' + H2 + ') by:admin',
    'ENDORSE_REVIEWER_TOP': 'ENDORSE (srv:abcdef00, sha256:' + H2 + ') by:reviewer:top',
    'ENDORSE_UNAUTHORIZED': 'ENDORSE (srv:abcdef00, sha256:' + H2 + ') by:user:x',
    'ENDORSE_SHORT': 'ENDORSE (user:g, sha256:' + H + ') by:reviewer',
}

DIRECT_FS_READ = (
    'DIRECT cap:' + H + ' (scope=fs.read, exp=60, from=user:g) '
    'call tool:(srv:abcdef00, sha256:' + H2 + ') {path: "/logs"}'
)
DIRECT_DENIED_EXPIRED = (
    'DIRECT cap:' + H + ' (scope=fs.read, exp=0, from=user:g) '
    'call tool:(srv:abcdef00, sha256:' + H2 + ') {path: "/logs"}'
)
DIRECT_FS_WRITE = (
    'DIRECT cap:' + H + ' (scope=fs.write, exp=60, from=user:a) '
    'call tool:(srv:abcdef00, sha256:' + H2 + ') {path: "/etc/passwd"}'
)


class TestConformance(unittest.TestCase):
    """Core conformance tests."""

    def test_all_7_acts_parse(self):
        progs = [PROGS['ASSERT_LOW'], PROGS['ASSERT_HIGH'], PROGS['QUERY_SIMPLE'],
                 PROGS['DIRECT_ALLOW'], PROGS['COMMIT_SIMPLE'], PROGS['GRANT_SIMPLE'],
                 PROGS['REVOKE_SIMPLE'], PROGS['ENDORSE_ADMIN'], PROGS['ENDORSE_REVIEWER_TOP'],
                 PROGS['ENDORSE_UNAUTHORIZED'], PROGS['ENDORSE_SHORT']]
        for src in progs:
            with self.subTest(name=src.split()[0]):
                acts = parse(src)
                self.assertEqual(len(acts), 1, f"{src.split()[0]}: expected 1 act, got {len(acts)}")

    def test_python_gate_all_acts(self):
        gate = Gate()
        allowed = [PROGS['ASSERT_LOW'], PROGS['ASSERT_HIGH'], PROGS['QUERY_SIMPLE'],
                   PROGS['DIRECT_ALLOW'], PROGS['COMMIT_SIMPLE'], PROGS['GRANT_SIMPLE'],
                   PROGS['REVOKE_SIMPLE'], PROGS['ENDORSE_ADMIN'],
                   PROGS['ENDORSE_REVIEWER_TOP'], PROGS['ENDORSE_SHORT']]
        for src in allowed:
            actions = parse(src)
            self.assertEqual(len(actions), 1, f"expected 1 act in {src!r}")
            gate.execute(actions[0])
            self.assertEqual(
                gate.audit[-1]['status'], 'ALLOW',
                f"expected ALLOW for {src!r}, audit entry: {gate.audit[-1]}",
            )
        with self.assertRaises(GateError) as ctx:
            gate.execute(parse(PROGS['ENDORSE_UNAUTHORIZED'])[0])
        self.assertEqual(ctx.exception.code, 'ENDORSE.UNAUTHORIZED')
        self.assertEqual(gate.audit[-1]['status'], 'DENY')
        self.assertTrue(
            gate.audit[-1].get('error', '').startswith('ENDORSE.UNAUTHORIZED'),
            f"audit must record ENDORSE.UNAUTHORIZED, got {gate.audit[-1]}",
        )

    def test_expiry_denies_expired_direct(self):
        gate = Gate()
        acts = parse(DIRECT_DENIED_EXPIRED)
        for act in acts:
            with self.assertRaises(GateError) as ctx:
                gate.execute(act)
            self.assertEqual(ctx.exception.code, 'EXPIRY.INVALID')

    def test_integrity_direct_low_denied_critical(self):
        """Rule 2 asserts a behavioral outcome, not an accepted-either one.

        A low-integrity runtime label admits a low-integrity DIRECT but is
        denied by a critical-integrity capability with
        INTEGRITY.DIRECT.DENIED. The capability barrier is constructed
        directly because the parser cannot express integrity_level.
        """
        cap_low = Capability(cap_hash=H, scope='fs.read', exp=60,
                             from_principal=Principal(id='user:g', hash=''),
                             integrity_level='low')
        cap_critical = Capability(cap_hash=H, scope='fs.read', exp=60,
                                  from_principal=Principal(id='user:g', hash=''),
                                  integrity_level='critical')
        call = ToolCall(
            tool=Reference(principal=Principal(id='srv:abcdef00', hash=''),
                           content_hash=H2),
            params={'path': '/logs'},
        )
        gate = Gate()
        gate.execute(DirectAct(capability=cap_low, call=call))
        self.assertEqual(gate.audit[-1]['status'], 'ALLOW')

        gate = Gate()
        with self.assertRaises(GateError) as ctx:
            gate.execute(DirectAct(capability=cap_critical, call=call))
        self.assertEqual(ctx.exception.code, 'INTEGRITY.DIRECT.DENIED')
        self.assertEqual(gate.audit[-1]['status'], 'DENY')
        self.assertTrue(gate.audit[-1].get('error', '').startswith('INTEGRITY.DIRECT.DENIED'))

    def test_endorse_authorization(self):
        gate = Gate()
        # admin should be allowed
        acts = parse(PROGS['ENDORSE_ADMIN'])
        for act in acts:
            result = gate.execute(act)
            self.assertTrue(result, f"ENDORSE by:admin should be ALLOW, got DENY")
        # reviewer:top should be allowed
        acts = parse(PROGS['ENDORSE_REVIEWER_TOP'])
        for act in acts:
            result = gate.execute(act)
            self.assertTrue(result, f"ENDORSE by:reviewer:top should be ALLOW, got DENY")
        # user:x should be denied
        acts = parse(PROGS['ENDORSE_UNAUTHORIZED'])
        for act in acts:
            with self.assertRaises(GateError) as ctx:
                gate.execute(act)
            self.assertEqual(ctx.exception.code, 'ENDORSE.UNAUTHORIZED')
        # reviewer alone (OR rule: 'reviewer'.startswith('reviewer')) is allowed
        acts = parse(PROGS['ENDORSE_SHORT'])
        for act in acts:
            result = gate.execute(act)
            self.assertTrue(result, f"ENDORSE by:reviewer alone should be ALLOWED, got DENY")


class TestLabels(unittest.TestCase):
    """Label lattice and provenance tests."""

    def test_lattice_join_integrity(self):
        """I3: every shared pair preserves lowest influencing integrity."""
        import json
        from pathlib import Path
        vectors = json.loads(Path(__file__).with_name('label_vectors.json').read_text())
        for i, left in enumerate(vectors['order']):
            for j, right in enumerate(vectors['order']):
                with self.subTest(left=left, right=right):
                    a = Label(provenance=('a',), integrity=left, confidentiality='secret')
                    b = Label(provenance=('b',), integrity=right, confidentiality='public')
                    result = a.join(b)
                    self.assertEqual(result.integrity, vectors['expected'][i][j])
                    self.assertEqual(result, b.join(a))
                    self.assertEqual(result.confidentiality, 'secret')
                    self.assertEqual(result.provenance, ('a', 'b'))

    def test_label_assigned_on_execute(self):
        gate = Gate()
        acts = parse(PROGS['ASSERT_LOW'])
        gate.execute(acts[0])
        self.assertIsNotNone(gate.label_of(acts[0]))


class TestParserEdgeCases(unittest.TestCase):
    """Parser edge cases and short principal IDs."""

    def test_short_principal_hash(self):
        src = 'DIRECT cap:' + H + ' (scope=fs.read, exp=60, from=user:9c1e) call tool:(srv:abcdef00, sha256:' + H2 + ') {path: "/logs"}'
        acts = parse(src)
        self.assertEqual(len(acts), 1)

    def test_dotted_scope(self):
        src = 'GRANT cap:' + H + ' (scope=fs.read.write, exp=60, from=user:g)'
        acts = parse(src)
        self.assertEqual(len(acts), 1)

    def test_comment_ignored(self):
        # Comments are skipped; a full act on each line parses to 2 acts.
        src = ("ASSERT ev:(user:g, sha256:" + H + ") data:<opaque, a> # note\n"
               "QUERY ev:(user:g, sha256:" + H + ") data:<opaque, b>")
        acts = parse(src)
        self.assertEqual(len(acts), 2)


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestConformance))
    suite.addTests(loader.loadTestsFromTestCase(TestLabels))
    suite.addTests(loader.loadTestsFromTestCase(TestParserEdgeCases))
    return suite


if __name__ == '__main__':
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite())
    # A conformance runner that exits 0 on failure is a false green gate.
    sys.exit(0 if result.wasSuccessful() else 1)
