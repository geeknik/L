"""Regression tests for gate label tracking (runtime label_of lookup).

The gate stores runtime labels keyed by ``id(act)`` for O(1) lookup.
``id()`` values are reused by CPython after an object is freed, so a
bare id key can alias a new, unrelated act with a stale label. Each
entry now holds a weak reference to the act so that:

  - a live act retains its label,
  - equal-valued but distinct acts remain separate,
  - a collected act leaves no stale entry behind,
  - a never-executed act returns None, and
  - an id-reused act never inherits a dangling label.
"""

import sys
import os
import gc
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + '/..')

import unittest
import weakref
from lang.ast import (
    Capability, CommitAct, DirectAct, GrantAct, RevokeAct, ToolCall, Reference, Principal,
    AssertAct, QueryAct, EndorseAct, Payload,
)
from lang.labels import Label
from gate.monitor import Gate, GateError

H = '0011223344556677889900112233445566778899001122334455667788990011'
H2 = 'abcdef0000000000000000000000000000000000000000000000000000000000000'

CRITICAL = Label(provenance=('runtime',), integrity='critical', confidentiality='public')


class TestGateLabelTracking(unittest.TestCase):
    """Verify label_of() identity semantics against id() churn."""

    def _make_commit(self, seed=0):
        ref = Reference(
            principal=Principal(id='srv:abcdef00', hash=''),
            content_hash=f'{seed:064x}',
        )
        return CommitAct(reference=ref)

    def _make_direct(self, ttl=60):
        cap = Capability(
            cap_hash=H,
            scope='fs.read',
            exp=ttl,
            from_principal=Principal(id='user:g', hash=''),
            integrity_level='low',
        )
        call = ToolCall(
            tool=Reference(principal=Principal(id='srv:abcdef00', hash=''), content_hash=H2),
            params={'path': '/logs'},
        )
        return DirectAct(capability=cap, call=call)

    def _make_critical_gate(self):
        return Gate(label_assigner=lambda act, incoming: CRITICAL)

    def test_live_act_retains_label(self):
        """A live, executed act must return its runtime-assigned label."""
        g = self._make_critical_gate()
        act = self._make_direct()
        g.execute(act)
        self.assertIs(g.label_of(act), CRITICAL)

    def test_never_executed_act_returns_none(self):
        """An act that was never executed must return None."""
        g = self._make_critical_gate()
        act = self._make_direct()
        self.assertIsNone(g.label_of(act))

    def test_distinct_equal_valued_acts_remain_separate(self):
        """Structurally equal but distinct acts must not share a label entry."""
        g = self._make_critical_gate()
        act1 = self._make_direct()
        act2 = self._make_direct()
        self.assertEqual(act1, act2)
        g.execute(act1)
        self.assertIs(g.label_of(act1), CRITICAL)
        self.assertIsNone(g.label_of(act2))

    def test_collected_act_leaves_no_stale_entry(self):
        """After an act is collected, its entry must be purged."""
        g = self._make_critical_gate()
        act = self._make_direct()
        g.execute(act)
        key = id(act)
        del act
        gc.collect()
        self.assertNotIn(key, g._session_labels)

    def test_id_reuse_does_not_return_stale_label(self):
        """A new act reusing a freed act's id must not inherit the old label.

        Direct reproduction of the reported defect: execute a batch of acts
        with runtime-assigned critical labels, free them, then allocate a
        fresh batch. CPython reuses the freed blocks for the new acts, and
        the suite asserts that every reused id now maps to None instead of
        leaking the previous act's label.
        """
        g = self._make_critical_gate()
        acts = [self._make_commit(i) for i in range(200)]
        for act in acts:
            g.execute(act)
        freed_ids = {id(act) for act in acts}
        del acts
        gc.collect()

        fresh = [self._make_commit(1000 + i) for i in range(200)]
        reused_ids = {id(act) for act in fresh} & freed_ids
        if not reused_ids:
            self.skipTest('No id collision observed; CPython allocator did not reuse blocks')
        for act in fresh:
            if id(act) in reused_ids:
                # The id reused here may belong to some tracked freed act.
                # Since entries are purged on collection, none may leak.
                self.assertIsNone(g.label_of(act))

    def test_stale_entry_purged_on_lookup(self):
        """A stale entry whose weakref points to a foreign object is purged.

        Deterministic regression at the identity-check layer: the entry is
        keyed to the querying act's id but wraps a different live object.
        label_of() must reject it and drop the entry.
        """
        g = self._make_critical_gate()
        act = self._make_direct()
        g.execute(act)

        other = self._make_direct()
        g._session_labels[id(other)] = (weakref.ref(act), CRITICAL)
        self.assertIsNone(g.label_of(other))
        self.assertNotIn(id(other), g._session_labels)


def _make_capability(cap_hash):
    return Capability(
        cap_hash=cap_hash,
        scope='fs.read',
        exp=60,
        from_principal=Principal(id='user:g', hash=''),
        integrity_level='low',
    )


class TestCapabilityHashAtGate(unittest.TestCase):
    """Gate-side cap_hash validation for directly constructed ASTs.

    The parser enforces the capability token, but direct AST callers can
    construct a Capability with an empty or malformed hash. The gate must
    require a non-empty string and raise REFERENCE.INVALID (matching Rust),
    with the audit entry recording DENY.
    """

    def _direct(self, cap_hash):
        call = ToolCall(
            tool=Reference(principal=Principal(id='srv:abcdef00', hash=''), content_hash=H2),
            params={'path': '/logs'},
        )
        return DirectAct(capability=_make_capability(cap_hash), call=call)

    def _grant(self, cap_hash):
        return GrantAct(capability=_make_capability(cap_hash))

    def _revoke(self, cap_hash):
        return RevokeAct(capability=_make_capability(cap_hash))

    def _makers(self):
        return (self._direct, self._grant, self._revoke)

    def _assert_denied(self, act):
        g = Gate()
        with self.assertRaises(GateError) as ctx:
            g.execute(act)
        self.assertEqual(ctx.exception.code, 'REFERENCE.INVALID')
        self.assertTrue(
            any(
                a['status'] == 'DENY' and a.get('error', '').startswith('REFERENCE.INVALID')
                for a in g.audit
            ),
            f"Audit must record DENY with REFERENCE.INVALID, got {g.audit}",
        )

    def test_empty_hash_rejected(self):
        for make in self._makers():
            with self.subTest(act_type=make.__name__):
                self._assert_denied(make(''))

    def test_non_string_hashes_rejected(self):
        """None, booleans, numbers, and containers must be rejected."""
        bad_values = (None, True, False, 1, 1.5, ['x'], {'x': 1}, ('x',))
        for bad in bad_values:
            for make in self._makers():
                with self.subTest(value=repr(bad), act_type=make.__name__):
                    self._assert_denied(make(bad))

    def test_valid_hash_accepted(self):
        for make in self._makers():
            with self.subTest(act_type=make.__name__):
                g = Gate()
                g.execute(make(H))
                self.assertTrue(any(a['status'] == 'ALLOW' for a in g.audit))


class TestStructuralGateBoundary(unittest.TestCase):
    """I4/I7 reject vectors for references and direct-AST containers."""

    def _reference_acts(self, ref):
        return (
            AssertAct(ref, Payload('x')), QueryAct(ref, Payload('x')),
            CommitAct(ref), EndorseAct(ref, Principal('admin', '')),
            DirectAct(_make_capability(H), ToolCall(ref, {})),
        )

    def _denied(self, act, code, gate=None):
        gate = gate if gate is not None else Gate()
        with self.assertRaises(GateError) as ctx:
            gate.execute(act)
        self.assertEqual(ctx.exception.code, code)
        self.assertEqual(gate.audit[-1]['status'], 'DENY')
        self.assertTrue(gate.audit[-1]['error'].startswith(code + ':'))

    def test_reference_fields_and_containers_rejected(self):
        bad_refs = [None, {}, 'reference']
        for bad in (None, '', False, 7, [], {}):
            bad_refs.append(Reference(Principal(bad, ''), H))
            bad_refs.append(Reference(Principal('srv:x', ''), bad))
        for bad in (None, '', {}, object()):
            bad_refs.append(Reference(bad, H))
        for ref in bad_refs:
            for act in self._reference_acts(ref):
                with self.subTest(act=act.act_type, reference_type=type(ref).__name__):
                    self._denied(act, 'REFERENCE.INVALID')

    def test_valid_references_across_all_acts(self):
        for act in self._reference_acts(Reference(Principal('srv:x', ''), H)):
            gate = Gate()
            gate.execute(act)
            self.assertEqual(gate.audit[-1]['status'], 'ALLOW')

    def test_capability_and_issuer_containers_rejected(self):
        for cap in (None, {}, 'capability'):
            for act in (GrantAct(cap), RevokeAct(cap), DirectAct(cap, None)):
                self._denied(act, 'CAPABILITY.INVALID')
        for issuer in (None, {}, 'user:g'):
            cap = Capability(H, 'fs.read', 60, issuer)
            for act in (GrantAct(cap), RevokeAct(cap), DirectAct(cap, None)):
                self._denied(act, 'CAPABILITY.INVALID')

    def test_tool_and_signer_containers_rejected(self):
        for call in (None, {}, 'tool'):
            self._denied(DirectAct(_make_capability(H), call), 'REFERENCE.INVALID')
        ref = Reference(Principal('srv:x', ''), H)
        for signer in (None, {}, 'admin', Principal('', ''), Principal(True, '')):
            self._denied(EndorseAct(ref, signer), 'REFERENCE.INVALID')

    def test_invalid_integrity_requirement_refuses(self):
        ref = Reference(Principal('srv:x', ''), H)
        for level in (None, '', [], 'unknown'):
            cap = Capability(H, 'fs.read', 60, Principal('user:g', ''), level)
            self._denied(DirectAct(cap, ToolCall(ref, {})), 'INTEGRITY.DIRECT.DENIED')

    def test_unknown_non_act_refuses(self):
        for act in (None, {}, object()):
            self._denied(act, 'ACT.UNSUPPORTED')

    def test_label_assignment_failures_deny_without_payload(self):
        """I1/I7: callback failures and invalid results cannot leave ENTER."""
        marker = 'SYNTHETIC_CALLBACK_PAYLOAD'
        def broken(act, incoming):
            raise ValueError(marker)
        act = CommitAct(Reference(Principal('srv:x', ''), H))
        for assigner in (broken, lambda act, incoming: None):
            gate = Gate(label_assigner=assigner)
            self._denied(act, 'LABEL.INVALID', gate)
            self.assertNotIn(marker, repr(gate.audit))
            self.assertIsNone(gate.label_of(act))

    def test_reentrant_assigner_keeps_each_audit_record(self):
        """I1/I7: nested ALLOW must not be overwritten by outer DENY."""
        inner = CommitAct(Reference(Principal('srv:x', ''), H))
        outer = CommitAct(Reference(Principal('', ''), H))
        def assign(act, incoming):
            if act is outer:
                gate.execute(inner, now=0)
            return Label()
        gate = Gate(label_assigner=assign)
        with self.assertRaises(GateError):
            gate.execute(outer, now=0)
        self.assertEqual([entry['status'] for entry in gate.audit], ['DENY', 'ALLOW'])
        self.assertEqual([entry['now'] for entry in gate.audit], [0, 0])

    def test_audit_retains_newest_records_without_payload(self):
        """I6/I7: retention is bounded and denial audit excludes input text."""
        from lang.limits import MAX_AUDIT_RECORDS
        gate = Gate()
        act = CommitAct(Reference(Principal('srv:x', ''), H))
        for now in range(MAX_AUDIT_RECORDS + 3):
            gate.execute(act, now=now)
        self.assertEqual(len(gate.audit), MAX_AUDIT_RECORDS)
        self.assertEqual(gate.audit[0]['now'], 3)
        marker = 'SYNTHETIC_PRIVATE_PRINCIPAL'
        self._denied(EndorseAct(act.reference, Principal(marker, '')),
                     'ENDORSE.UNAUTHORIZED', gate)
        self.assertEqual(len(gate.audit), MAX_AUDIT_RECORDS)
        self.assertNotIn(marker, repr(gate.audit))

    def test_unexpected_failure_gets_sanitized_denial(self):
        """I7: a broken trusted policy cannot leave an ENTER audit entry."""
        gate = Gate(signer_authority={'may_approve_integrity': [None]})
        act = EndorseAct(Reference(Principal('srv:x', ''), H), Principal('admin', ''))
        self._denied(act, 'GATE.INTERNAL', gate)


if __name__ == '__main__':
    unittest.main(verbosity=2)
