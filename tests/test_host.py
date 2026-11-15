"""I1/I3/I4/I6/I7/I8: actual local side effects behind the signed gate."""
from dataclasses import FrozenInstanceError, replace
from hashlib import sha256
import threading
import unittest

from gate.authority import Authority, TrustKey
from gate.host import HostError, LabeledInput, LocalHost, ToolRegistration
from lang.labels import Label
from lang.limits import MAX_SECURITY_RECORDS, MAX_SOURCE_BYTES


class TestLocalHost(unittest.TestCase):
    def setUp(self):
        self.authority = Authority()
        self.trust = TrustKey(self.authority.public_key,
                              frozenset(('grant', 'endorse', 'revoke')),
                              frozenset(('fs.read',)), 'critical')
        self.effects = []
        self.tool = ToolRegistration('srv:files', b'local read v1', 'secret', self.callback)
        self.host = self.new_host()
        self.source = self.make_source(self.tool)

    def callback(self, params):
        self.effects.append(params)
        return 'result'

    def new_host(self, **changes):
        config = dict(model_clearance='secret', clock=lambda: 110)
        config.update(changes)
        return LocalHost({'issuer': self.trust}, [self.tool], **config)

    def make_source(self, tool):
        return ('DIRECT cap:' + 'a'*64 + ' (scope=fs.read, exp=60, from=issuer) '
                'call tool:(srv:files, sha256:' + tool.content_hash + ') {path: "/logs", count: 1}')

    def statement(self, kind='grant', **changes):
        values = dict(version=1, kind=kind, issuer='issuer', subject=self.host.subject,
                      capability='a'*64, scope='fs.read', tool_principal=self.tool.principal,
                      tool_hash=self.tool.content_hash, integrity='high',
                      action_hash=sha256(self.source.encode()).hexdigest() if kind=='endorse' else '',
                      issued_at=100, expires_at=200,
                      nonce={'grant':'1','endorse':'2','revoke':'3'}[kind]*64)
        values.update(changes)
        return self.authority.sign(values)

    def deny(self, code, call, *args):
        before = len(self.effects)
        with self.assertRaises(HostError) as caught:
            call(*args)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(len(self.effects), before)

    def run_source(self, inputs=()):
        return self.host.run(inputs, lambda _: self.source)

    def test_actual_dispatch_requires_grant_and_exact_one_use_approval(self):
        self.deny('AUTH.REQUIRED', self.run_source)
        self.host.apply(self.statement())
        self.deny('INTEGRITY.DENIED', self.run_source)
        self.host.apply(self.statement('endorse'))
        result = self.run_source()
        self.assertEqual(self.effects, [{'path':'/logs', 'count':1}])
        self.assertEqual(result.text, 'result')
        self.assertEqual(result.label.integrity, 'low')
        self.deny('INTEGRITY.DENIED', self.run_source)
        self.host.apply(self.statement('revoke'))
        self.deny('AUTH.REVOKED', self.run_source)

    def test_confidentiality_checks_complete_batch_before_model_disclosure(self):
        self.host = self.new_host(model_clearance='public')
        seen = []
        batch = [LabeledInput('safe'), LabeledInput('PRIVATE', Label(confidentiality='secret'))]
        self.deny('HOST.CLEARANCE', self.host.run, batch, lambda items: seen.extend(items))
        self.assertEqual(seen, [])
        self.assertEqual(self.host.label, Label())
        self.assertNotIn('PRIVATE', repr(self.host.audit))

    def test_tool_clearance_denies_without_effect_after_model_clearance_passes(self):
        self.tool = replace(self.tool, clearance='public')
        self.host = self.new_host()
        self.host.apply(self.statement())
        self.host.apply(self.statement('endorse'))
        secret = LabeledInput('private', Label(('vault',), 'low', 'secret'))
        self.deny('HOST.CLEARANCE', self.run_source, [secret])

    def test_taint_provenance_and_output_confidentiality_accumulate(self):
        self.host = self.new_host(initial_integrity='high')
        self.host.apply(self.statement())
        low = LabeledInput('untrusted', Label(('web',), 'low', 'secret'))
        self.deny('INTEGRITY.DENIED', self.run_source, [low])
        self.assertEqual(self.host.label.integrity, 'low')
        self.host.apply(self.statement('endorse'))
        result = self.run_source([LabeledInput('trusted', Label(('user',), 'high'))])
        self.assertEqual(result.label, Label(('srv:files', 'user', 'web'), 'low', 'secret'))

    def test_changed_definition_and_unregistered_tool_never_dispatch(self):
        changed = replace(self.tool, definition=b'local read v2')
        self.assertNotEqual(changed.content_hash, self.tool.content_hash)
        self.tool = changed
        self.host = self.new_host()
        old_hash = sha256(b'local read v1').hexdigest()
        self.host.apply(self.statement(tool_hash=old_hash))
        self.host.apply(self.statement('endorse', tool_hash=old_hash))
        self.deny('HOST.TOOL', self.run_source)
        with self.assertRaises(FrozenInstanceError):
            self.tool.clearance = 'public'

    def test_tool_output_clearance_and_provenance_checked_before_dispatch(self):
        self.host = self.new_host(model_clearance='public')
        self.host.apply(self.statement())
        self.host.apply(self.statement('endorse'))
        self.deny('HOST.CLEARANCE', self.run_source)
        self.tool = replace(self.tool, output_confidentiality='public')
        self.host = self.new_host(model_clearance='public')
        self.host.apply(self.statement())
        self.host.apply(self.statement('endorse'))
        result = self.run_source()
        self.assertEqual(result.label, Label(('srv:files',), 'low', 'public'))
        self.host = self.new_host()
        self.host.apply(self.statement())
        self.host.apply(self.statement('endorse'))
        provenance = tuple(str(i) for i in range(MAX_SECURITY_RECORDS))
        self.deny('HOST.LIMIT', self.run_source, [LabeledInput('', Label(provenance))])

    def test_fresh_sessions_reject_old_signed_state(self):
        old = self.statement()
        previous = self.host.subject
        self.host = self.new_host()
        self.assertNotEqual(previous, self.host.subject)
        self.deny('AUTH.MISMATCH', self.host.apply, old)
        self.deny('AUTH.REQUIRED', self.run_source)

    def test_reentrant_model_and_callback_operations_refuse(self):
        def model(_):
            self.deny('HOST.REENTRANT', self.host.apply, self.statement())
            return self.source
        self.deny('AUTH.REQUIRED', self.host.run, [], model)
        def callback(params):
            self.deny('HOST.REENTRANT', self.host.run, [], model)
            return 'result'
        self.tool = replace(self.tool, callback=callback)
        self.host = self.new_host()
        self.host.apply(self.statement())
        self.host.apply(self.statement('endorse'))
        self.run_source()

    def test_malformed_or_excessive_batch_never_reaches_model(self):
        seen = []
        for batch in ([LabeledInput('x'*(MAX_SOURCE_BYTES+1))],
                      [LabeledInput('x')]*(MAX_SECURITY_RECORDS+1),
                      [LabeledInput('ok'), None],
                      [LabeledInput('x', Label(('x'*(MAX_SOURCE_BYTES+1),)))],
                      [LabeledInput('x', Label((None,)))],
                      [LabeledInput('\ud800')]):
            with self.assertRaises(HostError):
                self.host.run(batch, lambda values: seen.extend(values))
        self.assertEqual(seen, [])
        self.assertEqual(self.effects, [])

    def test_model_and_tool_failure_sanitized_and_approval_not_restored(self):
        def bad(_):
            raise RuntimeError('PRIVATE_MARKER')
        self.deny('HOST.FAILED', self.host.run, [], bad)
        self.tool = replace(self.tool, callback=bad)
        self.host = self.new_host()
        self.host.apply(self.statement())
        self.host.apply(self.statement('endorse'))
        self.deny('HOST.FAILED', self.run_source)
        self.deny('INTEGRITY.DENIED', self.run_source)
        self.assertNotIn('PRIVATE_MARKER', repr(self.host.audit))

    def test_non_direct_has_no_callback_effects_and_bad_registry_rejected(self):
        result = self.host.run([], lambda _: 'COMMIT (user:g, sha256:'+'b'*64+')')
        self.assertIsNone(result)
        self.assertEqual(self.effects, [])
        with self.assertRaises(HostError):
            LocalHost({}, [self.tool, self.tool], model_clearance='public')

    def test_concurrent_revocation_refuses_busy_then_succeeds_after_dispatch(self):
        entered, release = (threading.Event() for _ in range(2))
        failures = []
        def callback(params):
            entered.set()
            if not release.wait(3):
                raise RuntimeError('test deadline')
            return 'done'
        self.tool = replace(self.tool, callback=callback)
        self.host = self.new_host()
        self.host.apply(self.statement())
        self.host.apply(self.statement('endorse'))
        def dispatch():
            try:
                self.run_source()
            except Exception as error:
                failures.append(error)
        worker = threading.Thread(target=dispatch)
        worker.start()
        try:
            self.assertTrue(entered.wait(3))
            self.deny('HOST.BUSY', self.host.apply, self.statement('revoke'))
        finally:
            release.set()
            worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertFalse(failures)
        self.host.apply(self.statement('revoke'))
        self.deny('AUTH.REVOKED', self.run_source)

    def test_cross_thread_callback_reentry_refuses_without_deadlock(self):
        errors = []
        def reenter():
            try:
                self.run_source()
            except HostError as error:
                errors.append(error.code)
        def callback(params):
            worker = threading.Thread(target=reenter, daemon=True)
            worker.start()
            worker.join(1)
            if worker.is_alive():
                raise RuntimeError('cross-thread reentry blocked')
            return 'done'
        self.tool = replace(self.tool, callback=callback)
        self.host = self.new_host()
        self.host.apply(self.statement())
        self.host.apply(self.statement('endorse'))
        result = self.run_source()
        self.assertEqual(result.text, 'done')
        self.assertEqual(errors, ['HOST.BUSY'])

    def test_bounded_tool_output_and_cumulative_provenance(self):
        self.tool = replace(self.tool, callback=lambda _: 'x'*(MAX_SOURCE_BYTES+1))
        self.host = self.new_host()
        self.host.apply(self.statement())
        self.host.apply(self.statement('endorse'))
        self.deny('HOST.LIMIT', self.run_source)
        self.deny('INTEGRITY.DENIED', self.run_source)
        self.host = self.new_host()
        commit = lambda _: 'COMMIT (user:g, sha256:'+'b'*64+')'
        provenance = tuple(str(i) for i in range(MAX_SECURITY_RECORDS))
        self.host.run([LabeledInput('', Label(provenance))], commit)
        seen = []
        self.deny('HOST.LIMIT', self.host.run, [LabeledInput('', Label(('new',)))],
                  lambda values: seen.extend(values))
        self.assertEqual(seen, [])


if __name__ == '__main__':
    unittest.main()
