"""I1/I3/I4/I7: encrypted custody and fresh-subject trust rotation."""

from hashlib import sha256
import secrets
import threading
import unittest
from unittest.mock import patch

from nacl.secret import SecretBox

from gate.authority import Authority, TrustKey
from gate.host import HostError, LabeledInput, LocalHost, ToolRegistration
from gate.keystore import KeyStoreError, encrypt_key
from lang.labels import Label


class TestKeyStore(unittest.TestCase):
    def test_direct_encrypt_rejects_non_key_with_fixed_error(self):
        for value in (None, object(), b'PRIVATE_MARKER', 'PRIVATE_MARKER'):
            with self.assertRaises(KeyStoreError) as caught:
                encrypt_key(value, secrets.token_bytes(32))
            self.assertEqual(str(caught.exception), 'Invalid encrypted authority key')

    def test_restoration_preserves_identity_without_plaintext_export(self):
        authority = Authority()
        wrapping = secrets.token_bytes(32)
        blob = authority.export_encrypted(wrapping)
        restored = Authority.load_encrypted(blob, wrapping)
        self.assertEqual(restored.public_key, authority.public_key)
        # Inspect internally only to prove plaintext is absent; never print it.
        self.assertTrue(authority._key.encode() not in blob)
        self.assertTrue(authority._key.encode().hex() not in repr(authority))
        self.assertNotEqual(blob, authority.export_encrypted(wrapping))

    def test_tampering_wrong_key_and_malformed_blobs_refuse(self):
        wrapping = secrets.token_bytes(32)
        blob = Authority().export_encrypted(wrapping)
        cases = [b'', blob[:-1], blob+b'x', b'X'+blob[1:],
                 blob[:-1]+bytes([blob[-1] ^ 1]), None, 'not bytes']
        for malformed in cases:
            with self.subTest(case_type=type(malformed).__name__):
                with self.assertRaises(KeyStoreError) as caught:
                    Authority.load_encrypted(malformed, wrapping)
                self.assertEqual(str(caught.exception), 'Invalid encrypted authority key')
        with self.assertRaises(KeyStoreError):
            Authority.load_encrypted(blob, secrets.token_bytes(32))

    def test_wrapping_key_exact_type_and_length(self):
        authority = Authority()
        blob = authority.export_encrypted(secrets.token_bytes(32))
        for malformed in (None, 'x'*32, b'x'*31, b'x'*33, bytearray(32)):
            with self.assertRaises(KeyStoreError):
                authority.export_encrypted(malformed)
            with self.assertRaises(KeyStoreError):
                Authority.load_encrypted(blob, malformed)

    def test_authenticated_inner_version_must_match_outer_version(self):
        wrapping = secrets.token_bytes(32)
        marker = b'TSD-KEYSTORE-v1\x00'
        wrong_inner = b'TSD-KEYSTORE-v2\x00' + secrets.token_bytes(32)
        blob = marker + bytes(SecretBox(wrapping).encrypt(wrong_inner))
        with self.assertRaises(KeyStoreError):
            Authority.load_encrypted(blob, wrapping)


class TestTrustRotation(unittest.TestCase):
    def setUp(self):
        self.authority = Authority()
        self.effects = []
        self.tool = ToolRegistration('srv:files', b'read v1', 'secret', self.callback)
        self.trust = self.policy(self.authority)
        self.host = LocalHost({'issuer': self.trust}, [self.tool],
                              model_clearance='secret', initial_integrity='high', clock=lambda: 110)
        self.source = ('DIRECT cap:'+'a'*64+' (scope=fs.read, exp=60, from=issuer) '
                       'call tool:(srv:files, sha256:'+self.tool.content_hash+') {path: "logs"}')

    def callback(self, params):
        self.effects.append(params)
        return 'ok'

    def policy(self, authority):
        return TrustKey(authority.public_key, frozenset(('grant', 'endorse', 'revoke')),
                        frozenset(('fs.read',)), 'high')

    def statement(self, kind='grant', subject=None):
        return self.authority.sign(dict(
            version=1, kind=kind, issuer='issuer', subject=subject or self.host.subject,
            capability='a'*64, scope='fs.read', tool_principal=self.tool.principal,
            tool_hash=self.tool.content_hash, integrity='high', issued_at=100, expires_at=200,
            action_hash=sha256(self.source.encode()).hexdigest() if kind=='endorse' else '',
            nonce=('1' if kind=='grant' else '2')*64))

    def deny(self, code, function, *args):
        before = len(self.effects)
        with self.assertRaises(HostError) as caught:
            function(*args)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(len(self.effects), before)

    def run_source(self):
        return self.host.run([], lambda _: self.source)

    def test_rotation_retires_grants_approvals_and_preserves_all_labels(self):
        self.host.run([LabeledInput('untrusted', Label(('web',), 'low', 'secret'))],
                      lambda _: 'COMMIT (user:g, sha256:'+'b'*64+')')
        old_subject = self.host.subject
        grant, approval = self.statement(), self.statement('endorse')
        self.host.apply(grant)
        self.host.apply(approval)
        label = self.host.label
        self.host.rotate_trust({'issuer': self.trust})
        self.assertNotEqual(self.host.subject, old_subject)
        self.assertEqual(self.host.label, label)
        self.deny('AUTH.MISMATCH', self.host.apply, grant)
        self.deny('AUTH.MISMATCH', self.host.apply, approval)
        self.deny('AUTH.REQUIRED', self.run_source)
        self.host.apply(self.statement())
        self.deny('INTEGRITY.DENIED', self.run_source)
        self.host.apply(self.statement('endorse'))
        self.run_source()
        self.assertEqual(self.effects, [{'path': 'logs'}])

    def test_restored_and_replaced_authorities_sign_new_session(self):
        wrapping = secrets.token_bytes(32)
        self.authority = Authority.load_encrypted(self.authority.export_encrypted(wrapping), wrapping)
        self.host.apply(self.statement())
        self.run_source()
        old = self.statement()
        self.authority = Authority()
        self.host.rotate_trust({'issuer': self.policy(self.authority)})
        self.deny('AUTH.INVALID', self.host.apply, old)
        self.host.apply(self.statement())
        self.host.apply(self.statement('endorse'))
        self.run_source()

    def test_invalid_rotation_is_atomic_and_empty_trust_is_deny_all(self):
        self.host.apply(self.statement())
        old = self.host.subject
        self.deny('AUTH.INVALID', self.host.rotate_trust, {'issuer': object()})
        self.assertEqual(self.host.subject, old)
        self.run_source()
        self.host.rotate_trust({})
        self.assertNotEqual(self.host.subject, old)
        self.deny('AUTH.INVALID', self.host.apply, self.statement())

    def test_subject_collision_refuses_without_replacing_state(self):
        old = self.host.subject
        with patch('gate.host.secrets.token_hex', return_value=old.split(':', 1)[1]):
            self.deny('HOST.INVALID', self.host.rotate_trust, {'issuer': self.trust})
        self.assertEqual(self.host.subject, old)

    def test_busy_and_reentrant_rotation_do_not_mutate_session(self):
        old = self.host.subject
        failures = []
        def model(_):
            self.deny('HOST.REENTRANT', self.host.rotate_trust, {})
            def concurrent():
                try:
                    self.deny('HOST.BUSY', self.host.rotate_trust, {})
                except Exception as error:
                    failures.append(error)
            worker = threading.Thread(target=concurrent)
            worker.start()
            worker.join(2)
            self.assertFalse(worker.is_alive())
            return 'COMMIT (user:g, sha256:'+'b'*64+')'
        self.host.run([], model)
        self.assertFalse(failures)
        self.assertEqual(self.host.subject, old)


if __name__ == '__main__':
    unittest.main()
