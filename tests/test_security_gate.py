"""I1/I3/I4/I6/I7/I8: semantic gate decisions over signed authority evidence.

Keys are generated in memory for each test. The shared fixture contains only
public TEST ONLY data, never production keys or externally issued evidence.
"""

from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import unittest

from nacl.signing import SigningKey

from gate.authority import Authority, AuthorityError, DOMAIN, Envelope, TrustKey, decode_claims
from gate.security import SecurityError, SecurityGate
from lang.limits import MAX_AUDIT_RECORDS, MAX_AUTHORITY_BYTES, MAX_SECURITY_RECORDS


class TestSecurityGate(unittest.TestCase):
    def setUp(self):
        self.key = SigningKey.generate()
        self.trust = TrustKey(self.key.verify_key.encode(),
                              frozenset(('grant', 'endorse', 'revoke')),
                              frozenset(('fs.read',)), 'critical')
        self.gate = SecurityGate('session:alice', {'issuer': self.trust})
        self.source = ('DIRECT cap:' + 'a' * 64
                       + ' (scope=fs.read, exp=60, from=issuer) call tool:(srv:files, sha256:'
                       + 'b' * 64 + ') {path: "/logs"}')
        self.base = dict(version=1, kind='grant', issuer='issuer', subject='session:alice',
                         capability='a' * 64, scope='fs.read', tool_principal='srv:files',
                         tool_hash='b' * 64, integrity='high', action_hash='',
                         issued_at=100, expires_at=200, nonce='1' * 64)

    def raw(self, payload):
        return Envelope(payload, self.key.sign(DOMAIN + payload).signature)

    def signed(self, **changes):
        return self.raw(json.dumps(dict(self.base, **changes), sort_keys=True,
                                   separators=(',', ':')).encode())

    def deny(self, code, operation, *args):
        with self.assertRaises(SecurityError) as caught:
            operation(*args)
        self.assertEqual(caught.exception.code, code)

    def grant(self, **changes):
        self.gate.apply(self.signed(**changes), 110)

    def endorse(self, **changes):
        claims = dict(kind='endorse', nonce='2' * 64,
                      action_hash=sha256(self.source.encode()).hexdigest())
        claims.update(changes)
        self.gate.apply(self.signed(**claims), 110)

    def test_grant_endorse_one_use_revoke_lifecycle(self):
        self.deny('AUTH.REQUIRED', self.gate.execute, self.source, 110)
        self.grant()
        self.deny('INTEGRITY.DENIED', self.gate.execute, self.source, 110)
        self.endorse()
        self.gate.execute(self.source, 110)
        self.assertEqual(self.gate.integrity, 'low')
        self.deny('INTEGRITY.DENIED', self.gate.execute, self.source, 110)
        self.gate.apply(self.signed(kind='revoke', nonce='3' * 64), 110)
        self.deny('AUTH.REVOKED', self.gate.execute, self.source, 110)
        self.deny('AUTH.REVOKED', self.gate.apply, self.signed(nonce='4' * 64), 110)

    def test_tampering_unknown_keys_and_forged_signatures(self):
        envelope = self.signed()
        for forged in (replace(envelope, signature=bytes(64)),
                       replace(envelope, payload=envelope.payload.replace(b'fs.read', b'fs.exec')),
                       replace(envelope, signature=envelope.signature[:-1])):
            self.deny('AUTH.INVALID', self.gate.apply, forged, 110)
        empty = SecurityGate('session:alice', {})
        self.deny('AUTH.INVALID', empty.apply, envelope, 110)
        self.assertFalse(self.gate._grants)
        self.grant()  # Failed signatures did not consume the nonce.

    def test_exact_issuer_subject_roles_scopes_and_ceiling(self):
        for changed in (dict(issuer='issuer_extra'), dict(scope='fs.read.extra')):
            self.deny('AUTH.INVALID', self.gate.apply, self.signed(**changed), 110)
        self.deny('AUTH.MISMATCH', self.gate.apply, self.signed(subject='session:bob'), 110)
        for trust in (replace(self.trust, kinds=frozenset(('endorse',))),
                      replace(self.trust, max_integrity='low')):
            gate = SecurityGate('session:alice', {'issuer': trust})
            self.deny('AUTH.INVALID', gate.apply, self.signed(), 110)

    def test_duplicate_unknown_and_wrong_type_claims(self):
        good = json.dumps(self.base)
        raws = [(good[:-1] + ',"nonce":"' + '9' * 64 + '"}').encode(),
                (good[:-1] + ',"unexpected":1}').encode(), b'[]']
        for key, value in [('version', True), ('version', 1.0), ('issued_at', False),
                           ('issued_at', -1), ('expires_at', 2**63),
                           ('expires_at', '200'), ('subject', None), ('scope', []),
                           ('capability', 'a'*63), ('nonce', 'A'*64),
                           ('action_hash', 'a'*64), ('kind', 'unknown'),
                           ('subject', '\ud800')]:
            raws.append(json.dumps(dict(self.base, **{key: value})).encode())
        for raw in raws:
            with self.subTest(raw_length=len(raw)):
                self.deny('AUTH.INVALID', self.gate.apply, self.raw(raw), 110)
        self.assertFalse(self.gate._grants)

    def test_authority_size_and_signature_domain(self):
        self.deny('AUTH.INVALID', self.gate.apply,
                  self.raw(b' ' * (MAX_AUTHORITY_BYTES + 1)), 110)
        envelope = self.signed()
        wrong_domain = Envelope(envelope.payload, self.key.sign(envelope.payload).signature)
        self.deny('AUTH.INVALID', self.gate.apply, wrong_domain, 110)

    def test_expiry_future_issuance_and_clock_rollback(self):
        self.deny('AUTH.EXPIRED', self.gate.apply, self.signed(), 99)
        self.grant(integrity='low')
        self.gate.execute(self.source, 199)
        self.deny('AUTH.EXPIRED', self.gate.execute, self.source, 200)
        self.deny('TIME.INVALID', self.gate.execute, self.source, 199)
        for value in (True, -1, 2**63, 1.5, None):
            self.deny('TIME.INVALID', self.gate.execute, self.source, value)

    def test_replay_duplicate_capability_and_failed_apply_atomicity(self):
        self.grant()
        self.deny('AUTH.REPLAY', self.gate.apply, self.signed(), 110)
        self.deny('AUTH.REPLAY', self.gate.apply, self.signed(nonce='2'*64), 110)
        # A rejected duplicate ID must not consume the otherwise valid nonce.
        self.gate.apply(self.signed(capability='c'*64, nonce='2'*64), 110)

    def test_exact_action_binding_and_expired_approval(self):
        self.grant()
        self.endorse(expires_at=120)
        for source in (self.source.replace('/logs', '/private'), self.source + '\n'):
            self.deny('INTEGRITY.DENIED', self.gate.execute, source, 110)
        self.gate.execute(self.source, 110)  # Failed matches did not consume approval.
        self.endorse(nonce='3'*64, expires_at=120)
        self.deny('INTEGRITY.DENIED', self.gate.execute, self.source, 120)

    def test_direct_metadata_and_ttl_bound_to_grant(self):
        self.grant(integrity='low')
        for old, new in [('fs.read', 'fs.write'), ('from=issuer', 'from=other'),
                         ('srv:files', 'srv:other'), ('b'*64, 'c'*64),
                         ('exp=60', 'exp=101')]:
            self.deny('AUTH.MISMATCH', self.gate.execute, self.source.replace(old, new), 110)
        self.gate.execute(self.source.replace('exp=60', 'exp=100'), 199)

    def test_endorsement_metadata_and_authorized_revoke_owner(self):
        second_key = SigningKey.generate()
        second_trust = replace(self.trust, public_key=second_key.verify_key.encode())
        self.gate = SecurityGate('session:alice', {'issuer': self.trust, 'other': second_trust})
        self.grant()
        for change in (dict(tool_hash='c'*64), dict(integrity='critical'), dict(expires_at=201)):
            self.deny('AUTH.MISMATCH', self.gate.apply,
                      self.signed(kind='endorse', action_hash='d'*64, nonce='2'*64, **change), 110)
        values = dict(self.base, kind='revoke', issuer='other', nonce='2'*64)
        payload = json.dumps(values).encode()
        self.deny('AUTH.MISMATCH', self.gate.apply,
                  Envelope(payload, second_key.sign(DOMAIN+payload).signature), 110)
        self.assertFalse(self.gate._revoked)

    def test_revoke_removes_approval_and_cannot_be_undone(self):
        self.grant()
        self.endorse()
        self.gate.apply(self.signed(kind='revoke', nonce='3'*64), 110)
        self.assertFalse(self.gate._approvals)
        self.deny('AUTH.REVOKED', self.gate.apply,
                  self.signed(kind='endorse', nonce='4'*64, action_hash='d'*64), 110)

    def test_runtime_observation_only_lowers_integrity(self):
        self.gate = SecurityGate('session:alice', {'issuer': self.trust}, 'high')
        self.grant()
        self.gate.execute(self.source, 110)
        self.gate.observe('low')
        self.gate.observe('critical')
        self.assertEqual(self.gate.integrity, 'low')
        self.deny('INTEGRITY.DENIED', self.gate.execute, self.source, 110)

    def test_assert_query_lower_integrity_commit_does_not(self):
        for keyword in ('ASSERT', 'QUERY'):
            gate = SecurityGate('session:alice', {}, 'high')
            gate.execute(f'{keyword} ev:(user:g, sha256:{"b"*64}) data:<untrusted>', 110)
            self.assertEqual(gate.integrity, 'low')
        gate = SecurityGate('session:alice', {}, 'high')
        gate.execute(f'COMMIT (user:g, sha256:{"b"*64})', 110)
        self.assertEqual(gate.integrity, 'high')

    def test_model_cannot_issue_authority_or_use_anonymous_reference(self):
        cap = 'cap:'+'a'*64+' (scope=fs.read, exp=60, from=issuer)'
        for source in ('GRANT '+cap, 'REVOKE '+cap,
                       f'ENDORSE (srv:files, sha256:{"b"*64}) by:admin'):
            self.deny('AUTH.REQUIRED', self.gate.execute, source, 110)
        for source in (self.source+'\n'+self.source, '',
                       f'COMMIT (anon, sha256:{"b"*64})',
                       'COMMIT (user:g, sha256:aaaaaaaa)'):
            self.deny('ACT.INVALID', self.gate.execute, source, 110)

    def test_nonce_capacity_fails_closed_without_eviction(self):
        self.gate = SecurityGate('session:alice', {'issuer': self.trust}, 'high')
        self.grant()
        for index in range(MAX_SECURITY_RECORDS - 1):
            self.endorse(nonce=f'{index+2:064x}')
        self.deny('AUTH.REPLAY', self.gate.apply, self.signed(), 110)
        self.gate.execute(self.source, 110)
        self.deny('AUTH.CAPACITY', self.gate.apply,
                  self.signed(kind='revoke', nonce='f'*64), 110)
        self.assertFalse(self.gate._revoked)
        self.deny('AUTH.CAPACITY', self.gate.execute, self.source, 110)
        self.deny('AUTH.CAPACITY', self.gate.apply, self.signed(), 110)
        self.gate.execute(f'COMMIT (user:g, sha256:{"b"*64})', 110)

    def test_sanitized_bounded_audit(self):
        marker = 'SYNTHETIC_PRIVATE_PAYLOAD'
        for _ in range(MAX_AUDIT_RECORDS + 3):
            self.deny('ACT.INVALID', self.gate.execute, marker, 110)
        self.assertEqual(len(self.gate.audit), MAX_AUDIT_RECORDS)
        self.assertNotIn(marker, repr(self.gate.audit))
        self.assertTrue(all(entry['status']=='DENY' for entry in self.gate.audit))

    def test_ephemeral_authority_utility(self):
        authority = Authority()
        trust = replace(self.trust, public_key=authority.public_key)
        gate = SecurityGate('session:alice', {'issuer': trust})
        envelope = authority.sign(self.base)
        gate.apply(envelope, 110)
        self.assertNotIn('payload', repr(envelope))
        self.assertEqual(decode_claims(envelope.payload).issuer, 'issuer')

    def test_shared_public_interoperability_vector(self):
        fixture = json.loads((Path(__file__).parents[1]/'conformance/security_vectors.json').read_text())
        self._verify_fixture_lifecycle(fixture)

    def _verify_fixture_lifecycle(self, fixture):
        trust = replace(self.trust, public_key=bytes.fromhex(fixture['public_key_hex']))
        gate = SecurityGate(fixture['subject'], {fixture['issuer']: trust})
        def envelope(kind):
            value = fixture[kind]
            return Envelope(value['payload_utf8'].encode(), bytes.fromhex(value['signature_hex']))
        gate.apply(envelope('grant'), fixture['now'])
        self.deny('INTEGRITY.DENIED', gate.execute, fixture['source'], fixture['now'])
        gate.apply(envelope('endorse'), fixture['now'])
        gate.execute(fixture['source'], fixture['now'])
        gate.apply(envelope('revoke'), fixture['now'])
        self.deny('AUTH.REVOKED', gate.execute, fixture['source'], fixture['now'])

    def test_rust_issued_ephemeral_statements_verify_in_python(self):
        root = Path(__file__).parents[1]
        result = subprocess.run(
            ['cargo', 'run', '--locked', '--quiet', '--manifest-path',
             str(root/'rust/Cargo.toml'), '--example', 'authority_interop'],
            cwd=root, capture_output=True, text=True, timeout=60, check=True)
        self._verify_fixture_lifecycle(json.loads(result.stdout))

    def test_weak_points_cannot_be_trusted_or_used_as_signature_r(self):
        """I7: strict vetted point validation rejects identity-key forgery."""
        identity = b'\x01' + bytes(31)
        for public in (identity, bytes(32)):
            with self.assertRaises(AuthorityError):
                replace(self.trust, public_key=public)
        envelope = replace(self.signed(), signature=identity + bytes(32))
        self.deny('AUTH.INVALID', self.gate.apply, envelope, 110)

    def test_signed_critical_scope_requires_real_approval(self):
        scope = 'critical.files'
        trust = replace(self.trust, scopes=frozenset((scope,)))
        self.gate = SecurityGate('session:alice', {'issuer': trust})
        self.source = self.source.replace('fs.read', scope)
        self.base.update(scope=scope, integrity='critical')
        self.grant()
        self.deny('INTEGRITY.DENIED', self.gate.execute, self.source, 110)
        self.endorse()
        self.gate.execute(self.source, 110)

    def test_trusted_configuration_is_explicit_typed_and_bounded(self):
        for subject in ('', '\ud800', 's'*(MAX_AUTHORITY_BYTES+1), None):
            with self.assertRaises(SecurityError):
                SecurityGate(subject, {})
        for keys in (None, {'': self.trust}, {'\ud800': self.trust}, {'issuer': None},
                     {str(i): self.trust for i in range(MAX_SECURITY_RECORDS+1)}):
            with self.assertRaises(SecurityError):
                SecurityGate('session:alice', keys)
        for scopes in (frozenset(('*',)), frozenset(('bad scope',)),
                       frozenset(('s'*(MAX_AUTHORITY_BYTES+1),)),
                       frozenset(str(i) for i in range(MAX_SECURITY_RECORDS+1))):
            with self.assertRaises(AuthorityError):
                replace(self.trust, scopes=scopes)


if __name__ == '__main__':
    unittest.main()
