"""I6/I7: offline custody refuses unsafe files and never overwrites identities."""

import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from gate.authority import Envelope, TrustKey, verify
from gate.custody import CustodyError, init_authority, load_authority, read_private
from lang.limits import MAX_AUTHORITY_BYTES


class TestCustody(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.blobs = self.root / 'blobs'
        self.wraps = self.root / 'wraps'
        self.blobs.mkdir(mode=0o700)
        self.wraps.mkdir(mode=0o700)
        self.blob = self.blobs / 'authority'
        self.wrap = self.wraps / 'wrapping'

    def test_identity_restore_and_backup(self):
        authority = init_authority(self.blob, self.wrap)
        self.assertEqual(load_authority(self.blob, self.wrap).public_key, authority.public_key)
        backup = self.blobs / 'backup'
        backup.write_bytes(self.blob.read_bytes())
        backup.chmod(0o600)
        self.blob.unlink()
        backup.rename(self.blob)
        self.assertEqual(load_authority(self.blob, self.wrap).public_key, authority.public_key)
        self.assertEqual(self.wrap.stat().st_size, 32)

    def test_collision_preserves_existing_files(self):
        self.wrap.write_bytes(b'preexisting')
        self.wrap.chmod(0o600)
        with self.assertRaises(CustodyError):
            init_authority(self.blob, self.wrap)
        self.assertFalse(self.blob.exists())
        self.assertEqual(self.wrap.read_bytes(), b'preexisting')
        self.blob.write_bytes(b'other existing')
        with self.assertRaises(CustodyError):
            init_authority(self.blob, self.wrap)
        self.assertEqual(self.blob.read_bytes(), b'other existing')

    def test_failure_rolls_back_only_new_files(self):
        with patch('gate.custody.os.write', side_effect=OSError('sensitive text')):
            with self.assertRaises(CustodyError):
                init_authority(self.blob, self.wrap)
        self.assertFalse(self.blob.exists())
        self.assertFalse(self.wrap.exists())

    def test_short_writes_complete(self):
        real_write = os.write
        with patch('gate.custody.os.write', side_effect=lambda fd, data: real_write(fd, data[:3])):
            authority = init_authority(self.blob, self.wrap)
        self.assertEqual(load_authority(self.blob, self.wrap).public_key, authority.public_key)

    def test_zero_write_and_sync_failure_refuse_without_pair(self):
        for operation, replacement in (('write', {'return_value': 0}),
                                       ('fsync', {'side_effect': OSError('sync failed')})):
            with self.subTest(operation=operation):
                with patch('gate.custody.os.' + operation, **replacement):
                    with self.assertRaises(CustodyError):
                        init_authority(self.blob, self.wrap)
                self.assertFalse(self.blob.exists())
                self.assertFalse(self.wrap.exists())

    def test_wrong_owner_refused(self):
        init_authority(self.blob, self.wrap)
        with patch('gate.custody.os.geteuid', return_value=os.geteuid() + 1):
            with self.assertRaises(CustodyError):
                read_private(self.blob, MAX_AUTHORITY_BYTES)

    def test_init_symlink_collision_never_changes_target(self):
        target = self.wraps / 'existing'
        target.write_bytes(b'keep')
        self.wrap.symlink_to(target)
        with self.assertRaises(CustodyError):
            init_authority(self.blob, self.wrap)
        self.assertEqual(target.read_bytes(), b'keep')
        self.assertTrue(self.wrap.is_symlink())
        self.assertFalse(self.blob.exists())

    def test_reject_same_directory_or_path(self):
        for other in (self.blob, self.blobs / 'other'):
            with self.assertRaises(CustodyError):
                init_authority(self.blob, other)
        self.assertFalse(self.blob.exists())

    def test_reject_unsafe_paths_and_modes(self):
        init_authority(self.blob, self.wrap)
        for path in (Path('relative'), self.blobs / '..' / 'blobs' / 'authority'):
            with self.assertRaises(CustodyError):
                read_private(path, MAX_AUTHORITY_BYTES)
        for mode in (0o644, 0o400, 0o660):
            self.blob.chmod(mode)
            with self.assertRaises(CustodyError):
                read_private(self.blob, MAX_AUTHORITY_BYTES)
        self.blob.chmod(0o600)
        self.blobs.chmod(0o755)
        with self.assertRaises(CustodyError):
            read_private(self.blob, MAX_AUTHORITY_BYTES)

    def test_reject_symlinks_hardlinks_fifo_and_directory(self):
        init_authority(self.blob, self.wrap)
        link = self.blobs / 'link'
        link.symlink_to(self.blob)
        with self.assertRaises(CustodyError):
            read_private(link, MAX_AUTHORITY_BYTES)
        alias = self.root / 'alias'
        alias.symlink_to(self.blobs, target_is_directory=True)
        with self.assertRaises(CustodyError):
            read_private(alias / self.blob.name, MAX_AUTHORITY_BYTES)
        link.unlink()
        os.link(self.blob, link)
        with self.assertRaises(CustodyError):
            read_private(self.blob, MAX_AUTHORITY_BYTES)
        link.unlink()
        fifo = self.blobs / 'fifo'
        os.mkfifo(fifo, 0o600)
        with self.assertRaises(CustodyError):
            read_private(fifo, MAX_AUTHORITY_BYTES)
        with self.assertRaises(CustodyError):
            read_private(self.blobs, MAX_AUTHORITY_BYTES)

    def test_reject_oversize_wrong_key_and_tamper(self):
        init_authority(self.blob, self.wrap)
        original = self.wrap.read_bytes()
        self.wrap.write_bytes(os.urandom(32))
        with self.assertRaises(CustodyError):
            load_authority(self.blob, self.wrap)
        self.wrap.write_bytes(original)
        original_blob = self.blob.read_bytes()
        self.blob.write_bytes(original_blob[:-1] + bytes([original_blob[-1] ^ 1]))
        with self.assertRaises(CustodyError):
            load_authority(self.blob, self.wrap)
        self.blob.write_bytes(b'x' * (MAX_AUTHORITY_BYTES + 1))
        with self.assertRaises(CustodyError):
            read_private(self.blob, MAX_AUTHORITY_BYTES)
        for bound in (True, 0, -1):
            with self.assertRaises(CustodyError):
                read_private(self.blob, bound)

    def cli(self, operation, data=b''):
        return subprocess.run([sys.executable, '-m', 'cli.authority', operation,
                               '--key-store', str(self.blob), '--wrapping-key', str(self.wrap)],
                              input=data, capture_output=True, timeout=10)

    def test_real_cli_sign_and_public(self):
        created = self.cli('init')
        self.assertEqual(created.returncode, 0, created.stderr)
        public = json.loads(created.stdout)
        self.assertEqual(set(public), {'public_key'})
        inspected = self.cli('public')
        self.assertEqual(inspected.returncode, 0, inspected.stderr)
        self.assertEqual(json.loads(inspected.stdout), public)
        claims = dict(version=1, kind='grant', issuer='operator', subject='session',
                      capability='1' * 64, scope='files.read', tool_principal='srv:files',
                      tool_hash='2' * 64, integrity='high', action_hash='',
                      issued_at=100, expires_at=200, nonce='3' * 64)
        signed = self.cli('sign', json.dumps(claims).encode() + b'\n')
        self.assertEqual(signed.returncode, 0, signed.stderr)
        result = json.loads(signed.stdout)
        self.assertEqual(set(result), {'payload', 'signature'})
        key = TrustKey(bytes.fromhex(public['public_key']), frozenset({'grant'}),
                       frozenset({'files.read'}), 'high')
        verified = verify(Envelope(base64.b64decode(result['payload']),
                                   base64.b64decode(result['signature'])), {'operator': key})
        self.assertEqual(verified.subject, 'session')

    def test_cli_errors_are_fixed_and_payload_free(self):
        init_authority(self.blob, self.wrap)
        for payload in (b'{"secret":"do not echo"}\n', b'{}\n{}\n', b'{"x":1,"x":2}\n'):
            result = self.cli('sign', payload)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stdout, b'')
            self.assertEqual(result.stderr, b'Authority operation failed\n')
        result = self.cli('private-sensitive-unknown-option')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, b'Authority operation failed\n')


if __name__ == '__main__':
    unittest.main()
