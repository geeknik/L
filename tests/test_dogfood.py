"""I1/I3/I4/I7: the live dogfood adapter preserves the real gate boundary."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from demos.dogfood_host import DogfoodHost
from gate.host import HostError
from lang.limits import MAX_SOURCE_BYTES


class TestDogfood(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.bridge = DogfoodHost(self.root)

    def execute(self, source):
        return self.bridge.request({'op': 'execute', 'source': source})

    def test_live_read_write_and_low_labels(self):
        source = self.bridge.prepare('read', {'path': 'notes.txt'})
        self.assertEqual(self.bridge.effects, {'read': 0, 'write': 0})
        self.bridge.approve(source)
        result = self.execute(source)
        self.assertEqual(result['integrity'], 'low')
        self.assertIn('UNTRUSTED INSTRUCTION:', result['result'])
        quantities = {}
        for line in result['result'].splitlines():
            key, value = line.split(': ', 1)
            if key in ('alpha', 'beta', 'gamma'):
                quantities[key] = quantities.get(key, 0) + int(value)
        quantities['total'] = sum(quantities.values())
        text = json.dumps(quantities, separators=(',', ':'))
        source = self.bridge.prepare('write', {'path': 'report.txt', 'text': text})
        self.bridge.approve(source)
        self.assertEqual(self.execute(source)['status'], 'ALLOW')
        self.assertEqual((self.root/'report.txt').read_text(), text)
        self.assertTrue(self.bridge.status()['task_success'])

    def test_prepared_source_size_and_task_format_are_exact(self):
        overhead = len(self.bridge.prepare('write', {'path': 'report.txt', 'text': ''}).encode())
        source = self.bridge.prepare('write',
            {'path': 'report.txt', 'text': 'x'*(MAX_SOURCE_BYTES-overhead)})
        self.assertEqual(len(source.encode()), MAX_SOURCE_BYTES)
        for text in ('x'*(MAX_SOURCE_BYTES-overhead+1), '"'*(MAX_SOURCE_BYTES//2)):
            with self.assertRaises(HostError) as caught:
                self.bridge.prepare('write', {'path': 'report.txt', 'text': text})
            self.assertEqual(caught.exception.code, 'DOGFOOD.LIMIT')
        source = self.bridge.prepare('write',
            {'path': 'report.txt', 'text': json.dumps(self.bridge.expected, indent=2)})
        self.bridge.approve(source)
        self.execute(source)
        self.assertFalse(self.bridge.status()['task_success'])

    def test_unapproved_changed_and_replayed_source_have_no_extra_effect(self):
        source = self.bridge.prepare('write', {'path': 'report.txt', 'text': 'original'})
        with self.assertRaises(HostError) as caught:
            self.execute(source)
        self.assertEqual(caught.exception.code, 'INTEGRITY.DENIED')
        self.bridge.approve(source)
        for altered in (source.replace('original', 'changed'), source+' ',
                        source.replace('report.txt', 'stolen.txt')):
            with self.assertRaises(HostError):
                self.execute(altered)
        self.assertFalse((self.root/'report.txt').exists())
        self.assertEqual(self.bridge.effects['write'], 0)
        self.execute(source)
        with self.assertRaises(HostError):
            self.execute(source)
        self.assertEqual(self.bridge.effects['write'], 1)
        self.assertEqual((self.root/'report.txt').read_text(), 'original')

    def test_policy_and_callbacks_reject_paths_and_extra_fields(self):
        source = self.bridge.prepare('write', {'path': 'report.txt', 'text': 'value'})
        for path in ('stolen.txt', '../report.txt', '/tmp/report.txt'):
            with self.assertRaises(HostError):
                self.bridge.approve(source.replace('report.txt', path))
            with self.assertRaises(HostError):
                self.bridge._write({'path': path, 'text': 'value'})
        for arguments in ({'path': 'report.txt', 'text': 'value', 'extra': 1},
                          {'path': 'report.txt', 'text': 1}):
            with self.assertRaises(HostError):
                self.bridge.prepare('write', arguments)
        self.assertEqual(self.bridge.effects['write'], 0)
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ['notes.txt'])

    def test_revoke_prevents_execution_and_new_endorsements(self):
        source = self.bridge.prepare('write', {'path': 'report.txt', 'text': 'value'})
        self.bridge.approve(source)
        self.bridge.request({'op': 'revoke', 'tool': 'write'})
        for operation in (lambda: self.execute(source), lambda: self.bridge.approve(source)):
            with self.assertRaises(HostError) as caught:
                operation()
            self.assertEqual(caught.exception.code, 'AUTH.REVOKED')
        self.assertEqual(self.bridge.effects['write'], 0)

    def test_malformed_frame_does_not_crash_or_reuse_request(self):
        result = subprocess.run([sys.executable, '-m', 'demos.dogfood_host'],
            input=b'bad\n{"op":"status"}\nnull\n{"op":"finish"}\n',
            capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        lines = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(lines[1], {'error': 'DOGFOOD.INVALID'})
        self.assertEqual(lines[2]['effects'], {'read': 0, 'write': 0})
        self.assertEqual(lines[3], {'error': 'DOGFOOD.INVALID'})
        self.assertEqual(result.stderr, b'')
