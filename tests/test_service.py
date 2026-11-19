"""I1/I3/I4/I6/I7/I8: owned-host protocol and real subprocess effects."""
import base64
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from gate.authority import Authority, TrustKey
from gate.host import LocalHost, ToolRegistration
from gate.local_protocol import JsonLines
from gate.service import ConfigurationError, HostSession, load_session, serve
from lang.limits import MAX_LINE_BYTES, MAX_PROCESS_SECONDS


class TestOwnedHost(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.config_path = self.directory / 'config.json'
        self.effect = self.directory / 'effect'
        self.adapter = self.directory / 'adapter.py'
        self.adapter.write_text(
            'import json,sys\nfrom pathlib import Path\n'
            'request=json.load(sys.stdin)\n'
            'Path(sys.argv[1]).write_text(request["arguments"]["text"])\n'
            'print(json.dumps({"result":"written"}))\n')
        self.authority = Authority()
        self.config = {'version': 1, 'model_clearance': 'public',
                       'input_confidentiality': 'public',
                       'trusted_keys': {'issuer': {
                           'public_key': self.authority.public_key.hex(),
                           'kinds': ['grant', 'endorse', 'revoke'],
                           'scopes': ['fs.write'], 'max_integrity': 'high'}},
                       'tools': [{'principal': 'srv:files', 'definition': 'write v1',
                                  'argv': [sys.executable, str(self.adapter), str(self.effect)],
                                  'timeout': 2, 'clearance': 'public',
                                  'output_confidentiality': 'public'}]}
        self.save_config()

    def save_config(self, config=None):
        self.config_path.write_text(json.dumps(self.config if config is None else config))
        self.config_path.chmod(0o600)

    def source(self, info):
        return ('DIRECT cap:' + 'a' * 64 + ' (scope=fs.write, exp=60, from=issuer) '
                'call tool:(srv:files, sha256:' + info['tools'][0]['hash'] + ') {text: "effect"}')

    def signed(self, info, kind='grant', source=None):
        now = int(time.time())
        claims = dict(version=1, kind=kind, issuer='issuer', subject=info['subject'],
                      capability='a' * 64, scope='fs.write', tool_principal='srv:files',
                      tool_hash=info['tools'][0]['hash'], integrity='high',
                      action_hash=sha256(source.encode()).hexdigest() if kind == 'endorse' else '',
                      issued_at=now - 1, expires_at=now + 60,
                      nonce={'grant': '1', 'endorse': '2', 'revoke': '3'}[kind] * 64)
        envelope = self.authority.sign(claims)
        return {'op': 'apply', 'payload': base64.b64encode(envelope.payload).decode(),
                'signature': base64.b64encode(envelope.signature).decode()}

    def start(self):
        proc = subprocess.Popen([sys.executable, '-m', 'cli.host', '--config', str(self.config_path)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            if proc.poll() is None:
                proc.kill()
            proc.communicate(timeout=5)
        self.addCleanup(cleanup)
        return proc

    def exchange(self, proc, request):
        with JsonLines(proc.stdout.fileno(), proc.stdin.fileno(), timeout=3) as stream:
            stream.write(request)
            return stream.read()

    def test_real_process_signed_lifecycle_and_restart(self):
        proc = self.start()
        info = self.exchange(proc, {'op': 'info'})
        self.assertEqual(set(info), {'status', 'version', 'subject', 'tools'})
        self.assertNotIn(str(self.directory), json.dumps(info))
        source = self.source(info)
        execute = {'op': 'execute', 'source': source, 'inputs': ['untrusted']}
        denied = {'status': 'DENY', 'error': 'Operation denied'}
        self.assertEqual(self.exchange(proc, execute), denied)
        grant = self.signed(info)
        self.assertEqual(self.exchange(proc, grant), {'status': 'ALLOW'})
        self.assertEqual(self.exchange(proc, execute), denied)
        self.assertFalse(self.effect.exists())
        endorsement = self.signed(info, 'endorse', source)
        tampered = dict(endorsement, signature=base64.b64encode(bytes(64)).decode())
        self.assertEqual(self.exchange(proc, tampered), denied)
        self.assertEqual(self.exchange(proc, endorsement), {'status': 'ALLOW'})
        self.assertEqual(self.exchange(proc, execute), {'status': 'ALLOW', 'result': 'written'})
        self.assertEqual(self.effect.read_text(), 'effect')
        self.effect.unlink()
        self.assertEqual(self.exchange(proc, execute), denied)
        self.assertEqual(self.exchange(proc, self.signed(info, 'revoke')), {'status': 'ALLOW'})
        self.assertEqual(self.exchange(proc, execute), denied)
        self.assertFalse(self.effect.exists())
        self.assertEqual(self.exchange(proc, {'op': 'close'}), {'status': 'ALLOW'})
        self.assertEqual(proc.wait(timeout=5), 0)
        restarted = self.start()
        fresh = self.exchange(restarted, {'op': 'info'})
        self.assertNotEqual(fresh['subject'], info['subject'])
        self.assertEqual(self.exchange(restarted, grant), denied)

    def test_schema_errors_continue_without_echo_or_effects(self):
        proc = self.start()
        invalid = {'status': 'DENY', 'error': 'Invalid request'}
        for request in ({'op': 'approve', 'secret': 'PRIVATE_MARKER'},
                        {'op': 'reset'}, {'op': 'rotate'}, {'op': 'info', 'label': 'high'},
                        {'op': 'execute', 'source': 1, 'inputs': []},
                        {'op': 'execute', 'source': 'PRIVATE_MARKER', 'inputs': [{}]},
                        {'op': 'apply', 'payload': '!!', 'signature': '!!'}):
            self.assertEqual(self.exchange(proc, request), invalid)
        self.assertEqual(self.exchange(proc, {'op': 'info'})['status'], 'ALLOW')
        self.assertFalse(self.effect.exists())

    def test_malformed_and_oversized_frames_close(self):
        for frame in (b'{"op":"info","op":"close"}\n', b'PRIVATE_MARKER\n',
                      b'x' * (MAX_LINE_BYTES + 1) + b'\n', b'{"op":'):
            with self.subTest(frame_length=len(frame)):
                proc = self.start()
                out, err = proc.communicate(frame, timeout=5)
                self.assertNotEqual(proc.returncode, 0)
                self.assertEqual(json.loads(out), {'error': 'Invalid request', 'status': 'DENY'})
                self.assertEqual(err, b'')
        self.assertFalse(self.effect.exists())

    def test_utf8_frame_boundary(self):
        # I6/I7: count received UTF-8 bytes, excluding the line terminator.
        request = {'op': 'execute', 'source': 'COMMIT (user:g, sha256:' + 'a' * 64 + ')',
                   'inputs': ['']}

        def frame():
            return json.dumps(request, ensure_ascii=False, separators=(',', ':')).encode('utf-8')

        remaining = MAX_LINE_BYTES - len(frame())
        request['inputs'][0] = 'é' * (remaining // 2) + 'a' * (remaining % 2)
        self.assertEqual(len(frame()), MAX_LINE_BYTES)
        allowed = {'status': 'ALLOW', 'result': None}
        denied = {'status': 'DENY', 'error': 'Invalid request'}
        session = load_session(self.config_path)
        for extra, expected, status in (('', allowed, 0), ('a', denied, 1)):
            with self.subTest(extra=extra):
                request['inputs'][0] += extra
                proc = self.start()
                out, err = proc.communicate(frame() + b'\n', timeout=5)
                self.assertEqual(json.loads(out), expected)
                self.assertEqual(proc.returncode, status)
                self.assertEqual(err, b'')
                self.assertEqual(session.request(request), expected)
        self.assertFalse(self.effect.exists())

    def test_stalled_frame_fails_closed(self):
        session = load_session(self.config_path)
        read_fd, write_fd = os.pipe()
        out_read, out_write = os.pipe()
        results = []
        thread = threading.Thread(target=lambda: results.append(serve(session, read_fd, out_write, .05)))
        try:
            os.write(write_fd, b'{')
            thread.start()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(results, [1])
            self.assertTrue(session.closed)
            self.assertEqual(json.loads(os.read(out_read, MAX_LINE_BYTES)),
                             {'status': 'DENY', 'error': 'Invalid request'})
        finally:
            for fd in (read_fd, write_fd, out_read, out_write):
                os.close(fd)

    def test_config_rejects_unknown_fields_bad_roles_types_scopes_and_keys(self):
        cases = []
        for field, value in [('extra', True), ('version', True), ('model_clearance', 'admin'),
                             ('tools', {}), ('trusted_keys', []), ('input_confidentiality', 0)]:
            item = deepcopy(self.config)
            item[field] = value
            cases.append(item)
        for field, value in [('kinds', ['grant', 'grant']), ('kinds', ['approve']),
                             ('scopes', ['fs.write', 'fs.write']), ('scopes', ['fs/write']),
                             ('public_key', '0' * 64), ('max_integrity', 'god'), ('extra', 0)]:
            item = deepcopy(self.config)
            item['trusted_keys']['issuer'][field] = value
            cases.append(item)
        for field, value in [('argv', ['relative']), ('timeout', True),
                             ('timeout', MAX_PROCESS_SECONDS + 1),
                             ('clearance', 'admin'), ('definition', ''), ('extra', 0)]:
            item = deepcopy(self.config)
            item['tools'][0][field] = value
            cases.append(item)
        item = deepcopy(self.config)
        del item['tools'][0]['definition']
        cases.append(item)
        for config in cases:
            self.save_config(config)
            with self.assertRaises(ConfigurationError):
                load_session(self.config_path)

    def test_hash_binds_entire_config_and_is_key_order_independent(self):
        original = load_session(self.config_path).request({'op': 'info'})['tools'][0]['hash']
        reordered = deepcopy(self.config)
        reordered['tools'][0] = dict(reversed(list(reordered['tools'][0].items())))
        self.save_config(reordered)
        self.assertEqual(load_session(self.config_path).request({'op': 'info'})['tools'][0]['hash'], original)
        for field, value in [('argv', [sys.executable, str(self.adapter), '/different']),
                             ('timeout', 1), ('clearance', 'secret'),
                             ('output_confidentiality', 'secret'), ('definition', 'write v2')]:
            changed = deepcopy(self.config)
            changed['tools'][0][field] = value
            self.save_config(changed)
            self.assertNotEqual(load_session(self.config_path).request({'op': 'info'})['tools'][0]['hash'], original)

    def test_input_confidentiality_and_no_client_label_override(self):
        self.config['input_confidentiality'] = 'secret'
        self.save_config()
        session = load_session(self.config_path)
        info = session.request({'op': 'info'})
        source = self.source(info)
        self.assertEqual(session.request(self.signed(info))['status'], 'ALLOW')
        self.assertEqual(session.request(self.signed(info, 'endorse', source))['status'], 'ALLOW')
        self.assertEqual(session.request({'op': 'execute', 'source': source, 'inputs': ['secret']}),
                         {'status': 'DENY', 'error': 'Operation denied'})
        self.assertEqual(session.request({'op': 'execute', 'source': source, 'inputs': []}),
                         {'status': 'DENY', 'error': 'Operation denied'})
        self.assertFalse(self.effect.exists())
        self.assertEqual(session.request({'op': 'execute', 'source': source, 'inputs': [], 'label': 'high'}),
                         {'status': 'DENY', 'error': 'Invalid request'})

    def test_closed_session_never_dispatches(self):
        session = load_session(self.config_path)
        self.assertEqual(session.request({'op': 'close'}), {'status': 'ALLOW'})
        self.assertEqual(session.request({'op': 'info'}),
                         {'status': 'DENY', 'error': 'Invalid request'})
        self.assertFalse(self.effect.exists())

    def test_oversized_response_after_effect_closes_without_retry(self):
        effects = []
        def callback(params):
            effects.append(params)
            return '"' * MAX_LINE_BYTES
        tool = ToolRegistration('srv:files', b'output test', 'public', callback)
        key = TrustKey(self.authority.public_key, frozenset(('grant', 'endorse')),
                       frozenset(('fs.write',)), 'high')
        session = HostSession(LocalHost({'issuer': key}, [tool], model_clearance='public'),
                              [tool], 'public')
        info = session.request({'op': 'info'})
        source = self.source(info)
        self.assertEqual(session.request(self.signed(info))['status'], 'ALLOW')
        self.assertEqual(session.request(self.signed(info, 'endorse', source))['status'], 'ALLOW')
        request = {'op': 'execute', 'source': source, 'inputs': []}
        self.assertEqual(session.request(request), {'status': 'DENY', 'error': 'Operation denied'})
        self.assertTrue(session.closed)
        self.assertEqual(len(effects), 1)
        self.assertEqual(session.request(request)['status'], 'DENY')
        self.assertEqual(len(effects), 1)

    def test_internal_error_diagnostic_resets_and_is_not_exposed(self):
        session = load_session(self.config_path)
        source = self.source(session.request({'op': 'info'}))
        result = session.request({'op': 'execute', 'source': source, 'inputs': []})
        self.assertEqual(result, {'status': 'DENY', 'error': 'Operation denied'})
        self.assertEqual(session.last_error_code, 'AUTH.REQUIRED')
        result = session.request({'op': 'info', 'last_error_code': 'HOST.FAILED'})
        self.assertEqual(result, {'status': 'DENY', 'error': 'Invalid request'})
        self.assertIsNone(session.last_error_code)
        with self.assertRaises(AttributeError):
            session.last_error_code = 'HOST.FAILED'
        self.assertNotIn('last_error_code', session.request({'op': 'info'}))
