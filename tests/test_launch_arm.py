"""I6/I7: pinned launches, single attempts, bounded supervision, honest completion."""
from hashlib import sha256
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from benchmarks import launch_arm as launch


class TestArmLaunch(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='launch fixture ')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.checkout = self.root/'checkout with spaces'
        self.checkout.mkdir()
        self.protocol = self.root/'protocol with spaces.json'
        self.p = dict(status='approved', benchmark='fixture', revision=launch.REVISION,
                      model='fixture', settings=json.dumps(dict(elapsed_deadline_seconds=1,
                      forced_kill_grace_seconds=1)), policy='fixture', adapter_revision='a'*40,
                      max_steps=30, max_loss=.05, min_baseline_success=.5,
                      tasks=[dict(id='fixture/task with spaces;$(false)', seed=7)])
        self.protocol.write_text(json.dumps(self.p))
        self.destination = self.root/'prepared run'
        self.bindings = patch.object(launch, '_bindings').start()
        self.addCleanup(patch.stopall)
        self.digest = launch.prepare(self.checkout, self.protocol, 'b'*40, self.destination)
        self.manifest = self.destination/'manifest.json'

    def status(self, token='0000b'):
        return json.loads((self.destination/'attempts'/token/'status.json').read_text())

    def trace(self, changes=None):
        trace = dict(version=1, protocol_sha256=sha256(self.protocol.read_bytes()).hexdigest(),
                     adapter_revision='a'*40, id=self.p['tasks'][0]['id'], seed=7, arm='baseline',
                     success=True, error=None, security_violations=0,
                     events=[dict(step=0, operation='finish', status='ALLOW',
                                  input_sha256='c'*64, output_sha256='d'*64)])
        trace.update(changes or {})
        raw = json.dumps(trace).encode()
        (self.destination/'traces/0000b'/f'{sha256(raw).hexdigest()}.json').write_bytes(raw)

    def fake_process(self, changes=None, code=0, emit=True):
        process = Mock(pid=987654, wait=Mock(return_value=code))
        def spawn(*args, **kwargs):
            if emit:
                self.trace(changes)
            return process
        return process, spawn

    def test_exact_argv_and_successful_lifecycle(self):
        process, spawn = self.fake_process()
        with patch.object(launch.subprocess, 'Popen', side_effect=spawn) as popen, patch.object(launch.os, 'killpg'):
            self.assertEqual(launch.run(self.manifest, self.digest, '0000b'), 0)
        argv = popen.call_args.args[0]
        self.assertEqual(argv, [sys.executable, str(launch.ROOT/'benchmarks/run_agentdojo.py'),
                         '--checkout', str(self.checkout), '--protocol', str(self.protocol),
                         '--trace-root', str(self.destination/'traces/0000b'),
                         '--task', self.p['tasks'][0]['id'], '--arm', 'baseline'])
        self.assertEqual(popen.call_args.kwargs, dict(cwd=launch.ROOT, stderr=subprocess.DEVNULL,
                                                    start_new_session=True))
        self.assertEqual(self.status()['history'], ['claimed', 'process_started', 'task_finished'])
        self.assertTrue(self.status()['success'])
        self.assertGreaterEqual(process.wait.call_count, 2)
        self.assertEqual(self.bindings.call_count, 2)

    def test_task_failure_is_completed_not_infrastructure_failure(self):
        _, spawn = self.fake_process({'success': False})
        with patch.object(launch.subprocess, 'Popen', side_effect=spawn), patch.object(launch.os, 'killpg'):
            self.assertEqual(launch.run(self.manifest, self.digest, '0000b'), 0)
        self.assertEqual(self.status()['state'], 'task_finished')
        self.assertFalse(self.status()['success'])

    def test_exit_zero_without_trace_is_infrastructure_failure(self):
        _, spawn = self.fake_process(emit=False)
        with patch.object(launch.subprocess, 'Popen', side_effect=spawn), patch.object(launch.os, 'killpg'):
            self.assertEqual(launch.run(self.manifest, self.digest, '0000b'), 2)
        self.assertEqual(self.status()['state'], 'infrastructure_failure')

    def test_trace_binding_and_errors_fail_closed(self):
        for changes in ({'arm': 'gated'}, {'seed': True}, {'error': 'SECRET'}, {'id': 'wrong'},
                        {'success': 1}, {'extra': 0}, {'events': []}):
            with self.subTest(changes=changes):
                self.trace(changes)
                with self.assertRaises(launch.LaunchError):
                    launch._terminal(self.destination/'traces/0000b', self.p,
                                     sha256(self.protocol.read_bytes()).hexdigest(), self.p['tasks'][0], 'baseline')
                for path in (self.destination/'traces/0000b').iterdir():
                    path.unlink()

    def test_directory_enumeration_is_bounded(self):
        def entries():
            yield Mock(path='a.json')
            yield Mock(path='b.json')
            self.fail('unbounded directory enumeration')
        from contextlib import nullcontext
        with patch.object(launch.os, 'scandir', return_value=nullcontext(entries())), self.assertRaises(launch.LaunchError):
            launch._terminal(self.root, self.p, 'a'*64, self.p['tasks'][0], 'baseline')

    def test_missing_trace_directory_retains_claim_and_cannot_retry(self):
        (self.destination/'traces/0000b').rmdir()
        with patch.object(launch.subprocess, 'Popen') as popen:
            self.assertEqual(launch.run(self.manifest, self.digest, '0000b'), 2)
            original = self.status()
            with self.assertRaises(FileExistsError):
                launch.run(self.manifest, self.digest, '0000b')
            popen.assert_not_called()
        self.assertEqual(original, self.status())
        self.assertEqual(original['history'], ['claimed', 'setup_refused'])

    def test_mutated_source_refused_after_claim(self):
        self.bindings.side_effect = launch.LaunchError('fixed')
        with patch.object(launch.subprocess, 'Popen') as popen:
            self.assertEqual(launch.run(self.manifest, self.digest, '0000b'), 2)
            popen.assert_not_called()
        self.assertEqual(self.status()['state'], 'setup_refused')

    def test_wrong_token_and_manifest_tamper_never_spawn(self):
        with patch.object(launch.subprocess, 'Popen') as popen:
            for token in ('../0000b', '0001b', '0000x', '0b', '0000b/extra'):
                with self.subTest(token=token), self.assertRaises(launch.LaunchError):
                    launch.run(self.manifest, self.digest, token)
            self.manifest.write_bytes(self.manifest.read_bytes()+b' ')
            with self.assertRaises(launch.LaunchError):
                launch.run(self.manifest, self.digest, '0000b')
            popen.assert_not_called()
        self.assertEqual(list((self.destination/'attempts').iterdir()), [])

    def test_extra_manifest_field_rejected_even_with_matching_digest(self):
        manifest = json.loads(self.manifest.read_text())
        manifest['argv'] = ['SECRET']
        raw = json.dumps(manifest).encode()
        self.manifest.write_bytes(raw)
        with self.assertRaises(launch.LaunchError):
            launch.run(self.manifest, sha256(raw).hexdigest(), '0000b')

    def test_protocol_tamper_rejected(self):
        self.protocol.write_text(self.protocol.read_text()+' ')
        with self.assertRaises(launch.LaunchError):
            launch.run(self.manifest, self.digest, '0000b')

    def test_preflight_consumes_deadline_without_spawning(self):
        with patch.object(launch.time, 'monotonic', side_effect=[0, 2]), patch.object(launch.subprocess, 'Popen') as popen:
            self.assertEqual(launch.run(self.manifest, self.digest, '0000b'), 2)
            popen.assert_not_called()
        self.assertEqual(self.status()['state'], 'setup_refused')

    def test_log_write_failure_still_terminates_and_reaps(self):
        process, spawn = self.fake_process(emit=False)
        original = launch._record
        def record(attempt, data, state, reason=None):
            if state == 'process_started':
                raise OSError('SECRET')
            original(attempt, data, state, reason)
        with patch.object(launch, '_record', side_effect=record), patch.object(launch.subprocess, 'Popen', side_effect=spawn), patch.object(launch.os, 'killpg') as kill:
            self.assertEqual(launch.run(self.manifest, self.digest, '0000b'), 2)
        kill.assert_any_call(process.pid, signal.SIGTERM)
        kill.assert_any_call(process.pid, signal.SIGKILL)
        process.wait.assert_called()
        self.assertNotIn('SECRET', json.dumps(self.status()))

    def test_real_harmless_process_timeout_is_reaped(self):
        real_popen = subprocess.Popen
        processes = []
        def spawn(*args, **kwargs):
            child = real_popen([sys.executable, '-c', 'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)'],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               start_new_session=True)
            processes.append(child)
            return child
        with patch.object(launch.subprocess, 'Popen', side_effect=spawn):
            self.assertEqual(launch.run(self.manifest, self.digest, '0000b'), 2)
        self.assertEqual(processes[0].poll(), -signal.SIGKILL)
        self.assertEqual(self.status()['reason'], 'PROCESS.TIMEOUT')

    def test_generated_wrapper_executes_with_space_paths_and_fixed_error(self):
        self.manifest.write_bytes(self.manifest.read_bytes()+b' ')
        result = subprocess.run([str(self.destination/'arms/0000b')], cwd='/', capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'Benchmark launch refused\n')

    def test_prepare_rejects_existing_destination_and_invalid_settings(self):
        with self.assertRaises(launch.LaunchError):
            launch.prepare(self.checkout, self.protocol, 'b'*40, self.destination)
        for settings in ({'elapsed_deadline_seconds': True, 'forced_kill_grace_seconds': 1},
                         {'elapsed_deadline_seconds': 1, 'forced_kill_grace_seconds': 0}):
            self.p['settings'] = json.dumps(settings)
            self.protocol.write_text(json.dumps(self.p))
            with self.assertRaises(launch.LaunchError):
                launch.prepare(self.checkout, self.protocol, 'b'*40, self.root/'new')
        self.assertFalse((self.root/'new').exists())

    def test_concurrent_claim_allows_only_one_spawn(self):
        from concurrent.futures import ThreadPoolExecutor
        _, spawn = self.fake_process()
        def run():
            try:
                return launch.run(self.manifest, self.digest, '0000b')
            except FileExistsError:
                return 'duplicate'
        with patch.object(launch.subprocess, 'Popen', side_effect=spawn) as popen, patch.object(launch.os, 'killpg'):
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _: run(), range(2)))
            self.assertCountEqual(results, [0, 'duplicate'])
            self.assertEqual(popen.call_count, 1)
        self.assertEqual(self.status()['history'], ['claimed', 'process_started', 'task_finished'])

    def test_prepare_publication_failure_removes_manifest(self):
        destination = self.root/'broken prepare'
        original = launch._sync
        def sync(path):
            if path == destination:
                raise OSError('fixture')
            original(path)
        with patch.object(launch, '_sync', side_effect=sync), self.assertRaises(OSError):
            launch.prepare(self.checkout, self.protocol, 'b'*40, destination)
        self.assertTrue(destination.is_dir())
        self.assertFalse((destination/'manifest.json').exists())

    def test_spawn_failure_is_sanitized_and_claim_retained(self):
        with patch.object(launch.subprocess, 'Popen', side_effect=OSError('SECRET')):
            self.assertEqual(launch.run(self.manifest, self.digest, '0000b'), 2)
        self.assertEqual(self.status()['history'], ['claimed', 'infrastructure_failure'])
        self.assertNotIn('SECRET', json.dumps(self.status()))

    def test_nonzero_exit_is_not_task_finished_even_with_trace(self):
        _, spawn = self.fake_process(code=1)
        with patch.object(launch.subprocess, 'Popen', side_effect=spawn), patch.object(launch.os, 'killpg'):
            self.assertEqual(launch.run(self.manifest, self.digest, '0000b'), 2)
        self.assertEqual(self.status()['state'], 'infrastructure_failure')

    def test_production_binding_checks_are_required(self):
        # Stop only the fixture's binding stub, exercising the real trust checks.
        patch.stopall()
        good = subprocess.CompletedProcess(['git'], 0, b'', b'')
        dirty = subprocess.CompletedProcess(['git'], 0, b'benchmarks/untracked.py', b'')
        with patch.object(launch, 'frozen_protocol_matches', return_value=True) as frozen, \
             patch.object(launch, 'measured_source_matches', return_value=True) as measured, \
             patch.object(launch, 'checkout_valid', return_value=True) as checkout, \
             patch.object(launch.subprocess, 'run', side_effect=[good, dirty]):
            with self.assertRaises(launch.LaunchError):
                launch._bindings(self.protocol.read_bytes(), self.p, 'b'*40, self.checkout)
            frozen.assert_called_once()
            measured.assert_called_once()
            checkout.assert_called_once_with(self.checkout)

    def test_wrapper_extra_arguments_refuse_without_echo(self):
        result = subprocess.run([str(self.destination/'arms/0000b'), 'SECRET'],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stderr, b'Benchmark launch refused\n')
        self.assertEqual(list((self.destination/'attempts').iterdir()), [])

    def test_cli_invalid_arguments_are_sanitized(self):
        from contextlib import redirect_stderr
        from io import StringIO
        for args in (['SECRET'], ['run', 'SECRET'], ['prepare', '--SECRET']):
            with self.subTest(args=args), redirect_stderr(StringIO()) as output:
                self.assertEqual(launch.main(args), 2)
            self.assertEqual(output.getvalue(), 'Benchmark launch refused\n')
