"""Fake backend only: no benchmark prompts, solutions or upstream imports."""
from hashlib import sha256
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import base64

from benchmarks.agentdojo_host import (AdapterError, AgentDojoBackend, TraceContext,
                                      Worker, canonical, main, write_trace)
from lang.limits import MAX_ARG_DEPTH, MAX_ARG_NODES, MAX_SOURCE_BYTES
from gate.service import HostSession


class FakeBackend:
    prompt = 'FIXTURE_PROMPT'
    def __init__(self):
        self.tools = {'echo': {'name': 'echo', 'description': 'Test only',
                              'parameters': {'type': 'object', 'properties': {'value': {}}}}}
        self.calls = []
        self.answers = []
        self.failure = None

    def call(self, name, arguments):
        if self.failure is not None:
            raise self.failure
        self.calls.append((name, arguments))
        return json.dumps(arguments, ensure_ascii=False)

    def finish(self, answer):
        self.answers.append(answer)
        return answer == 'done'


class TestAgentDojoWorker(unittest.TestCase):
    def send(self, worker, **request):
        return worker.handle(canonical(request))

    def test_both_arms_preserve_rich_arguments_and_finish_once(self):
        rich = {'quotes': '"x"\\\n雪', 'list': [True, None, -1, 2.5, {'x': 'data'}]}
        for arm in ('baseline', 'gated'):
            backend = FakeBackend()
            worker = Worker(backend, arm, 10)
            self.assertEqual(worker.initial()['tools'], ['echo'])
            self.assertIn('schema', self.send(worker, op='schema', tool='echo'))
            response = self.send(worker, op='call', tool='echo', args={'value': rich})
            self.assertEqual(json.loads(response['result']), {'value': rich})
            self.assertEqual(backend.calls, [('echo', {'value': rich})])
            if arm == 'gated':
                self.assertEqual(worker.host.audit[-1]['operation'], 'RUN')
                self.assertEqual(worker.host.label.integrity, 'low')
            final = self.send(worker, op='finish', answer='done')
            self.assertTrue(final['success'])
            self.assertEqual([e['step'] for e in final['events']], [0, 1, 2])
            self.assertNotIn('FIXTURE_PROMPT', json.dumps(final))
            self.assertEqual(self.send(worker, op='finish', answer='again'), {'error': 'BENCH.TERMINAL'})
            self.assertEqual(backend.answers, ['done'])

    def test_gated_callback_cannot_execute_after_grants_retired(self):
        backend = FakeBackend()
        worker = Worker(backend, 'gated', 5)
        worker.host.rotate_trust({})
        response = self.send(worker, op='call', tool='echo', args={'value': 'x'})
        self.assertIn('error', response)
        self.assertEqual(backend.calls, [])
        self.assertEqual(worker.events[-1]['status'], 'DENY')

    def test_invalid_requests_consume_budget_without_side_effects(self):
        for arm in ('baseline', 'gated'):
            backend = FakeBackend()
            worker = Worker(backend, arm, 4)
            for index, request in enumerate((b'{"op":"call","op":"schema"}',
                            canonical({'op': 'call', 'tool': 'echo', 'args': {'unknown': 1}}),
                            canonical({'op': 'schema', 'tool': 'echo', 'extra': True}),
                            canonical({'op': 'call', 'tool': 'unknown', 'args': {}}))):
                response = worker.handle(request)
                if index < 3:
                    self.assertEqual(response, {'error': 'BENCH.INVALID'})
                else:
                    self.assertFalse(response['success'])
                    self.assertEqual(response['reason'], 'budget_exhausted')
            self.assertTrue(worker.terminal)
            self.assertTrue(worker.finished)
            self.assertEqual(self.send(worker, op='finish', answer='done'), {'error': 'BENCH.TERMINAL'})
            self.assertEqual(backend.calls, [])
            self.assertEqual(backend.answers, [])
            self.assertEqual(len(worker.events), 5)

    def test_exhausted_and_abandoned_keep_failure_trace_without_evaluation(self):
        for reason in ('budget_exhausted', 'abandoned'):
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as directory:
                context = TraceContext('a'*64, 'b'*40, 'banking/user_task_0', 0, Path(directory))
                backend = FakeBackend()
                worker = Worker(backend, 'gated', 2, context)
                self.send(worker, op='call', tool='echo', args={'value': 'one'})
                if reason == 'budget_exhausted':
                    final = self.send(worker, op='schema', tool='echo')
                else:
                    final = worker.finalize_abandoned()
                self.assertTrue(worker.finished)
                self.assertTrue(worker.terminal)
                self.assertFalse(final['success'])
                self.assertEqual(final['reason'], reason)
                self.assertEqual(len(backend.calls), 1)
                self.assertEqual(backend.answers, [])
                last = worker.events[-1]
                self.assertEqual(last['operation'], 'finish')
                self.assertEqual(last['status'], 'DENY')
                self.assertEqual(last['input_sha256'], sha256(('TSD-BENCH-'+reason+'-v1').encode()).hexdigest())
                self.assertEqual(last['output_sha256'], sha256(canonical({'success':False,'reason':reason})).hexdigest())
                artifact = Path(directory)/(final['trace_sha256']+'.json')
                raw = artifact.read_bytes()
                self.assertEqual(sha256(raw).hexdigest(), final['trace_sha256'])
                trace = json.loads(raw)
                self.assertFalse(trace['success'])
                self.assertIsNone(trace['error'])
                self.assertEqual(trace['events'], worker.events)
                self.assertEqual([event['step'] for event in worker.events], list(range(len(worker.events))))
                self.assertEqual(worker.finalize_abandoned(), {'error':'BENCH.TERMINAL'})

    def test_exhaustion_retains_infrastructure_failure_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            backend = FakeBackend()
            backend.failure = RuntimeError('PRIVATE_MARKER')
            worker = Worker(backend, 'gated', 1,
                            TraceContext('a'*64,'b'*40,'banking/user_task_0',0,Path(directory)))
            final = self.send(worker, op='call', tool='echo', args={})
            trace = json.loads((Path(directory)/(final['trace_sha256']+'.json')).read_bytes())
            self.assertEqual(trace['error'], 'BENCH.FAILED')
            self.assertEqual([e['status'] for e in trace['events']], ['ERROR','DENY'])
            self.assertFalse(trace['success'])
            self.assertEqual(backend.answers, [])

    def test_depth_nodes_bytes_nonfinite_and_cycles_refuse(self):
        invalid = [b'\xff', b'{"a":NaN}', b'{"a":1e999}', b'{"a":"\\ud800"}',
                   b'['*(MAX_ARG_DEPTH+2)+b'0'+b']'*(MAX_ARG_DEPTH+2),
                   b'{"a":['+b'0,'*MAX_ARG_NODES+b'0]}', b' '*(MAX_SOURCE_BYTES+1)]
        for raw in invalid:
            worker = Worker(FakeBackend(), 'baseline', 2)
            self.assertEqual(worker.handle(raw), {'error': 'BENCH.INVALID'})
        cyclic = []; cyclic.append(cyclic)
        with self.assertRaises(AdapterError):
            canonical(cyclic)

    def test_infrastructure_errors_are_sanitized_in_both_arms(self):
        for arm in ('baseline', 'gated'):
            backend = FakeBackend()
            backend.failure = RuntimeError('PRIVATE_MARKER')
            worker = Worker(backend, arm, 5)
            response = self.send(worker, op='call', tool='echo', args={})
            self.assertEqual(response, {'error': 'BENCH.FAILED'})
            self.assertEqual(worker.events[-1]['status'], 'ERROR')
            self.assertEqual(worker.error, 'BENCH.FAILED')
            self.assertNotIn('PRIVATE_MARKER', json.dumps(worker.events))
            backend.failure = AdapterError()
            self.send(worker, op='call', tool='echo', args={})
            self.assertEqual(worker.events[-1]['status'], 'DENY')

    def test_evaluator_failure_is_not_a_measured_failure(self):
        backend = FakeBackend()
        with patch.object(backend, 'finish', side_effect=ValueError('PRIVATE_MARKER')):
            worker = Worker(backend, 'baseline', 2)
            result = self.send(worker, op='finish', answer='done')
        self.assertEqual(result['error'], 'BENCH.FAILED')
        self.assertEqual(worker.error, 'BENCH.FAILED')
        self.assertTrue(worker.terminal)

    def test_upstream_evaluation_trace_fallback_once_without_sdk_import(self):
        class Task:
            def __init__(self, result): self.result, self.trace_calls, self.utility_calls = result, 0, 0
            def utility_from_traces(self, *args): self.trace_calls += 1; return self.result
            def utility(self, *args): self.utility_calls += 1; return True
        for initial in (None, False, True):
            backend = AgentDojoBackend.__new__(AgentDojoBackend)
            backend.task = Task(initial)
            backend.before, backend.environment, backend.traces = object(), object(), []
            self.assertEqual(backend.finish('answer'), initial is not False)
            self.assertEqual(backend.task.trace_calls, 1)
            self.assertEqual(backend.task.utility_calls, int(initial is None))

    def test_content_addressed_trace_exclusive_mode_and_no_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            context = TraceContext('a'*64, 'b'*40, 'banking/user_task_0', 0, Path(directory))
            worker = Worker(FakeBackend(), 'gated', 5, context)
            self.send(worker, op='call', tool='echo', args={'value': 'PRIVATE_MARKER'})
            final = self.send(worker, op='finish', answer='done')
            digest = final['trace_sha256']
            artifact = Path(directory)/(digest+'.json')
            raw = artifact.read_bytes()
            self.assertEqual(sha256(raw).hexdigest(), digest)
            self.assertEqual(artifact.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(b'PRIVATE_MARKER', raw)
            evidence = json.loads(raw)
            self.assertEqual(evidence['events'][-1]['operation'], 'finish')
            self.assertTrue(evidence['success'])
            self.assertIsNone(evidence['error'])
            with self.assertRaises(FileExistsError):
                write_trace(context, 'gated', True, None, worker.events)
            artifact.unlink()
            artifact.symlink_to(Path(directory)/'outside')
            with self.assertRaises(FileExistsError):
                write_trace(context, 'gated', True, None, worker.events)
            self.assertFalse((Path(directory)/'outside').exists())

    def test_cli_without_sandbox_or_approval_refuses_before_sdk(self):
        environment = dict(os.environ)
        environment.pop('TSD_BENCH_SANDBOX', None)
        result = subprocess.run([sys.executable, '-m', 'benchmarks.agentdojo_host',
                                 '--task', 'banking/user_task_0'], env=environment,
                                text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout), {'error': 'BENCH.FAILED'})
        self.assertEqual(result.stderr, '')

    def test_cli_eof_writes_abandoned_failure_and_exits_normally(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            protocol = root/'protocol.json'
            protocol.write_bytes(canonical({'status':'approved', 'max_steps':2,
                'adapter_revision':'b'*40, 'tasks':[{'id':'banking/user_task_0','seed':0}]}))
            backend = FakeBackend()
            output = io.StringIO()
            argv = ['worker', '--task', 'banking/user_task_0', '--arm', 'gated',
                    '--max-steps', '2', '--protocol', str(protocol), '--trace-root', directory]
            with io.TextIOWrapper(io.BytesIO(b'')) as incoming, redirect_stdout(output), \
                    patch('sys.argv', argv), patch('sys.stdin', incoming), \
                    patch.dict(os.environ, {'TSD_BENCH_SANDBOX':'1'}), \
                    patch('benchmarks.agentdojo_host.AgentDojoBackend', return_value=backend):
                self.assertEqual(main(), 0)
            lines = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual(len(lines), 2)
            self.assertEqual(lines[-1]['reason'], 'abandoned')
            self.assertFalse(lines[-1]['success'])
            self.assertTrue((root/(lines[-1]['trace_sha256']+'.json')).is_file())
            self.assertEqual(backend.calls, [])
            self.assertEqual(backend.answers, [])


    def test_controller_receives_grants_and_execute_without_endorsements(self):
        observed = []
        original = HostSession.request
        def record(session, request):
            observed.append(request)
            return original(session, request)
        with patch.object(HostSession, 'request', record):
            backend = FakeBackend()
            worker = Worker(backend, 'gated', 5)
            self.assertIn('result', self.send(worker, op='call', tool='echo', args={'value': 2.5}))
        self.assertEqual([item['op'] for item in observed], ['apply', 'execute'])
        claims = json.loads(base64.b64decode(observed[0]['payload']))
        self.assertEqual(claims['kind'], 'grant')
        self.assertEqual(claims['integrity'], 'low')
        self.assertEqual(set(observed[1]), {'op', 'source', 'inputs'})
        self.assertEqual(backend.calls, [('echo', {'value': 2.5})])

    def test_controller_framing_limit_is_equal_before_either_arm_effects(self):
        # Raw argument and L source fit; the full owned execute frame does not.
        for arm in ('baseline', 'gated'):
            backend = FakeBackend()
            worker = Worker(backend, arm, 5)
            response = self.send(worker, op='call', tool='echo',
                                 args={'value': 'x' * (MAX_SOURCE_BYTES // 2)})
            self.assertEqual(response, {'error': 'BENCH.INVALID'})
            self.assertEqual(backend.calls, [])
            self.assertEqual(worker.events[-1]['status'], 'DENY')
            self.assertIsNone(worker.error)

    def test_controller_closed_state_prevents_future_dispatch_in_both_arms(self):
        for arm in ('baseline', 'gated'):
            backend = FakeBackend()
            worker = Worker(backend, arm, 5)
            worker.session.request({'op': 'close'})
            self.assertEqual(self.send(worker, op='call', tool='echo', args={}),
                             {'error': 'BENCH.INVALID'})
            self.assertEqual(backend.calls, [])

    def test_oversized_result_closes_both_arms_without_repeating_effect(self):
        class LargeBackend(FakeBackend):
            def call(self, name, arguments):
                super().call(name, arguments)
                return '"' * MAX_SOURCE_BYTES
        for arm in ('baseline', 'gated'):
            backend = LargeBackend()
            worker = Worker(backend, arm, 5)
            for _ in range(2):
                self.assertEqual(self.send(worker, op='call', tool='echo', args={}),
                                 {'error': 'BENCH.INVALID'})
            self.assertTrue(worker.session.closed)
            self.assertEqual(len(backend.calls), 1)
            self.assertIsNone(worker.error)


if __name__ == '__main__':
    unittest.main()
