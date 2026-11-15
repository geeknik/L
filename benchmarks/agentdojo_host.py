"""Isolated, single-task AgentDojo worker. No provider credentials are needed."""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import random
import re
import sys
import time
from typing import Any, Protocol

from gate.authority import Authority, TrustKey
from gate.host import HostError, LabeledInput, LocalHost, ToolRegistration
from lang.limits import MAX_ARG_DEPTH, MAX_ARG_NODES, MAX_SOURCE_BYTES, MAX_SECURITY_RECORDS


class AdapterError(Exception):
    def __init__(self) -> None:
        super().__init__('BENCH.INVALID')


def _fail(*args: object) -> Any:
    raise AdapterError()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AdapterError()
        result[key] = value
    return result


def _validate(value: Any) -> None:
    stack = [(value, 0)]
    count = 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > MAX_ARG_NODES or depth > MAX_ARG_DEPTH:
            raise AdapterError()
        if type(item) is dict:
            if len(item) > MAX_ARG_NODES - count:
                raise AdapterError()
            for key, child in item.items():
                if type(key) is not str:
                    raise AdapterError()
                stack.extend(((key, depth+1), (child, depth+1)))
        elif type(item) is list:
            if len(item) > MAX_ARG_NODES - count:
                raise AdapterError()
            stack.extend((child, depth+1) for child in item)
        elif type(item) is str:
            if len(item) > MAX_SOURCE_BYTES or len(item.encode('utf-8')) > MAX_SOURCE_BYTES:
                raise AdapterError()
        elif type(item) is float:
            if not math.isfinite(item):
                raise AdapterError()
        elif type(item) is int:
            if not -(2**63) <= item < 2**63:
                raise AdapterError()
        elif item is not None and type(item) is not bool:
            raise AdapterError()


def canonical(value: Any) -> bytes:
    _validate(value)
    data = json.dumps(value, ensure_ascii=False, allow_nan=False,
                      sort_keys=True, separators=(',', ':')).encode('utf-8')
    if len(data) > MAX_SOURCE_BYTES:
        raise AdapterError()
    return data


def parse_request(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) > MAX_SOURCE_BYTES:
        raise AdapterError()
    text = raw.decode('utf-8')
    depth = nodes = 0
    quoted = escaped = atom = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted, atom = True, False
            nodes += 1
        elif char in '[{':
            depth += 1
            nodes += 1
            atom = False
        elif char in ']}':
            depth -= 1
            atom = False
        elif char in ',: \r\n\t':
            atom = False
        elif not atom:
            nodes += 1
            atom = True
        if depth < 0 or depth > MAX_ARG_DEPTH+1 or nodes > MAX_ARG_NODES:
            raise AdapterError()
    value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_fail)
    if type(value) is not dict:
        raise AdapterError()
    canonical(value)
    return value


class Backend(Protocol):
    prompt: str
    tools: dict[str, dict[str, Any]]

    def call(self, name: str, arguments: dict[str, Any]) -> str: ...
    def finish(self, answer: str) -> bool: ...


@dataclass(frozen=True)
class TraceContext:
    protocol_sha256: str
    adapter_revision: str
    task: str
    seed: int
    directory: Path

    def __post_init__(self) -> None:
        if (type(self.protocol_sha256) is not str or not re.fullmatch('[0-9a-f]{64}', self.protocol_sha256)
                or type(self.adapter_revision) is not str or not re.fullmatch('[0-9a-f]{40}', self.adapter_revision)
                or type(self.task) is not str or not re.fullmatch('[a-z]+/user_task_[0-9]+', self.task)
                or type(self.seed) is not int or not 0 <= self.seed <= 2147483647
                or not isinstance(self.directory, Path)):
            raise AdapterError()


def write_trace(context: TraceContext, arm: str, success: bool,
                error: str | None, events: list[dict[str, Any]]) -> str:
    data = canonical(dict(version=1, protocol_sha256=context.protocol_sha256,
                          adapter_revision=context.adapter_revision, id=context.task,
                          seed=context.seed, arm=arm, success=success, error=error,
                          security_violations=0, events=events)) + b'\n'
    if len(data) > MAX_SOURCE_BYTES:
        raise AdapterError()
    digest = sha256(data).hexdigest()
    name = digest + '.json'
    directory = os.open(context.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            os.unlink(name, dir_fd=directory)
            raise
    finally:
        os.close(directory)
    return digest


class Worker:
    def __init__(self, backend: Backend, arm: str, max_steps: int,
                 trace: TraceContext | None = None) -> None:
        if arm not in ('baseline', 'gated') or type(max_steps) is not int or not 1 <= max_steps <= MAX_ARG_NODES:
            raise AdapterError()
        if not 0 < len(backend.tools) <= MAX_SECURITY_RECORDS:
            raise AdapterError()
        self.backend, self.arm, self.max_steps, self.trace = backend, arm, max_steps, trace
        self.events: list[dict[str, Any]] = []
        self.terminal = False
        self.finished = False
        self.error: str | None = None
        self.registrations: dict[str, ToolRegistration] = {}
        self.capabilities: dict[str, str] = {}
        authority = Authority()
        for name, definition in backend.tools.items():
            if not re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', name):
                raise AdapterError()
            def callback(params: dict[str, str | int], tool: str = name) -> str:
                raw = params.get('json')
                if type(raw) is not str or set(params) != {'json'}:
                    raise AdapterError()
                arguments = parse_request(raw.encode())
                try:
                    return self.backend.call(tool, arguments)
                except AdapterError:
                    raise HostError('BENCH.INVALID') from None
            self.registrations[name] = ToolRegistration('bench:'+name, canonical(definition),
                                                        'public', callback)
            self.capabilities[name] = sha256(('cap:'+name).encode()).hexdigest()
        trust = TrustKey(authority.public_key, frozenset(('grant',)),
                         frozenset('bench.'+name for name in backend.tools), 'low')
        self.host = LocalHost({'bench': trust}, list(self.registrations.values()), model_clearance='public')
        now = int(time.time())
        for name, registration in self.registrations.items():
            self.host.apply(authority.sign(dict(
                version=1, kind='grant', issuer='bench', subject=self.host.subject,
                capability=self.capabilities[name], scope='bench.'+name,
                tool_principal=registration.principal, tool_hash=registration.content_hash,
                integrity='low', action_hash='', issued_at=now, expires_at=now+3600,
                nonce=sha256(('nonce:'+name).encode()).hexdigest())))

    def initial(self) -> dict[str, Any]:
        result = {'prompt': self.backend.prompt, 'tools': sorted(self.backend.tools)}
        canonical(result)
        return result

    def _dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        op = request.get('op')
        if op == 'finish' and set(request) == {'op', 'answer'} and type(request['answer']) is str:
            self.terminal = True
            self.finished = True
            try:
                success = self.backend.finish(request['answer'])
            except Exception:
                raise RuntimeError('Evaluator failed') from None
            if type(success) is not bool:
                raise RuntimeError('Invalid evaluator')
            return {'success': success}
        if op not in ('schema', 'call') or set(request) != ({'op', 'tool'} if op == 'schema' else {'op', 'tool', 'args'}):
            raise AdapterError()
        name = request['tool']
        if type(name) is not str or name not in self.registrations:
            raise AdapterError()
        definition = self.backend.tools[name]
        if op == 'schema':
            return {'schema': definition}
        arguments = request['args']
        properties = definition['parameters'].get('properties', {})
        if type(arguments) is not dict or not set(arguments) <= set(properties):
            raise AdapterError()
        encoded = canonical(arguments).decode()
        registration = self.registrations[name]
        source = ('DIRECT cap:'+self.capabilities[name]+' (scope=bench.'+name+', exp=3600, from=bench) '
                  'call tool:('+registration.principal+', sha256:'+registration.content_hash+
                  ') {json: "'+encoded.replace('"', '""')+'"}')
        # Apply the same transport size constraint to both arms.
        if len(source.encode()) > MAX_SOURCE_BYTES:
            raise AdapterError()
        if self.arm == 'gated':
            result = self.host.run([LabeledInput(encoded)], lambda _: source)
            if result is None:
                raise AdapterError()
            output = result.text
        else:
            output = registration.callback({'json': encoded})
        if type(output) is not str:
            raise AdapterError()
        return {'result': output}

    def handle(self, raw: bytes) -> dict[str, Any]:
        if self.terminal or len(self.events) >= self.max_steps:
            self.terminal = True
            return {'error': 'BENCH.TERMINAL'}
        operation, status = 'call', 'ALLOW'
        try:
            request = parse_request(raw)
            if request.get('op') in ('schema', 'call', 'finish'):
                operation = request['op']
            result = self._dispatch(request)
            canonical(result)
        except HostError as error:
            if error.code == 'HOST.FAILED':
                status, result = 'ERROR', {'error': 'BENCH.FAILED'}
                self.error = 'BENCH.FAILED'
            else:
                status, result = 'DENY', {'error': 'BENCH.INVALID'}
        except (AdapterError, ValueError, TypeError, UnicodeError, RecursionError):
            status, result = 'DENY', {'error': 'BENCH.INVALID'}
        except Exception:
            status, result = 'ERROR', {'error': 'BENCH.FAILED'}
            self.error = 'BENCH.FAILED'
        self.events.append(dict(step=len(self.events), operation=operation, status=status,
                                input_sha256=sha256(raw).hexdigest(),
                                output_sha256=sha256(canonical(result)).hexdigest()))
        if self.finished:
            return self._complete(result)
        if len(self.events) >= self.max_steps:
            return self._finalize_failure('budget_exhausted')
        return result

    def _complete(self, result: dict[str, Any]) -> dict[str, Any]:
        result['events'] = list(self.events)
        if self.trace is not None:
            try:
                result['trace_sha256'] = write_trace(self.trace, self.arm,
                    result.get('success') is True, self.error, self.events)
            except Exception:
                self.error = 'BENCH.TRACE'
                return {'error': 'BENCH.TRACE'}
        return result

    def _finalize_failure(self, reason: str) -> dict[str, Any]:
        self.terminal = self.finished = True
        result = {'success': False, 'reason': reason}
        marker = ('TSD-BENCH-'+reason+'-v1').encode('ascii')
        self.events.append(dict(step=len(self.events), operation='finish', status='DENY',
                                input_sha256=sha256(marker).hexdigest(),
                                output_sha256=sha256(canonical(result)).hexdigest()))
        return self._complete(result)

    def finalize_abandoned(self) -> dict[str, Any]:
        """Retain EOF as a task failure without inventing an evaluator result."""
        if self.terminal:
            return {'error': 'BENCH.TERMINAL'}
        return self._finalize_failure('abandoned')


class AgentDojoBackend:
    def __init__(self, task_id: str, seed: int) -> None:
        # Optional upstream dependencies are deliberately imported only here.
        from agentdojo.task_suite import get_suite  # type: ignore[import-not-found]
        from agentdojo.functions_runtime import FunctionsRuntime  # type: ignore[import-not-found]
        random.seed(seed)
        suite_name, task_name = task_id.split('/')
        suite = get_suite('v1.2.2', suite_name)
        self.task = suite.get_user_task_by_id(task_name)
        self.environment = self.task.init_environment(suite.load_and_inject_default_environment({}))
        self.before = self.environment.model_copy(deep=True)
        self.prompt = self.task.PROMPT
        allowed = {'banking_client', 'calendar_client', 'cloud_drive_client', 'email_client',
                   'file_reader', 'slack', 'travel_booking_client', 'user_account', 'web'}
        for tool in suite.tools:
            if tool.run.__module__ not in {'agentdojo.default_suites.v1.tools.'+m for m in allowed}:
                raise AdapterError()
        self.runtime = FunctionsRuntime(suite.tools)
        self.tools = {tool.name: {'name': tool.name, 'description': tool.description,
                                 'parameters': tool.parameters.model_json_schema()} for tool in suite.tools}
        self.traces: list[Any] = []

    def call(self, name: str, arguments: dict[str, Any]) -> str:
        from agentdojo.functions_runtime import FunctionCall
        from agentdojo.agent_pipeline.tool_execution import tool_result_to_str  # type: ignore[import-not-found]
        self.traces.append(FunctionCall(function=name, args=arguments))
        with open(os.devnull, 'w') as sink, redirect_stdout(sink), redirect_stderr(sink):
            result, error = self.runtime.run_function(self.environment, name, arguments)
        if error is not None:
            raise AdapterError()
        output: str = tool_result_to_str(result)
        return output

    def finish(self, answer: str) -> bool:
        with open(os.devnull, 'w') as sink, redirect_stdout(sink), redirect_stderr(sink):
            result = self.task.utility_from_traces(answer, self.before, self.environment, self.traces)
            if result is None:
                result = self.task.utility(answer, self.before, self.environment)
        if type(result) is not bool:
            raise RuntimeError('Invalid evaluator')
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', action='store_true')
    parser.add_argument('--task')
    parser.add_argument('--arm', choices=('baseline', 'gated'), default='gated')
    parser.add_argument('--max-steps', type=int, default=30)
    parser.add_argument('--seed', type=int, default=0)
    parser.add_argument('--protocol', type=Path)
    parser.add_argument('--trace-root', type=Path)
    args = parser.parse_args()
    try:
        if args.catalog:
            with open(os.devnull, 'w') as sink, redirect_stdout(sink), redirect_stderr(sink):
                from agentdojo.task_suite import get_suites
                catalog = {name: sorted(suite.user_tasks) for name, suite in get_suites('v1.2.2').items()}
            print(canonical(catalog).decode())
            return 0
        if os.environ.get('TSD_BENCH_SANDBOX') != '1' or not args.task or args.protocol is None or args.trace_root is None:
            raise AdapterError()
        with args.protocol.open('rb') as stream:
            raw = stream.read(MAX_SOURCE_BYTES+1)
        protocol = parse_request(raw)
        if (protocol.get('status') != 'approved' or protocol.get('max_steps') != args.max_steps
                or {'id': args.task, 'seed': args.seed} not in protocol.get('tasks', [])):
            raise AdapterError()
        context = TraceContext(sha256(raw).hexdigest(), protocol['adapter_revision'],
                               args.task, args.seed, args.trace_root)
        with open(os.devnull, 'w') as sink, redirect_stdout(sink), redirect_stderr(sink):
            backend = AgentDojoBackend(args.task, args.seed)
        worker = Worker(backend, args.arm, args.max_steps, context)
        print(canonical(worker.initial()).decode(), flush=True)
        while not worker.terminal:
            raw = sys.stdin.buffer.readline(MAX_SOURCE_BYTES+1)
            if not raw:
                print(canonical(worker.finalize_abandoned()).decode(), flush=True)
                break
            if len(raw) > MAX_SOURCE_BYTES:
                print('{"error":"BENCH.INVALID"}', flush=True)
                return 1
            print(canonical(worker.handle(raw)).decode(), flush=True)
        return 0 if worker.finished and worker.error is None else 1
    except Exception:
        print('{"error":"BENCH.FAILED"}', flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
