"""Prepare pinned arm wrappers and supervise one non-retryable benchmark attempt."""
import argparse
from hashlib import sha256
import json
from itertools import islice
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from typing import Any, Never

from benchmarks.run_agentdojo import ROOT, REVISION, checkout_valid
from benchmarks.utility_report import EvidenceError, _pairs, read
from lang.limits import MAX_PROCESS_SECONDS, MAX_SECURITY_RECORDS, MAX_WIRE_BYTES
from scripts.release_check import MEASURED_PATHS, frozen_protocol_matches, measured_source_matches


class LaunchError(Exception):
    """A fixed diagnostic; never includes paths or input content."""


def _require(value: bool) -> None:
    if not value:
        raise LaunchError('Benchmark launch refused')


def _fields(value: Any, names: set[str]) -> None:
    _require(type(value) is dict and set(value) == names)


def _digest(value: Any, size: int = 64) -> bool:
    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}', value) is not None


def _directory(path: Path) -> None:
    _require(path.is_absolute() and path.resolve(strict=True) == path and path.is_dir())


def _bindings(raw: bytes, protocol: dict[str, Any], commit: str, checkout: Path) -> None:
    _require(frozen_protocol_matches(ROOT, raw, commit, protocol['adapter_revision']))
    _require(measured_source_matches(ROOT, protocol['adapter_revision']) and checkout_valid(checkout))
    for args in (['diff', '--quiet', 'HEAD', '--', *MEASURED_PATHS],
                 ['ls-files', '--others', '--exclude-standard', '--', *MEASURED_PATHS]):
        result = subprocess.run(['git', '--no-replace-objects', *args], cwd=ROOT,
                                capture_output=True, timeout=MAX_PROCESS_SECONDS)
        _require(result.returncode == 0 and not result.stdout)


def _protocol(path: Path) -> tuple[bytes, dict[str, Any], int, int]:
    raw, p = read(path)
    _fields(p, {'status', 'benchmark', 'revision', 'model', 'settings', 'policy',
                'adapter_revision', 'max_steps', 'max_loss', 'min_baseline_success', 'tasks'})
    _require(p['status'] == 'approved' and p['revision'] == REVISION
             and _digest(p['adapter_revision'], 40))
    for key in ('benchmark', 'model', 'settings', 'policy'):
        _require(type(p[key]) is str and bool(p[key].strip()))
    _require(type(p['max_steps']) is int and 1 <= p['max_steps'] <= MAX_SECURITY_RECORDS)
    for key in ('max_loss', 'min_baseline_success'):
        _require(type(p[key]) in (float, int) and 0 < p[key] < 1)
    tasks = p['tasks']
    _require(type(tasks) is list and 1 <= len(tasks) <= MAX_SECURITY_RECORDS)
    seen: set[str] = set()
    for task in tasks:
        _fields(task, {'id', 'seed'})
        _require(type(task['id']) is str and bool(task['id']) and task['id'] not in seen
                 and type(task['seed']) is int and 0 <= task['seed'] <= 2147483647)
        seen.add(task['id'])
    settings = json.loads(p['settings'], object_pairs_hook=_pairs)
    _require(type(settings) is dict)
    elapsed, grace = settings.get('elapsed_deadline_seconds'), settings.get('forced_kill_grace_seconds')
    _require(type(elapsed) is int and 1 <= elapsed <= MAX_SECURITY_RECORDS
             and type(grace) is int and 1 <= grace <= MAX_PROCESS_SECONDS)
    return raw, p, int(elapsed), int(grace)


def _write(path: Path, raw: bytes, mode: int = 0o600) -> None:
    _require(len(raw) <= MAX_WIRE_BYTES)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _sync(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def prepare(checkout: Path, protocol: Path, commit: str, destination: Path) -> str:
    checkout, protocol = checkout.resolve(strict=True), protocol.absolute()
    destination = destination.absolute()
    _directory(destination.parent)
    _require(not destination.exists() and not destination.is_symlink() and _digest(commit, 40))
    _require(not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in sys.executable))
    raw, p, _, _ = _protocol(protocol)
    _bindings(raw, p, commit, checkout)
    manifest = dict(version=1, project=str(ROOT), checkout=str(checkout), protocol=str(protocol),
                    destination=str(destination), protocol_commit=commit, protocol_sha256=sha256(raw).hexdigest())
    encoded = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
    digest = sha256(encoded).hexdigest()
    destination.mkdir(mode=0o700)
    for name in ('traces', 'attempts', 'arms'):
        (destination/name).mkdir(mode=0o700)
    for index in range(len(p['tasks'])):
        for arm in ('b', 'g'):
            token = f'{index:04d}{arm}'
            (destination/'traces'/token).mkdir(mode=0o700)
            wrapper = (f'#!{sys.executable}\nimport sys\nsys.path.insert(0, {str(ROOT)!r})\n'
                       'from benchmarks.launch_arm import main\n'
                       'if len(sys.argv) != 1:\n    print("Benchmark launch refused", file=sys.stderr)\n    raise SystemExit(2)\n'
                       f'raise SystemExit(main(["run", {str(destination/"manifest.json")!r}, '
                       f'{digest!r}, {token!r}]))\n')
            _write(destination/'arms'/token, wrapper.encode(), 0o700)
    _sync(destination/'arms'); _sync(destination/'traces'); _sync(destination/'attempts')
    try:
        _write(destination/'manifest.json', encoded)  # Publication comes last.
        _sync(destination); _sync(destination.parent)
    except BaseException:
        (destination/'manifest.json').unlink(missing_ok=True)
        raise
    return digest


def _record(attempt: Path, record: dict[str, Any], state: str, reason: str | None = None) -> None:
    record['state'], record['reason'] = state, reason
    record['history'].append(state)
    temporary = attempt/'status.pending'
    _write(temporary, json.dumps(record, sort_keys=True, separators=(',', ':')).encode())
    os.replace(temporary, attempt/'status.json')
    _sync(attempt)


def _terminal(trace_root: Path, protocol: dict[str, Any], digest: str,
              task: dict[str, Any], arm: str) -> tuple[str, bool]:
    with os.scandir(trace_root) as entries:
        files = [Path(entry.path) for entry in islice(entries, 2)]
    _require(len(files) == 1 and _digest(files[0].stem) and files[0].suffix == '.json')
    raw, trace = read(files[0])
    _require(sha256(raw).hexdigest() == files[0].stem)
    _fields(trace, {'version', 'protocol_sha256', 'adapter_revision', 'id', 'seed', 'arm',
                    'success', 'error', 'security_violations', 'events'})
    _require(type(trace['version']) is int and trace['version'] == 1
             and trace['protocol_sha256'] == digest and trace['adapter_revision'] == protocol['adapter_revision']
             and trace['id'] == task['id'] and trace['arm'] == arm
             and type(trace['seed']) is int and trace['seed'] == task['seed']
             and type(trace['success']) is bool and trace['error'] is None
             and type(trace['security_violations']) is int and trace['security_violations'] == 0)
    events = trace['events']
    _require(type(events) is list and 1 <= len(events) <= MAX_SECURITY_RECORDS)
    for index, event in enumerate(events):
        _fields(event, {'step', 'operation', 'status', 'input_sha256', 'output_sha256'})
        _require(type(event['step']) is int and event['step'] == index
                 and type(event['operation']) is str and bool(event['operation'].strip())
                 and event['status'] in ('ALLOW', 'DENY', 'ERROR')
                 and _digest(event['input_sha256']) and _digest(event['output_sha256']))
    _require(events[-1]['operation'] == 'finish')
    return files[0].stem, bool(trace['success'])


def _stop(process: subprocess.Popen[bytes], grace: int) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def run(manifest_path: Path, manifest_digest: str, token: str) -> int:
    started = time.monotonic()
    raw, m = read(manifest_path)
    _require(_digest(manifest_digest) and sha256(raw).hexdigest() == manifest_digest)
    _fields(m, {'version', 'project', 'checkout', 'protocol', 'destination', 'protocol_commit', 'protocol_sha256'})
    _require(type(m['version']) is int and m['version'] == 1 and m['project'] == str(ROOT)
             and _digest(m['protocol_commit'], 40) and _digest(m['protocol_sha256']))
    for key in ('checkout', 'protocol', 'destination'):
        _require(type(m[key]) is str and Path(m[key]).is_absolute())
    destination, checkout, protocol = Path(m['destination']), Path(m['checkout']), Path(m['protocol'])
    _directory(destination); _directory(destination/'attempts')
    _require(manifest_path.absolute() == destination/'manifest.json')
    protocol_raw, p, elapsed, grace = _protocol(protocol)
    _require(sha256(protocol_raw).hexdigest() == m['protocol_sha256'])
    _require(re.fullmatch('[0-9]{4}[bg]', token) is not None and int(token[:4]) < len(p['tasks']))
    task, arm = p['tasks'][int(token[:4])], 'baseline' if token[-1] == 'b' else 'gated'
    attempt = destination/'attempts'/token
    attempt.mkdir(mode=0o700)  # Exclusive reservation; never removed on failure.
    _sync(attempt.parent)
    record: dict[str, Any] = dict(version=1, token=token, id=task['id'], arm=arm,
                                  manifest_sha256=manifest_digest, history=[], success=None, trace_sha256=None)
    _record(attempt, record, 'claimed')
    process: subprocess.Popen[bytes] | None = None
    try:
        trace_root = destination/'traces'/token
        _directory(trace_root)
        with os.scandir(trace_root) as entries:
            _require(next(entries, None) is None)
        _bindings(protocol_raw, p, m['protocol_commit'], checkout)
        _require(time.monotonic() - started < elapsed)
    except (OSError, ValueError, LaunchError, subprocess.SubprocessError):
        _record(attempt, record, 'setup_refused', 'SETUP.INVALID')
        return 2
    try:
        command = [sys.executable, str(ROOT/'benchmarks/run_agentdojo.py'), '--checkout', str(checkout),
                   '--protocol', str(protocol), '--trace-root', str(trace_root), '--task', task['id'], '--arm', arm]
        process = subprocess.Popen(command, cwd=ROOT, stderr=subprocess.DEVNULL, start_new_session=True)
        _record(attempt, record, 'process_started')
        remaining = elapsed - (time.monotonic() - started)
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, elapsed)
        code = process.wait(timeout=remaining)
        _stop(process, grace)
        process = None
        _require(code == 0)
        trace, success = _terminal(trace_root, p, m['protocol_sha256'], task, arm)
        record['trace_sha256'], record['success'] = trace, success
        _record(attempt, record, 'task_finished')
        return 0
    except subprocess.TimeoutExpired:
        _record(attempt, record, 'infrastructure_failure', 'PROCESS.TIMEOUT')
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            LaunchError, EvidenceError, subprocess.SubprocessError):
        _record(attempt, record, 'infrastructure_failure', 'PROCESS.OR_TRACE.INVALID')
    finally:
        if process is not None:
            _stop(process, grace)
    return 2


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        raise LaunchError('Benchmark launch refused')


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    preparation = commands.add_parser('prepare')
    for name in ('checkout', 'protocol', 'destination'):
        preparation.add_argument('--'+name, type=Path, required=True)
    preparation.add_argument('--protocol-commit', required=True)
    execute = commands.add_parser('run')
    execute.add_argument('manifest', type=Path); execute.add_argument('digest'); execute.add_argument('token')
    try:
        args = parser.parse_args(argv)
        if args.command == 'prepare':
            print(prepare(args.checkout, args.protocol, args.protocol_commit, args.destination))
            return 0
        result = run(args.manifest, args.digest, args.token)
        if result:
            print('Benchmark launch refused', file=sys.stderr)
        return result
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            EvidenceError, LaunchError, subprocess.SubprocessError):
        print('Benchmark launch refused', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
