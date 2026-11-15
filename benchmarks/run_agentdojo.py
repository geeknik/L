"""Launch the pinned benchmark worker with no host network, home, or credentials."""
import argparse
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
from typing import Any

from lang.limits import MAX_BENCH_MEMORY_BYTES, MAX_PROCESS_SECONDS, MAX_SECURITY_RECORDS, MAX_WIRE_BYTES

ROOT = Path(__file__).resolve().parents[1]
REVISION = '089ed468cf3ed0322acc66b0211f26d9d90dbf60'


def checkout_valid(checkout: Path) -> bool:
    try:
        head = subprocess.run(['git', '--no-replace-objects', 'rev-parse', 'HEAD'],
            cwd=checkout, capture_output=True, timeout=MAX_PROCESS_SECONDS, check=True)
        clean = subprocess.run(['git', 'status', '--porcelain', '--untracked-files=no'],
            cwd=checkout, capture_output=True, timeout=MAX_PROCESS_SECONDS, check=True)
        for extra in ([], ['--ignored']):
            files = subprocess.run(['git', 'ls-files', '--others', '--exclude-standard',
                                    *extra, '--', 'src'], cwd=checkout,
                capture_output=True, timeout=MAX_PROCESS_SECONDS, check=True)
            if files.stdout.strip():
                return False
        return head.stdout.strip().decode() == REVISION and not clean.stdout.strip()
    except (OSError, ValueError, subprocess.SubprocessError):
        return False


def sandbox_command(checkout: Path, worker_args: list[str],
                    protocol: Path | None = None, evidence: Path | None = None) -> list[str]:
    checkout = checkout.resolve(strict=True)
    python = checkout/'.venv/bin/python'
    if not python.is_file() or not checkout_valid(checkout):
        raise ValueError('Pinned benchmark checkout or interpreter unavailable')
    command = ['/usr/bin/bwrap', '--unshare-all', '--die-with-parent', '--new-session',
               '--cap-drop', 'ALL', '--clearenv', '--ro-bind', '/usr', '/usr',
               '--ro-bind', '/lib', '/lib', '--ro-bind', '/lib64', '/lib64',
               '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp',
               '--setenv', 'PATH', '/usr/bin', '--setenv', 'HOME', '/tmp',
               '--setenv', 'PYTHONPATH', '/workspace',
               '--setenv', 'PYTHONDONTWRITEBYTECODE', '1',
               '--setenv', 'PYTHONPYCACHEPREFIX', '/tmp/python-cache',
               '--setenv', 'OPENBLAS_NUM_THREADS', '1',
               '--setenv', 'OMP_NUM_THREADS', '1',
               '--setenv', 'TSD_BENCH_SANDBOX', '1']
    for name in ('src', '.venv'):
        path = str(checkout/name)
        command += ['--ro-bind', path, path]
    for name in ('lang', 'gate', 'benchmarks'):
        command += ['--ro-bind', str(ROOT/name), '/workspace/'+name]
    if protocol is not None and evidence is not None:
        command += ['--ro-bind', str(protocol.resolve(strict=True)), '/protocol.json',
                    '--bind', str(evidence.resolve(strict=True)), '/evidence']
    command += ['--chdir', '/workspace', str(python), '-u',
                '/workspace/benchmarks/agentdojo_host.py', *worker_args]
    return command


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate protocol field')
        value[key] = item
    return value


def selected_task(protocol: Path, task_id: str) -> tuple[int, int]:
    with protocol.open('rb') as stream:
        raw = stream.read(MAX_WIRE_BYTES+1)
    if len(raw) > MAX_WIRE_BYTES:
        raise ValueError('Protocol exceeds limit')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs)
    if (type(value) is not dict or value.get('status') != 'approved'
            or value.get('revision') != REVISION or type(value.get('tasks')) is not list):
        raise ValueError('Approved protocol required')
    steps = value.get('max_steps')
    if type(steps) is not int or not 1 <= steps <= MAX_SECURITY_RECORDS:
        raise ValueError('Invalid benchmark step budget')
    matches = [task for task in value['tasks'] if type(task) is dict and task.get('id') == task_id]
    if len(matches) != 1 or type(matches[0].get('seed')) is not int or matches[0]['seed'] < 0:
        raise ValueError('Task is not uniquely frozen')
    return matches[0]['seed'], steps


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, required=True)
    parser.add_argument('--catalog', action='store_true')
    parser.add_argument('--protocol', type=Path)
    parser.add_argument('--trace-root', type=Path)
    parser.add_argument('--task')
    parser.add_argument('--arm', choices=('baseline', 'gated'))
    args = parser.parse_args()
    try:
        if args.catalog:
            if any((args.protocol, args.trace_root, args.task, args.arm)):
                raise ValueError('Catalog has no execution options')
            command = sandbox_command(args.checkout, ['--catalog'])
        else:
            if not all((args.protocol, args.trace_root, args.task, args.arm)):
                raise ValueError('Explicit task, arm, protocol and trace directory required')
            seed, steps = selected_task(args.protocol, args.task)
            if args.trace_root.is_symlink() or not args.trace_root.is_dir():
                raise ValueError('Existing real trace directory required')
            command = sandbox_command(args.checkout, [
                '--task', args.task, '--arm', args.arm, '--seed', str(seed),
                '--max-steps', str(steps), '--protocol', '/protocol.json', '--trace-root', '/evidence'],
                args.protocol, args.trace_root)
        resource.setrlimit(resource.RLIMIT_AS, (MAX_BENCH_MEMORY_BYTES, MAX_BENCH_MEMORY_BYTES))
        resource.setrlimit(resource.RLIMIT_CPU, (MAX_PROCESS_SECONDS, MAX_PROCESS_SECONDS))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        os.execv(command[0], command)
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        print('Benchmark launch refused', file=sys.stderr)
        return 2
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
