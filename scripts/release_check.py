"""Final 1.0 preflight. Missing decisions or real evidence are release blockers."""
import argparse
from pathlib import Path
import re
import subprocess
import sys
import tomllib

from benchmarks.utility_report import EvidenceError, evaluate, read, verify_traces
from lang.limits import MAX_WIRE_BYTES

ROOT = Path(__file__).resolve().parents[1]
MEASURED_PATHS = ['lang', 'gate', 'proxy', 'cli', 'rust', 'pyproject.toml',
                  'uv.lock', 'benchmarks', 'scripts',
                  ':(exclude)benchmarks/utility_protocol.json']


def measured_source_matches(root: Path, revision: object) -> bool:
    """Permit evidence/docs commits, but never stale executable code or dependencies."""
    if not isinstance(revision, str) or re.fullmatch('[0-9a-f]{40}', revision) is None:
        return False
    commit = subprocess.run(['git', '--no-replace-objects', 'cat-file', '-t', revision], cwd=root,
                            capture_output=True, timeout=10)
    if commit.returncode or commit.stdout.strip() != b'commit':
        return False
    diff = subprocess.run(['git', '--no-replace-objects', 'diff', '--quiet', revision, 'HEAD', '--', *MEASURED_PATHS],
                          cwd=root, capture_output=True, timeout=10)
    return diff.returncode == 0


def frozen_protocol_matches(root: Path, raw: bytes, freeze: object, adapter: object) -> bool:
    """Check retained Git binding, not historical approval or measurement honesty."""
    if len(raw) > MAX_WIRE_BYTES:
        return False
    for revision in (freeze, adapter):
        if type(revision) is not str or re.fullmatch('[0-9a-f]{40}', revision) is None:
            return False
        commit = subprocess.run(['git','--no-replace-objects','cat-file','-t',revision],
                                cwd=root,capture_output=True,timeout=10)
        if commit.returncode or commit.stdout.strip() != b'commit':
            return False
    for older, newer in ((adapter,freeze),(freeze,'HEAD')):
        ancestry = subprocess.run(['git','--no-replace-objects','merge-base','--is-ancestor',
                                   str(older),str(newer)],cwd=root,capture_output=True,timeout=10)
        if ancestry.returncode:
            return False
    path = str(freeze)+':benchmarks/utility_protocol.json'
    size = subprocess.run(['git','--no-replace-objects','cat-file','-s',path],
                          cwd=root,capture_output=True,timeout=10)
    if size.returncode or not size.stdout.strip().isdigit() or int(size.stdout) > MAX_WIRE_BYTES:
        return False
    blob = subprocess.run(['git','--no-replace-objects','cat-file','blob',path],
                          cwd=root,capture_output=True,timeout=10)
    return blob.returncode == 0 and blob.stdout == raw


def blockers(root: Path, results: Path | None, trace_root: Path | None = None) -> list[str]:
    failures: list[str] = []
    try:
        python = tomllib.loads((root/'pyproject.toml').read_text())['project']
        rust = tomllib.loads((root/'rust/Cargo.toml').read_text())['package']
        if python['version'] != '1.0.0' or rust['version'] != '1.0.0':
            failures.append('Final version must be 1.0.0 in both package manifests')
        license_id = python.get('license')
        if (license_id not in ('MIT', 'Apache-2.0', 'LicenseRef-Proprietary')
                or rust.get('license') != license_id or not (root/'LICENSE').is_file()
                or not (root/'LICENSE').read_text().strip()):
            failures.append('Repository license selection and LICENSE file are missing')
    except (OSError,ValueError,KeyError,TypeError,AttributeError):
        failures.append('Package metadata could not be verified')
    try:
        raw, protocol = read(root/'benchmarks/utility_protocol.json')
        if results is None:
            failures.append('Real paired agent-utility results are missing')
        else:
            _, values = read(results)
            if not evaluate(raw,protocol,values)['pass']:
                failures.append('Agent-utility acceptance criterion did not pass')
            if trace_root is None:
                failures.append('Retained utility trace directory is missing')
            else:
                verify_traces(raw,protocol,values,trace_root)
            if not frozen_protocol_matches(root,raw,values['protocol_commit'],protocol['adapter_revision']):
                failures.append('Utility protocol freeze commit could not be verified')
            if not measured_source_matches(root, protocol['adapter_revision']):
                failures.append('Utility evidence does not match the release implementation')
        if type(protocol) is not dict or protocol.get('status') != 'approved':
            failures.append('Benchmark model, tasks, policy and threshold are not approved/frozen')
    except (EvidenceError,OSError,ValueError,TypeError,UnicodeError,RecursionError,subprocess.SubprocessError):
        failures.append('Utility evidence is invalid or does not match the frozen protocol')
    try:
        head = subprocess.run(['git','rev-parse','--verify','HEAD'],cwd=root,
                              capture_output=True,timeout=10)
        if head.returncode != 0:
            failures.append('No source commit exists to identify the release')
        status = subprocess.run(['git','status','--porcelain','--untracked-files=all'],
                                cwd=root,capture_output=True,timeout=10)
        if status.returncode != 0 or status.stdout.strip():
            failures.append('Release source tree is not clean and fully tracked')
    except (OSError,subprocess.SubprocessError):
        failures.append('Release source revision could not be verified')
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results',type=Path,help='Real paired utility evidence JSON')
    parser.add_argument('--trace-root',type=Path,help='Directory containing retained trace artifacts')
    args = parser.parse_args()
    failures = blockers(ROOT,args.results,args.trace_root)
    if failures:
        print('RELEASE BLOCKED')
        for failure in failures:
            print('- '+failure)
        return 1
    # Preflight cannot replace execution of the full software/artifact checks.
    result = subprocess.run([sys.executable,'scripts/verify.py'],cwd=ROOT)
    if result.returncode:
        return 1
    print('Technical release preflight passed; publishing still requires maintainer approval and trace review')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
