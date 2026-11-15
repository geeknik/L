"""Final 1.0 preflight. Missing decisions or real evidence are release blockers."""
import argparse
from pathlib import Path
import re
import subprocess
import sys
import tomllib

from benchmarks.utility_report import EvidenceError, evaluate, read

ROOT = Path(__file__).resolve().parents[1]
MEASURED_PATHS = ['lang', 'gate', 'proxy', 'cli', 'rust', 'pyproject.toml',
                  'uv.lock', 'benchmarks', 'scripts',
                  ':(exclude)benchmarks/utility_protocol.json']


def measured_source_matches(root: Path, revision: object) -> bool:
    """Permit evidence/docs commits, but never stale executable code or dependencies."""
    if not isinstance(revision, str) or re.fullmatch('[0-9a-f]{40}', revision) is None:
        return False
    commit = subprocess.run(['git', 'cat-file', '-t', revision], cwd=root,
                            capture_output=True, timeout=10)
    if commit.returncode or commit.stdout.strip() != b'commit':
        return False
    diff = subprocess.run(['git', 'diff', '--quiet', revision, 'HEAD', '--', *MEASURED_PATHS],
                          cwd=root, capture_output=True, timeout=10)
    return diff.returncode == 0


def blockers(root: Path, results: Path | None) -> list[str]:
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
    args = parser.parse_args()
    failures = blockers(ROOT,args.results)
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
