"""Run the local release checks; any failed command makes verification fail."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def run_checks(commands: list[list[str]]) -> int:
    env = dict(os.environ, PYTHONPATH=str(ROOT), PYTHONDONTWRITEBYTECODE='1')
    for command in commands:
        print('+ ' + ' '.join(command), flush=True)
        try:
            result = subprocess.run(command, cwd=ROOT, env=env, timeout=300)
        except (OSError, subprocess.TimeoutExpired):
            print('Verification command could not complete', file=sys.stderr)
            return 1
        if result.returncode != 0:
            return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fuzz-cases', type=int, default=500)
    args = parser.parse_args()
    if args.fuzz_cases < 1:
        parser.error('--fuzz-cases must be positive')
    py = sys.executable
    return run_checks([
        [py, 'scripts/generate_limits.py', '--check'],
        [py, '-m', 'mypy', '--strict', '--explicit-package-bases', 'lang', 'gate', 'proxy', 'cli',
         'benchmarks/utility_report.py', 'scripts/check_artifacts.py', 'scripts/release_check.py',
         'demos/dogfood_host.py', 'demos/owned_host.py',
         'benchmarks/run_agentdojo.py', 'benchmarks/agentdojo_host.py'],
        ['cargo', 'test', '--locked', '--manifest-path', 'rust/Cargo.toml'],
        ['cargo', 'clippy', '--locked', '--manifest-path', 'rust/Cargo.toml',
         '--all-targets', '--', '-D', 'warnings'],
        [py, '-W', 'error::ResourceWarning', '-m', 'unittest', 'discover', '-s', 'tests'],
        [py, '-m', 'conformance.runtests'],
        [py, 'demos/run_exploits.py'],
        [py, '-m', 'demos.security_demo'],
        [py, 'conformance/diff_fuzz.py', str(args.fuzz_cases), '--seed', '0'],
        [py, 'benchmarks/run_benchmark.py'],
        [py, 'scripts/check_artifacts.py'],
    ])


if __name__ == '__main__':
    raise SystemExit(main())
