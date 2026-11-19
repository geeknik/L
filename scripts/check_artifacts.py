"""Build and install distribution artifacts away from the source checkout."""
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = {'.git', '.venv', '__pycache__', '.code-review-graph', 'AGENTS.md',
             'CLAUDE.md', '.env', 'target', '.mypy_cache', '.local', 'release-evidence'}


def check_paths(names: list[str]) -> None:
    for name in names:
        path = Path(name)
        if (path.is_absolute() or '..' in path.parts
                or any(part in FORBIDDEN or part.startswith('.env.') for part in path.parts)
                or path.suffix in ('.pyc', '.pyo')):
            raise ValueError('Unsafe distribution content')


def run(args: list[str], cwd: Path) -> None:
    env = dict(os.environ)
    env.pop('PYTHONPATH', None)
    subprocess.run(args, cwd=cwd, env=env, check=True, timeout=300)


def main() -> int:
    try:
        with tempfile.TemporaryDirectory(prefix='tsd-artifact-') as temporary:
            work = Path(temporary)
            output = work/'dist'
            run(['uv', 'build', '--out-dir', str(output)], ROOT)
            wheels = list(output.glob('*.whl'))
            sources = list(output.glob('*.tar.gz'))
            if len(wheels) != 1 or len(sources) != 1:
                raise ValueError('Missing distribution')
            with zipfile.ZipFile(wheels[0]) as wheel:
                check_paths(wheel.namelist())
                for required in ('gate/security.py', 'gate/host.py', 'gate/process.py',
                                 'gate/keystore.py', 'gate/custody.py', 'gate/service.py',
                                 'gate/local_protocol.py', 'cli/host.py', 'cli/authority.py',
                                 'lang/wire.py', 'cli/tsd_scanner.py'):
                    if required not in wheel.namelist():
                        raise ValueError('Incomplete wheel')
            with tarfile.open(sources[0]) as source:
                members = source.getmembers()
                check_paths([item.name for item in members])
                if any(not (item.isfile() or item.isdir()) for item in members):
                    raise ValueError('Unsafe source member')
                if not any(item.isfile() and Path(item.name).parts[1:] == ('SECURITY.md',)
                           for item in members):
                    raise ValueError('Source distribution is missing SECURITY.md')
            environment = work/'environment'
            run(['uv', 'venv', '--python', sys.executable, str(environment)], work)
            requirements = work/'requirements.txt'
            run(['uv', 'export', '--locked', '--no-dev', '--no-emit-project',
                 '--output-file', str(requirements), '--quiet'], ROOT)
            python = environment/'bin/python'
            run(['uv', 'pip', 'sync', '--python', str(python), str(requirements)], work)
            run(['uv', 'pip', 'install', '--python', str(python), '--no-deps', str(wheels[0])], work)
            smoke = (
                'from gate.authority import Authority; from gate.host import LocalHost; '
                'from gate.process import ModelProcess; from gate.keystore import KeyStoreError; '
                'from lang.wire import encode,decode,project,unproject; '
                'from lang.parser import parse; '
                'acts=parse("COMMIT (user:g, sha256:abcdef00)"); '
                'blob=encode(acts); assert decode(blob)==acts; '
                'assert unproject(project(blob))==blob; assert len(Authority().public_key)==32'
            )
            run([str(python), '-I', '-c', smoke], work)
            run([str(environment/'bin/tsd-scan'), '--help'], work)
            run([str(environment/'bin/tsd-proxy'), '--help'], work)
            run([str(environment/'bin/tsd-host'), '--help'], work)
            run([str(environment/'bin/tsd-authority'), '--help'], work)
        print('Distribution build, contents and isolated install verified')
        return 0
    except (OSError, ValueError, subprocess.SubprocessError, tarfile.TarError,
            zipfile.BadZipFile):
        print('Distribution verification failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
