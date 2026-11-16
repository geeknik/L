"""Real local CLI lifecycle; temporary fixture policy, never a production signer.

Run ``uv run --locked python demos/owned_host.py`` from the repository root.
All signing is an explicit fixture decision; no model request is auto-approved.
"""

from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gate.local_protocol import JsonLines, ProtocolError, decode_object, encode_object
from lang.limits import MAX_PROCESS_SECONDS


class DemoError(Exception):
    def __init__(self) -> None:
        super().__init__('Owned host demonstration failed')


def _require(condition: bool) -> None:
    if not condition:
        raise DemoError()


def _authority(operation: str, blob: Path, wrapping: Path,
               claims: dict[str, Any] | None = None) -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, '-m', 'cli.authority', operation, '--key-store', str(blob),
         '--wrapping-key', str(wrapping)],
        input=b'' if claims is None else encode_object(claims) + b'\n',
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=MAX_PROCESS_SECONDS)
    _require(completed.returncode == 0 and completed.stdout.endswith(b'\n'))
    return decode_object(completed.stdout[:-1])


@contextmanager
def _host(config: Path) -> Iterator[JsonLines]:
    process = subprocess.Popen([sys.executable, '-m', 'cli.host', '--config', str(config)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, bufsize=0)
    try:
        if process.stdin is None or process.stdout is None:
            raise DemoError()
        with JsonLines(process.stdout.fileno(), process.stdin.fileno()) as stream:
            yield stream
            _require(_exchange(stream, {'op': 'close'}) == {'status': 'ALLOW'})
        _require(process.wait(timeout=MAX_PROCESS_SECONDS) == 0)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=MAX_PROCESS_SECONDS)
        if process.stdin is not None:
            process.stdin.close()
        if process.stdout is not None:
            process.stdout.close()


def _exchange(stream: JsonLines, request: dict[str, Any]) -> dict[str, Any]:
    stream.write(request)
    response = stream.read()
    if response is None:
        raise DemoError()
    return response


def run() -> dict[str, bool]:
    """Exercise installed modules with ephemeral keys and a fixed local effect."""
    with tempfile.TemporaryDirectory(prefix='tsd-owned-host-') as directory:
        root = Path(directory)
        for name in ('blob', 'wrapping', 'host'):
            (root / name).mkdir(mode=0o700)
        blob, wrapping = root / 'blob' / 'authority', root / 'wrapping' / 'key'
        public = _authority('init', blob, wrapping)
        _require(_authority('public', blob, wrapping) == public)
        effect, adapter = root / 'host' / 'effect', root / 'host' / 'adapter.py'
        adapter.write_text(
            'import json,sys\nfrom pathlib import Path\n'
            'request=json.load(sys.stdin)\n'
            'if request != {"arguments":{"text":"fixture"}}: sys.exit(1)\n'
            'Path(sys.argv[1]).write_text("fixture")\n'
            'print(json.dumps({"result":"written"}))\n', encoding='utf-8')
        config = root / 'host' / 'config.json'
        config.write_bytes(encode_object({
            'version': 1, 'model_clearance': 'public', 'input_confidentiality': 'public',
            'trusted_keys': {'operator': {'public_key': public['public_key'],
                'kinds': ['grant', 'endorse', 'revoke'], 'scopes': ['demo.write'],
                'max_integrity': 'high'}},
            'tools': [{'principal': 'demo:writer', 'definition': 'fixed local fixture',
                'argv': [sys.executable, str(adapter), str(effect)],
                'timeout': MAX_PROCESS_SECONDS, 'clearance': 'public',
                'output_confidentiality': 'public'}]}))
        config.chmod(0o600)
        denied = {'status': 'DENY', 'error': 'Operation denied'}
        with _host(config) as stream:
            info = _exchange(stream, {'op': 'info'})
            source = ('DIRECT cap:' + 'a' * 64
                + ' (scope=demo.write, exp=60, from=operator) call tool:(demo:writer, sha256:'
                + info['tools'][0]['hash'] + ') {text: "fixture"}')
            execute = {'op': 'execute', 'source': source, 'inputs': ['untrusted fixture']}
            _require(_exchange(stream, execute) == denied and not effect.exists())
            now = int(time.time())
            claims = dict(version=1, kind='grant', issuer='operator', subject=info['subject'],
                capability='a' * 64, scope='demo.write', tool_principal='demo:writer',
                tool_hash=info['tools'][0]['hash'], integrity='low', action_hash='',
                issued_at=now - 1, expires_at=now + 60, nonce='1' * 64)
            grant = dict(op='apply', **_authority('sign', blob, wrapping, claims))
            _require(_exchange(stream, grant) == {'status': 'ALLOW'})
            _require(_exchange(stream, execute) == {'status': 'ALLOW', 'result': 'written'})
            _require(effect.read_text() == 'fixture')
            effect.unlink()
            revoke = dict(claims, kind='revoke', nonce='2' * 64)
            _require(_exchange(stream, dict(op='apply', **_authority('sign', blob, wrapping, revoke)))
                     == {'status': 'ALLOW'})
            _require(_exchange(stream, execute) == denied and not effect.exists())
            # Separate high-integrity capability requires an exact signed endorsement.
            high_source = source.replace('cap:' + 'a' * 64, 'cap:' + 'b' * 64)
            high_execute = dict(execute, source=high_source)
            high = dict(claims, capability='b' * 64, integrity='high', nonce='3' * 64)
            _require(_exchange(stream, dict(op='apply', **_authority('sign', blob, wrapping, high)))
                     == {'status': 'ALLOW'})
            _require(_exchange(stream, high_execute) == denied and not effect.exists())
            endorsement = dict(high, kind='endorse', nonce='4' * 64,
                               action_hash=sha256(high_source.encode()).hexdigest())
            _require(_exchange(stream, dict(op='apply', **_authority('sign', blob, wrapping, endorsement)))
                     == {'status': 'ALLOW'})
            _require(_exchange(stream, high_execute) == {'status': 'ALLOW', 'result': 'written'})
            _require(effect.read_text() == 'fixture')
            effect.unlink()
            _require(_exchange(stream, high_execute) == denied and not effect.exists())
        with _host(config) as stream:
            fresh = _exchange(stream, {'op': 'info'})
            _require(fresh['subject'] != info['subject'])
            _require(_exchange(stream, grant) == denied)
            _require(_exchange(stream, execute) == denied and not effect.exists())
    _require(not root.exists())
    return {'pregrant_denied': True, 'low_grant_effect': True, 'revocation_denied': True,
            'exact_endorsement_effect': True, 'endorsement_replay_denied': True,
            'restart_replay_denied': True, 'temporary_state_removed': True}


def main() -> int:
    try:
        report = run()
    except (DemoError, ProtocolError, OSError, ValueError, KeyError, TypeError,
            subprocess.TimeoutExpired):
        print('Owned host demonstration failed', file=sys.stderr)
        return 1
    print(encode_object(report).decode('ascii'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
