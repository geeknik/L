"""Local callback demo: ephemeral authority, no network or exported private key.

Run from the repository root with ``python -m demos.security_demo``.
This is a semantic gate integration example, not a utility benchmark.
"""
from hashlib import sha256
import time

from gate.authority import Authority, TrustKey
from gate.host import HostError, LabeledInput, LocalHost, ToolRegistration
from lang.labels import Label


def main() -> int:
    authority = Authority()
    trust = TrustKey(authority.public_key, frozenset(('grant', 'endorse', 'revoke')),
                     frozenset(('demo.read',)), 'high')
    effects: list[dict[str, str | int]] = []

    def local_read(params: dict[str, str | int]) -> str:
        effects.append(params)
        return 'local demonstration result'

    tool = ToolRegistration('demo:reader', b'demo read-only callback v1', 'public', local_read)
    host = LocalHost({'operator': trust}, [tool], model_clearance='public')
    source = ('DIRECT cap:' + 'a'*64
              + ' (scope=demo.read, exp=60, from=operator) call tool:(demo:reader, sha256:'
              + tool.content_hash + ') {item: "sample"}')
    now = int(time.time())
    grant: dict[str, object] = dict(
        version=1, kind='grant', issuer='operator', subject=host.subject,
        capability='a'*64, scope='demo.read', tool_principal=tool.principal,
        tool_hash=tool.content_hash, integrity='high', action_hash='',
        issued_at=now, expires_at=now+60, nonce='1'*64)
    host.apply(authority.sign(grant))
    inputs = [LabeledInput('untrusted retrieved text', Label(('retrieval',), 'low'))]
    try:
        host.run(inputs, lambda _: source)
    except HostError as error:
        if error.code != 'INTEGRITY.DENIED' or effects:
            return 1
    else:
        return 1
    approval = dict(grant, kind='endorse', nonce='2'*64,
                    action_hash=sha256(source.encode()).hexdigest())
    host.apply(authority.sign(approval))
    output = host.run([], lambda _: source)
    if effects != [{'item': 'sample'}] or output is None or output.label.integrity != 'low':
        return 1
    host.apply(authority.sign(dict(grant, kind='revoke', nonce='3'*64)))
    try:
        host.run([], lambda _: source)
    except HostError as error:
        if error.code != 'AUTH.REVOKED' or len(effects) != 1:
            return 1
    else:
        return 1
    print('PASS: unendorsed input refused; exact approved callback ran once; revocation refused retry.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
