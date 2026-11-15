#!/usr/bin/env python3
"""Differential fuzz test for TSD Python and Rust implementations.

Compares every parsed AST field and gate result, including parser rejection.
Unexpected exceptions and Rust process failures fail the run independently.

This is a required part of the v1.0 verification scope (differential fuzzing
between Python and Rust for the one-parse property).
"""

import os
import argparse
import json
import random
import subprocess
import sys
import tempfile

# Add the project root to Python path so imports resolve.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from lang.parser import parse, ParseError
from lang.ast import AssertAct, QueryAct, DirectAct, CommitAct, GrantAct, RevokeAct, EndorseAct
from gate.monitor import Gate, GateError

RUST_BIN = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'rust', 'target', 'debug', 'tsd-rust'
)


def generate_random_program(max_acts: int = 5, rng: random.Random | None = None) -> str:
    """Generate a random L program composed of the 7 act types."""
    rng = rng if rng is not None else random.Random()
    lines = []
    for _ in range(rng.randint(1, max_acts)):
        act = rng.choice(['ASSERT', 'QUERY', 'DIRECT', 'COMMIT', 'GRANT', 'REVOKE', 'ENDORSE'])
        h1 = f'{rng.randrange(16**64):064x}'
        h2 = f'{rng.randrange(16**64):064x}'
        short = rng.choice(['g', 'a', 'b', '9c1e', 'abcdef00', '00112233'])
        p = f'user:{short}'
        if act in ('ASSERT', 'QUERY'):
            lines.append(f"{act} ev:({p}, sha256:{h1}) data:<opaque, sample>")
        elif act == 'DIRECT':
            scope = rng.choice(['fs.read', 'fs.write', 'net.api'])
            exp = rng.choice([0, 30, 60, 3600])
            # Varied tool-call params to exercise the shared numeric/contract:
            # small ints, 8+ digit decimals (HASH tokenized as int), i64 boundary,
            # quoted strings, bare identifiers, multiline strings with escapes.
            # Keys are unique so random.sample never produces duplicate keys.
            param_pool = [
                'path: "/logs"',
                'path2: "/etc/passwd"',
                'count: 123',
                'count2: 12345678',
                'count3: 9223372036854775807',
                'count4: 0',
                'mode: rw',
                'mode2: read',
                'name: test',
                'msg: "hello\\nworld"',
                'json: "{""key"":""value""}"',
                'quote: """"',
                'multiline: "hello\n  world"',
                'idx: 42',
                'flag: true',
                'large: 100000000000',
            ]
            n_params = rng.randint(1, 3)
            chosen = rng.sample(param_pool, min(n_params, len(param_pool)))
            param_block = '{' + ', '.join(chosen) + '}'
            lines.append(
                f"DIRECT cap:{h1} (scope={scope}, exp={exp}, from={p}) "
                f"call tool:(srv:abc, sha256:{h2}) {param_block}"
            )
        elif act == 'COMMIT':
            lines.append(f"COMMIT (user:{short}, sha256:{h1})")
        elif act in ('GRANT', 'REVOKE'):
            scope = rng.choice(['fs.read', 'fs.write', 'net.api'])
            exp = rng.choice([0, 60])
            lines.append(f"{act} cap:{h1} (scope={scope}, exp={exp}, from={p})")
        elif act == 'ENDORSE':
            signer = rng.choice(['admin', 'reviewer:top', 'user:x', 'reviewer', 'top_secret'])
            lines.append(f"ENDORSE (user:{short}, sha256:{h1}) by:{signer}")
    return '\n'.join(lines) + '\n'


def canonical_params(act) -> str:
    """Canonical param dump: sorted key=value lines, value tagged s:/i: for type.
    Unambiguous: backslash and newline are escaped inside string values so a
    multiline string and separate key=value lines never collide.
    """
    params = getattr(getattr(act, 'call', None), 'params', None) or {}
    lines = []
    for k in sorted(params):
        v = params[k]
        if isinstance(v, str):
            escaped = v.replace('\\', '\\\\').replace('\n', '\\n')
            lines.append(f"P {k} s:{escaped}")
        elif isinstance(v, int):
            lines.append(f"P {k} i:{v}")
        else:
            lines.append(f"P {k} ?:missing")
    return "\n".join(lines)


def canonical_act(act) -> list:
    """Complete typed AST projection defined in spec/ast-comparison.md."""
    def principal(p):
        return [p.id, p.hash]

    def reference(r):
        return [principal(r.principal), r.content_hash]

    def capability(c):
        return [c.cap_hash, c.scope, c.exp, principal(c.from_principal), c.integrity_level]

    if isinstance(act, (AssertAct, QueryAct)):
        return [act.act_type, reference(act.evidence), [act.data.content, act.data.is_opaque]]
    if isinstance(act, DirectAct):
        params = []
        for key, value in sorted(act.call.params.items()):
            if type(value) is str:
                tagged = ['str', value]
            elif type(value) is int:
                tagged = ['int', value]
            else:
                raise TypeError('Unsupported AST parameter type')
            params.append([key, tagged])
        return ['DIRECT', capability(act.capability), reference(act.call.tool), params]
    if isinstance(act, CommitAct):
        return ['COMMIT', reference(act.reference)]
    if isinstance(act, (GrantAct, RevokeAct)):
        return [act.act_type, capability(act.capability)]
    if isinstance(act, EndorseAct):
        return ['ENDORSE', reference(act.reference), principal(act.signer)]
    raise TypeError('Unsupported AST act type')


def run_python(src: str) -> list:
    """Expected parse rejection is data; all other parser faults propagate."""
    try:
        acts = parse(src)
    except ParseError:
        return ['PARSE_ERROR']
    g = Gate()
    records = []
    for act in acts:
        try:
            g.execute(act)
            decision = ['ALLOW']
        except GateError as e:
            decision = ['DENY', e.code]
        records.append([canonical_act(act), decision])
    return ['OK', records]


def run_rust(src: str) -> list:
    with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', suffix='.tsd', delete=False) as f:
        f.write(src)
        fname = f.name
    try:
        proc = subprocess.run(
            [RUST_BIN, '--emit-ast', fname],
            capture_output=True, text=True, timeout=30
        )
        if proc.returncode != 0:
            raise RuntimeError(f'Rust oracle failed with exit status {proc.returncode}: {proc.stderr.strip()}')
        result = json.loads(proc.stdout)
        if result != ['PARSE_ERROR'] and not (
            isinstance(result, list) and len(result) == 2 and result[0] == 'OK'
            and isinstance(result[1], list)
        ):
            raise ValueError('Invalid Rust oracle result envelope')
        return result
    finally:
        os.unlink(fname)


H = 'a' * 64
REPLAY_CORPUS = (
    ('I5', f'COMMIT (admin, sha256:{H})'),
    ('I5', f'COMMIT (user:123, sha256:{H})'),
    ('I5', f'COMMIT (srv:abcdef00, sha256:{H})'),
    ('I5', f'ENDORSE (user:g, sha256:{H}) by:reviewer'),
    ('I7', f'ENDORSE (user:g, sha256:{H})'),
    ('I7', f'ASSERT wrong:(user:g, sha256:{H}) data:<x>'),
    ('I7', f'ASSERT ev:(user:g, sha256:{H}) data:<unfinished'),
    ('I7', f'GRANT cap:{H} (scope=fs.read, exp=1, exp=2, from=user:g)'),
    ('I7', f'GRANT cap:{H} (scope=fs.read, exp=9223372036854775808, from=user:g)'),
)


def run_diff(iterations: int = 200, seed: int = 0, replay: tuple[str, ...] = ()):
    rng = random.Random(seed)
    programs = [src for _, src in REPLAY_CORPUS] + list(replay)
    for i in range(iterations):
        program = generate_random_program(max_acts=rng.randint(1, 5), rng=rng)
        # Invalid suffix proves a malformed later act rejects the whole input.
        if i % 3 == 0:
            program += '\nCOMMIT ('
        elif i % 3 == 1:
            program = program[:rng.randrange(len(program))]
        programs.append(program)
    mismatches = []
    for i, prog in enumerate(programs):
        py_out = run_python(prog)
        rust_out = run_rust(prog)
        if py_out != rust_out:
            mismatches.append((i, prog, py_out, rust_out))
            if len(mismatches) >= 10:
                break
    return mismatches


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('iterations', type=int, nargs='?', default=200)
    parser.add_argument('--seed', type=int, default=0)
    parser.add_argument('--replay', action='append', default=[], metavar='FILE')
    args = parser.parse_args()
    if args.iterations < 0:
        parser.error('iterations must be non-negative')
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    subprocess.run(['cargo', 'build', '--locked', '--quiet', '--manifest-path',
                    os.path.join(root, 'rust', 'Cargo.toml')], check=True)
    replay = []
    for path in args.replay:
        with open(path, encoding='utf-8') as source:
            replay.append(source.read())
    print(f'Differential seed: {args.seed}', flush=True)
    mismatches = run_diff(iterations=args.iterations, seed=args.seed, replay=tuple(replay))
    if mismatches:
        print(f"DIFF FUZZ FOUND {len(mismatches)} MISMATCHES:")
        for i, prog, py_out, rust_out in mismatches:
            print(f"\n--- mismatch #{i} ---\nPROGRAM:\n{prog}")
            print(f"PYTHON:\n{py_out}")
            print(f"RUST:\n{rust_out}")
        return 1
    print(f"DIFF FUZZ PASSED: {args.iterations} generated programs plus {len(REPLAY_CORPUS) + len(replay)} replay cases; complete ASTs and gate decisions compared.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
