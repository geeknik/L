"""I5/I7: full AST comparison must detect semantic drift and unexpected faults."""

import random
import json
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from conformance import diff_fuzz as oracle
from lang.ast import Capability, DirectAct, Payload, Principal, Reference, ToolCall
from lang.parser import parse
from lang.limits import MAX_SOURCE_BYTES

H = 'a' * 64


class TestCompleteASTOracle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        subprocess.run(['cargo', 'build', '--locked', '--quiet', '--manifest-path',
                        str(root / 'rust/Cargo.toml')], check=True)

    def test_reference_and_payload_differences_do_not_collide(self):
        original = parse(f'ASSERT ev:(user:g, sha256:{H}) data:<first>')[0]
        r = original.evidence
        variants = [
            replace(original, evidence=replace(r, content_hash='b' * 64)),
            replace(original, evidence=replace(r, principal=replace(r.principal, id='user:x'))),
            replace(original, evidence=replace(r, principal=replace(r.principal, hash='b' * 64))),
            replace(original, data=Payload('second', True)),
            replace(original, data=Payload('first', False)),
        ]
        for other in variants:
            with self.subTest(other=other):
                self.assertNotEqual(oracle.canonical_act(original), oracle.canonical_act(other))

    def test_every_capability_field_is_compared(self):
        p = Principal('user:g', '0' * 64)
        cap = Capability(H, 'fs.read', 60, p)
        original = DirectAct(cap, ToolCall(Reference(p, H), {}))
        variants = [replace(cap, cap_hash='b' * 64), replace(cap, scope='fs.write'),
                    replace(cap, exp=61), replace(cap, from_principal=replace(p, id='user:x')),
                    replace(cap, from_principal=replace(p, hash='b' * 64)),
                    replace(cap, integrity_level='high')]
        for other in variants:
            self.assertNotEqual(oracle.canonical_act(original),
                                oracle.canonical_act(replace(original, capability=other)))

    def test_signer_fields_are_compared(self):
        act = parse(f'ENDORSE (user:g, sha256:{H}) by:admin')[0]
        for signer in [replace(act.signer, id='reviewer'), replace(act.signer, hash='b' * 64)]:
            self.assertNotEqual(oracle.canonical_act(act),
                                oracle.canonical_act(replace(act, signer=signer)))

    def test_parameter_types_and_multiline_values_do_not_collide(self):
        prefix = f'DIRECT cap:{H} (scope=fs.read, exp=1, from=user:g) call tool:(srv:x, sha256:{H}) '
        pairs = [('{a: "x\nP b i:1"}', '{a: "x", b: 1}'),
                 ('{a: "1"}', '{a: 1}'), ('{a: "x\\n"}', '{a: "x\n"}')]
        for first, second in pairs:
            self.assertNotEqual(oracle.run_python(prefix + first), oracle.run_python(prefix + second))
            for text in (prefix + first, prefix + second):
                self.assertEqual(oracle.run_python(text), oracle.run_rust(text))

    def test_all_act_fields_round_trip_with_rust(self):
        programs = [
            f'ASSERT ev:(user:g, sha256:{H}) data:<line\n\t雪\x01>',
            f'QUERY ev:(user:g, sha256:{H}) data:"quoted"',
            f'DIRECT cap:{H} (scope=fs.read, exp=0, from=user:g) call tool:(srv:x, sha256:{H}) {{n: 42}}',
            f'COMMIT (user:g, sha256:{H})',
            f'GRANT cap:{H} (scope=fs.read, exp=60, from=user:g)',
            f'REVOKE cap:{H} (scope=fs.write, exp=1, from=user:x)',
            f'ENDORSE (user:g, sha256:{H}) by:admin',
        ]
        for source in programs:
            with self.subTest(source=source):
                self.assertEqual(oracle.run_python(source), oracle.run_rust(source))
        self.assertEqual(oracle.run_python('\n'.join(programs)), oracle.run_rust('\n'.join(programs)))

    def test_expected_rejects_compare_equal(self):
        for source in ('COMMIT (', f'ASSERT ev:(user:g, sha256:{H}) data:<unfinished'):
            self.assertEqual(oracle.run_python(source), ['PARSE_ERROR'])
            self.assertEqual(oracle.run_rust(source), ['PARSE_ERROR'])

    def test_python_crash_is_not_parse_rejection(self):
        with patch.object(oracle, 'parse', side_effect=RuntimeError('synthetic fault')):
            with self.assertRaises(RuntimeError):
                oracle.run_python('anything')

    def test_rust_process_failures_are_not_parse_rejection(self):
        for status in (1, 101, -11):
            result = subprocess.CompletedProcess([], status, '["PARSE_ERROR"]', 'synthetic fault')
            with patch.object(oracle.subprocess, 'run', return_value=result):
                with self.assertRaises(RuntimeError):
                    oracle.run_rust('anything')
        with patch.object(oracle.subprocess, 'run', side_effect=subprocess.TimeoutExpired([], 30)):
            with self.assertRaises(subprocess.TimeoutExpired):
                oracle.run_rust('anything')

    def test_invalid_oracle_output_is_a_failure(self):
        for output in ('', 'not-json', '{}', '["OK"]'):
            with patch.object(oracle.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, output, '')):
                with self.assertRaises(ValueError):
                    oracle.run_rust('anything')

    def test_seed_is_reproducible(self):
        first, second = random.Random(17), random.Random(17)
        self.assertEqual([oracle.generate_random_program(rng=first) for _ in range(10)],
                         [oracle.generate_random_program(rng=second) for _ in range(10)])

    def test_replay_cases_have_explicit_expected_outcomes(self):
        for invariant, source in oracle.REPLAY_CORPUS:
            expected = 'OK' if invariant == 'I5' else 'PARSE_ERROR'
            with self.subTest(source=source):
                python = oracle.run_python(source)
                self.assertEqual(python[0], expected)
                self.assertEqual(python, oracle.run_rust(source))

    def test_legacy_emit_remains_available(self):
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8') as source:
            source.write(f'COMMIT (user:g, sha256:{H})')
            source.flush()
            result = subprocess.run([oracle.RUST_BIN, '--emit', source.name], capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout, 'ACTS=1\nCOMMIT ALLOW\n')

    def test_rust_file_size_limit_and_boundary(self):
        with tempfile.NamedTemporaryFile() as source:
            # Sparse file proves the CLI need not allocate the whole input.
            source.truncate(MAX_SOURCE_BYTES * 128)
            source.flush()
            result = subprocess.run([oracle.RUST_BIN, '--emit-ast', source.name],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout), ['PARSE_ERROR'])
            result = subprocess.run([oracle.RUST_BIN, source.name],
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            source.seek(0)
            source.write(b' ' * MAX_SOURCE_BYTES)
            source.truncate()
            source.flush()
            result = subprocess.run([oracle.RUST_BIN, '--emit-ast', source.name],
                                    capture_output=True, text=True, check=True, timeout=10)
            self.assertEqual(json.loads(result.stdout), ['OK', []])

    def test_rust_missing_file_is_not_parse_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([oracle.RUST_BIN, '--emit-ast', str(Path(directory) / 'missing')],
                                    capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('PARSE_ERROR', result.stdout)


if __name__ == '__main__':
    unittest.main()
