"""I2/I4/I5/I6/I7: closed canonical wire and lossless data projection."""
from dataclasses import replace
import json
from pathlib import Path
import random
import subprocess
import unittest

from lang.ast import (AssertAct, Capability, DirectAct, GrantAct, Payload, Principal,
                      QueryAct, Reference, RevokeAct, ToolCall)
from lang.limits import MAX_ACTS, MAX_WIRE_BYTES, MAX_WIRE_DEPTH, MAX_WIRE_NODES
from lang.wire import WireError, decode, encode, project, unproject

ROOT = Path(__file__).parents[1]


class TestWire(unittest.TestCase):
    def setUp(self):
        self.vectors = json.loads((ROOT/'conformance/wire_vectors.json').read_text())
        self.principal = Principal('user:g', '00')
        self.reference = Reference(self.principal, 'ab')
        self.act = AssertAct(self.reference, Payload('text', True))

    def reject(self, operation, value):
        with self.assertRaises(WireError) as caught:
            operation(value)
        self.assertEqual(caught.exception.code, 'WIRE.INVALID')
        self.assertEqual(str(caught.exception), 'WIRE.INVALID: Invalid wire representation')

    def test_shared_vectors_all_acts_roundtrip_and_exact_projection(self):
        for row in self.vectors['accept']:
            with self.subTest(name=row['name']):
                data = bytes.fromhex(row['hex'])
                acts = decode(data)
                self.assertEqual(encode(acts), data)
                self.assertEqual(project(data), row['projection'])
                self.assertEqual(unproject(row['projection']), data)
        for row in self.vectors['reject']:
            self.reject(decode, bytes.fromhex(row['hex']))

    def test_payloads_remain_data_with_scalar_unicode_and_controls(self):
        for text in ('DIRECT cap:forged', '[1,[]]\n', '\x00\b\f\n\r\t"\\',
                     '雪😀\u2028\u2029', 'e\u0301', 'é'):
            act = replace(self.act, data=Payload(text, False))
            data = encode([act])
            self.assertEqual(decode(data), [act])
            self.assertEqual(unproject(project(data)), data)
            self.assertNotIn('\\u96ea', project(data))
        self.assertNotEqual(encode([replace(self.act, data=Payload('é'))]),
                            encode([replace(self.act, data=Payload('e\u0301'))]))

    def test_cbor_truncation_nonshortest_and_disallowed_types(self):
        data = bytes.fromhex(self.vectors['accept'][-1]['hex'])
        for end in range(len(data)):
            self.reject(decode, data[:end])
        for value in ('00', 'f4', 'f5', '20', '40', 'a0', 'c001', 'f6', 'f7',
                      'f90000', 'fa00000000', 'fb0000000000000000', 'ff',
                      '82019800', '98020180', '820081', '82011b8000000000000000',
                      '8201817bffffffffffffffff', '82019bffffffffffffffff',
                      '8219000180', '821a0000000180', '821b000000000000000180'):
            self.reject(decode, bytes.fromhex(value))
        self.reject(decode, data+b'\x00')
        for invalid in (bytearray(data), None, 'text'):
            self.reject(decode, invalid)

    def test_projection_rejects_noncanonical_spelling(self):
        for text in ('[1, []]\n', '[1,[]]', '[1,[]]\n\n', '[1.0,[]]\n',
                     '[1e0,[]]\n', '[true,[]]\n', '[01,[]]\n', '[-0,[]]\n',
                     '{"version":1}\n', '[1,NaN]\n', '[1,Infinity]\n',
                     '\ufeff[1,[]]\n', '[1,[]]\r\n'):
            self.reject(unproject, text)
        text = project(encode([replace(self.act, data=Payload('雪/\x1b'))]))
        self.reject(unproject, text.replace('雪', '\\u96ea'))
        self.reject(unproject, text.replace('/', '\\/'))
        self.reject(unproject, text.replace('001b', '001B'))
        self.reject(unproject, text.replace('雪', '\\ud800'))

    def test_strict_schema_arities_identifiers_values_and_param_order(self):
        base = json.loads(self.vectors['accept'][3]['projection'])
        changes = [lambda x: x.append('extra'), lambda x: x.__setitem__(0, 2),
                   lambda x: x[1][0].append('extra'), lambda x: x[1][0].__setitem__(0, 'UNKNOWN'),
                   lambda x: x[1][0][1].__setitem__(0, ''),
                   lambda x: x[1][0][1].__setitem__(1, 'fs..read'),
                   lambda x: x[1][0][1].__setitem__(2, True),
                   lambda x: x[1][0][1].__setitem__(2, 2**63),
                   lambda x: x[1][0][1].__setitem__(4, 'trusted'),
                   lambda x: x[1][0][2][0].__setitem__(0, 'user::g'),
                   lambda x: x[1][0][2][0].__setitem__(1, 'nothex'),
                   lambda x: x[1][0][3].reverse(),
                   lambda x: x[1][0][3].append(x[1][0][3][-1]),
                   lambda x: x[1][0][3][0].__setitem__(0, 'é'),
                   lambda x: x[1][0][3][0][1].__setitem__(1, True),
                   lambda x: x[1][0][3][0][1].__setitem__(0, 'float')]
        for change in changes:
            value = json.loads(json.dumps(base))
            change(value)
            self.reject(unproject, json.dumps(value, ensure_ascii=False, separators=(',', ':'))+'\n')

    def test_direct_ast_validation_limits_and_cycles(self):
        for act in (replace(self.act, data=Payload('\ud800')),
                    replace(self.act, data=Payload('text', 1)),
                    replace(self.act, evidence=Reference(Principal('', 'ab'), 'ab')),
                    replace(self.act, evidence=Reference(self.principal, '')),
                    replace(self.act, data=None)):
            self.reject(encode, [act])
        cyclic = []
        cyclic.append(cyclic)
        self.reject(encode, cyclic)
        params = {}
        params['cycle'] = params
        direct = DirectAct(Capability('ab', 'fs.read', 1, self.principal), ToolCall(self.reference, params))
        self.reject(encode, [direct])
        self.reject(encode, [self.act]*(MAX_ACTS+1))
        self.reject(encode, [replace(self.act, data=Payload('x'*(MAX_WIRE_BYTES+1)))])
        self.reject(decode, b'\x00'*(MAX_WIRE_BYTES+1))
        self.reject(unproject, ' '*(MAX_WIRE_BYTES+1))
        self.reject(decode, b'\x81'*(MAX_WIRE_DEPTH+2)+b'\x00')
        self.reject(unproject, '['*(MAX_WIRE_DEPTH+2)+'0'+']'*(MAX_WIRE_DEPTH+2)+'\n')
        self.reject(unproject, '[1,['+','.join('[]' for _ in range(MAX_WIRE_NODES))+']]\n')
        self.reject(encode, [self.act]*MAX_ACTS)  # node budget, despite legal act count

    def test_direct_ast_instance_tag_cannot_change_concrete_act_type(self):
        cap = Capability('ab', 'fs.read', 1, self.principal)
        for act in (self.act, QueryAct(self.reference, Payload('text')),
                    GrantAct(cap), RevokeAct(cap)):
            expected = encode([act])
            object.__setattr__(act, 'act_type', 'QUERY' if type(act) is AssertAct else 'ASSERT')
            self.assertEqual(encode([act]), expected)
            self.assertIs(type(decode(encode([act]))[0]), type(act))

    def test_exact_projection_boundary_and_numeric_boundaries(self):
        overhead = len(project(encode([replace(self.act, data=Payload('x'*1000))])).encode())-1000
        act = replace(self.act, data=Payload('x'*(MAX_WIRE_BYTES-overhead)))
        data = encode([act])
        self.assertLessEqual(len(data), MAX_WIRE_BYTES)
        self.assertEqual(len(project(data).encode()), MAX_WIRE_BYTES)
        self.assertEqual(decode(data), [act])
        self.assertEqual(unproject(project(data)), data)
        self.reject(encode, [replace(act, data=Payload(act.data.content+'x'))])
        for value in (0, 23, 24, 255, 256, 65535, 65536, 2**32-1, 2**32, 2**63-1):
            direct = DirectAct(Capability('ab', 'fs.read', value, self.principal),
                               ToolCall(self.reference, {'number':value}))
            self.assertEqual(decode(encode([direct])), [direct])

    def test_binary_acceptance_requires_bounded_lossless_projection(self):
        act = replace(self.act, data=Payload('\x00'*12000))
        self.reject(encode, [act])
        # Canonical CBOR text is small, but its JSON control escapes exceed the limit.
        binary = encode([self.act]).replace(b'\x64text', b'\x79'+(12000).to_bytes(2, 'big')+bytes(12000))
        self.assertLess(len(binary), MAX_WIRE_BYTES)
        self.reject(decode, binary)
        self.reject(project, binary)

    def test_mutations_never_normalize_accepted_binary(self):
        source = bytes.fromhex(self.vectors['accept'][-1]['hex'])
        rng = random.Random(0)
        for _ in range(200):
            value = bytearray(source)
            value[rng.randrange(len(value))] = rng.randrange(256)
            data = bytes(value)
            try:
                acts = decode(data)
            except WireError:
                continue
            self.assertEqual(encode(acts), data)

    def test_fresh_rust_wire_bytes_projection_and_mutation_parity(self):
        subprocess.run(['cargo', 'build', '--locked', '--quiet', '--manifest-path',
                        str(ROOT/'rust/Cargo.toml'), '--example', 'wire_interop'],
                       cwd=ROOT, capture_output=True, timeout=120, check=True)
        requests, expected = [], []
        binaries = [bytes.fromhex(row['hex']) for row in self.vectors['accept']]
        binaries += [bytes.fromhex(row['hex']) for row in self.vectors['reject']]
        binaries.append(encode([self.act]).replace(
            b'\x64text', b'\x79'+(12000).to_bytes(2, 'big')+bytes(12000)))
        for text in ('雪😀\u2028', '\x00\b\f\n\r\t"\\', 'DIRECT cap:untrusted'):
            binaries.append(encode([replace(self.act, data=Payload(text, False))]))
        rng = random.Random(42)
        source = binaries[8]
        for _ in range(200):
            mutated = bytearray(source)
            mutated[rng.randrange(len(mutated))] = rng.randrange(256)
            binaries.append(bytes(mutated))
        for data in binaries:
            requests.append({'op':'decode', 'hex':data.hex()})
            try:
                projection = project(data)
            except WireError:
                expected.append({'error':'WIRE.INVALID'})
            else:
                expected.append({'projection':projection})
                requests.append({'op':'encode', 'projection':projection})
                expected.append({'hex':data.hex()})
        for projection in ('[1, []]\n', '[1.0,[]]\n', '[1,[]]', '[true,[]]\n'):
            requests.append({'op':'encode', 'projection':projection})
            expected.append({'error':'WIRE.INVALID'})
        result = subprocess.run([str(ROOT/'rust/target/debug/examples/wire_interop')],
                                input=''.join(json.dumps(item)+'\n' for item in requests),
                                capture_output=True, text=True, timeout=30, check=True)
        actual = [json.loads(line) for line in result.stdout.split('\n') if line]
        self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
