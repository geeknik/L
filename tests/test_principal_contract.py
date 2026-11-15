"""Shared principal grammar (I4/I5/I7) and parser limit (I6) regressions.

The Rust probe is compiled from current source in a temporary directory, so
these tests cannot accidentally validate a stale cargo binary.
"""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from lang.limits import MAX_SOURCE_BYTES, MAX_TOKENS, MAX_ACTS
from lang.parser import ParseError, parse, tokenize


ROOT = Path(__file__).resolve().parents[1]


class TestPrincipalContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        directory = Path(cls.temp.name)
        cls.probe = directory / 'principal-probe'
        modules = '\n'.join(
            f'#[path={json.dumps(str(ROOT / "rust" / "src" / (name + ".rs")))}] mod {name};'
            for name in ('ast', 'parser', 'limits')
        )
        source = modules + r'''
use std::io::Read;
fn main() {
    let mut source = String::new();
    std::io::stdin().read_to_string(&mut source).unwrap();
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode == "tokens" {
        match parser::tokenize(&source) {
            Ok(tokens) => println!("{}", tokens.len() - 1),
            Err(_) => std::process::exit(2),
        }
        return;
    }
    let acts = match parser::parse(&source) {
        Ok(acts) => acts,
        Err(_) => std::process::exit(2),
    };
    if mode == "count" { println!("{}", acts.len()); return; }
    for act in acts {
        let (reference, signer) = match act {
            ast::Act::Commit(a) => (a.reference, None),
            ast::Act::Endorse(a) => (a.reference, Some(a.signer)),
            ast::Act::Assert(a) => (a.evidence, None),
            _ => panic!("unsupported test fixture act"),
        };
        println!("{}\t{}", reference.principal.id, reference.principal.hash);
        if let Some(signer) = signer { println!("{}\t{}", signer.id, signer.hash); }
    }
}
'''
        path = directory / 'probe.rs'
        path.write_text(source)
        subprocess.run(
            ['rustc', '--edition=2024', '-Awarnings', str(path), '-o', str(cls.probe)],
            check=True, capture_output=True, text=True, timeout=60,
        )

    def _rust(self, source: str, mode: str = '') -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.probe), mode], input=source, capture_output=True,
            text=True, timeout=10,
        )

    def test_shared_principal_vectors(self) -> None:
        vectors = json.loads((ROOT / 'conformance' / 'principal_vectors.json').read_text())
        for vector in vectors:
            with self.subTest(vector=vector['name'], invariant=vector['invariant']):
                result = self._rust(vector['source'])
                if not vector['accept']:
                    with self.assertRaises(ParseError):
                        parse(vector['source'])
                    self.assertEqual(result.returncode, 2, result.stderr)
                    continue
                acts = parse(vector['source'])
                self.assertEqual(len(acts), 1)
                act = acts[0]
                reference = act.reference
                self.assertEqual(reference.principal.id, vector['principal'])
                self.assertEqual(reference.principal.hash, vector['principal_hash'])
                expected = f"{vector['principal']}\t{vector['principal_hash']}\n"
                if 'signer' in vector:
                    self.assertEqual(act.signer.id, vector['signer'])
                    self.assertEqual(act.signer.hash, '0' * 64)
                    expected += f"{vector['signer']}\t{'0' * 64}\n"
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)

    def test_source_byte_limit(self) -> None:
        for source in [' ' * MAX_SOURCE_BYTES, '#' + 'é' * ((MAX_SOURCE_BYTES - 2) // 2) + 'x']:
            self.assertEqual(len(source.encode('utf-8')), MAX_SOURCE_BYTES)
            self.assertEqual(parse(source), [])
            self.assertEqual(self._rust(source, 'count').returncode, 0)
            with self.assertRaises(ParseError):
                parse(source + 'x')
            self.assertEqual(self._rust(source + 'x', 'count').returncode, 2)
        with self.assertRaises(ParseError):
            parse('\ud800')

    def test_token_limit(self) -> None:
        source = 'x ' * MAX_TOKENS
        self.assertEqual(len(tokenize(source)) - 1, MAX_TOKENS)
        result = self._rust(source, 'tokens')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(MAX_TOKENS))
        with self.assertRaises(ParseError):
            tokenize(source + 'x')
        self.assertEqual(self._rust(source + 'x', 'tokens').returncode, 2)

    def test_act_limit(self) -> None:
        unit = 'COMMIT (sha256:aaaaaaaa)\n'
        source = unit * MAX_ACTS
        self.assertEqual(len(parse(source)), MAX_ACTS)
        result = self._rust(source, 'count')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(MAX_ACTS))
        with self.assertRaises(ParseError):
            parse(source + unit)
        self.assertEqual(self._rust(source + unit, 'count').returncode, 2)

    def test_unicode_inside_payload_is_preserved(self) -> None:
        source = 'ASSERT ev:(user:g, sha256:aaaaaaaa) data:"\u2003\x1c"'
        self.assertEqual(parse(source)[0].data.content, '\u2003\x1c')
        self.assertEqual(self._rust(source, 'count').returncode, 0)
