"""I7: artifact scans refuse local state and traversal paths."""
import unittest
from scripts.check_artifacts import check_paths


class TestArtifactPaths(unittest.TestCase):
    def test_reject_local_state_and_unsafe_paths(self):
        for name in ('/tmp/source.py', '../secret', 'pkg/.env', 'pkg/.env.local',
                     'pkg/.git/config', 'pkg/.venv/key', 'pkg/rust/target/binary',
                     'pkg/__pycache__/a.pyc', 'pkg/AGENTS.md', 'pkg/CLAUDE.md'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                check_paths([name])

    def test_accept_runtime_and_contract_sources(self):
        check_paths(['gate/security.py', 'lang/wire.py', 'pkg/rust/Cargo.lock',
                     'pkg/spec/wire.md', 'pkg/tests/test_security_gate.py'])
