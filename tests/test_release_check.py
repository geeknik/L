"""I7: absent release facts are blockers, never inferred from green unit tests."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.release_check import blockers, measured_source_matches


class TestReleaseCheck(unittest.TestCase):
    def test_empty_checkout_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch('scripts.release_check.subprocess.run',
                       return_value=subprocess.CompletedProcess(['git'],1,b'',b'')):
                failures=blockers(Path(directory),None)
        self.assertIn('Package metadata could not be verified',failures)
        self.assertIn('No source commit exists to identify the release',failures)
        self.assertGreaterEqual(len(failures),3)

    def test_missing_license_evidence_and_dirty_tree_block(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'rust').mkdir(); (root/'benchmarks').mkdir()
            (root/'pyproject.toml').write_text('[project]\nversion="1.0.0"\n')
            (root/'rust/Cargo.toml').write_text('[package]\nversion="1.0.0"\n')
            (root/'benchmarks/utility_protocol.json').write_text('{"status":"unapproved"}')
            with patch('scripts.release_check.subprocess.run',
                       return_value=subprocess.CompletedProcess(['git'],0,b'?? source.py\n',b'')):
                failures=blockers(root,None)
        self.assertIn('Repository license selection and LICENSE file are missing',failures)
        self.assertIn('Real paired agent-utility results are missing',failures)
        self.assertIn('Release source tree is not clean and fully tracked',failures)

    def test_measured_revision_requires_unchanged_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(['git', '-c', 'user.name=Fixture', '-c',
                    'user.email=fixture@example.invalid', *args], cwd=root,
                    stderr=subprocess.DEVNULL).strip()
            git('init')
            (root/'gate').mkdir(); (root/'benchmarks').mkdir()
            (root/'gate/runtime.py').write_text('original\n')
            git('add', '.'); git('commit', '-m', 'measured fixture')
            revision = git('rev-parse', 'HEAD').decode()
            self.assertTrue(measured_source_matches(root, revision))
            self.assertFalse(measured_source_matches(root, '0'*40))
            self.assertFalse(measured_source_matches(root, '--all'))
            (root/'benchmarks/utility_protocol.json').write_text('{}')
            (root/'README.md').write_text('evidence documentation')
            git('add', '.'); git('commit', '-m', 'evidence fixture')
            self.assertTrue(measured_source_matches(root, revision))
            (root/'gate/runtime.py').write_text('changed\n')
            git('add', '.'); git('commit', '-m', 'changed implementation')
            self.assertFalse(measured_source_matches(root, revision))

    def test_placeholder_empty_or_conflicting_license_is_blocked(self):
        for python_license, rust_license, text in [
                ('pending', 'pending', 'placeholder'), ('MIT', 'MIT', ''),
                ('MIT', 'Apache-2.0', 'fixture'), ('MIT', '', 'fixture')]:
            with self.subTest(python=python_license, rust=rust_license, text=text):
                with tempfile.TemporaryDirectory() as directory:
                    root=Path(directory); (root/'rust').mkdir()
                    (root/'pyproject.toml').write_text(
                        f'[project]\nversion="1.0.0"\nlicense="{python_license}"\n')
                    (root/'rust/Cargo.toml').write_text(
                        f'[package]\nversion="1.0.0"\nlicense="{rust_license}"\n')
                    (root/'LICENSE').write_text(text)
                    with patch('scripts.release_check.subprocess.run', return_value=
                               subprocess.CompletedProcess(['git'],0,b'',b'')):
                        failures=blockers(root,None)
                    self.assertIn('Repository license selection and LICENSE file are missing',failures)
