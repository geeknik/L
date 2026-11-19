"""I7: absent release facts are blockers, never inferred from green unit tests."""
from pathlib import Path
from hashlib import sha256
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts.release_check import blockers, frozen_protocol_matches, measured_source_matches


class TestReleaseCheck(unittest.TestCase):
    def test_release_requires_real_retained_files_even_when_metrics_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory);root=work/'repo';root.mkdir();traces=work/'traces';traces.mkdir()
            def git(*args):
                return subprocess.check_output(['git','-c','user.name=Fixture','-c',
                    'user.email=fixture@example.invalid',*args],cwd=root,stderr=subprocess.DEVNULL).strip()
            git('init');(root/'rust').mkdir();(root/'benchmarks').mkdir()
            (root/'pyproject.toml').write_text('[project]\nversion="1.0.0"\nlicense="MIT"\n')
            (root/'rust/Cargo.toml').write_text('[package]\nversion="1.0.0"\nlicense="MIT"\n')
            (root/'LICENSE').write_text('TEST FIXTURE ONLY')
            git('add','.');git('commit','-m','adapter fixture')
            adapter=git('rev-parse','HEAD').decode()
            protocol=dict(status='approved',benchmark='TEST FIXTURE ONLY',revision='a'*40,
                          model='fixture',settings='frozen',policy='frozen',adapter_revision=adapter,
                          max_steps=2,max_loss=.99,min_baseline_success=.5,tasks=[{'id':'task','seed':0}])
            raw=json.dumps(protocol).encode();digest=sha256(raw).hexdigest()
            (root/'benchmarks/utility_protocol.json').write_bytes(raw)
            git('add','.');git('commit','-m','freeze fixture')
            freeze=git('rev-parse','HEAD').decode()
            run=dict(id='task',seed=0,baseline_success=True,gated_success=True,error=None,security_violations=0)
            for arm in ('baseline','gated'):
                trace=dict(version=1,protocol_sha256=digest,adapter_revision=adapter,id='task',seed=0,
                           arm=arm,success=True,error=None,security_violations=0,events=[dict(
                               step=0,operation='finish',status='ALLOW',input_sha256='a'*64,output_sha256='b'*64)])
                data=json.dumps(trace).encode();trace_digest=sha256(data).hexdigest()
                (traces/(trace_digest+'.json')).write_bytes(data)
                run[arm+'_trace_sha256']=trace_digest
            values=dict(protocol_sha256=digest,protocol_commit=freeze,kind='real-agent',runs=[run])
            results=work/'results.json';results.write_text(json.dumps(values))
            self.assertEqual(blockers(root,results,traces),[])
            self.assertIn('Retained utility trace directory is missing',blockers(root,results))
            values['protocol_commit']='0'*40;results.write_text(json.dumps(values))
            self.assertIn('Utility protocol freeze commit could not be verified',blockers(root,results,traces))
            values['protocol_commit']=freeze;results.write_text(json.dumps(values))
            (traces/(run['baseline_trace_sha256']+'.json')).unlink()
            self.assertIn('Utility evidence is invalid or does not match the frozen protocol',
                          blockers(root,results,traces))

    def test_freeze_requires_exact_committed_protocol_and_ancestry(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            def git(*args):
                return subprocess.check_output(['git','-c','user.name=Fixture','-c',
                    'user.email=fixture@example.invalid',*args],cwd=root,stderr=subprocess.DEVNULL).strip()
            git('init');(root/'benchmarks').mkdir()
            (root/'source').write_text('fixture')
            git('add','.');git('commit','-m','adapter')
            adapter=git('rev-parse','HEAD').decode()
            raw=b'{"status":"approved"}\n'
            (root/'benchmarks/utility_protocol.json').write_bytes(raw)
            git('add','.');git('commit','-m','freeze')
            freeze=git('rev-parse','HEAD').decode()
            self.assertTrue(frozen_protocol_matches(root,raw,freeze,adapter))
            self.assertFalse(frozen_protocol_matches(root,raw+b' ',freeze,adapter))
            self.assertFalse(frozen_protocol_matches(root,raw,'0'*40,adapter))
            blob=git('rev-parse',freeze+':benchmarks/utility_protocol.json').decode()
            self.assertFalse(frozen_protocol_matches(root,raw,blob,adapter))
            (root/'later').write_text('later');git('add','.');git('commit','-m','later')
            later=git('rev-parse','HEAD').decode()
            self.assertFalse(frozen_protocol_matches(root,raw,freeze,later))
            git('checkout','--detach',adapter)
            self.assertFalse(frozen_protocol_matches(root,raw,freeze,adapter))

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
            git('replace', revision, git('rev-parse', 'HEAD').decode())
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


    def test_release_channel_requires_exact_version_pair(self):
        # I7: an RC must never silently pass the final-release metadata check.
        cases = [
            ('final', '1.0.0', '1.0.0', True),
            ('final', '1.0.1', '1.0.1', True),
            ('final', '1.0.1', '1.0.2', False),
            ('final', '1.0.01', '1.0.01', False),
            ('final', '1.1.0', '1.1.0', False),
            ('rc', '1.0.0rc1', '1.0.0-rc.1', True),
            ('final', '1.0.0rc1', '1.0.0-rc.1', False),
            ('rc', '1.0.0', '1.0.0', False),
            ('rc', '1.0.0rc1', '1.0.0-rc.2', False),
            ('rc', '1.0.0rc1', '1.0.0', False),
            ('bogus', '1.0.0', '1.0.0', False),
        ]
        for channel, python_version, rust_version, valid in cases:
            with self.subTest(channel=channel, python=python_version, rust=rust_version):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    (root/'rust').mkdir()
                    (root/'pyproject.toml').write_text(
                        f'[project]\nversion="{python_version}"\nlicense="MIT"\n')
                    (root/'rust/Cargo.toml').write_text(
                        f'[package]\nversion="{rust_version}"\nlicense="MIT"\n')
                    (root/'LICENSE').write_text('TEST FIXTURE ONLY')
                    failures = blockers(root, None, channel=channel)
                    version_errors = [message for message in failures
                                      if 'channel' in message]
                    self.assertEqual(not version_errors, valid)
                    self.assertTrue(failures)  # No evidence: never release-ready.
