"""I6/I7: benchmark setup must not silently bypass isolation or protocol gates."""
import json
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from benchmarks.run_agentdojo import REVISION, checkout_valid, sandbox_command, selected_task
from lang.limits import MAX_SECURITY_RECORDS


class TestBenchmarkLauncher(unittest.TestCase):
    def test_command_has_no_home_network_or_credential_mount(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'.venv/bin').mkdir(parents=True)
            (root/'.venv/bin/python').touch()
            with patch('benchmarks.run_agentdojo.checkout_valid', return_value=True):
                command=sandbox_command(root,['--catalog'])
        self.assertEqual(command[0], '/usr/bin/bwrap')
        for flag in ('--unshare-all','--clearenv','--new-session','--die-with-parent'):
            self.assertIn(flag,command)
        self.assertNotIn('--share-net',command)
        self.assertNotIn('/home',command)
        self.assertNotIn('--ro-bind-try',command)
        self.assertNotIn('/', command)
        self.assertEqual(command[-1], '--catalog')
        self.assertIn('/tmp/python-cache', command)

    def test_extra_source_or_ignored_bytecode_is_rejected(self):
        def result(raw=b''):
            return subprocess.CompletedProcess(['git'], 0, raw, b'')
        for source, ignored in ((b'src/extra.py', b''), (b'', b'src/__pycache__/extra.pyc')):
            with patch('benchmarks.run_agentdojo.subprocess.run', side_effect=[
                    result(REVISION.encode()), result(), result(source), result(ignored)]):
                self.assertFalse(checkout_valid(Path('/fixture')))

    def test_wrong_checkout_fails_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                sandbox_command(Path(directory), ['--catalog'])

    def test_only_unique_approved_task_and_bounded_steps(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'protocol.json'
            base=dict(status='approved',revision=REVISION,max_steps=30,
                      tasks=[dict(id='suite/user_task_0',seed=0)])
            path.write_text(json.dumps(base))
            self.assertEqual(selected_task(path,'suite/user_task_0'),(0,30))
            for change in (dict(status='unapproved'),dict(max_steps=True),
                           dict(max_steps=MAX_SECURITY_RECORDS+1),dict(tasks=base['tasks']*2),dict(revision='0'*40)):
                path.write_text(json.dumps(base|change))
                with self.assertRaises(ValueError):
                    selected_task(path,'suite/user_task_0')
