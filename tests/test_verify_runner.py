"""I7: CI must stop on failed commands, including abnormal termination."""
import contextlib
import io
import subprocess
import unittest
from unittest.mock import patch
from scripts.verify import run_checks


class TestVerifyRunner(unittest.TestCase):
    def test_failed_command_stops_remaining_checks(self):
        for code in (1, 2, -9):
            with self.subTest(code=code), contextlib.redirect_stdout(io.StringIO()):
                with patch('scripts.verify.subprocess.run',
                           return_value=subprocess.CompletedProcess(['test'], code)) as run:
                    self.assertEqual(run_checks([['first'], ['never']]), 1)
                    self.assertEqual(run.call_count, 1)

    def test_success_runs_every_check(self):
        with contextlib.redirect_stdout(io.StringIO()):
            with patch('scripts.verify.subprocess.run',
                       return_value=subprocess.CompletedProcess(['test'], 0)) as run:
                self.assertEqual(run_checks([['first'], ['second']]), 0)
                self.assertEqual(run.call_count, 2)

    def test_missing_tool_and_timeout_fail(self):
        for error in (FileNotFoundError(), subprocess.TimeoutExpired(['test'], 1)):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                with patch('scripts.verify.subprocess.run', side_effect=error):
                    self.assertEqual(run_checks([['test']]), 1)
