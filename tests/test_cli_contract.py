"""I6/I7: bounded CLI ingress and single-pass timing contract."""
import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from benchmarks.run_benchmark import main as benchmark_main, run_single_task
from lang.limits import MAX_SOURCE_BYTES
from lang.parser import parse


class TestCliContract(unittest.TestCase):
    def test_oversized_file_is_sanitized_and_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'large.tsd'
            path.write_text('PRIVATE_MARKER' + 'x' * MAX_SOURCE_BYTES)
            for output in ('text', 'json'):
                result = subprocess.run([sys.executable, '-m', 'cli.tsd_scanner',
                                         str(path), '--output', output],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn('PRIVATE_MARKER', result.stdout + result.stderr)

    def test_benchmark_parses_once_and_times_only_gate(self):
        fixture = Path(__file__).resolve().parents[1] / 'benchmarks/task_file_access.tsd'
        with patch('benchmarks.run_benchmark.parse', wraps=parse) as parse_mock:
            with patch('gate.monitor.Gate.scan', side_effect=AssertionError('reparse')):
                valid, stats = run_single_task(fixture)
        self.assertTrue(valid)
        self.assertEqual(parse_mock.call_count, 1)
        self.assertGreater(stats['acts_count'], 0)

    def test_empty_benchmark_is_not_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'empty.tsd'
            path.write_text('# no acts')
            self.assertFalse(run_single_task(path)[0])

    def test_benchmark_command_fails_on_rejected_positive_control(self):
        for source in ('# empty', 'invalid syntax',
                       'GRANT cap:abcdef00 (scope=fs.read, exp=0, from=user:g)'):
            with self.subTest(source=source), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'task.tsd'
                path.write_text(source)
                with patch('benchmarks.run_benchmark.BENCH_DIR', Path(tmp)):
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(benchmark_main(), 1)
