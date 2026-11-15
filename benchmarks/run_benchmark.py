#!/usr/bin/env python3
"""Synthetic parse/gate microbenchmark; not an agent utility evaluation.

Evaluates representative agent tasks for parse + gate performance,
pass/fail rates, and throughput.
"""

import sys
import time
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / '..'))

from lang.parser import parse
from gate.monitor import Gate, GateError
from lang.limits import MAX_SOURCE_BYTES

BENCH_DIR = Path(__file__).parent


def run_single_task(file_path: Path) -> tuple[bool, dict]:
    """Run a single benchmark task and return (success, stats)."""
    stats = {
        'file': str(file_path),
        'parse_time_ms': 0.0,
        'gate_time_ms': 0.0,
        'acts_count': 0,
        'valid': False,
        'failed_at': None,
        'error': None,
    }

    try:
        with file_path.open('rb') as stream:
            raw = stream.read(MAX_SOURCE_BYTES + 1)
        if len(raw) > MAX_SOURCE_BYTES:
            raise ValueError('Input too large')
        source = raw.decode('utf-8')

        # Parse timing
        parse_start = time.perf_counter()
        acts = parse(source)
        parse_end = time.perf_counter()
        stats['parse_time_ms'] = (parse_end - parse_start) * 1000
        stats['acts_count'] = len(acts)

        # Gate timing
        gate = Gate()
        gate_start = time.perf_counter()
        ok = bool(acts)
        for act in acts:
            try:
                gate.execute(act)
            except GateError:
                ok = False
        audit = gate.audit
        gate_end = time.perf_counter()
        stats['gate_time_ms'] = (gate_end - gate_start) * 1000
        stats['valid'] = ok

        if not ok:
            for entry in audit:
                if entry['status'] == 'DENY':
                    stats['failed_at'] = entry.get('act')
                    stats['error'] = entry.get('error', '')
                    break

    except Exception:
        stats['error'] = 'Input or benchmark evaluation failed'

    return stats['valid'], stats


def main():
    print("=" * 70)
    print("  L Language Synthetic Parse/Gate Microbenchmark")
    print("=" * 70)

    # Find benchmark files
    task_files = sorted(BENCH_DIR.glob('*.tsd'))
    if not task_files:
        print("❌ No benchmark files found in", BENCH_DIR)
        return 1

    print(f"Running {len(task_files)} representative agent task patterns...\n")

    results = []
    for file_path in task_files:
        name = file_path.stem.replace('task_', '').replace('_', ' ').title()
        print(f"[{name}]")
        valid, stats = run_single_task(file_path)
        results.append(stats)

        status = "✅ PASS" if valid else "❌ FAIL"
        print(f"  {status} — acts {stats['acts_count']}, parse {stats['parse_time_ms']:.2f}ms, gate {stats['gate_time_ms']:.2f}ms")
        if stats['error']:
            print(f"    error: {stats['error']}")
        print()

    # Compute summary
    total_acts = sum(r['acts_count'] for r in results)
    valid_count = sum(1 for r in results if r['valid'])
    parse_times = [r['parse_time_ms'] for r in results if r['parse_time_ms'] > 0]
    gate_times = [r['gate_time_ms'] for r in results if r['gate_time_ms'] > 0]

    total_parse_ms = sum(parse_times)
    total_gate_ms = sum(gate_times)

    avg_parse_ms = total_parse_ms / len(parse_times) if parse_times else 0
    avg_gate_ms = total_gate_ms / len(gate_times) if gate_times else 0

    throughput_acts_per_sec = (total_acts / ((total_parse_ms + total_gate_ms) / 1000)) if (total_parse_ms + total_gate_ms) > 0 else 0

    print("=" * 70)
    print("  Summary")
    print("=" * 70)
    print(f"Tasks: {len(task_files)}")
    print(f"Passes: {valid_count}/{len(task_files)}")
    print(f"Acts per task: {total_acts // len(task_files)}")
    print(f"Total parse time: {total_parse_ms:.2f}ms (avg {avg_parse_ms:.2f}ms)")
    print(f"Total gate time: {total_gate_ms:.2f}ms (avg {avg_gate_ms:.2f}ms)")
    print(f"Throughput: {throughput_acts_per_sec:.0f} acts/sec")

    if valid_count == len(task_files):
        print("\n✅ ALL SYNTHETIC CHECKS PASS — agent utility has not been measured")
        return 0
    else:
        print("\n❌ SYNTHETIC CHECK FAILED — a positive-control task was refused")
        return 1


if __name__ == '__main__':
    sys.exit(main())
