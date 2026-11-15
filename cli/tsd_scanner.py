#!/usr/bin/env python3
"""TSD CLI scanner - command-line interface for L language validation."""

import argparse
import sys
from pathlib import Path

from lang.parser import parse
from gate.monitor import Gate, GateError
from lang.limits import MAX_SOURCE_BYTES

def main() -> None:
    """Scan one L source file and exit with a status that reflects the result.

    Exit codes: 0 = validation passed, 1 = validation failed (the scan
    completed and reported failures), 2 = unexpected error (bad arguments,
    unreadable file, internal exception). A scanner that exits 0 on
    "VALIDATION FAILED" is a false green gate.
    """
    parser = argparse.ArgumentParser(description='TSD (Trust-Typed Language) Scanner')
    parser.add_argument('file', type=Path, help='Path to L language source file')
    parser.add_argument('--output', choices=['text', 'json'], default='text', help='Output format')

    args = parser.parse_args()

    try:
        # Read source file
        with open(args.file, 'rb') as f:
            raw = f.read(MAX_SOURCE_BYTES + 1)
        if len(raw) > MAX_SOURCE_BYTES:
            raise ValueError('Input too large')
        source = raw.decode('utf-8')

        # Parse and validate
        acts = parse(source)
        gate = Gate()
        ok = True
        for act in acts:
            try:
                gate.execute(act)
            except GateError:
                ok = False
        audit = gate.audit

        if args.output == 'json':
            import json
            result = {
                'file': str(args.file),
                'valid': ok,
                'acts': len(acts),
                'audit': audit
            }
            print(json.dumps(result, indent=2))
        else:
            print(f"File: {args.file}")
            print(f"Valid: {ok}")
            print(f"Acts parsed: {len(acts)}")
            print("\nAudit trail:")
            for entry in audit:
                status = entry['status']
                error = entry.get('error', '')
                print(f"  [{status}] {entry['act']}")
                if error:
                    print(f"    ❌ {error}")
            if ok:
                print("\n✅ VALIDATION PASSED")
            else:
                print("\n❌ VALIDATION FAILED")

        # Exit status reflects the validation result for BOTH output formats.
        sys.exit(0 if ok else 1)

    except Exception:
        print("Error: unable to validate input", file=sys.stderr)
        sys.exit(2)

if __name__ == '__main__':
    main()
