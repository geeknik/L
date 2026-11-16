"""Private inherited-stdio entry point for the project-owned enforcing host."""

import argparse
from pathlib import Path
import sys

from gate.custody import CustodyError
from gate.service import ConfigurationError, load_session, serve


def main() -> int:
    parser = argparse.ArgumentParser(description='Local enforcing host')
    parser.add_argument('--config', required=True, type=Path)
    args = parser.parse_args()
    try:
        session = load_session(args.config)
        return serve(session, sys.stdin.fileno(), sys.stdout.fileno())
    except (ConfigurationError, CustodyError, OSError, ValueError):
        print('Host unavailable', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
