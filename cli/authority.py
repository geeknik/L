"""Offline operator CLI. Never install authority material in the model host."""

import argparse
import base64
from pathlib import Path
import sys
from typing import NoReturn

from gate.authority import AuthorityError
from gate.custody import CustodyError, init_authority, load_authority
from gate.local_protocol import JsonLines, ProtocolError


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise CustodyError()


def main(argv: list[str] | None = None) -> int:
    try:
        parser = _Parser(description='Offline authority custody and explicit signing')
        parser.add_argument('operation', choices=('init', 'public', 'sign'))
        parser.add_argument('--key-store', required=True, type=Path)
        parser.add_argument('--wrapping-key', required=True, type=Path)
        args = parser.parse_args(argv)
        authority = (init_authority(args.key_store, args.wrapping_key)
                     if args.operation == 'init'
                     else load_authority(args.key_store, args.wrapping_key))
        with JsonLines(sys.stdin.fileno(), sys.stdout.fileno()) as stream:
            if args.operation == 'sign':
                claims = stream.read()
                if claims is None or stream.read() is not None:
                    raise CustodyError()
                envelope = authority.sign(claims)
                stream.write({'payload': base64.b64encode(envelope.payload).decode('ascii'),
                              'signature': base64.b64encode(envelope.signature).decode('ascii')})
            else:
                stream.write({'public_key': authority.public_key.hex()})
        return 0
    except (CustodyError, AuthorityError, ProtocolError, OSError, ValueError):
        sys.stderr.write('Authority operation failed\n')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
