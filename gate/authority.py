"""Signed local authority statements. Private keys never enter the gate.

This module delegates Ed25519 operations to libsodium through PyNaCl. Statements are
verified over their exact bytes, not a reconstructed or normalized JSON object.
"""

from dataclasses import dataclass, field
import json
import re
from typing import Mapping

from nacl.bindings import crypto_core_ed25519_is_valid_point
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from gate.keystore import decrypt_key, encrypt_key
from lang.limits import MAX_AUTHORITY_BYTES, MAX_SECURITY_RECORDS

DOMAIN = b'TSD-AUTHORITY-v1\x00'
LEVELS = ('low', 'medium', 'high', 'critical')
KINDS = frozenset(('grant', 'endorse', 'revoke'))
I64_MAX = 9223372036854775807
_HEX = re.compile(r'[0-9a-f]{64}\Z')
_SCOPE = re.compile(r'[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*\Z')
_PRINCIPAL = re.compile(r'[A-Za-z0-9_]+(?::[A-Za-z0-9_]+)*\Z')


class AuthorityError(Exception):
    """Fixed, payload-free failure from the authority boundary."""

    def __init__(self) -> None:
        super().__init__('Invalid authority statement')
        self.code = 'AUTH.INVALID'


def is_hash(value: object) -> bool:
    return isinstance(value, str) and _HEX.fullmatch(value) is not None


def is_identity(value: object) -> bool:
    if type(value) is not str or not value:
        return False
    try:
        return len(value.encode('utf-8')) <= MAX_AUTHORITY_BYTES
    except UnicodeError:
        return False


@dataclass(frozen=True)
class Envelope:
    payload: bytes = field(repr=False)
    signature: bytes = field(repr=False)


@dataclass(frozen=True)
class TrustKey:
    public_key: bytes = field(repr=False)
    kinds: frozenset[str]
    scopes: frozenset[str]
    max_integrity: str

    def __post_init__(self) -> None:
        if (type(self.public_key) is not bytes or len(self.public_key) != 32
                or not crypto_core_ed25519_is_valid_point(self.public_key)
                or not isinstance(self.kinds, frozenset) or not self.kinds <= KINDS
                or not isinstance(self.scopes, frozenset)
                or len(self.scopes) > MAX_SECURITY_RECORDS
                or any(not is_identity(s) or _SCOPE.fullmatch(s) is None for s in self.scopes)
                or self.max_integrity not in LEVELS):
            raise AuthorityError()


@dataclass(frozen=True)
class Claims:
    version: int
    kind: str
    issuer: str
    subject: str
    capability: str
    scope: str
    tool_principal: str
    tool_hash: str
    integrity: str
    action_hash: str
    issued_at: int
    expires_at: int
    nonce: str


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise AuthorityError()
        result[key] = value
    return result


def _reject_number(value: str) -> object:
    raise AuthorityError()


def _parse_integer(value: str) -> int:
    if value == '-0':
        raise AuthorityError()
    return int(value)


def decode_claims(payload: bytes) -> Claims:
    """Validate bounded untrusted claims; this alone grants no authority."""
    if type(payload) is not bytes or not 0 < len(payload) <= MAX_AUTHORITY_BYTES:
        raise AuthorityError()
    try:
        values = json.loads(payload.decode('utf-8'), object_pairs_hook=_pairs,
                            parse_constant=_reject_number, parse_float=_reject_number,
                            parse_int=_parse_integer)
        if not isinstance(values, dict) or set(values) != set(Claims.__dataclass_fields__):
            raise AuthorityError()
        for key in ('version', 'issued_at', 'expires_at'):
            if type(values[key]) is not int or not 0 <= values[key] <= I64_MAX:
                raise AuthorityError()
        if values['version'] != 1 or values['issued_at'] >= values['expires_at']:
            raise AuthorityError()
        for key in set(values) - {'version', 'issued_at', 'expires_at'}:
            if type(values[key]) is not str:
                raise AuthorityError()
            # serde/Rust strings are Unicode scalar values, not lone surrogates.
            values[key].encode('utf-8')
        if (values['kind'] not in KINDS or values['integrity'] not in LEVELS
                or not values['issuer'] or not values['subject']
                or _SCOPE.fullmatch(values['scope']) is None
                or _PRINCIPAL.fullmatch(values['tool_principal']) is None
                or values['tool_principal'] == 'anon'):
            raise AuthorityError()
        if any(not is_hash(values[key]) for key in ('capability', 'tool_hash', 'nonce')):
            raise AuthorityError()
        if values['kind'] == 'endorse':
            if not is_hash(values['action_hash']):
                raise AuthorityError()
        elif values['action_hash'] != '':
            raise AuthorityError()
        return Claims(**values)
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise AuthorityError() from None


def verify(envelope: Envelope, trusted_keys: Mapping[str, TrustKey]) -> Claims:
    """Authenticate exact statement bytes and the key's provisioned authority."""
    if (not isinstance(envelope, Envelope) or type(envelope.signature) is not bytes
            or len(envelope.signature) != 64
            or not crypto_core_ed25519_is_valid_point(envelope.signature[:32])):
        raise AuthorityError()
    claims = decode_claims(envelope.payload)
    key = trusted_keys.get(claims.issuer)
    if (not isinstance(key, TrustKey) or claims.kind not in key.kinds
            or claims.scope not in key.scopes
            or LEVELS.index(claims.integrity) > LEVELS.index(key.max_integrity)):
        raise AuthorityError()
    try:
        VerifyKey(key.public_key).verify(DOMAIN + envelope.payload, envelope.signature)
    except (BadSignatureError, ValueError, TypeError):
        raise AuthorityError() from None
    return claims


class Authority:
    """Signer utility for a trusted authority process, never a host gate.

    Keys are generated in memory and exported only as authenticated ciphertext.
    Deployment storage and wrapping-key custody remain operator responsibilities.
    """

    def __init__(self) -> None:
        self._key = SigningKey.generate()

    @property
    def public_key(self) -> bytes:
        return self._key.verify_key.encode()

    def export_encrypted(self, wrapping_key: bytes) -> bytes:
        """Return an encrypted blob; never write or export a plaintext seed."""
        return encrypt_key(self._key, wrapping_key)

    @classmethod
    def load_encrypted(cls, blob: bytes, wrapping_key: bytes) -> 'Authority':
        """Restore only signing identity, not session or authorization state."""
        key = decrypt_key(blob, wrapping_key)
        authority = cls.__new__(cls)
        authority._key = key
        return authority

    def sign(self, values: Mapping[str, object]) -> Envelope:
        try:
            payload = json.dumps(dict(values), sort_keys=True, separators=(',', ':'),
                                 ensure_ascii=True, allow_nan=False).encode('utf-8')
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise AuthorityError() from None
        decode_claims(payload)
        return Envelope(payload, self._key.sign(DOMAIN + payload).signature)
