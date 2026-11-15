"""Bounded encrypted key blobs; storage and wrapping-key custody are host-owned."""

from nacl.bindings import crypto_sign_SEEDBYTES
from nacl.exceptions import CryptoError
from nacl.secret import SecretBox
from nacl.signing import SigningKey

_VERSION = b'TSD-KEYSTORE-v1\x00'
_PLAIN_SIZE = len(_VERSION) + crypto_sign_SEEDBYTES
_BLOB_SIZE = len(_VERSION) + SecretBox.NONCE_SIZE + SecretBox.MACBYTES + _PLAIN_SIZE


class KeyStoreError(Exception):
    def __init__(self) -> None:
        self.code = 'KEYSTORE.INVALID'
        super().__init__('Invalid encrypted authority key')


def _box(wrapping_key: bytes) -> SecretBox:
    if type(wrapping_key) is not bytes or len(wrapping_key) != SecretBox.KEY_SIZE:
        raise KeyStoreError()
    return SecretBox(wrapping_key)


def encrypt_key(key: SigningKey, wrapping_key: bytes) -> bytes:
    """Encrypt a library signing key using a fresh library-generated nonce."""
    if not isinstance(key, SigningKey):
        raise KeyStoreError()
    box = _box(wrapping_key)
    try:
        return _VERSION + bytes(box.encrypt(_VERSION + key.encode()))
    except (CryptoError, ValueError, TypeError):
        raise KeyStoreError() from None


def decrypt_key(blob: bytes, wrapping_key: bytes) -> SigningKey:
    """Authenticate the exact bounded envelope before creating a signing key."""
    box = _box(wrapping_key)
    if type(blob) is not bytes or len(blob) != _BLOB_SIZE or not blob.startswith(_VERSION):
        raise KeyStoreError()
    try:
        plaintext = box.decrypt(blob[len(_VERSION):])
        if len(plaintext) != _PLAIN_SIZE or not plaintext.startswith(_VERSION):
            raise KeyStoreError()
        return SigningKey(plaintext[len(_VERSION):])
    except (CryptoError, ValueError, TypeError):
        raise KeyStoreError() from None
