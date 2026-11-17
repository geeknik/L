# Authority custody and session retirement

This contract supplements `security-gate.md` and `local-host.md`. It does not
change signed claims or the L wire format. The low-level Python `Authority` API
can export and restore an encrypted in-memory key blob; that API provides no
filesystem or password interface. The separate `gate/custody.py` layer and
`tsd-authority` offline CLI implement the project's filesystem custody profile;
see [owned-host.md](owned-host.md) and the
[operator workflow](owned-host-operations.md). Ed25519 signing continues to use
PyNaCl.

`Authority.export_encrypted(wrapping_key)` and
`Authority.load_encrypted(blob, wrapping_key)` use PyNaCl SecretBox authenticated
encryption with a fresh library-generated nonce. The wrapping key must be exactly
32 random bytes from a cryptographic generator, supplied by the trusted operator.
It is not a password. No custom key derivation or cryptography is implemented.
The plaintext is the version marker `TSD-KEYSTORE-v1\0` followed by the 32-byte
Ed25519 seed. The blob is that same marker followed by SecretBox's nonce, MAC,
and ciphertext encoding. The marker inside the authenticated plaintext prevents
version confusion. Only the exact resulting length is accepted; wrong versions,
truncation, trailing bytes, tampering and wrong keys raise a fixed KeyStoreError.
No plaintext seed export API is provided. Key objects omit secrets from repr;
these in-memory APIs do not log or write key material. The separate custody layer
writes the encrypted blob and wrapping key only to their protected files.

The operator must store ciphertext atomically in access-controlled storage and
keep the wrapping key separately, with least privilege, backup, recovery and
rotation policy. The owned-host custody profile uses separate private directories
under an isolated operator identity; it does not require an external secret
manager. This OS-protected storage is not an HSM and does not defend against
compromise of the operator UID. The encrypted blob is sensitive. Possession
of both blob and wrapping key confers signing authority. Python cannot guarantee
memory zeroization, protection from a compromised process, or suppression of
debugger/core-dump copies. This API does not provide those guarantees. Restoring
a signing key does not restore any session, grant, approval or revocation state.

`LocalHost.rotate_trust(trusted_keys)` retires the current session under the same
nonblocking operation lock as execution and apply. It constructs and validates a
new SecurityGate with a new unpredictable subject before replacing the old gate.
Current provenance, confidentiality and lowered integrity are preserved; grants,
approvals, replay records and capacity state belong to the retired subject and
are not transferred. Existing host audit records are retained. Old statements
cannot authorize the new subject even when a signing key remains trusted. New
statements must bind the new subject. Invalid configuration or subject collision
leaves the original session unchanged. Concurrent rotation returns HOST.BUSY;
same-thread reentry returns HOST.REENTRANT. There is no automatic retry.

An operator revoking a compromised signer replaces the trust map without that
key. Every retained signer must issue fresh statements for the new session.
An empty trust map is valid deny-all. This intentionally retires sessions rather
than resuming them or pretending discarded revocation records remain durable.

Regression tests exercise ciphertext integrity, identity-preserving restore,
old-evidence refusal, new authorization, preserved taint/confidentiality/provenance,
invalid configuration atomicity, and busy/reentrant rotation. I1/I3 hold because
rotation cannot raise integrity; I4/I7 hold because fresh subject binding rejects
retired evidence and every decryption error refuses without exposing secrets.
