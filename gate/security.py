"""Per-session semantic security decisions for a trusted, single-owner host.

The host supplies authenticated identity, trusted input labels and clock, and
serializes calls. State is intentionally process-local, not restart durable.
An allowed return value is a decision; this module never executes a tool.
"""

from hashlib import sha256
from typing import Mapping

from gate.authority import (AuthorityError, Claims, Envelope, I64_MAX, LEVELS,
                            TrustKey, is_hash, is_identity, verify)
from gate.monitor import Gate, GateError
from lang.ast import (Act, AssertAct, CommitAct, DirectAct, EndorseAct, GrantAct,
                      QueryAct, Reference, RevokeAct)
from lang.limits import MAX_AUDIT_RECORDS, MAX_SECURITY_RECORDS
from lang.parser import ParseError, parse


class SecurityError(Exception):
    """Stable code and fixed text; no caller data in public errors."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f'{code}: Security gate refused operation')


class SecurityGate:
    def __init__(self, subject: str, trusted_keys: Mapping[str, TrustKey],
                 initial_integrity: str = 'low') -> None:
        if (not is_identity(subject) or initial_integrity not in LEVELS
                or not isinstance(trusted_keys, Mapping)
                or len(trusted_keys) > MAX_SECURITY_RECORDS
                or any(not is_identity(k) or not isinstance(v, TrustKey)
                       for k, v in trusted_keys.items())):
            raise SecurityError('AUTH.INVALID')
        self.subject = subject
        self._trusted_keys = dict(trusted_keys)
        self._integrity = initial_integrity
        self._last_now: int | None = None
        self._grants: dict[str, Claims] = {}
        self._revoked: set[str] = set()
        self._nonces: set[tuple[str, str]] = set()
        self._approvals: dict[tuple[str, str], Claims] = {}
        self._exhausted = False
        self.audit: list[dict[str, str]] = []

    @property
    def integrity(self) -> str:
        return self._integrity

    def _record(self, operation: str, code: str | None = None) -> None:
        entry = {'operation': operation, 'status': 'DENY' if code else 'ALLOW'}
        if code:
            entry['code'] = code
        self.audit.append(entry)
        del self.audit[:-MAX_AUDIT_RECORDS]

    def _clock(self, now: int) -> None:
        if (type(now) is not int or not 0 <= now <= I64_MAX
                or (self._last_now is not None and now < self._last_now)):
            raise SecurityError('TIME.INVALID')
        self._last_now = now

    def observe(self, integrity: str) -> None:
        """Trusted host input notification; labels can only decrease."""
        if integrity not in LEVELS:
            self._record('OBSERVE', 'AUTH.INVALID')
            raise SecurityError('AUTH.INVALID')
        self._integrity = LEVELS[min(LEVELS.index(self._integrity), LEVELS.index(integrity))]
        self._record('OBSERVE')

    def _live_grant(self, capability: str, now: int) -> Claims:
        if capability in self._revoked:
            raise SecurityError('AUTH.REVOKED')
        grant = self._grants.get(capability)
        if grant is None:
            raise SecurityError('AUTH.REQUIRED')
        if now >= grant.expires_at:
            raise SecurityError('AUTH.EXPIRED')
        return grant

    @staticmethod
    def _same_metadata(claims: Claims, grant: Claims) -> bool:
        return all(getattr(claims, key) == getattr(grant, key) for key in
                   ('subject', 'capability', 'scope', 'tool_principal', 'tool_hash', 'integrity'))

    def apply(self, envelope: Envelope, now: int) -> None:
        """Verify the complete signed statement before mutating authority state."""
        try:
            self._clock(now)
            if self._exhausted:
                raise SecurityError('AUTH.CAPACITY')
            try:
                claims = verify(envelope, self._trusted_keys)
            except AuthorityError:
                raise SecurityError('AUTH.INVALID') from None
            if claims.subject != self.subject:
                raise SecurityError('AUTH.MISMATCH')
            if not claims.issued_at <= now < claims.expires_at:
                raise SecurityError('AUTH.EXPIRED')
            nonce = (claims.issuer, claims.nonce)
            if nonce in self._nonces:
                raise SecurityError('AUTH.REPLAY')
            if len(self._nonces) >= MAX_SECURITY_RECORDS:
                raise SecurityError('AUTH.CAPACITY')
            if claims.kind == 'grant':
                if claims.capability in self._revoked:
                    raise SecurityError('AUTH.REVOKED')
                if claims.capability in self._grants:
                    raise SecurityError('AUTH.REPLAY')
                if len(self._grants) >= MAX_SECURITY_RECORDS:
                    raise SecurityError('AUTH.CAPACITY')
                self._grants[claims.capability] = claims
            else:
                grant = self._live_grant(claims.capability, now)
                if not self._same_metadata(claims, grant):
                    raise SecurityError('AUTH.MISMATCH')
                if claims.kind == 'endorse':
                    if claims.expires_at > grant.expires_at:
                        raise SecurityError('AUTH.MISMATCH')
                    key = (claims.capability, claims.action_hash)
                    if key not in self._approvals and len(self._approvals) >= MAX_SECURITY_RECORDS:
                        raise SecurityError('AUTH.CAPACITY')
                    self._approvals[key] = claims
                else:
                    if claims.issuer != grant.issuer:
                        raise SecurityError('AUTH.MISMATCH')
                    if len(self._revoked) >= MAX_SECURITY_RECORDS:
                        raise SecurityError('AUTH.CAPACITY')
                    self._revoked.add(claims.capability)
                    del self._grants[claims.capability]
                    self._approvals = {k: v for k, v in self._approvals.items()
                                       if k[0] != claims.capability}
            self._nonces.add(nonce)
        except SecurityError as error:
            if error.code == 'AUTH.CAPACITY':
                self._exhausted = True
            self._record('APPLY', error.code)
            raise
        self._record('APPLY')

    @staticmethod
    def _bound_reference(ref: Reference) -> bool:
        return ref.principal.id != 'anon' and is_hash(ref.content_hash)

    def execute(self, source: str, now: int) -> Act:
        """Authorize one exact source act against session state, not model labels."""
        try:
            self._clock(now)
            try:
                if type(source) is not str:
                    raise SecurityError('ACT.INVALID')
                acts = parse(source)
                if len(acts) != 1:
                    raise SecurityError('ACT.INVALID')
                act = acts[0]
                # Structural Gate is used only as a validator, never as authority.
                Gate().execute(act, now=now)
            except (ParseError, GateError, ValueError, TypeError, UnicodeError):
                raise SecurityError('ACT.INVALID') from None
            if isinstance(act, (GrantAct, EndorseAct, RevokeAct)):
                raise SecurityError('AUTH.REQUIRED')
            if isinstance(act, DirectAct):
                if self._exhausted:
                    raise SecurityError('AUTH.CAPACITY')
                cap = act.capability
                if not is_hash(cap.cap_hash) or not self._bound_reference(act.call.tool):
                    raise SecurityError('ACT.INVALID')
                grant = self._live_grant(cap.cap_hash, now)
                if (cap.scope != grant.scope or cap.from_principal.id != grant.issuer
                        or act.call.tool.principal.id != grant.tool_principal
                        or act.call.tool.content_hash != grant.tool_hash
                        or cap.exp > grant.expires_at - grant.issued_at):
                    raise SecurityError('AUTH.MISMATCH')
                if LEVELS.index(self._integrity) < LEVELS.index(grant.integrity):
                    key = (cap.cap_hash, sha256(source.encode('utf-8')).hexdigest())
                    approval = self._approvals.get(key)
                    if (approval is None or now >= approval.expires_at
                            or LEVELS.index(approval.integrity) < LEVELS.index(grant.integrity)):
                        raise SecurityError('INTEGRITY.DENIED')
                    del self._approvals[key]
            elif isinstance(act, (AssertAct, QueryAct)):
                if not self._bound_reference(act.evidence):
                    raise SecurityError('ACT.INVALID')
                self._integrity = 'low'
            elif isinstance(act, CommitAct):
                if not self._bound_reference(act.reference):
                    raise SecurityError('ACT.INVALID')
            else:
                raise SecurityError('ACT.INVALID')
        except SecurityError as error:
            self._record('EXECUTE', error.code)
            raise
        self._record('EXECUTE')
        return act
