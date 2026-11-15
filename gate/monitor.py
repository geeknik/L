"""L: A Trust-Typed Language for Agents — gate (reference monitor).

The gate sits between every model and everything it can touch, enforcing:
  1. The runtime assigns labels; the model never writes its own.
  2. A DIRECT executes only if its capability admits the directive's integrity.
  3. Raising integrity requires an explicit ENDORSE signed by a principal with authority.
  4. Every reference is (principal, content hash) and every act expires.
"""

import time
import weakref
from typing import Callable, Mapping, Optional, Sequence, Tuple, cast

from lang.ast import (
    Act, DirectAct, EndorseAct, AssertAct, QueryAct, CommitAct, GrantAct, RevokeAct,
    Principal, Reference, Capability, ToolCall,
)
from lang.labels import Label, LOW, INTEGRITY_ORDER, integrity_at_least
from lang.limits import MAX_AUDIT_RECORDS


class GateError(Exception):
    def __init__(self, code: str, message: str, act: Optional[Act] = None) -> None:
        self.code = code
        self.message = message
        self.act = act
        super().__init__(f"GateError [{code}]: {message}")


class Gate:
    """Reference monitor enforcing the four rules."""

    def __init__(
        self,
        label_assigner: Optional[Callable[[Act, Optional[Label]], Label]] = None,
        signer_authority: Optional[Mapping[str, object]] = None,
    ) -> None:
        self._assigner = label_assigner or self._default_assigner
        self._authority = signer_authority if signer_authority is not None else {
            'authorized': True,
            'may_approve_integrity': [('admin', 'any'), ('reviewer', 'top_secret')],
        }
        # Runtime label storage: id(act) -> (weakref(act), Label).
        # The weakref keeps the mapping from outliving the act and lets
        # label_of() verify the queried object is the same object.
        self._session_labels: dict[int, tuple[weakref.ReferenceType[Act], Label]] = {}
        self.audit: list[dict[str, object]] = []

    # ── Rule 1: runtime assigns labels; the model never writes its own ───────

    def _default_assigner(self, act: Act, incoming_label: Optional[Label] = None) -> Label:
        if incoming_label is None:
            incoming_label = LOW
        return incoming_label.join(
            Label(provenance=(act.act_type,), integrity='low', confidentiality='public')
        )

    def _assign_label_to(self, act: Act, incoming_label: Optional[Label] = None) -> Label:
        assigned = self._assigner(act, incoming_label)
        if not isinstance(assigned, Label):
            raise GateError('LABEL.INVALID', 'Runtime label assignment failed')
        key = id(act)
        labels = self._session_labels
        def _drop(_ref: weakref.ReferenceType[Act], _key: int = key) -> None:
            entry = labels.get(_key)
            if entry is not None and entry[0] is _ref:
                labels.pop(_key, None)
        labels[key] = (weakref.ref(act, _drop), assigned)
        return assigned

    def label_of(self, act: Act) -> Optional[Label]:
        """Return the runtime label assigned to *act*, or None.

        Entries are keyed by ``id(act)`` for O(1) lookup, but each entry also
        holds a weak reference to the act. Since CPython reuses ``id()`` values
        after an object is freed, a bare id key can return a stale label for an
        unrelated new act. We therefore verify that the stored weak reference
        still resolves to the exact object being queried before returning the
        label, and drop the entry if it does not. Weakref callbacks remove
        entries when their acts are collected, so no act is retained
        indefinitely.

        A plain ``WeakKeyDictionary`` is unsuitable here: AST nodes are frozen
        dataclasses whose equality is structural (and whose ``params`` dict is
        unhashable), so equal-valued but distinct acts would collide.
        """
        entry = self._session_labels.get(id(act))
        if entry is None:
            return None
        ref, label = entry
        if ref() is not act:
            # Stale entry: id was reused by a different act after collection,
            # or a live-but-different object now occupies this id slot.
            self._session_labels.pop(id(act), None)
            return None
        return label

    # ── Rule 2: DIRECT integrity check ───────────────────────────────────────

    def _check_capability_structure(self, cap: Capability) -> None:
        """Validate capability hash, scope and from_principal grammar at gate boundary.

        This prevents bypassing parser validation by constructing Capability directly.
        """
        if not isinstance(cap, Capability):
            raise GateError('CAPABILITY.INVALID', 'Invalid capability structure')
        # cap_hash: a non-empty string (matches Rust's cap_hash.is_empty() check;
        # non-string values cannot exist in Rust's String field, so any
        # non-string here is outside the trusted boundary)
        if not isinstance(cap.cap_hash, str) or cap.cap_hash == '':
            raise GateError(
                code='REFERENCE.INVALID',
                message="Capability must have non-empty hash",
                act=None,
            )
        # scope: non-empty sequence of ASCII identifier segments separated by dots
        if not cap.scope or not isinstance(cap.scope, str):
            raise GateError(
                code='CAPABILITY.INVALID',
                message="Capability scope must be non-empty",
                act=None,
            )
        for seg in cap.scope.split('.'):
            if not seg:
                raise GateError(
                    code='CAPABILITY.INVALID',
                    message=f"Invalid scope segment '{seg}'",
                    act=None,
                )
            if not all(c.isascii() and (c.isalnum() or c == '_') for c in seg):
                raise GateError(
                    code='CAPABILITY.INVALID',
                    message=f"Invalid scope segment '{seg}' (must be ASCII alphanumeric or '_')",
                    act=None,
                )
        # from_principal: non-empty id with ':'-separated non-empty ASCII segments
        if not isinstance(cap.from_principal, Principal):
            raise GateError('CAPABILITY.INVALID', 'Invalid capability issuer')
        pid = cap.from_principal.id
        if not pid or not isinstance(pid, str):
            raise GateError(
                code='CAPABILITY.INVALID',
                message="Capability from_principal must be non-empty",
                act=None,
            )
        for seg in pid.split(':'):
            if not seg:
                raise GateError(
                    code='CAPABILITY.INVALID',
                    message=f"Invalid from_principal segment in '{pid}'",
                    act=None,
                )
            if not all(c.isascii() and (c.isalnum() or c == '_') for c in seg):
                raise GateError(
                    code='CAPABILITY.INVALID',
                    message=f"Invalid from_principal segment '{seg}' (must be ASCII alphanumeric or '_')",
                    act=None,
                )

    def _check_direct_integrity(self, act: DirectAct, cap: Capability, runtime_label: Label) -> None:
        if (not isinstance(cap.integrity_level, str)
                or cap.integrity_level not in INTEGRITY_ORDER
                or not integrity_at_least(runtime_label.integrity, cap.integrity_level)):
            raise GateError(
                code='INTEGRITY.DIRECT.DENIED',
                message=(f"Directive integrity '{runtime_label.integrity}' "
                         f"does not meet capability requirement '{cap.integrity_level}'"),
                act=act,
            )

    # ── Rule 3: ENDORSE authorization for raising integrity ───────────────────

    def _check_authorization(self, signer: Principal, target_ref: Reference) -> None:
        if (not isinstance(signer, Principal)
                or not isinstance(signer.id, str) or not signer.id):
            raise GateError('REFERENCE.INVALID', 'Invalid endorsement signer')
        allowed = cast(Sequence[tuple[str, str]],
                       self._authority.get('may_approve_integrity', []))
        if not any(signer.id.startswith(p) or signer.id.endswith(h) for p, h in allowed):
            raise GateError(
                code='ENDORSE.UNAUTHORIZED',
                message=f"Signer '{signer.id}' lacks authority to elevate integrity",
                act=None,
            )

    # ── Rule 4: reference format and expiry ─────────────────────────────────

    def _check_reference(self, ref: Reference) -> None:
        if (not isinstance(ref, Reference)
                or not isinstance(ref.principal, Principal)
                or not isinstance(ref.principal.id, str) or not ref.principal.id
                or not isinstance(ref.content_hash, str) or not ref.content_hash):
            raise GateError(
                code='REFERENCE.INVALID',
                message="Reference must be (principal, content hash)",
                act=None,
            )

    def _check_ttl(self, ttl_seconds: object) -> None:
        """Rule 4: every act must have positive TTL.

        NOTE for v1.0: this check validates TTL *syntax* (positive integer).
        It does NOT enforce expiration against elapsed time — that requires
        trusted issuance/deadline metadata (e.g., created_at epoch) which is
        deferred to v2.0 per DESIGN.md. The gate still rejects non-positive TTL.
        """
        # Require an actual integer within the shared positive range.
        # bool is excluded explicitly because isinstance(True, int) is True.
        if (
            ttl_seconds is None
            or not isinstance(ttl_seconds, int)
            or isinstance(ttl_seconds, bool)
            or not (1 <= ttl_seconds <= 9223372036854775807)
        ):
            raise GateError(
                code='EXPIRY.INVALID',
                message="Capability TTL must be an integer in 1..=i64::MAX",
                act=None,
            )

    # ── Execute an act through the gate ───────────────────────────────────────

    def execute(self, act: Act, now: Optional[int] = None) -> Act:
        """Run the act through all four rules. Returns the act if allowed."""
        now = int(time.time()) if now is None else now
        supported = (DirectAct, EndorseAct, AssertAct, QueryAct, CommitAct, GrantAct, RevokeAct)
        act_type = next((kind.act_type for kind in supported if isinstance(act, kind)), 'UNKNOWN')
        entry: dict[str, object] = {'act': act_type, 'now': now, 'status': 'ENTER'}
        self.audit.append(entry)
        del self.audit[:-MAX_AUDIT_RECORDS]
        try:
            if not isinstance(act, supported):
                raise GateError('ACT.UNSUPPORTED', 'Unsupported act type')
            try:
                runtime_label = self._assign_label_to(act, LOW)
            except Exception:
                raise GateError('LABEL.INVALID', 'Runtime label assignment failed') from None
            if isinstance(act, DirectAct):
                self._check_capability_structure(act.capability)
                self._check_direct_integrity(act, act.capability, runtime_label)
                if not isinstance(act.call, ToolCall):
                    raise GateError('REFERENCE.INVALID', 'Invalid tool call structure')
                self._check_reference(act.call.tool)
                self._check_ttl(act.capability.exp)
            elif isinstance(act, EndorseAct):
                self._check_reference(act.reference)
                self._check_authorization(act.signer, act.reference)
            elif isinstance(act, (AssertAct, QueryAct)):
                self._check_reference(act.evidence)
            elif isinstance(act, CommitAct):
                self._check_reference(act.reference)
            elif isinstance(act, (GrantAct, RevokeAct)):
                self._check_capability_structure(act.capability)
                self._check_ttl(act.capability.exp)
            else:
                raise GateError(
                    code='ACT.UNSUPPORTED',
                    message=f"Unsupported act type: {type(act).__name__}",
                    act=act,
                )

            entry['status'] = 'ALLOW'
            return act
        except GateError as e:
            entry['status'] = 'DENY'
            entry['error'] = f"{e.code}: Gate refused act"
            raise
        except Exception:
            entry['status'] = 'DENY'
            entry['error'] = 'GATE.INTERNAL: Gate evaluation failed'
            raise GateError('GATE.INTERNAL', 'Gate evaluation failed') from None

    # ── Public scan API (used by TSD scanner) ──────────────────────────────────

    def scan(self, source: str) -> Tuple[bool, list[dict[str, object]]]:
        """Parse source text and return whether any rule was violated."""
        from lang.parser import parse
        acts = parse(source)
        allowed_all = True
        for act in acts:
            try:
                self.execute(act)
            except GateError:
                allowed_all = False
        return allowed_all, self.audit
