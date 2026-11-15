"""Local trusted host integration; no provider transport or callback cancellation.

Adapters and callbacks are trusted local code responsible for their I/O deadlines.
The host serializes operations and refuses same-thread reentry. Private signing
keys never enter this module; sessions cannot be resumed after reconstruction.
"""

from contextlib import contextmanager
from dataclasses import dataclass, field
from hashlib import sha256
import re
import secrets
import threading
import time
from types import MappingProxyType
from typing import Callable, Iterator, Mapping, Sequence

from gate.authority import Envelope, TrustKey
from gate.security import SecurityError, SecurityGate
from lang.ast import DirectAct
from lang.labels import CONFIDENTIALITY_ORDER, INTEGRITY_ORDER, Label
from lang.limits import MAX_AUDIT_RECORDS, MAX_SECURITY_RECORDS, MAX_SOURCE_BYTES

ToolCallback = Callable[[dict[str, str | int]], str]
ModelAdapter = Callable[[tuple[str, ...]], str]


class HostError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f'{code}: Local host refused operation')


def _size(text: str) -> int:
    if type(text) is not str:
        raise HostError('HOST.INVALID')
    if len(text) > MAX_SOURCE_BYTES:
        raise HostError('HOST.LIMIT')
    try:
        size = len(text.encode('utf-8'))
    except UnicodeError:
        raise HostError('HOST.INVALID') from None
    if size > MAX_SOURCE_BYTES:
        raise HostError('HOST.LIMIT')
    return size


@dataclass(frozen=True)
class LabeledInput:
    text: str = field(repr=False)
    label: Label = field(default_factory=Label)


@dataclass(frozen=True)
class ToolRegistration:
    principal: str
    definition: bytes = field(repr=False)
    clearance: str
    callback: ToolCallback = field(repr=False)
    output_confidentiality: str | None = None
    content_hash: str = field(init=False)

    def __post_init__(self) -> None:
        if (type(self.principal) is not str or self.principal == 'anon'
                or not re.fullmatch(r'[A-Za-z0-9_]+(?::[A-Za-z0-9_]+)*', self.principal)
                or type(self.definition) is not bytes or not self.definition
                or len(self.definition) > MAX_SOURCE_BYTES
                or self.clearance not in CONFIDENTIALITY_ORDER
                or (self.output_confidentiality is not None
                    and self.output_confidentiality not in CONFIDENTIALITY_ORDER)
                or not callable(self.callback)):
            raise HostError('HOST.INVALID')
        _size(self.principal)
        object.__setattr__(self, 'content_hash', sha256(self.definition).hexdigest())


class LocalHost:
    def __init__(self, trusted_keys: Mapping[str, TrustKey],
                 tools: Sequence[ToolRegistration], *, model_clearance: str,
                 initial_integrity: str = 'low',
                 clock: Callable[[], int] | None = None) -> None:
        if (model_clearance not in CONFIDENTIALITY_ORDER
                or not isinstance(tools, (tuple, list))
                or len(tools) > MAX_SECURITY_RECORDS):
            raise HostError('HOST.INVALID')
        registry: dict[tuple[str, str], ToolRegistration] = {}
        for tool in tools:
            if not isinstance(tool, ToolRegistration):
                raise HostError('HOST.INVALID')
            key = (tool.principal, tool.content_hash)
            if key in registry:
                raise HostError('HOST.INVALID')
            registry[key] = tool
        self._tools = MappingProxyType(registry)
        try:
            self._gate = SecurityGate('session:' + secrets.token_hex(32), trusted_keys,
                                      initial_integrity=initial_integrity)
        except SecurityError:
            raise HostError('HOST.INVALID') from None
        self._label = Label(integrity=initial_integrity)
        self._clearance = model_clearance
        self._clock = clock if clock is not None else lambda: int(time.time())
        if not callable(self._clock):
            raise HostError('HOST.INVALID')
        self._lock = threading.Lock()
        self._owner: int | None = None
        self._audit: list[dict[str, str]] = []

    @property
    def subject(self) -> str:
        return self._gate.subject

    @property
    def label(self) -> Label:
        return self._label

    @property
    def audit(self) -> tuple[Mapping[str, str], ...]:
        return tuple(MappingProxyType(entry.copy()) for entry in self._audit)

    @contextmanager
    def _operation(self, kind: str) -> Iterator[None]:
        if self._owner == threading.get_ident():
            raise HostError('HOST.REENTRANT')
        if not self._lock.acquire(blocking=False):
            raise HostError('HOST.BUSY')
        try:
            self._owner = threading.get_ident()
            entry = {'operation': kind, 'status': 'DENY'}
            try:
                yield
                entry['status'] = 'ALLOW'
            except SecurityError as error:
                entry['code'] = error.code
                raise HostError(error.code) from None
            except HostError as error:
                entry['code'] = error.code
                raise
            except Exception:
                entry['code'] = 'HOST.FAILED'
                raise HostError('HOST.FAILED') from None
            finally:
                self._audit.append(entry)
                del self._audit[:-MAX_AUDIT_RECORDS]
                self._owner = None
        finally:
            self._lock.release()

    def apply(self, envelope: Envelope) -> None:
        with self._operation('APPLY'):
            self._gate.apply(envelope, self._clock())

    def rotate_trust(self, trusted_keys: Mapping[str, TrustKey]) -> None:
        """Retire authority state under a fresh subject without clearing taint."""
        with self._operation('ROTATE'):
            subject = 'session:' + secrets.token_hex(32)
            if subject == self._gate.subject:
                raise HostError('HOST.INVALID')
            replacement = SecurityGate(subject, trusted_keys,
                                       initial_integrity=self._gate.integrity)
            self._gate = replacement

    def _inputs(self, inputs: Sequence[LabeledInput]) -> tuple[str, ...]:
        if not isinstance(inputs, (tuple, list)) or len(inputs) > MAX_SECURITY_RECORDS:
            raise HostError('HOST.LIMIT')
        joined = self._label
        total = 0
        texts: list[str] = []
        for value in inputs:
            if not isinstance(value, LabeledInput) or not isinstance(value.label, Label):
                raise HostError('HOST.INVALID')
            label = value.label
            if (label.integrity not in INTEGRITY_ORDER
                    or label.confidentiality not in CONFIDENTIALITY_ORDER
                    or type(label.provenance) is not tuple
                    or len(label.provenance) > MAX_SECURITY_RECORDS):
                raise HostError('HOST.INVALID')
            total += _size(value.text)
            provenance_bytes = 0
            for principal in label.provenance:
                provenance_bytes += _size(principal)
                if provenance_bytes > MAX_SOURCE_BYTES:
                    raise HostError('HOST.LIMIT')
            joined = joined.join(label)
            if (total > MAX_SOURCE_BYTES or len(joined.provenance) > MAX_SECURITY_RECORDS
                    or sum(_size(p) for p in joined.provenance) > MAX_SOURCE_BYTES):
                raise HostError('HOST.LIMIT')
            texts.append(value.text)
        if not joined.may_flow_to(self._clearance):
            raise HostError('HOST.CLEARANCE')
        self._gate.observe(joined.integrity)
        self._label = joined
        return tuple(texts)

    def run(self, inputs: Sequence[LabeledInput], model: ModelAdapter) -> LabeledInput | None:
        with self._operation('RUN'):
            texts = self._inputs(inputs)
            if not callable(model):
                raise HostError('HOST.INVALID')
            source = model(texts)
            _size(source)
            act = self._gate.execute(source, self._clock())
            self._label = Label(self._label.provenance, self._gate.integrity,
                                self._label.confidentiality)
            if not isinstance(act, DirectAct):
                return None
            key = (act.call.tool.principal.id, act.call.tool.content_hash)
            tool = self._tools.get(key)
            if tool is None:
                raise HostError('HOST.TOOL')
            if not self._label.may_flow_to(tool.clearance):
                raise HostError('HOST.CLEARANCE')
            output_label = self._label.join(Label(
                (tool.principal,), 'low', tool.output_confidentiality or tool.clearance))
            if (len(output_label.provenance) > MAX_SECURITY_RECORDS
                    or sum(_size(p) for p in output_label.provenance) > MAX_SOURCE_BYTES):
                raise HostError('HOST.LIMIT')
            if not output_label.may_flow_to(self._clearance):
                raise HostError('HOST.CLEARANCE')
            # No automatic retry or approval restoration after any callback failure.
            self._gate.observe('low')
            self._label = output_label
            result = tool.callback(dict(act.call.params))
            _size(result)
            return LabeledInput(result, self._label)
