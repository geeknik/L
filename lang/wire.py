"""Closed deterministic CBOR AST codec. Decoding never authorizes execution."""
from __future__ import annotations

import json
import re
from typing import NoReturn, TypeAlias

from lang.ast import (Act, AssertAct, Capability, CommitAct, DirectAct, EndorseAct,
                      GrantAct, Payload, Principal, QueryAct, Reference, RevokeAct, ToolCall)
from lang.limits import MAX_ACTS, MAX_WIRE_BYTES, MAX_WIRE_DEPTH, MAX_WIRE_NODES

Value: TypeAlias = int | bool | str | list['Value']
_MAX_INT = 9223372036854775807


class WireError(Exception):
    def __init__(self) -> None:
        self.code = 'WIRE.INVALID'
        super().__init__('WIRE.INVALID: Invalid wire representation')


def _fail(*args: object) -> NoReturn:
    raise WireError()


def _utf8(value: object) -> bytes:
    if type(value) is not str or len(value) > MAX_WIRE_BYTES:
        _fail()
    try:
        data = value.encode('utf-8')
    except UnicodeError:
        raise WireError() from None
    if len(data) > MAX_WIRE_BYTES:
        _fail()
    return data


def _head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes(((major << 5) | value,))
    width = next(n for n in (1, 2, 4, 8) if value < 1 << (n*8))
    return bytes(((major << 5) | {1:24, 2:25, 4:26, 8:27}[width],)) + value.to_bytes(width, 'big')


class _Builder:
    """Account for every model allocation, including repeated AST references."""
    def __init__(self) -> None:
        self.nodes = 0
        self.size = 0

    def _charge(self, size: int) -> None:
        self.nodes += 1
        self.size += size
        if self.nodes > MAX_WIRE_NODES or self.size > MAX_WIRE_BYTES:
            _fail()

    def scalar(self, value: object) -> Value:
        if type(value) is str:
            data = _utf8(value)
            self._charge(len(_head(3, len(data))) + len(data))
            return value
        if type(value) is bool:
            self._charge(1)
            return value
        if type(value) is int and 0 <= value <= _MAX_INT:
            self._charge(len(_head(0, value)))
            return value
        _fail()

    def array(self, values: list[Value]) -> Value:
        self._charge(len(_head(4, len(values))))
        return values


def _model(acts: list[Act] | tuple[Act, ...]) -> Value:
    if type(acts) not in (list, tuple) or len(acts) > MAX_ACTS:
        _fail()
    build = _Builder()
    s, a = build.scalar, build.array

    def principal(value: Principal) -> Value:
        if type(value) is not Principal:
            _fail()
        return a([s(value.id), s(value.hash)])

    def reference(value: Reference) -> Value:
        if type(value) is not Reference:
            _fail()
        return a([principal(value.principal), s(value.content_hash)])

    def capability(value: Capability) -> Value:
        if type(value) is not Capability:
            _fail()
        return a([s(value.cap_hash), s(value.scope), s(value.exp),
                  principal(value.from_principal), s(value.integrity_level)])

    records: list[Value] = []
    for act in acts:
        if type(act) in (AssertAct, QueryAct) and isinstance(act, (AssertAct, QueryAct)):
            if type(act.data) is not Payload:
                _fail()
            record = a([s('ASSERT' if type(act) is AssertAct else 'QUERY'), reference(act.evidence),
                        a([s(act.data.content), s(act.data.is_opaque)])])
        elif type(act) is DirectAct:
            if type(act.call) is not ToolCall or type(act.call.params) is not dict:
                _fail()
            params = act.call.params
            if len(params) > MAX_WIRE_NODES or any(type(k) is not str for k in params):
                _fail()
            # Validate keys before sorting; no attacker-defined comparisons.
            for key in params:
                _utf8(key)
            entries: list[Value] = []
            for key in sorted(params):
                value = params[key]
                if type(value) not in (str, int):
                    _fail()
                entries.append(a([s(key), a([s('str' if type(value) is str else 'int'), s(value)])]))
            record = a([s('DIRECT'), capability(act.capability), reference(act.call.tool), a(entries)])
        elif type(act) is CommitAct:
            record = a([s('COMMIT'), reference(act.reference)])
        elif type(act) in (GrantAct, RevokeAct) and isinstance(act, (GrantAct, RevokeAct)):
            record = a([s('GRANT' if type(act) is GrantAct else 'REVOKE'), capability(act.capability)])
        elif type(act) is EndorseAct:
            record = a([s('ENDORSE'), reference(act.reference), principal(act.signer)])
        else:
            _fail()
        records.append(record)
    return a([s(1), a(records)])


def _array(value: Value, size: int | None = None) -> list[Value]:
    if type(value) is not list or (size is not None and len(value) != size):
        _fail()
    return value


def _string(value: Value, pattern: str | None = None) -> str:
    if type(value) is not str or (pattern is not None and not re.fullmatch(pattern, value)):
        _fail()
    return value


def _integer(value: Value) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_INT:
        _fail()
    return value


def _unmodel(root: Value) -> list[Act]:
    root_fields = _array(root, 2)
    if _integer(root_fields[0]) != 1:
        _fail()
    records = _array(root_fields[1])
    if len(records) > MAX_ACTS:
        _fail()

    def principal(value: Value) -> Principal:
        fields = _array(value, 2)
        return Principal(_string(fields[0], r'[A-Za-z0-9_]+(?::[A-Za-z0-9_]+)*'),
                         _string(fields[1], r'[A-Fa-f0-9]+'))

    def reference(value: Value) -> Reference:
        fields = _array(value, 2)
        return Reference(principal(fields[0]), _string(fields[1], r'[A-Fa-f0-9]+'))

    def capability(value: Value) -> Capability:
        fields = _array(value, 5)
        integrity = _string(fields[4])
        if integrity not in ('low', 'medium', 'high', 'critical'):
            _fail()
        return Capability(_string(fields[0], r'[A-Fa-f0-9]+'),
                          _string(fields[1], r'[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*'),
                          _integer(fields[2]), principal(fields[3]), integrity)

    acts: list[Act] = []
    for record in records:
        fields = _array(record)
        if not fields:
            _fail()
        kind = _string(fields[0])
        if kind in ('ASSERT', 'QUERY'):
            _array(record, 3)
            payload = _array(fields[2], 2)
            if type(payload[1]) is not bool:
                _fail()
            cls = AssertAct if kind == 'ASSERT' else QueryAct
            acts.append(cls(reference(fields[1]), Payload(_string(payload[0]), payload[1])))
        elif kind == 'DIRECT':
            _array(record, 4)
            params: dict[str, str | int] = {}
            previous = ''
            for entry in _array(fields[3]):
                pair = _array(entry, 2)
                key = _string(pair[0], r'[A-Za-z0-9_]+')
                if key <= previous:
                    _fail()
                previous = key
                tagged = _array(pair[1], 2)
                tag = _string(tagged[0])
                if tag == 'str':
                    params[key] = _string(tagged[1])
                elif tag == 'int':
                    params[key] = _integer(tagged[1])
                else:
                    _fail()
            acts.append(DirectAct(capability(fields[1]), ToolCall(reference(fields[2]), params)))
        elif kind == 'COMMIT':
            _array(record, 2)
            acts.append(CommitAct(reference(fields[1])))
        elif kind in ('GRANT', 'REVOKE'):
            _array(record, 2)
            acts.append(GrantAct(capability(fields[1])) if kind == 'GRANT'
                        else RevokeAct(capability(fields[1])))
        elif kind == 'ENDORSE':
            _array(record, 3)
            acts.append(EndorseAct(reference(fields[1]), principal(fields[2])))
        else:
            _fail()
    return acts


def _binary(model: Value) -> bytes:
    result = bytearray()
    nodes = 0

    def emit(value: Value, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_WIRE_NODES or depth > MAX_WIRE_DEPTH:
            _fail()
        if type(value) is list:
            if len(value) > MAX_WIRE_NODES - nodes:
                _fail()
            result.extend(_head(4, len(value)))
            for child in value:
                emit(child, depth+1)
        else:
            if type(value) is str:
                data = _utf8(value)
                prefix = _head(3, len(data))
            elif type(value) is bool:
                prefix, data = bytes((245 if value else 244,)), b''
            elif type(value) is int and 0 <= value <= _MAX_INT:
                prefix, data = _head(0, value), b''
            else:
                _fail()
            if len(result) + len(prefix) + len(data) > MAX_WIRE_BYTES:
                _fail()
            result.extend(prefix)
            result.extend(data)
        if len(result) > MAX_WIRE_BYTES:
            _fail()
    emit(model, 0)
    return bytes(result)


def _read(data: bytes) -> Value:
    if type(data) is not bytes or len(data) > MAX_WIRE_BYTES:
        _fail()
    pos = 0
    nodes = 0

    def read(depth: int) -> Value:
        nonlocal pos, nodes
        nodes += 1
        if nodes > MAX_WIRE_NODES or depth > MAX_WIRE_DEPTH or pos >= len(data):
            _fail()
        initial = data[pos]
        pos += 1
        if initial in (244, 245):
            return initial == 245
        major, info = initial >> 5, initial & 31
        if major not in (0, 3, 4) or info > 27:
            _fail()
        length = info
        if info >= 24:
            width = 1 << (info-24)
            if pos+width > len(data):
                _fail()
            length = int.from_bytes(data[pos:pos+width], 'big')
            pos += width
            if length < (24 if width == 1 else 1 << (8*(width//2))):
                _fail()
        if major == 0:
            return _integer(length)
        if length > len(data)-pos:
            _fail()
        if major == 3:
            try:
                text = data[pos:pos+length].decode('utf-8')
            except UnicodeError:
                raise WireError() from None
            pos += length
            return text
        if length > MAX_WIRE_NODES-nodes:
            _fail()
        return [read(depth+1) for _ in range(length)]
    model = read(0)
    if pos != len(data):
        _fail()
    return model


def encode(acts: list[Act] | tuple[Act, ...]) -> bytes:
    model = _model(acts)
    _unmodel(model)
    _check_projection_size(model)
    return _binary(model)


def decode(data: bytes) -> list[Act]:
    model = _read(data)
    acts = _unmodel(model)
    _check_projection_size(model)
    return acts


def _check_projection_size(model: Value) -> None:
    # Measure escaping before JSONEncoder can allocate an expanded string chunk.
    size = 1  # final LF

    def measure(value: Value) -> None:
        nonlocal size
        if type(value) is list:
            size += 2 + max(0, len(value)-1)
            for child in value:
                measure(child)
        elif type(value) is str:
            size += 2
            for char in value:
                size += (2 if char in '"\\\b\f\n\r\t' else
                         6 if ord(char) < 32 else len(char.encode('utf-8')))
        elif type(value) is bool:
            size += 4 if value else 5
        else:
            size += len(str(value))
        if size > MAX_WIRE_BYTES:
            _fail()
    measure(model)


def _projection(model: Value) -> str:
    _check_projection_size(model)
    pieces: list[str] = []
    total = 1
    for piece in json.JSONEncoder(ensure_ascii=False, separators=(',', ':')).iterencode(model):
        total += len(_utf8(piece))
        if total > MAX_WIRE_BYTES:
            _fail()
        pieces.append(piece)
    return ''.join(pieces) + '\n'


def project(data: bytes) -> str:
    model = _read(data)
    _unmodel(model)
    return _projection(model)


def unproject(text: str) -> bytes:
    _utf8(text)
    # Reject excessive nesting before the JSON decoder allocates containers.
    depth, quoted, escaped, atom, nodes = 0, False, False, False, 0
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
            atom = False
            nodes += 1
        elif char == '[':
            depth += 1
            nodes += 1
            atom = False
            if depth > MAX_WIRE_DEPTH+1:
                _fail()
        elif char == ']':
            depth -= 1
            atom = False
        elif char == '{':
            _fail()
        elif char in ', \t\r\n':
            atom = False
        elif not atom:
            atom = True
            nodes += 1
        if nodes > MAX_WIRE_NODES or depth < 0:
            _fail()
    try:
        model = json.loads(text, parse_float=_fail, parse_constant=_fail,
                           object_pairs_hook=_fail)
        data = _binary(model)
        _unmodel(model)
        if _projection(model) != text:
            _fail()
        return data
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise WireError() from None
