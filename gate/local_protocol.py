"""Bounded strict JSON lines for the project-owned POSIX transport."""
import json
import os
import select
import time
from types import TracebackType
from typing import Any

from lang.limits import MAX_ARG_DEPTH, MAX_ARG_NODES, MAX_LINE_BYTES, MAX_PROCESS_SECONDS


class ProtocolError(Exception):
    def __init__(self) -> None:
        super().__init__('Invalid local protocol')


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ProtocolError()
        result[key] = value
    return result


def _number(_: str) -> Any:
    raise ProtocolError()


def _validate(value: object) -> None:
    if type(value) is not dict:
        raise ProtocolError()
    pending: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    text_bytes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > MAX_ARG_NODES or depth > MAX_ARG_DEPTH:
            raise ProtocolError()
        if type(item) is dict:
            if len(item) > MAX_ARG_NODES:
                raise ProtocolError()
            for key, child in item.items():
                if type(key) is not str or len(key) > MAX_LINE_BYTES:
                    raise ProtocolError()
                text_bytes += len(key.encode('utf-8'))
                pending.append((child, depth + 1))
        elif type(item) is list:
            if len(item) > MAX_ARG_NODES:
                raise ProtocolError()
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            if len(item) > MAX_LINE_BYTES:
                raise ProtocolError()
            text_bytes += len(item.encode('utf-8'))
        elif type(item) is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise ProtocolError()
        elif item is not None and type(item) is not bool:
            raise ProtocolError()
        if text_bytes > MAX_LINE_BYTES:
            raise ProtocolError()


def decode_object(raw: bytes) -> dict[str, Any]:
    try:
        if type(raw) is not bytes or not raw or len(raw) > MAX_LINE_BYTES:
            raise ProtocolError()
        value: Any = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                                parse_constant=_number, parse_float=_number)
        _validate(value)
        if not isinstance(value, dict):
            raise ProtocolError()
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise ProtocolError() from None


def encode_object(value: dict[str, Any]) -> bytes:
    try:
        _validate(value)
        raw = json.dumps(value, ensure_ascii=True, allow_nan=False,
                         separators=(',', ':'), sort_keys=True).encode('ascii')
        if len(raw) > MAX_LINE_BYTES:
            raise ProtocolError()
        return raw
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise ProtocolError() from None


class JsonLines:
    """Own blocking modes, not descriptor lifetime; deadlines bound pipe waits."""
    def __init__(self, input_fd: int, output_fd: int,
                 timeout: float = MAX_PROCESS_SECONDS) -> None:
        if (os.name != 'posix' or type(input_fd) is not int or input_fd < 0
                or type(output_fd) is not int or output_fd < 0
                or type(timeout) not in (int, float)
                or not 0 < timeout <= MAX_PROCESS_SECONDS):
            raise ProtocolError()
        self.input_fd = input_fd
        self.output_fd = output_fd
        self.timeout = timeout
        self._buffer = bytearray()
        self._modes: dict[int, bool] = {}

    def __enter__(self) -> 'JsonLines':
        if self._modes:
            raise ProtocolError()
        try:
            for fd in {self.input_fd, self.output_fd}:
                self._modes[fd] = os.get_blocking(fd)
                os.set_blocking(fd, False)
        except (OSError, ValueError, OverflowError):
            self._restore()
            raise ProtocolError() from None
        return self

    def _restore(self) -> None:
        for fd, mode in self._modes.items():
            try:
                os.set_blocking(fd, mode)
            except OSError:
                pass
        self._modes.clear()

    def __exit__(self, exc_type: type[BaseException] | None,
                 exc: BaseException | None, traceback: TracebackType | None) -> None:
        self._restore()

    def _wait(self, fd: int, writing: bool, deadline: float) -> None:
        if not self._modes:
            raise ProtocolError()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProtocolError()
        ready_read, ready_write, _ = select.select(
            [] if writing else [fd], [fd] if writing else [], [], remaining)
        if not (ready_read or ready_write):
            raise ProtocolError()

    def read(self) -> dict[str, Any] | None:
        if not self._modes:
            raise ProtocolError()
        deadline = time.monotonic() + self.timeout
        try:
            while True:
                index = self._buffer.find(b'\n')
                if index >= 0:
                    if index > MAX_LINE_BYTES:
                        raise ProtocolError()
                    raw = bytes(self._buffer[:index])
                    del self._buffer[:index + 1]
                    return decode_object(raw)
                if len(self._buffer) > MAX_LINE_BYTES:
                    raise ProtocolError()
                self._wait(self.input_fd, False, deadline)
                try:
                    chunk = os.read(self.input_fd, min(4096, MAX_LINE_BYTES + 1 - len(self._buffer)))
                except (BlockingIOError, InterruptedError):
                    continue
                if not chunk:
                    if self._buffer:
                        raise ProtocolError()
                    return None
                self._buffer.extend(chunk)
        except (OSError, ValueError):
            raise ProtocolError() from None

    def write(self, value: dict[str, Any]) -> None:
        data = encode_object(value) + b'\n'
        deadline = time.monotonic() + self.timeout
        offset = 0
        try:
            while offset < len(data):
                self._wait(self.output_fd, True, deadline)
                try:
                    count = os.write(self.output_fd, data[offset:])
                except (BlockingIOError, InterruptedError):
                    continue
                if count <= 0:
                    raise ProtocolError()
                offset += count
        except (OSError, ValueError):
            raise ProtocolError() from None
