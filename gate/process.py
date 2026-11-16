"""Bounded POSIX subprocess transport for trusted LocalHost adapters.

This is process lifecycle management, not an operating-system sandbox. Fixed
operator-installed programs must not execute model-proposed actions themselves.
"""

from dataclasses import dataclass
import json
import os
import selectors
import signal
import subprocess
import time
from typing import Any

from gate.host import HostError
from lang.limits import MAX_ARG_NODES, MAX_PROCESS_SECONDS, MAX_SOURCE_BYTES


def _text_size(value: str) -> int:
    if type(value) is not str or len(value) > MAX_SOURCE_BYTES:
        raise HostError('PROCESS.INVALID')
    try:
        size = len(value.encode('utf-8'))
    except UnicodeError:
        raise HostError('PROCESS.INVALID') from None
    if size > MAX_SOURCE_BYTES:
        raise HostError('PROCESS.LIMIT')
    return size


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Invalid response')
        result[key] = value
    return result


def _constant(_: str) -> None:
    raise ValueError('Invalid response')


@dataclass(frozen=True)
class ProcessAdapter:
    argv: tuple[str, ...]
    timeout: float = MAX_PROCESS_SECONDS

    def __post_init__(self) -> None:
        if (os.name != 'posix' or type(self.argv) is not tuple or not self.argv
                or len(self.argv) > MAX_ARG_NODES
                or type(self.timeout) not in (int, float)
                or not 0 < self.timeout <= MAX_PROCESS_SECONDS):
            raise HostError('PROCESS.INVALID')
        total = 0
        for arg in self.argv:
            total += _text_size(arg)
            if '\x00' in arg or total > MAX_SOURCE_BYTES:
                raise HostError('PROCESS.INVALID')
        if not os.path.isabs(self.argv[0]):
            raise HostError('PROCESS.INVALID')

    def _exchange(self, request: dict[str, Any], field: str) -> str:
        data = json.dumps(request, ensure_ascii=False, allow_nan=False,
                          separators=(',', ':')).encode('utf-8') + b'\n'
        if len(data) > MAX_SOURCE_BYTES:
            raise HostError('PROCESS.LIMIT')
        try:
            raw = self._run(data)
            response = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                                  parse_constant=_constant)
            if (type(response) is not dict or set(response) != {field}
                    or type(response[field]) is not str):
                raise ValueError('Invalid response')
            result: str = response[field]
            _text_size(result)
            return result
        except HostError:
            raise
        except (ValueError, TypeError, UnicodeError, RecursionError, OSError):
            raise HostError('PROCESS.FAILED') from None

    def _run(self, data: bytes) -> bytes:
        deadline = time.monotonic() + self.timeout
        proc = subprocess.Popen(self.argv, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                shell=False, start_new_session=True, close_fds=True,
                                env={'PATH': os.defpath}, bufsize=0)
        if proc.stdin is None or proc.stdout is None or proc.stderr is None:
            proc.kill()
            proc.wait()
            raise HostError('PROCESS.FAILED')
        out = bytearray()
        stderr_size = 0
        sent = 0
        try:
            with selectors.DefaultSelector() as selector:
                for pipe, event, name in ((proc.stdin, selectors.EVENT_WRITE, 'in'),
                                          (proc.stdout, selectors.EVENT_READ, 'out'),
                                          (proc.stderr, selectors.EVENT_READ, 'err')):
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, event, name)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise HostError('PROCESS.TIMEOUT')
                    for key, _ in selector.select(remaining):
                        try:
                            if key.data == 'in':
                                sent += os.write(key.fd, data[sent:])
                                if sent == len(data):
                                    selector.unregister(key.fileobj)
                                    proc.stdin.close()
                            else:
                                chunk = os.read(key.fd, min(4096, MAX_SOURCE_BYTES + 1))
                                if not chunk:
                                    selector.unregister(key.fileobj)
                                elif key.data == 'out':
                                    if len(out) + len(chunk) > MAX_SOURCE_BYTES:
                                        raise HostError('PROCESS.LIMIT')
                                    out.extend(chunk)
                                else:
                                    stderr_size += len(chunk)
                                    if stderr_size > MAX_SOURCE_BYTES:
                                        raise HostError('PROCESS.LIMIT')
                        except BlockingIOError:
                            continue
                        except BrokenPipeError:
                            raise HostError('PROCESS.FAILED') from None
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise HostError('PROCESS.TIMEOUT')
                if proc.wait(timeout=remaining) != 0:
                    raise HostError('PROCESS.FAILED')
        except subprocess.TimeoutExpired:
            raise HostError('PROCESS.TIMEOUT') from None
        finally:
            # Also stop descendants that kept the process group after parent exit.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            proc.stdin.close()
            proc.stdout.close()
            proc.stderr.close()
        return bytes(out)


class ModelProcess(ProcessAdapter):
    def __call__(self, inputs: tuple[str, ...]) -> str:
        if type(inputs) is not tuple or len(inputs) > MAX_ARG_NODES:
            raise HostError('PROCESS.INVALID')
        total = 0
        for value in inputs:
            total += _text_size(value)
            if total > MAX_SOURCE_BYTES:
                raise HostError('PROCESS.LIMIT')
        return self._exchange({'inputs': inputs}, 'source')


class ToolProcess(ProcessAdapter):
    def __call__(self, arguments: dict[str, str | int]) -> str:
        if type(arguments) is not dict or len(arguments) > MAX_ARG_NODES:
            raise HostError('PROCESS.INVALID')
        total = 0
        for key, value in arguments.items():
            total += _text_size(key)
            if type(value) is str:
                total += _text_size(value)
            elif type(value) is not int or not 0 <= value <= 9223372036854775807:
                raise HostError('PROCESS.INVALID')
            if total > MAX_SOURCE_BYTES:
                raise HostError('PROCESS.LIMIT')
        return self._exchange({'arguments': arguments}, 'result')
