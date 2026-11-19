"""Project-owned local host: public verification only, fixed trusted adapters."""

import base64
import binascii
from pathlib import Path
from typing import Any, Sequence

from gate.authority import AuthorityError, Envelope, TrustKey, is_hash, is_identity
from gate.custody import read_private
from gate.host import HostError, LabeledInput, LocalHost, ToolRegistration
from gate.local_protocol import JsonLines, ProtocolError, decode_object, encode_object
from gate.process import ToolProcess
from lang.labels import CONFIDENTIALITY_ORDER, Label
from lang.limits import (MAX_AUTHORITY_BYTES, MAX_LINE_BYTES, MAX_PROCESS_SECONDS,
                         MAX_SECURITY_RECORDS)


class ConfigurationError(Exception):
    def __init__(self) -> None:
        super().__init__('Invalid host configuration')


def _fields(value: Any, fields: set[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise ValueError()
    return value


def _strings(value: Any) -> list[str]:
    if (type(value) is not list or len(value) > MAX_SECURITY_RECORDS
            or any(type(item) is not str for item in value)):
        raise ValueError()
    return value


def _confidentiality(value: Any) -> str:
    if type(value) is not str or value not in CONFIDENTIALITY_ORDER:
        raise ValueError()
    return value


def _base64(value: Any, limit: int) -> bytes:
    if type(value) is not str or len(value) > 4 * ((limit + 2) // 3):
        raise ValueError()
    raw = base64.b64decode(value, validate=True)
    if len(raw) > limit or base64.b64encode(raw).decode('ascii') != value:
        raise ValueError()
    return raw


class HostSession:
    """Controller for a trusted in-memory host or a protected configuration.

    Construct only in trusted host code; no request can replace host policy.
    """

    def __init__(self, host: LocalHost, tools: Sequence[ToolRegistration],
                 input_confidentiality: str) -> None:
        self._host = host
        self._tools = tuple(tools)
        self._input_confidentiality = _confidentiality(input_confidentiality)
        self._last_error_code: str | None = None
        self.closed = False

    @property
    def last_error_code(self) -> str | None:
        """Trusted diagnostic for the last request; never part of the wire response."""
        return self._last_error_code

    def request(self, request: dict[str, Any]) -> dict[str, Any]:
        self._last_error_code = None
        try:
            if self.closed:
                raise ValueError()
            # Bound direct calls without expanding valid UTF-8 wire requests
            # into longer ASCII escape sequences.
            request = decode_object(encode_object(request, ensure_ascii=False))
            op = request.get('op')
            if op == 'info':
                _fields(request, {'op'})
                return {'status': 'ALLOW', 'version': 1, 'subject': self._host.subject,
                        'tools': [{'principal': t.principal, 'hash': t.content_hash}
                                  for t in self._tools]}
            if op == 'close':
                _fields(request, {'op'})
                self.closed = True
                return {'status': 'ALLOW'}
            if op == 'apply':
                _fields(request, {'op', 'payload', 'signature'})
                envelope = Envelope(_base64(request['payload'], MAX_AUTHORITY_BYTES),
                                    _base64(request['signature'], 64))
                self._host.apply(envelope)
                return {'status': 'ALLOW'}
            if op == 'execute':
                _fields(request, {'op', 'source', 'inputs'})
                source = request['source']
                if type(source) is not str:
                    raise ValueError()
                inputs = _strings(request['inputs'])
                label = Label(integrity='low', confidentiality=self._input_confidentiality)
                # The proposed source is itself untrusted even with an empty batch.
                labeled = [LabeledInput(text, label) for text in inputs] or [LabeledInput('', label)]
                result = self._host.run(labeled,
                                        lambda _: source)
                response = {'status': 'ALLOW', 'result': None if result is None else result.text}
                try:
                    encode_object(response)
                except ProtocolError:
                    # Effects may already exist. Never restore approval or continue.
                    self.closed = True
                    raise HostError('HOST.LIMIT') from None
                return response
            raise ValueError()
        except (ValueError, TypeError, UnicodeError, binascii.Error, ProtocolError):
            return {'status': 'DENY', 'error': 'Invalid request'}
        except HostError as error:
            self._last_error_code = error.code
            return {'status': 'DENY', 'error': 'Operation denied'}


def load_session(path: Path) -> HostSession:
    """Read protected policy and bind the complete tool definition to its hash."""
    try:
        config = _fields(decode_object(read_private(path, MAX_LINE_BYTES)),
                         {'version', 'model_clearance', 'input_confidentiality',
                          'trusted_keys', 'tools'})
        if type(config['version']) is not int or config['version'] != 1:
            raise ValueError()
        clearance = _confidentiality(config['model_clearance'])
        input_confidentiality = _confidentiality(config['input_confidentiality'])
        keys = config['trusted_keys']
        if type(keys) is not dict or len(keys) > MAX_SECURITY_RECORDS:
            raise ValueError()
        trust: dict[str, TrustKey] = {}
        for issuer, raw in keys.items():
            if not is_identity(issuer):
                raise ValueError()
            key = _fields(raw, {'public_key', 'kinds', 'scopes', 'max_integrity'})
            if not is_hash(key['public_key']):
                raise ValueError()
            kinds, scopes = _strings(key['kinds']), _strings(key['scopes'])
            if len(set(kinds)) != len(kinds) or len(set(scopes)) != len(scopes):
                raise ValueError()
            if type(key['max_integrity']) is not str:
                raise ValueError()
            trust[issuer] = TrustKey(bytes.fromhex(key['public_key']),
                                    frozenset(kinds), frozenset(scopes), key['max_integrity'])
        raw_tools = config['tools']
        if type(raw_tools) is not list or len(raw_tools) > MAX_SECURITY_RECORDS:
            raise ValueError()
        tools: list[ToolRegistration] = []
        for raw in raw_tools:
            tool = _fields(raw, {'principal', 'definition', 'argv', 'timeout',
                                 'clearance', 'output_confidentiality'})
            if (type(tool['definition']) is not str or not tool['definition']
                    or type(tool['timeout']) is not int):
                raise ValueError()
            argv = _strings(tool['argv'])
            callback = ToolProcess(tuple(argv), tool['timeout'])
            tools.append(ToolRegistration(tool['principal'], encode_object(tool),
                                          _confidentiality(tool['clearance']), callback,
                                          _confidentiality(tool['output_confidentiality'])))
        host = LocalHost(trust, tools, model_clearance=clearance, initial_integrity='low')
        session = HostSession(host, tools, input_confidentiality)
        # Refuse unusable configurations before starting a session.
        encode_object(session.request({'op': 'info'}))
        return session
    except (ValueError, TypeError, KeyError, HostError, AuthorityError, ProtocolError):
        raise ConfigurationError() from None


def serve(session: HostSession, input_fd: int, output_fd: int,
          timeout: float = MAX_PROCESS_SECONDS) -> int:
    """Fail-stop on framing failures; complete schema refusals may continue."""
    try:
        with JsonLines(input_fd, output_fd, timeout=timeout) as stream:
            try:
                while not session.closed:
                    request = stream.read()
                    if request is None:
                        session.closed = True
                        return 0
                    stream.write(session.request(request))
                return 0
            except (ProtocolError, OSError):
                session.closed = True
                try:
                    stream.write({'status': 'DENY', 'error': 'Invalid request'})
                except (ProtocolError, OSError):
                    pass
                return 1
    except (ProtocolError, OSError):
        session.closed = True
        return 1
