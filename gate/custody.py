"""Descriptor-checked local authority custody; requires private operator directories."""

from contextlib import contextmanager
import os
from pathlib import Path
import stat
from typing import Iterator

from nacl.secret import SecretBox

from gate.authority import Authority
from gate.keystore import KeyStoreError
from lang.limits import MAX_AUTHORITY_BYTES, MAX_LINE_BYTES


class CustodyError(Exception):
    def __init__(self) -> None:
        super().__init__('Invalid private storage')


@contextmanager
def _parent(path: Path) -> Iterator[tuple[int, str]]:
    if (not isinstance(path, Path) or not path.is_absolute()
            or '..' in path.parts or len(path.parts) < 2):
        raise CustodyError()
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=fd)
            os.close(fd)
            fd = next_fd
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise CustodyError()
        yield fd, path.name
    finally:
        os.close(fd)


def _check_file(info: os.stat_result) -> None:
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise CustodyError()


def read_private(path: Path, max_bytes: int) -> bytes:
    """Read a bounded private regular file without following any symbolic link."""
    if type(max_bytes) is not int or not 0 < max_bytes <= MAX_LINE_BYTES:
        raise CustodyError()
    try:
        with _parent(path) as (parent, name):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                before = os.fstat(fd)
                _check_file(before)
                if not 0 < before.st_size <= max_bytes:
                    raise CustodyError()
                result = bytearray()
                while len(result) <= max_bytes:
                    chunk = os.read(fd, max_bytes + 1 - len(result))
                    if not chunk:
                        break
                    result.extend(chunk)
                after = os.fstat(fd)
                _check_file(after)
                if (len(result) != before.st_size or len(result) > max_bytes
                        or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                        != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                    raise CustodyError()
                return bytes(result)
            finally:
                os.close(fd)
    except (OSError, ValueError):
        raise CustodyError() from None


def _create(parent: int, name: str, data: bytes,
            created: list[tuple[int, str, int, int]]) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | os.O_NONBLOCK, 0o600, dir_fd=parent)
    try:
        info = os.fstat(fd)
        created.append((parent, name, info.st_dev, info.st_ino))
        os.fchmod(fd, 0o600)
        _check_file(os.fstat(fd))
        offset = 0
        while offset < len(data):
            count = os.write(fd, data[offset:])
            if count <= 0:
                raise CustodyError()
            offset += count
        os.fsync(fd)
        _check_file(os.fstat(fd))
    finally:
        os.close(fd)
    os.fsync(parent)


def _separate(first: int, second: int) -> None:
    a, b = os.fstat(first), os.fstat(second)
    if (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino):
        raise CustodyError()


def init_authority(blob_path: Path, wrapping_path: Path) -> Authority:
    """Create a pair exclusively; never overwrite or remove someone else's files."""
    try:
        with _parent(blob_path) as (blob_dir, blob_name), \
                _parent(wrapping_path) as (wrap_dir, wrap_name):
            _separate(blob_dir, wrap_dir)
            authority = Authority()
            wrapping = os.urandom(SecretBox.KEY_SIZE)
            blob = authority.export_encrypted(wrapping)
            created: list[tuple[int, str, int, int]] = []
            try:
                _create(blob_dir, blob_name, blob, created)
                _create(wrap_dir, wrap_name, wrapping, created)
            except (OSError, CustodyError):
                for parent, name, device, inode in reversed(created):
                    try:
                        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                        if (info.st_dev, info.st_ino) == (device, inode):
                            os.unlink(name, dir_fd=parent)
                            os.fsync(parent)
                    except OSError:
                        pass
                raise CustodyError() from None
            return authority
    except (OSError, ValueError, KeyStoreError):
        raise CustodyError() from None


def load_authority(blob_path: Path, wrapping_path: Path) -> Authority:
    """Restore signing identity using authenticated ciphertext and separate custody."""
    try:
        with _parent(blob_path) as (blob_dir, _), _parent(wrapping_path) as (wrap_dir, _):
            _separate(blob_dir, wrap_dir)
        return Authority.load_encrypted(read_private(blob_path, MAX_AUTHORITY_BYTES),
                                        read_private(wrapping_path, SecretBox.KEY_SIZE))
    except (OSError, ValueError, KeyStoreError):
        raise CustodyError() from None
