"""Unprivileged private-state file primitives shared by registry and ingress.

Every path is validated before use: all ancestors must be non-symlink
directories owned by root or the effective UID, and no ancestor may be
group/other writable except root-owned sticky directories such as /tmp.
The private directory itself must be owned by the effective UID with no
group/other permission bits. Files must be regular, euid-owned and exactly
mode 0600; existing foreign files are never silently repaired. This is
deliberately separate from the root-only worker SecurePaths checks.
"""
import json
import os
import stat
import tempfile

import artifacts
import worker


class PathError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _file_state(path):
    try:
        return os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        raise PathError('path-unavailable') from None


def _sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _sync_dir_checked(path):
    try:
        _sync_dir(path)
    except OSError:
        raise PathError('path-unavailable') from None


def check_private_dir(path):
    """Require ``path`` to be an euid-owned directory with ``& 0o077 == 0``
    and every ancestor to satisfy the root-or-euid/non-writable rule."""
    euid = os.geteuid()
    current = ''
    checked = False
    for part in [p for p in path.split('/') if p]:
        current += '/' + part
        st = os.lstat(current)
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
            raise PathError('path-unsafe')
        mode = stat.S_IMODE(st.st_mode)
        if current == path:
            if st.st_uid != euid or mode & 0o077:
                raise PathError('path-unsafe')
            checked = True
        elif st.st_uid not in (0, euid) \
                or (mode & 0o022
                    and not (st.st_uid == 0 and mode & stat.S_ISVTX)):
            raise PathError('path-unsafe')
    if not checked:
        st = os.lstat(path)
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) \
                or st.st_uid != euid \
                or stat.S_IMODE(st.st_mode) & 0o077:
            raise PathError('path-unsafe')


def check_private_file(path):
    """Return True when ``path`` exists as a regular euid-owned 0600 file;
    False when missing; PathError otherwise."""
    st = _file_state(path)
    if st is None:
        return False
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() \
            or stat.S_IMODE(st.st_mode) != 0o600:
        raise PathError('path-unsafe')
    return True


def ensure_private_file(path):
    """Like check_private_file but durably creates a missing file;
    returns True when the file was created. The inode is never
    unlinked or replaced once created: a parent-sync failure keeps it
    so a lock or journal already opened on it cannot be split, and the
    parent is fsynced again on every subsequent success path."""
    parent = os.path.dirname(path)
    check_private_dir(parent)
    if check_private_file(path):
        _sync_dir_checked(parent)
        return False
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        check_private_file(path)
        _sync_dir_checked(parent)
        return False
    try:
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)
    _sync_dir_checked(parent)
    return True


def read_json(path, limit):
    """Read a strict JSON document from a private file; None when missing."""
    if not check_private_file(path):
        return None
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with os.fdopen(fd, 'rb') as handle:
            data = handle.read(limit + 1)
    except OSError:
        raise PathError('path-unavailable') from None
    if len(data) > limit:
        raise PathError('path-unsafe')
    try:
        value = worker.load_json_bytes(data)
    except worker.WorkerError:
        raise PathError('path-unsafe') from None
    try:
        if artifacts.canonical_bytes(value) != data:
            raise PathError('path-unsafe')
    except artifacts.ArtifactError:
        raise PathError('path-unsafe') from None
    return value


def write_json(path, value):
    """Atomically replace ``path`` with canonical JSON, durably."""
    parent = os.path.dirname(path)
    check_private_dir(parent)
    check_private_file(path)
    try:
        data = artifacts.canonical_bytes(value)
    except artifacts.ArtifactError:
        raise PathError('path-unsafe') from None
    fd, tmp = tempfile.mkstemp(dir=parent, prefix='.statefiles-')
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.replace(tmp, path)
        _sync_dir_checked(parent)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
