"""Sealed workload-secret-bundle escrow (trusted-caller library).

``nexus-secrets`` is the encrypted-secret transport half of recovery:
a recovery manifest's ``secretBundle`` carries only the reference
triple ``{secretSetRef, versionDigest, bundleDigest}`` (see
console/recovery.py) — this module produces and consumes the sealed
bundle those digests point at.

A bundle is an opaque sealed byte string plus a small JSON envelope:

    {schemaVersion:1, kind:'workload-secret-bundle', secretSetRef,
     versionDigest, bundleDigest, sealingScheme, createdAt}

``versionDigest`` is the SHA256 of the canonical plaintext secret-set
payload (the logical version of the secret set, independent of
sealing randomness); ``bundleDigest`` is the SHA256 of the sealed
bytes — the exact value a manifest's ``secretBundle.bundleDigest``
must equal. ``seal`` turns a private directory of secret files into
the blob+envelope; ``verify`` proves the digest binding; ``provision``
unseals into a root-0700 private directory only after the envelope,
the caller-supplied manifest binding and the blob digest all agree —
contents are never printed, logged or written near the Nix store.

SEALING PRIMITIVE: ``AgeSealer`` implements the ``Sealer`` seam
with the pinned ``age`` binary (X25519 recipients; the payload is a
ChaCha20-Poly1305 STREAM AEAD) as a fixed-argv bounded subprocess.
The key is a verbatim age key file: an identity file
(``AGE-SECRET-KEY-1...`` lines plus ``#`` comments, as ``age-keygen``
emits) seals and opens, while a recipients-only file (public
``age1...`` lines) seals without ever holding unseal capability —
the escrow shape is "seal anywhere with the recipient, provision
only where the identity lives". Secret material never touches a
filesystem or argv: the child reads the identity through an
anonymous memfd as ``/proc/self/fd/N``. age accepts no associated
data, so the SHA-256 of the caller's AAD is prepended to the
plaintext as a fixed-format header line and verified byte-exact
after decryption — a blob sealed under one envelope can never open
under another. The pinned tool supplies no headless passphrase mode
(``age -p`` prompts on a TTY), so the asymmetric identity model is
the supported shape. ``UnavailableSealer`` remains the default for
direct ``SecretsService`` construction — callers opt in — while the
``nexus-secrets`` CLI wires ``AgeSealer`` when no sealer is
injected; the ``workload-secrets`` host module pins ``pkgs.age``
in the wrapper's runtime inputs.

KEY SOURCE: a private euid-owned 0600 key file pinned in a
root-owned config JSON read through the same safe-ancestor +
O_NOFOLLOW + fstat pattern as the backup worker's config. For
``AgeSealer`` that file is the age identity or recipients file
described above.

MODULE-NAME NOTE: this file shadows the stdlib ``secrets`` module
for every sibling module under this directory (``import secrets`` in
server.py, registry.py, ingress.py, console_api.py resolves here).
The real stdlib module is loaded below and every undefined attribute
falls through to it, so their token primitives are unchanged.
"""

import argparse
import base64
import binascii
import copy
import hashlib
import importlib.util
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import sysconfig
import time

import artifacts
import catalog
import statefiles
import worker


def _load_stdlib_secrets():
    """Load the real stdlib ``secrets`` module by file path, bypassing
    the sys.modules shadow this file creates for ``import secrets``."""
    path = os.path.join(sysconfig.get_path('stdlib'), 'secrets.py')
    spec = importlib.util.spec_from_file_location(
        '_nexus_stdlib_secrets', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_STDLIB_SECRETS = _load_stdlib_secrets()


def __getattr__(name):
    # Fall through to the real stdlib ``secrets`` module for any name
    # this module does not define (token_hex, token_urlsafe,
    # compare_digest, ...), preserving sibling-module behavior.
    return getattr(_STDLIB_SECRETS, name)


class SecretsError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class Sealer:
    """Narrow cipher-primitive seam.

    ``scheme`` is the ``sealingScheme`` token recorded in the envelope
    and is bound into the sealed bytes through the AAD. ``seal`` maps
    (key, plaintext, aad) to an opaque blob; ``open`` reverses it and
    MUST raise ``SecretsError('unseal-failed')`` — carrying no detail —
    for any integrity, authenticity or format failure. The production
    implementation is ``AgeSealer`` (a fixed-argv bounded subprocess to
    the pinned ``age`` binary); ``UnavailableSealer`` remains the
    default for direct ``SecretsService`` construction so library
    callers opt in explicitly.
    """
    scheme = None

    def seal(self, key, plaintext, aad):
        raise NotImplementedError

    def open(self, key, blob, aad):
        raise NotImplementedError


class UnavailableSealer(Sealer):
    """Conservative default: refuse both directions until a caller
    injects a real sealer such as ``AgeSealer``."""
    scheme = None

    def seal(self, key, plaintext, aad):
        raise SecretsError('sealer-unavailable')

    def open(self, key, blob, aad):
        raise SecretsError('sealer-unavailable')


_SCHEMA_VERSION = 1
_KIND = 'workload-secret-bundle'
_SET_KIND = 'workload-secret-set'
_ENVELOPE_FIELDS = ('schemaVersion', 'kind', 'secretSetRef',
                    'versionDigest', 'bundleDigest', 'sealingScheme',
                    'createdAt')
_BINDING_FIELDS = ('secretSetRef', 'versionDigest', 'bundleDigest')
_SET_FIELDS = ('schemaVersion', 'kind', 'secretSetRef', 'files')
_CONFIG_FIELDS = {'schemaVersion', 'keyFile'}
_SEAL_REQUEST = {'schemaVersion', 'action', 'secretSetRef',
                 'sourceDir', 'bundleFile'}
_VERIFY_REQUEST = {'schemaVersion', 'action', 'envelope', 'bundleFile'}
_PROVISION_REQUEST = {'schemaVersion', 'action', 'envelope',
                      'bundleFile', 'targetDir', 'binding'}
_INSPECT_REQUEST = {'schemaVersion', 'action', 'envelope'}
_INSPECT_BLOB_REQUEST = {'schemaVersion', 'action', 'envelope',
                         'bundleFile'}
_NAME_RE = re.compile(r'[A-Za-z0-9_.-]{1,255}')
_MAX_REQUEST_BYTES = 65536
_MAX_CONFIG_BYTES = 64 * 1024
_MAX_ENVELOPE_BYTES = 16 * 1024
_MAX_FILES = 64
_MAX_FILE_BYTES = 256 * 1024
_MAX_SET_BYTES = 2 * 1024 * 1024
_MAX_BLOB_BYTES = 8 * 1024 * 1024
_KEY_MIN_BYTES = 32
_KEY_MAX_BYTES = 4096
_MAX_TIME = 2**53
_NIX_STORE = '/nix/store'
_INTERNAL_ERRORS = (OSError, ValueError, KeyError, TypeError,
                    AttributeError, RecursionError)
_lstat = os.lstat
_fstat = os.fstat


def _response(response, stdout=None):
    out = sys.stdout if stdout is None else stdout
    out.write(artifacts.canonical_bytes(response).decode('utf-8')
              + '\n')


def _within(path, ancestor):
    return path == ancestor or path.startswith(ancestor + '/')


def _digest_of(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _now(clock):
    try:
        value = clock()
    except Exception:
        raise SecretsError('clock-invalid') from None
    if type(value) is bool or type(value) not in (int, float) \
            or value != value or value in (float('inf'),
                                           float('-inf')):
        raise SecretsError('clock-invalid')
    value = int(value)
    if not 0 <= value <= _MAX_TIME:
        raise SecretsError('clock-invalid')
    return value


def _check_key(key):
    if type(key) is not bytes \
            or not _KEY_MIN_BYTES <= len(key) <= _KEY_MAX_BYTES:
        raise SecretsError('key-invalid')


def _check_sealer(sealer):
    scheme = getattr(sealer, 'scheme', None)
    if type(scheme) is not str:
        raise SecretsError('sealer-unavailable')
    try:
        catalog.identifier(scheme, 'sealingScheme')
    except catalog.CatalogError:
        raise SecretsError('sealer-unavailable') from None


# -- age sealer ----------------------------------------------------------

_AGE_SCHEME = 'age-x25519-v1'
_AGE_TIMEOUT = 60
_AGE_STDERR_MAX = 64 * 1024
_AGE_MAX_KEY_LINES = 16
# Header line prepended to the plaintext before encryption; age
# takes no AAD, so the caller's AAD is bound by this digest instead
# and verified byte-exact on open before any plaintext is returned.
_AGE_HEADER = b'nexus-secret-bundle age-x25519-v1 sha256:'
_AGE_SECRET_LINE = re.compile(r'AGE-SECRET-KEY-1[0-9A-Za-z]{30,120}')
_AGE_RECIPIENT_LINE = re.compile(r'age1[0-9a-z]{30,120}')


def _age_key_material(key, code):
    """Split key bytes into ``(identities, recipients)``.

    The key file is a verbatim age key file: blank lines and ``#``
    comments are ignored; every other line must be an X25519 secret
    (``AGE-SECRET-KEY-1...``) or public recipient (``age1...``).
    Anything else — ssh keys, plugin lines, garbage — is rejected so
    the ``age-x25519-v1`` token can never silently name another
    primitive."""
    if type(key) is not bytes:
        raise SecretsError(code)
    try:
        text = key.decode('ascii')
    except UnicodeDecodeError:
        raise SecretsError(code) from None
    identities = []
    recipients = []
    for line in text.split('\n'):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if _AGE_SECRET_LINE.fullmatch(stripped) is not None:
            identities.append(stripped)
        elif _AGE_RECIPIENT_LINE.fullmatch(stripped) is not None:
            recipients.append(stripped)
        else:
            raise SecretsError(code)
    if not 0 < len(identities) + len(recipients) <= _AGE_MAX_KEY_LINES:
        raise SecretsError(code)
    return identities, recipients


def _identity_memfd(identities, code):
    """Copy identity lines into an anonymous memfd. The age child
    opens it as ``/proc/self/fd/N``: secret material never touches a
    filesystem, never enters argv and dies with the last fd."""
    payload = ('\n'.join(identities) + '\n').encode('ascii')
    try:
        fd = os.memfd_create('nexus-age-identity')
    except AttributeError:
        raise SecretsError('sealer-unavailable') from None
    except OSError:
        raise SecretsError(code) from None
    try:
        view = memoryview(payload)
        while view:
            view = view[os.write(fd, view):]
        os.lseek(fd, 0, os.SEEK_SET)
    except OSError:
        os.close(fd)
        raise SecretsError(code) from None
    return fd


class _AgeRunner:
    """Bounded fixed-argv runner for the pinned ``age`` binary.

    The same discipline as ``repository.BoundedRunner`` — shell-free
    argv, a new session/process group, a fixed minimal environment,
    a monotonic deadline, byte caps on both output streams and a
    whole-group kill on any breach — extended with a nonblocking
    stdin feed and an inherited-fd table so the identity can ride a
    memfd (``/proc/self/fd/N``) instead of a filesystem path.
    Command output and secret material never reach error text; every
    failure raises ``SecretsError(code)`` with the caller's code.
    """

    def __init__(self, env=None):
        self.env = {'PATH': os.environ.get('PATH', os.defpath),
                    'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'} \
            if env is None else dict(env)

    def _reap(self, proc):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            pass
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                stream.close()
            except (OSError, AttributeError):
                pass

    def run(self, argv, *, code, data=b'', pass_fds=(),
            max_out=_MAX_BLOB_BYTES, timeout=_AGE_TIMEOUT):
        try:
            proc = subprocess.Popen(
                argv, shell=False, env=self.env,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True,
                pass_fds=pass_fds)
        except OSError:
            raise SecretsError(code) from None
        deadline = time.monotonic() + timeout
        completed = None
        selector = None
        try:
            selector = selectors.DefaultSelector()
            selector.register(proc.stdout, selectors.EVENT_READ,
                              ('out', bytearray(), max_out))
            selector.register(proc.stderr, selectors.EVENT_READ,
                              ('err', bytearray(), _AGE_STDERR_MAX))
            os.set_blocking(proc.stdin.fileno(), False)
            selector.register(proc.stdin, selectors.EVENT_WRITE,
                              ('in', None, None))
            pending = memoryview(data)
            streams = {}
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SecretsError(code)
                for key, _mask in selector.select(min(remaining, 1.0)):
                    which, buffer, cap = key.data
                    if which == 'in':
                        if not pending:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        try:
                            written = os.write(key.fileobj.fileno(),
                                               pending)
                        except BlockingIOError:
                            continue
                        except OSError:
                            # The child closed stdin (failing fast):
                            # drop the write side, keep draining.
                            pending = memoryview(b'')
                            selector.unregister(key.fileobj)
                            try:
                                key.fileobj.close()
                            except OSError:
                                pass
                            continue
                        pending = pending[written:]
                        if not pending:
                            selector.unregister(key.fileobj)
                            try:
                                key.fileobj.close()
                            except OSError:
                                pass
                        continue
                    try:
                        chunk = os.read(key.fileobj.fileno(), 65536)
                    except OSError:
                        raise SecretsError(code) from None
                    buffer += chunk
                    if len(buffer) > cap:
                        raise SecretsError(code)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    streams[which] = buffer
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SecretsError(code)
                try:
                    exit_code = proc.wait(timeout=min(remaining, 1.0))
                    break
                except subprocess.TimeoutExpired:
                    continue
            completed = subprocess.CompletedProcess(
                argv, exit_code, bytes(streams.get('out', b'')),
                bytes(streams.get('err', b'')))
            return completed
        except OSError:
            raise SecretsError(code) from None
        finally:
            # Any exception or interruption leaves no live child, no
            # live process-group member and no open pipe behind.
            if completed is None:
                self._reap(proc)
            else:
                for stream in (proc.stdin, proc.stdout, proc.stderr):
                    try:
                        stream.close()
                    except (OSError, AttributeError):
                        pass
            if selector is not None:
                try:
                    selector.close()
                except OSError:
                    pass


class AgeSealer(Sealer):
    """Real sealer over the pinned ``age`` binary (X25519).

    ``key`` is the raw content of an age key file. Identity files
    (``AGE-SECRET-KEY-1...`` lines) seal via ``age -e -a -i FD`` — the
    identity's own recipient — and open via ``age -d -i FD``, with
    the identity passed on an anonymous memfd so the secret never
    touches a filesystem or argv. Recipients-only files
    (``age1...`` lines) seal via ``age -e -a -r RECIPIENT`` and can
    never open: the escrow shape "seal anywhere with the public
    recipient, provision only where the identity lives".

    age accepts no associated data, so seal prepends
    ``_AGE_HEADER + sha256(aad)`` as a header line to the plaintext
    and open verifies it byte-exact before returning anything — a
    blob sealed under one envelope can never open under another.
    """
    scheme = _AGE_SCHEME

    def __init__(self, *, binary='age', runner=None):
        self._binary = binary
        self._runner = _AgeRunner() if runner is None else runner

    def seal(self, key, plaintext, aad):
        identities, recipients = _age_key_material(key, 'key-invalid')
        argv = [self._binary, '-e', '-a']
        fd = None
        try:
            if identities:
                fd = _identity_memfd(identities, 'sealer-failed')
                argv += ['-i', '/proc/self/fd/' + str(fd)]
            for recipient in recipients:
                argv += ['-r', recipient]
            header = _AGE_HEADER + hashlib.sha256(aad).hexdigest() \
                .encode('ascii') + b'\n'
            result = self._runner.run(
                argv, data=header + plaintext,
                pass_fds=() if fd is None else (fd,),
                max_out=_MAX_BLOB_BYTES, code='sealer-failed')
        finally:
            if fd is not None:
                os.close(fd)
        if result.returncode != 0 or not result.stdout:
            raise SecretsError('sealer-failed')
        return result.stdout

    def open(self, key, blob, aad):
        identities, _recipients = _age_key_material(
            key, 'unseal-failed')
        if not identities:
            raise SecretsError('unseal-failed')
        fd = _identity_memfd(identities, 'unseal-failed')
        try:
            result = self._runner.run(
                [self._binary, '-d', '-i', '/proc/self/fd/' + str(fd)],
                data=blob, pass_fds=(fd,),
                max_out=_MAX_SET_BYTES + 1024, code='unseal-failed')
        finally:
            os.close(fd)
        if result.returncode != 0:
            raise SecretsError('unseal-failed')
        raw = result.stdout
        expect = _AGE_HEADER + hashlib.sha256(aad).hexdigest() \
            .encode('ascii')
        line, sep, payload = raw.partition(b'\n')
        if not sep or line != expect:
            raise SecretsError('unseal-failed')
        return payload


# -- envelope contract --------------------------------------------------

def validate_envelope(value):
    """Strictly validate a bundle envelope; return a defensive copy."""
    if type(value) is not dict \
            or set(value) != set(_ENVELOPE_FIELDS):
        raise SecretsError('invalid-envelope')
    record = copy.deepcopy(value)
    if type(record['schemaVersion']) is not int \
            or record['schemaVersion'] != _SCHEMA_VERSION:
        raise SecretsError('invalid-envelope')
    if type(record['kind']) is not str or record['kind'] != _KIND:
        raise SecretsError('invalid-envelope')
    try:
        catalog.identifier(record['secretSetRef'], 'secretSetRef')
        catalog._digest(record['versionDigest'], 'versionDigest')
        catalog._digest(record['bundleDigest'], 'bundleDigest')
        catalog.identifier(record['sealingScheme'], 'sealingScheme')
    except catalog.CatalogError:
        raise SecretsError('invalid-envelope') from None
    if type(record['createdAt']) is not int \
            or not 0 <= record['createdAt'] <= _MAX_TIME:
        raise SecretsError('invalid-envelope')
    return record


def encode_envelope(value):
    record = validate_envelope(value)
    try:
        raw = artifacts.canonical_bytes(record)
    except artifacts.ArtifactError:
        raise SecretsError('invalid-envelope') from None
    if len(raw) > _MAX_ENVELOPE_BYTES:
        raise SecretsError('invalid-envelope')
    return raw


def _reject_constant(value):
    raise SecretsError('invalid-json')


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SecretsError('invalid-json')
        result[key] = value
    return result


def decode_envelope(raw):
    """Byte-exact canonical decode, mirroring recovery.decode_manifest."""
    if type(raw) is not bytes or not raw \
            or len(raw) > _MAX_ENVELOPE_BYTES:
        raise SecretsError('invalid-envelope')
    try:
        value = json.loads(raw, parse_constant=_reject_constant,
                           object_pairs_hook=_no_duplicate_keys)
    except SecretsError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError,
            ValueError):
        raise SecretsError('invalid-envelope') from None
    record = validate_envelope(value)
    if encode_envelope(record) != raw:
        raise SecretsError('invalid-envelope')
    return record


def manifest_binding(envelope):
    """The exact ``secretBundle`` triple a recovery manifest carries."""
    record = validate_envelope(envelope)
    return {key: record[key] for key in _BINDING_FIELDS}


def validate_binding(value):
    """Strictly validate a caller-supplied manifest secretBundle."""
    if type(value) is not dict \
            or set(value) != set(_BINDING_FIELDS):
        raise SecretsError('invalid-binding')
    try:
        catalog.identifier(value['secretSetRef'], 'secretSetRef')
        catalog._digest(value['versionDigest'], 'versionDigest')
        catalog._digest(value['bundleDigest'], 'bundleDigest')
    except catalog.CatalogError:
        raise SecretsError('invalid-binding') from None
    return {key: value[key] for key in _BINDING_FIELDS}


def _aad(record):
    """Envelope fields bound into the sealed bytes (everything except
    createdAt and bundleDigest, which the blob itself derives)."""
    return artifacts.canonical_bytes({
        'kind': _KIND,
        'secretSetRef': record['secretSetRef'],
        'sealingScheme': record['sealingScheme'],
        'versionDigest': record['versionDigest']})


# -- filesystem safety ---------------------------------------------------

def _check_ancestors(path, euid):
    """Every component above the final one must be a non-symlink
    directory owned by root-or-euid and not group/other writable;
    root-owned sticky directories are allowed."""
    current = ''
    parts = [part for part in path.split('/') if part]
    for part in parts[:-1]:
        current += '/' + part
        st = _lstat(current)
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) \
                or st.st_uid not in (0, euid) \
                or (stat.S_IMODE(st.st_mode) & 0o022
                    and not (st.st_uid == 0
                             and st.st_mode & stat.S_ISVTX)):
            raise SecretsError('path-unsafe')


def _check_config_path(path):
    """Root-owned non-symlink regular file under safe ancestors
    (Nix-store 0444 root files are allowed)."""
    _check_ancestors(path, os.geteuid())
    st = _lstat(path)
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) \
            or st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
        raise SecretsError('path-unsafe')


def _read_config_file(path):
    """Bounded root-owned config read: safe path, O_NOFOLLOW open,
    fstat confirmation of the same regular file, limit+1 bytes."""
    try:
        worker._path(path, 'config')
    except worker.WorkerError as error:
        raise SecretsError(error.code) from None
    _check_config_path(path)
    try:
        st = _lstat(path)
    except OSError:
        raise SecretsError('path-unavailable') from None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise SecretsError('path-unavailable') from None
    try:
        fst = _fstat(fd)
        if not stat.S_ISREG(fst.st_mode) \
                or fst.st_uid != 0 or stat.S_IMODE(fst.st_mode) & 0o022 \
                or (fst.st_ino, fst.st_dev) != (st.st_ino, st.st_dev):
            raise SecretsError('path-unsafe')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            raw = handle.read(_MAX_CONFIG_BYTES + 1)
    except OSError:
        raise SecretsError('path-unavailable') from None
    finally:
        os.close(fd)
    if len(raw) > _MAX_CONFIG_BYTES:
        raise SecretsError('invalid-config')
    return raw


def _read_key_file(path):
    """Bounded private key read: euid-owned exactly-0600 regular file
    under private ancestors, O_NOFOLLOW, 32..4096 bytes of key."""
    try:
        worker._path(path, 'keyFile')
    except worker.WorkerError:
        raise SecretsError('invalid-config') from None
    try:
        statefiles.check_private_dir(os.path.dirname(path))
        present = statefiles.check_private_file(path)
    except statefiles.PathError as error:
        raise SecretsError(error.code) from None
    except OSError:
        raise SecretsError('path-unavailable') from None
    if not present:
        raise SecretsError('key-missing')
    try:
        st = _lstat(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise SecretsError('key-unavailable') from None
    try:
        fst = _fstat(fd)
        if not stat.S_ISREG(fst.st_mode) \
                or fst.st_uid != os.geteuid() \
                or stat.S_IMODE(fst.st_mode) != 0o600 \
                or (fst.st_ino, fst.st_dev) != (st.st_ino, st.st_dev):
            raise SecretsError('key-unavailable')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            raw = handle.read(_KEY_MAX_BYTES + 1)
    except OSError:
        raise SecretsError('key-unavailable') from None
    finally:
        os.close(fd)
    _check_key(raw)
    return raw


def _fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise SecretsError('path-unavailable') from None
    try:
        os.fsync(fd)
    except OSError:
        raise SecretsError('path-unavailable') from None
    finally:
        os.close(fd)


def _read_blob(path):
    """Bounded read of a sealed bundle file. The blob is ciphertext —
    it must be a regular non-symlink root-or-euid-owned file but is
    not required to be 0600 (transports may publish it)."""
    try:
        worker._path(path, 'bundleFile')
    except worker.WorkerError:
        raise SecretsError('invalid-request') from None
    try:
        st = _lstat(path)
    except OSError:
        raise SecretsError('bundle-unavailable') from None
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) \
            or st.st_uid not in (0, os.geteuid()):
        raise SecretsError('path-unsafe')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise SecretsError('bundle-unavailable') from None
    try:
        fst = _fstat(fd)
        if not stat.S_ISREG(fst.st_mode) \
                or (fst.st_ino, fst.st_dev) != (st.st_ino, st.st_dev):
            raise SecretsError('path-unsafe')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            raw = handle.read(_MAX_BLOB_BYTES + 1)
    except OSError:
        raise SecretsError('bundle-unavailable') from None
    finally:
        os.close(fd)
    if not raw or len(raw) > _MAX_BLOB_BYTES:
        raise SecretsError('invalid-bundle')
    return raw


def _write_blob(path, blob):
    """Durable exclusive create of the sealed bundle (0600, fsynced)
    inside an already-private parent; never follows symlinks."""
    try:
        worker._path(path, 'bundleFile')
    except worker.WorkerError:
        raise SecretsError('invalid-request') from None
    if _within(path, _NIX_STORE):
        raise SecretsError('path-unsafe')
    parent = os.path.dirname(path)
    try:
        statefiles.check_private_dir(parent)
    except statefiles.PathError as error:
        raise SecretsError(error.code) from None
    except OSError:
        raise SecretsError('path-unavailable') from None
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise SecretsError('path-unsafe') from None
    except OSError:
        raise SecretsError('path-unavailable') from None
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(blob)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    except OSError:
        raise SecretsError('path-unavailable') from None
    finally:
        os.close(fd)
    _fsync_dir(parent)


def _check_secret_entry(path, name):
    """lstat + open-fstat recheck: a regular euid-owned file with no
    group/other permission bits, read through O_NOFOLLOW."""
    try:
        st = _lstat(path)
    except OSError:
        raise SecretsError('path-unavailable') from None
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) \
            or st.st_uid != os.geteuid() \
            or stat.S_IMODE(st.st_mode) & 0o077:
        raise SecretsError('path-unsafe')
    if st.st_size > _MAX_FILE_BYTES:
        raise SecretsError('invalid-secret-set')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise SecretsError('path-unavailable') from None
    try:
        fst = _fstat(fd)
        if not stat.S_ISREG(fst.st_mode) \
                or fst.st_uid != os.geteuid() \
                or stat.S_IMODE(fst.st_mode) & 0o077 \
                or (fst.st_ino, fst.st_dev) != (st.st_ino, st.st_dev):
            raise SecretsError('path-unsafe')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            raw = handle.read(_MAX_FILE_BYTES + 1)
    except OSError:
        raise SecretsError('path-unavailable') from None
    finally:
        os.close(fd)
    if len(raw) > _MAX_FILE_BYTES:
        raise SecretsError('invalid-secret-set')
    return raw


def _name_ok(name):
    return type(name) is str and name not in ('.', '..') \
        and _NAME_RE.fullmatch(name) is not None


# -- seal / verify / provision -------------------------------------------

def _read_secret_set(source_dir, secret_set_ref):
    """Snapshot a private secret dir into the canonical inner payload."""
    try:
        worker._path(source_dir, 'sourceDir')
        catalog.identifier(secret_set_ref, 'secretSetRef')
    except (worker.WorkerError, catalog.CatalogError):
        raise SecretsError('invalid-request') from None
    if _within(source_dir, _NIX_STORE):
        raise SecretsError('path-unsafe')
    try:
        statefiles.check_private_dir(source_dir)
    except statefiles.PathError as error:
        raise SecretsError(error.code) from None
    except FileNotFoundError:
        raise SecretsError('path-unavailable') from None
    except OSError:
        raise SecretsError('path-unavailable') from None
    try:
        names = os.listdir(source_dir)
    except OSError:
        raise SecretsError('path-unavailable') from None
    if not 0 < len(names) <= _MAX_FILES:
        raise SecretsError('invalid-secret-set')
    files = []
    for name in names:
        if not _name_ok(name):
            raise SecretsError('invalid-secret-set')
        raw = _check_secret_entry(os.path.join(source_dir, name), name)
        files.append((name, raw))
    files.sort()
    if sum(len(raw) for _name, raw in files) > _MAX_SET_BYTES:
        raise SecretsError('invalid-secret-set')
    entries = [{'name': name,
                'data': base64.b64encode(raw).decode('ascii')}
               for name, raw in files]
    inner = {'schemaVersion': _SCHEMA_VERSION, 'kind': _SET_KIND,
             'secretSetRef': secret_set_ref, 'files': entries}
    try:
        payload = artifacts.canonical_bytes(inner)
    except artifacts.ArtifactError:
        raise SecretsError('invalid-secret-set') from None
    if len(payload) > _MAX_SET_BYTES:
        raise SecretsError('invalid-secret-set')
    return payload


def seal(source_dir, secret_set_ref, *, key, sealer, clock=time.time):
    """Seal a private secret dir; return ``(blob, envelope)``.

    The caller supplies the key and a ``Sealer`` implementation; the
    default ``UnavailableSealer`` refuses — no confidentiality claim
    exists until a pinned AEAD sealer is wired. The sealed bytes bind
    kind/secretSetRef/sealingScheme/versionDigest as AAD so a blob can
    never be re-paired with a different envelope."""
    _check_sealer(sealer)
    _check_key(key)
    payload = _read_secret_set(source_dir, secret_set_ref)
    created = _now(clock)
    version_digest = _digest_of(payload)
    aad = artifacts.canonical_bytes({
        'kind': _KIND, 'secretSetRef': secret_set_ref,
        'sealingScheme': sealer.scheme,
        'versionDigest': version_digest})
    try:
        blob = sealer.seal(key, payload, aad)
    except SecretsError:
        raise
    except Exception:
        # Seam output text is never trusted: a sealer failure carries
        # no detail so secret bytes can never ride an exception.
        raise SecretsError('sealer-failed') from None
    if type(blob) is not bytes or not blob \
            or len(blob) > _MAX_BLOB_BYTES:
        raise SecretsError('sealer-failed')
    envelope = validate_envelope({
        'schemaVersion': _SCHEMA_VERSION, 'kind': _KIND,
        'secretSetRef': secret_set_ref,
        'versionDigest': version_digest,
        'bundleDigest': _digest_of(blob),
        'sealingScheme': sealer.scheme,
        'createdAt': created})
    return blob, envelope


def verify(envelope, blob):
    """Prove schema validity plus blob↔bundleDigest agreement."""
    record = validate_envelope(envelope)
    if type(blob) is not bytes or not blob \
            or len(blob) > _MAX_BLOB_BYTES:
        raise SecretsError('invalid-bundle')
    if _digest_of(blob) != record['bundleDigest']:
        raise SecretsError('bundle-digest-mismatch')
    return record


def _decode_inner(raw):
    """Strict decode of the canonical plaintext secret-set payload.
    Any deviation is 'unseal-failed' — opened bytes whose shape does
    not parse are an integrity failure, never a partial accept."""
    if type(raw) is not bytes or not raw or len(raw) > _MAX_SET_BYTES:
        raise SecretsError('unseal-failed')
    try:
        value = json.loads(raw, parse_constant=_reject_constant,
                           object_pairs_hook=_no_duplicate_keys)
    except SecretsError:
        raise SecretsError('unseal-failed') from None
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError,
            ValueError):
        raise SecretsError('unseal-failed') from None
    if type(value) is not dict or set(value) != set(_SET_FIELDS):
        raise SecretsError('unseal-failed')
    if value['schemaVersion'] != _SCHEMA_VERSION \
            or type(value['schemaVersion']) is not int \
            or type(value['kind']) is not str \
            or value['kind'] != _SET_KIND:
        raise SecretsError('unseal-failed')
    try:
        catalog.identifier(value['secretSetRef'], 'secretSetRef')
    except catalog.CatalogError:
        raise SecretsError('unseal-failed') from None
    files = value['files']
    if type(files) is not list or not 0 < len(files) <= _MAX_FILES:
        raise SecretsError('unseal-failed')
    entries = []
    names = []
    total = 0
    for entry in files:
        if type(entry) is not dict or set(entry) != {'name', 'data'} \
                or not _name_ok(entry.get('name')):
            raise SecretsError('unseal-failed')
        data = entry['data']
        if type(data) is not str or len(data) > _MAX_SET_BYTES:
            raise SecretsError('unseal-failed')
        try:
            decoded = base64.b64decode(data.encode('ascii'),
                                       validate=True)
        except (binascii.Error, ValueError, UnicodeEncodeError):
            raise SecretsError('unseal-failed') from None
        if len(decoded) > _MAX_FILE_BYTES \
                or base64.b64encode(decoded).decode('ascii') != data:
            raise SecretsError('unseal-failed')
        total += len(decoded)
        entries.append((entry['name'], decoded))
        names.append(entry['name'])
    if len(set(names)) != len(names) or names != sorted(names) \
            or total > _MAX_SET_BYTES:
        raise SecretsError('unseal-failed')
    try:
        if artifacts.canonical_bytes(value) != raw:
            raise SecretsError('unseal-failed')
    except artifacts.ArtifactError:
        raise SecretsError('unseal-failed') from None
    return {'secretSetRef': value['secretSetRef'], 'files': entries}


def _check_target(target_dir):
    """Target must resolve to an exactly-0700 euid-owned non-symlink
    empty private dir — created on demand — under safe ancestors,
    never inside the Nix store."""
    try:
        worker._path(target_dir, 'targetDir')
    except worker.WorkerError:
        raise SecretsError('invalid-request') from None
    if _within(target_dir, _NIX_STORE):
        raise SecretsError('path-unsafe')
    euid = os.geteuid()
    _check_ancestors(target_dir, euid)
    try:
        st = _lstat(target_dir)
    except FileNotFoundError:
        try:
            os.mkdir(target_dir, 0o700)
        except OSError:
            raise SecretsError('path-unavailable') from None
        _fsync_dir(os.path.dirname(target_dir))
        return
    except OSError:
        raise SecretsError('path-unavailable') from None
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) \
            or st.st_uid != euid \
            or stat.S_IMODE(st.st_mode) != 0o700:
        raise SecretsError('path-unsafe')
    try:
        if os.listdir(target_dir):
            raise SecretsError('target-not-empty')
    except OSError:
        raise SecretsError('path-unavailable') from None


def _write_secret(path, raw):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise SecretsError('path-unsafe') from None
    except OSError:
        raise SecretsError('path-unavailable') from None
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(raw)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    except OSError:
        raise SecretsError('path-unavailable') from None
    finally:
        os.close(fd)


def provision(envelope, blob, target_dir, *, key, sealer, binding=None):
    """Unseal a verified bundle into a private 0700 directory.

    Every gate runs before any write: envelope schema, the optional
    manifest binding triple, the blob's bundleDigest, the sealing
    scheme's availability, the AEAD open, the strict inner decode and
    the versionDigest re-derivation. File contents never appear in
    responses, logs or exception text."""
    record = verify(envelope, blob)
    if binding is not None:
        if validate_binding(binding) != manifest_binding(record):
            raise SecretsError('bundle-binding-mismatch')
    _check_sealer(sealer)
    if record['sealingScheme'] != sealer.scheme:
        raise SecretsError('sealing-scheme-unknown')
    _check_key(key)
    try:
        payload = sealer.open(key, blob, _aad(record))
    except SecretsError as error:
        # A conforming sealer raises 'unseal-failed'; remap any other
        # code so no hint about the failure escapes the seam.
        if error.code == 'unseal-failed':
            raise
        raise SecretsError('unseal-failed') from None
    except Exception:
        raise SecretsError('unseal-failed') from None
    inner = _decode_inner(payload)
    if inner['secretSetRef'] != record['secretSetRef'] \
            or _digest_of(payload) != record['versionDigest']:
        raise SecretsError('unseal-failed')
    _check_target(target_dir)
    for name, raw in inner['files']:
        _write_secret(os.path.join(target_dir, name), raw)
    _fsync_dir(target_dir)
    _fsync_dir(os.path.dirname(target_dir))
    return {'secretSetRef': record['secretSetRef'],
            'versionDigest': record['versionDigest'],
            'bundleDigest': record['bundleDigest'],
            'fileCount': len(inner['files'])}


# -- service + CLI --------------------------------------------------------


def _validate_config(config):
    if type(config) is not dict or set(config) != _CONFIG_FIELDS:
        raise SecretsError('invalid-config')
    if type(config['schemaVersion']) is not int \
            or config['schemaVersion'] != _SCHEMA_VERSION:
        raise SecretsError('invalid-config')
    key_file = config['keyFile']
    if key_file is not None:
        try:
            worker._path(key_file, 'keyFile')
        except worker.WorkerError:
            raise SecretsError('invalid-config') from None
    return dict(config)


class SecretsService:
    """Bounded seal/verify/provision/inspect dispatch.

    No durable journal exists: every verb is a one-shot operation
    whose only filesystem effect is the requested private output.
    """

    def __init__(self, config, *, sealer=None, clock=time.time):
        self._config = _validate_config(config)
        self._sealer = UnavailableSealer() if sealer is None else sealer
        self._clock = clock
        self._key_value = None
        self._key_loaded = False

    def _key(self):
        if not self._key_loaded:
            key_file = self._config['keyFile']
            if key_file is None:
                raise SecretsError('key-unavailable')
            self._key_value = _read_key_file(key_file)
            self._key_loaded = True
        return self._key_value

    def _seal(self, request):
        try:
            catalog.identifier(request['secretSetRef'],
                               'request secretSetRef')
            worker._path(request['sourceDir'], 'request sourceDir')
            worker._path(request['bundleFile'], 'request bundleFile')
        except (catalog.CatalogError, worker.WorkerError):
            raise SecretsError('invalid-request') from None
        if _within(request['bundleFile'], request['sourceDir']):
            raise SecretsError('invalid-request')
        blob, envelope = seal(request['sourceDir'],
                              request['secretSetRef'],
                              key=self._key(), sealer=self._sealer,
                              clock=self._clock)
        _write_blob(request['bundleFile'], blob)
        return {'schemaVersion': 1, 'status': 'completed',
                'action': 'seal', 'envelope': envelope}

    def _verify(self, request):
        record = verify(request['envelope'],
                        _read_blob(request['bundleFile']))
        return {'schemaVersion': 1, 'status': 'completed',
                'action': 'verify', 'envelope': record}

    def _provision(self, request):
        try:
            worker._path(request['targetDir'], 'request targetDir')
        except worker.WorkerError:
            raise SecretsError('invalid-request') from None
        binding = request['binding']
        if binding is not None and type(binding) is not dict:
            raise SecretsError('invalid-request')
        record = provision(request['envelope'],
                           _read_blob(request['bundleFile']),
                           request['targetDir'],
                           key=self._key(), sealer=self._sealer,
                           binding=binding)
        return {'schemaVersion': 1, 'status': 'completed',
                'action': 'provision',
                'secretSetRef': record['secretSetRef'],
                'versionDigest': record['versionDigest'],
                'bundleDigest': record['bundleDigest'],
                'fileCount': record['fileCount']}

    def _inspect(self, request):
        record = validate_envelope(request['envelope'])
        response = {'schemaVersion': 1, 'status': 'completed',
                    'action': 'inspect', 'envelope': record}
        if 'bundleFile' in request:
            blob = _read_blob(request['bundleFile'])
            verify(record, blob)
            response['bundleBytes'] = len(blob)
            response['digestMatches'] = True
        return response

    def execute(self, request):
        try:
            if type(request) is not dict \
                    or type(request.get('schemaVersion')) is not int \
                    or request['schemaVersion'] != 1 \
                    or type(request.get('action')) is not str:
                raise SecretsError('invalid-request')
            action = request['action']
            if action == 'seal':
                if set(request) != _SEAL_REQUEST:
                    raise SecretsError('invalid-request')
                return self._seal(request)
            if action == 'verify':
                if set(request) != _VERIFY_REQUEST \
                        or type(request['envelope']) is not dict:
                    raise SecretsError('invalid-request')
                return self._verify(request)
            if action == 'provision':
                if set(request) != _PROVISION_REQUEST \
                        or type(request['envelope']) is not dict:
                    raise SecretsError('invalid-request')
                return self._provision(request)
            if action == 'inspect':
                if set(request) not in (_INSPECT_REQUEST,
                                        _INSPECT_BLOB_REQUEST) \
                        or type(request['envelope']) is not dict:
                    raise SecretsError('invalid-request')
                return self._inspect(request)
            raise SecretsError('invalid-request')
        except SecretsError as error:
            return {'schemaVersion': 1, 'status': 'blocked',
                    'error': error.code}
        except worker.WorkerError as error:
            return {'schemaVersion': 1, 'status': 'blocked',
                    'error': error.code}
        except statefiles.PathError as error:
            return {'schemaVersion': 1, 'status': 'blocked',
                    'error': error.code}
        except _INTERNAL_ERRORS:
            return {'schemaVersion': 1, 'status': 'blocked',
                    'error': 'internal-error'}


def main(argv=None, *, sealer=None, stdin=None, stdout=None,
         clock=time.time):
    parser = argparse.ArgumentParser(prog='nexus-secrets')
    parser.add_argument('--config', required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    for verb in ('seal', 'verify', 'provision', 'inspect'):
        commands.add_parser(verb)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        _response({'schemaVersion': 1, 'status': 'error',
                   'error': 'requires-root'}, stdout)
        return 1
    try:
        raw_config = _read_config_file(args.config)
        config = worker.load_json_bytes(raw_config)
        instance = SecretsService(
            config, sealer=AgeSealer() if sealer is None else sealer,
            clock=clock)
    except (SecretsError, worker.WorkerError) as error:
        _response({'schemaVersion': 1, 'status': 'error',
                   'error': error.code}, stdout)
        return 1
    except _INTERNAL_ERRORS:
        _response({'schemaVersion': 1, 'status': 'error',
                   'error': 'invalid-config'}, stdout)
        return 1
    source = sys.stdin.buffer if stdin is None else stdin
    raw = source.read(_MAX_REQUEST_BYTES + 1)
    if len(raw) > _MAX_REQUEST_BYTES:
        _response({'schemaVersion': 1, 'status': 'error',
                   'error': 'request-too-large'}, stdout)
        return 1
    try:
        request = worker.load_json_bytes(raw)
    except worker.WorkerError as error:
        _response({'schemaVersion': 1, 'status': 'error',
                   'error': error.code}, stdout)
        return 1
    response = instance.execute(request)
    _response(response, stdout)
    return 0 if response.get('status') == 'completed' else 1


if __name__ == '__main__':
    sys.exit(main())
