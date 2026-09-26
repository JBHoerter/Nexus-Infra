"""Local worker executor for Nexus workload instances.

Durable, exactly-once operation journal in ``<stateDir>/worker.db``;
every action validates, journals, applies and receipts under a single
host flock so crashes replay rather than double-execute.

``prepare`` refuses a pre-existing instance dir
(``storage-state-conflict``) by deliberate invariant. ``adopt`` (M8) is
the strictly validated exception for DRBD failover: the replicated
instance dir may pre-exist only when its ownership is exactly the bound
slot's ``uidBase`` (failover pairs keep ``uidBase`` symmetric so no idmap
translation is needed — the separate restore path exists for cold
restores), every declared ``stateMount`` id is present as a directory
with slot-expected ownership, and nothing else sits at the top level
besides the worker's own files. Valid adoptions are journaled with
``adopted`` provenance so ``observe``/status can report it. Adoption is
always explicit: no component performs it automatically, and there is
no automatic failover trigger here — a future authorized failover
controller (or operator) issues the request
(docs/replication-failover-design.md).

Secret provisioning. A definition carrying ``secretSetRef`` makes the
worker unseal the host-escrowed bundle into ``<instanceDir>/secrets``
during prepare: the pinned ``secretsProgram`` (``nexus-secrets
provision``) runs once per instance under the same journal boundary as
state-dir allocation, output is post-verified, everything is chowned to
the slot's ``uidBase`` and the canonical binding triple is durably
journaled as the ``.nexus-secrets`` marker. The directory is mounted
read-only at ``/run/secrets`` in the container and deliberately lives
inside the replicated instance dir: it is never captured as workload
state (backup binds only declared ``stateMount`` leaves) but travels
with a DRBD replica, so ``adopt`` requires — and never rewrites — a
valid marker-bound secrets dir. A secrets-bearing definition without
the full program/config/bundleDir trio stays rejected with
``secret-provisioning-unavailable``.

Dependency readiness is control-plane owned: the worker sees only
local instances and cannot evaluate cross-host dependencies, so it
stays fail-closed — a request for a definition with non-empty
``dependencies`` is accepted only when it carries the
controller-emitted ``dependenciesResolved`` marker set to the exact
JSON boolean true (an OPTIONAL member of the strict non-observe
request field set); anything else fails ``dependency-not-resolved``.
Internal control-plane-ordered checks (permit guard, restore staging)
carry no request and do not re-check: the dep gate already ran before
the controller dispatched that step.
"""
import argparse
import base64
import binascii
import copy
import fcntl
import ipaddress
import json
import os
import re
import selectors
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import artifacts
import catalog


class WorkerError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class UncertainError(Exception):
    def __init__(self, code='operation-uncertain'):
        super().__init__(code)
        self.code = code


_MAX_REQUEST_BYTES = 16384
_MAX_I64 = 2**63 - 1
_IDENTIFIER_RE = re.compile(r'[a-z][a-z0-9-]{0,62}')
_HEX32_RE = re.compile(r'[0-9a-f]{32}')
_PATH_RE = re.compile(r'/[A-Za-z0-9_/.-]+')
_NIX_BASE32_ALPHABET = '0123456789abcdfghijklmnpqrsvwxyz'
_REQUEST_FIELDS = {'schemaVersion', 'operationId', 'action', 'workloadId',
                   'revisionDigest', 'instanceId', 'generation'}
_CAPTURE_FIELDS = _REQUEST_FIELDS | {'captureId'}
_OBSERVE_FIELDS = {'schemaVersion', 'action', 'instanceId'}
# ``dependenciesResolved`` is the controller's OPTIONAL proof marker on
# any non-observe request (see ``controller._worker_request``): the
# worker sees only local instances and cannot evaluate cross-host
# dependency readiness, so it stays fail-closed — a definition with
# non-empty ``dependencies`` is admissible only when the request
# carries this field set to the exact JSON boolean true. Dep-less
# workloads may omit it entirely; it never appears on observe, whose
# strict field set is separate.
_REQUEST_OPTIONAL = {'dependenciesResolved'}
_RESERVE_PHASES = ('preparing', 'prepared', 'starting', 'running', 'stopping',
                   'unknown')
_PERMIT_SECONDS = 60
_VERIFY_BATCH = 128
_SHOW_PROPERTIES = ('LoadState', 'ActiveState', 'SubState', 'MainPID',
                    'ControlGroup')
_RESTORE_SENTINEL = '.nexus-restore-pending'
# Top-level names the worker itself may place inside an instance dir:
# the durable restore sentinel plus the restore staging area (the staging
# name is shared with restore.py — keep them identical). Adoption of a
# replicated dir tolerates exactly these extras; anything else conflicts.
_ADOPT_OWN_FILES = frozenset({_RESTORE_SENTINEL, '.nexus-restore-staging'})
# Provisioned secrets live inside the instance dir as ``secrets/`` —
# inside the replicated storage tree so a DRBD failover carries them,
# but never part of a backup capture, which binds only the declared
# ``stateMount`` leaves. The durable ``.nexus-secrets`` marker holds the
# canonical manifest binding triple ({secretSetRef, versionDigest,
# bundleDigest}); a marker matching the escrowed envelope is what makes
# an already-populated dir resumable instead of a teardown/reprovision.
_SECRETS_DIR = 'secrets'
_SECRETS_MARKER = '.nexus-secrets'
_SECRETS_MOUNT = '/run/secrets'
_SECRET_BINDING_FIELDS = frozenset(
    {'secretSetRef', 'versionDigest', 'bundleDigest'})
_SECRET_RECORD_FIELDS = frozenset({'schemaVersion', 'envelope', 'binding'})
_SECRET_RECORD_MAX = 64 * 1024
_SECRET_MARKER_MAX = 4096
_SECRETS_CLI_TIMEOUT = 120
_SECRETS_CLI_MAX_OUTPUT = 64 * 1024
# All-or-none worker config trio; all values are absolute paths.
_CONFIG_SECRETS = ('secretsProgram', 'secretsConfigFile',
                   'secretsBundleDir')


def _fields(value, expected, context):
    if type(value) is not dict or set(value) != set(expected):
        raise WorkerError('invalid-' + context + '-fields')


def _identifier(value, context):
    if type(value) is not str or _IDENTIFIER_RE.fullmatch(value) is None:
        raise WorkerError('invalid-' + context)


def _hex32(value, context):
    if type(value) is not str or _HEX32_RE.fullmatch(value) is None:
        raise WorkerError('invalid-' + context)


def _digest(value, context):
    if type(value) is not str or not value.startswith('sha256:') \
            or re.fullmatch(r'[0-9a-f]{64}', value[7:]) is None:
        raise WorkerError('invalid-' + context)


def _integer(value, low, high, context):
    if type(value) is not int or not low <= value <= high:
        raise WorkerError('invalid-' + context)


def _path(value, context):
    if type(value) is not str or _PATH_RE.fullmatch(value) is None \
            or '//' in value or value.endswith('/') \
            or any(part in ('', '.', '..') for part in value.split('/')[1:]):
        raise WorkerError('invalid-' + context)


def _within(path, ancestor):
    return path == ancestor or path.startswith(ancestor + '/')


def _ipv4(value, context):
    if type(value) is not str:
        raise WorkerError('invalid-' + context)
    try:
        address = ipaddress.IPv4Address(value)
    except ValueError:
        raise WorkerError('invalid-' + context) from None
    if str(address) != value or not address.is_private \
            or address.is_loopback or address.is_multicast \
            or address.is_unspecified or address.is_link_local:
        raise WorkerError('invalid-' + context)


def _secrets_names(definition):
    """Top-level worker-owned entries a secrets-bearing instance dir
    may carry beyond the declared mount leaves: the provisioned
    ``secrets/`` dir and its ``.nexus-secrets`` binding marker."""
    return {_SECRETS_DIR, _SECRETS_MARKER} \
        if definition['secretSetRef'] is not None else set()


def _id_list(value, context):
    if type(value) is not list or len(value) > 64:
        raise WorkerError('invalid-' + context)
    for item in value:
        _identifier(item, context)
    if len(set(value)) != len(value):
        raise WorkerError('invalid-' + context)


def _store_path(value, context):
    if type(value) is not str or artifacts._STORE_PATH_RE.fullmatch(value) is None:
        raise WorkerError('invalid-' + context)


def validate_config(config):
    _fields({key: value for key, value in config.items()
             if key not in _CONFIG_SECRETS},
            {'schemaVersion', 'hostId', 'architecture', 'stateDir',
             'storage', 'capacity', 'capabilities', 'approvedBundles',
             'slots'}, 'config')
    # The secrets trio is all-or-none: a program without its config or
    # escrow dir can never provision, so partial configuration is a
    # config error rather than a deferred runtime surprise.
    present = [key for key in _CONFIG_SECRETS if key in config]
    if present and len(present) != len(_CONFIG_SECRETS):
        raise WorkerError('invalid-config-secrets')
    for key in _CONFIG_SECRETS:
        if key in config:
            _path(config[key], 'config-' + key)
    _integer(config['schemaVersion'], 1, 1, 'config-schemaVersion')
    _identifier(config['hostId'], 'config-hostId')
    if config['architecture'] not in ('x86_64-linux', 'aarch64-linux') \
            or type(config['architecture']) is not str:
        raise WorkerError('invalid-config-architecture')
    _path(config['stateDir'], 'config-stateDir')
    _fields(config['storage'], {'root', 'mountPoint', 'uuid'}, 'storage')
    _path(config['storage']['root'], 'storage-root')
    _path(config['storage']['mountPoint'], 'storage-mountPoint')
    if config['storage']['mountPoint'] == '/':
        raise WorkerError('invalid-storage-mountPoint')
    if config['storage']['root'] != config['storage']['mountPoint'] \
            and not _within(config['storage']['root'],
                            config['storage']['mountPoint']):
        raise WorkerError('invalid-storage-mountPoint')
    if _within(config['stateDir'], config['storage']['mountPoint']) \
            or _within(config['stateDir'], config['storage']['root']):
        raise WorkerError('invalid-config-stateDir')
    if type(config['storage']['uuid']) is not str \
            or re.fullmatch(r'[0-9A-Fa-f-]{8,64}', config['storage']['uuid']) is None:
        raise WorkerError('invalid-storage-uuid')
    _fields(config['capacity'], {'memoryMiB', 'cpuMillis', 'stateBytes'}, 'capacity')
    for key in ('memoryMiB', 'cpuMillis', 'stateBytes'):
        _integer(config['capacity'][key], 0, _MAX_I64, 'capacity-' + key)
    _id_list(config['capabilities'], 'capabilities')
    if type(config['approvedBundles']) is not list or not config['approvedBundles'] \
            or len(config['approvedBundles']) > 64:
        raise WorkerError('invalid-approvedBundles')
    for bundle in config['approvedBundles']:
        _store_path(bundle, 'approvedBundles')
    if len(set(config['approvedBundles'])) != len(config['approvedBundles']):
        raise WorkerError('invalid-approvedBundles')
    if type(config['slots']) is not list or not 1 <= len(config['slots']) <= 64:
        raise WorkerError('invalid-slots')
    seen_ids, seen_uids, seen_addresses = set(), set(), set()
    for slot in config['slots']:
        _fields(slot, {'id', 'uidBase', 'hostAddress', 'localAddress'}, 'slot')
        _identifier(slot['id'], 'slot-id')
        if type(slot['uidBase']) is not int or slot['uidBase'] <= 0 \
                or slot['uidBase'] % 65536 != 0 \
                or slot['uidBase'] > 2**32 - 131072:
            raise WorkerError('invalid-slot-uidBase')
        _ipv4(slot['hostAddress'], 'slot-hostAddress')
        _ipv4(slot['localAddress'], 'slot-localAddress')
        if slot['hostAddress'] == slot['localAddress']:
            raise WorkerError('invalid-slot-address')
        for seen, value in ((seen_ids, slot['id']), (seen_uids, slot['uidBase']),
                            (seen_addresses, slot['hostAddress']),
                            (seen_addresses, slot['localAddress'])):
            if value in seen:
                raise WorkerError('invalid-slot-conflict')
            seen.add(value)
    return copy.deepcopy(config)


class Runner:
    def run(self, argv):
        return subprocess.run(argv, capture_output=True, text=True, timeout=300)


class SecretsCliRunner:
    """Bounded runner for the pinned ``nexus-secrets`` executable.

    Fixed shell-free argv, a fixed minimal environment, a new
    session/process group, a monotonic deadline, byte caps on both
    output streams and a whole-group kill on any breach — the same
    discipline as the reporter's CLI runner — with the small request
    document fed on stdin. The response document carries only binding
    digests, never secret material; every transport failure raises the
    caller's uniform code.
    """

    def __init__(self, env=None):
        # Explicit minimal environment: no inherited PATH tricks,
        # locale overrides or secret-bearing variables reach the child.
        self.env = {'PATH': os.environ.get('PATH', os.defpath),
                    'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'} \
            if env is None else dict(env)

    def _reap(self, proc):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

    def run(self, argv, data=b'', *, timeout=_SECRETS_CLI_TIMEOUT,
            max_out=_SECRETS_CLI_MAX_OUTPUT):
        """Bounded nexus-secrets spawn. Returns a CompletedProcess with
        bytes streams; raises ``WorkerError('secrets-provision-failed')``
        for any transport breach — argv/timeout/env problems look
        identical to a failed child, never silently retried."""
        try:
            proc = subprocess.Popen(argv, shell=False, env=self.env,
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    start_new_session=True)
        except OSError:
            raise WorkerError('secrets-provision-failed') from None
        deadline = time.monotonic() + timeout
        completed = None
        selector = None
        try:
            try:
                proc.stdin.write(data)
                proc.stdin.close()
            except (BrokenPipeError, OSError):
                raise WorkerError('secrets-provision-failed') from None
            finally:
                proc.stdin = None
            selector = selectors.DefaultSelector()
            selector.register(proc.stdout, selectors.EVENT_READ,
                              ('out', bytearray(), max_out))
            selector.register(proc.stderr, selectors.EVENT_READ,
                              ('err', bytearray(), max_out))
            streams = {}
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise WorkerError('secrets-provision-failed')
                for key, _ in selector.select(min(remaining, 1.0)):
                    which, buffer, cap = key.data
                    try:
                        chunk = os.read(key.fileobj.fileno(), 65536)
                    except OSError:
                        raise WorkerError(
                            'secrets-provision-failed') from None
                    buffer += chunk
                    if len(buffer) > cap:
                        raise WorkerError('secrets-provision-failed')
                    if not chunk:
                        selector.unregister(key.fileobj)
                    streams[which] = buffer
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise WorkerError('secrets-provision-failed')
                try:
                    code = proc.wait(timeout=min(remaining, 1.0))
                    break
                except subprocess.TimeoutExpired:
                    continue
            completed = subprocess.CompletedProcess(
                argv, code, bytes(streams.get('out', b'')),
                bytes(streams.get('err', b'')))
            return completed
        except OSError:
            raise WorkerError('secrets-provision-failed') from None
        finally:
            if selector is not None:
                try:
                    selector.close()
                except OSError:
                    pass
            if completed is None:
                self._reap(proc)
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass


class HostFilesystem:
    def lstat(self, path):
        return os.lstat(path)

    def sync_dir(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def mkdir(self, path, mode):
        os.mkdir(path, mode)
        os.chmod(path, mode)
        self.sync_dir(path)
        self.sync_dir(os.path.dirname(path))

    def listdir(self, path):
        return os.listdir(path)

    def create_file(self, path, mode):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     mode)
        try:
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        self.sync_dir(os.path.dirname(path))

    def write_file(self, path, data, mode):
        directory = os.path.dirname(path)
        if os.path.islink(path):
            raise WorkerError('path-unsafe')
        fd, temporary = tempfile.mkstemp(dir=directory, prefix='.worker-')
        try:
            with os.fdopen(fd, 'wb') as handle:
                handle.write(
                    data if type(data) is bytes else data.encode('utf-8'))
                os.fchmod(handle.fileno(), mode)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise

    def chown(self, path, uid, gid):
        os.chown(path, uid, gid, follow_symlinks=False)

    def unlink(self, path):
        os.unlink(path)

    def rmdir(self, path):
        os.rmdir(path)

    def exists(self, path):
        return os.path.exists(path)

    def is_symlink(self, path):
        return os.path.islink(path)

    def statvfs(self, path):
        return os.statvfs(path)

    def read_text(self, path):
        return Path(path).read_text()

    def read_bytes(self, path):
        return Path(path).read_bytes()

    def read_bounded(self, path, limit):
        with open(path, 'rb') as handle:
            return handle.read(limit + 1)


class Clock:
    def time(self):
        return time.time()

    def monotonic(self):
        return time.monotonic()


def _host_boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def _nix_base32_bytes(text):
    value = 0
    for char in text:
        value = value * 32 + _NIX_BASE32_ALPHABET.index(char)
    return value.to_bytes(32, 'little')


def nar_hash_bytes(value):
    if type(value) is not str:
        raise WorkerError('invalid-narHash')
    if value.startswith('sha256:'):
        tail = value[7:]
        if re.fullmatch(r'[0-9a-f]{64}', tail):
            return bytes.fromhex(tail)
        if re.fullmatch(r'[01][0123456789abcdfghijklmnpqrsvwxyz]{51}', tail):
            return _nix_base32_bytes(tail)
    elif value.startswith('sha256-'):
        tail = value[7:]
        if len(tail) == 44:
            try:
                decoded = base64.b64decode(tail, validate=True)
            except (ValueError, binascii.Error):
                decoded = None
            if decoded is not None and len(decoded) == 32 \
                    and base64.b64encode(decoded).decode() == tail:
                return decoded
    raise WorkerError('invalid-narHash')


def _machine_name(instance_id):
    return 'n' + base64.b32encode(bytes.fromhex(instance_id)).decode().lower()[:10]


def _reject_constant(value):
    raise WorkerError('invalid-json-constant')


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise WorkerError('invalid-json-duplicate')
        result[key] = value
    return result


def load_json_bytes(raw):
    if type(raw) is bytes:
        try:
            raw = raw.decode('utf-8')
        except UnicodeDecodeError:
            raise WorkerError('invalid-json') from None
    try:
        return json.loads(raw, parse_constant=_reject_constant,
                          object_pairs_hook=_no_duplicate_keys)
    except (json.JSONDecodeError, RecursionError):
        raise WorkerError('invalid-json') from None


def validate_request(request):
    if type(request) is not dict:
        raise WorkerError('invalid-request-fields')
    if 'dependenciesResolved' in request \
            and type(request['dependenciesResolved']) is not bool:
        raise WorkerError('invalid-request-fields')
    fields = set(request) - _REQUEST_OPTIONAL
    if fields not in (_REQUEST_FIELDS, _OBSERVE_FIELDS, _CAPTURE_FIELDS):
        raise WorkerError('invalid-request-fields')
    _integer(request['schemaVersion'], 1, 1, 'schemaVersion')
    if fields == _OBSERVE_FIELDS:
        if 'dependenciesResolved' in request:
            raise WorkerError('invalid-request-fields')
        if request['action'] != 'observe':
            raise WorkerError('invalid-action')
        _hex32(request['instanceId'], 'instanceId')
        return request['action'], request
    expected = _CAPTURE_FIELDS \
        if request['action'] in ('freeze', 'thaw') else _REQUEST_FIELDS
    if fields != expected:
        raise WorkerError('invalid-request-fields')
    if request['action'] not in ('prepare', 'adopt', 'start', 'stop',
                                 'retire', 'freeze', 'thaw'):
        raise WorkerError('invalid-action')
    _hex32(request['operationId'], 'operationId')
    _identifier(request['workloadId'], 'workloadId')
    _digest(request['revisionDigest'], 'revisionDigest')
    _hex32(request['instanceId'], 'instanceId')
    _integer(request['generation'], 1, _MAX_I64, 'generation')
    if 'captureId' in request:
        _hex32(request['captureId'], 'captureId')
    return request['action'], request


_MACHINE_RE = re.compile(r'n[a-z2-7]{10}')

_SCHEMA = '''
CREATE TABLE IF NOT EXISTS instances(
    instance_id TEXT PRIMARY KEY,
    workload_id TEXT NOT NULL,
    revision_digest TEXT NOT NULL,
    generation INTEGER NOT NULL,
    slot_id TEXT NOT NULL UNIQUE,
    machine_name TEXT NOT NULL UNIQUE,
    phase TEXT NOT NULL,
    requirements TEXT NOT NULL DEFAULT '{}',
    binding_json TEXT,
    boot_id TEXT,
    permit_deadline REAL,
    permit INTEGER NOT NULL DEFAULT 0,
    retired INTEGER NOT NULL DEFAULT 0,
    adopted INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS current_workload
    ON instances(workload_id) WHERE phase IN
    ('preparing','prepared','starting','running','stopping','unknown');
CREATE TABLE IF NOT EXISTS generations(workload_id TEXT PRIMARY KEY, generation INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS operations(
    operation_id TEXT PRIMARY KEY, request TEXT NOT NULL,
    status TEXT NOT NULL, result TEXT);
CREATE TABLE IF NOT EXISTS captures(
    capture_id TEXT PRIMARY KEY,
    instance_id TEXT NOT NULL,
    workload_id TEXT NOT NULL,
    revision_digest TEXT NOT NULL,
    generation INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('held','released')));
CREATE UNIQUE INDEX IF NOT EXISTS held_workload_capture
    ON captures(workload_id) WHERE status='held';
'''

_INTERNAL_ERRORS = (artifacts.ArtifactError, catalog.CatalogError, OSError,
                    sqlite3.Error, subprocess.TimeoutExpired, ValueError)


def verify_closure(manifest, runner):
    result = runner.run(
        ['nix', '--extra-experimental-features', 'nix-command',
         '--store', 'daemon', 'path-info', '--recursive', '--json',
         '--json-format', '1', manifest['root']])
    if result.returncode != 0:
        raise WorkerError('store-verify-failed')
    try:
        records = json.loads(result.stdout)
    except ValueError:
        raise WorkerError('store-schema-unexpected') from None
    if type(records) is dict:
        records = [dict(record, path=path) if type(record) is dict else record
                   for path, record in records.items()]
    if type(records) is not list:
        raise WorkerError('store-schema-unexpected')
    expected = {}
    for entry in manifest['closure']:
        if entry['path'] in expected:
            raise WorkerError('store-closure-mismatch')
        expected[entry['path']] = (nar_hash_bytes(entry['narHash']),
                                   entry['narSize'],
                                   sorted(entry['references']))
    seen = set()
    for record in records:
        if type(record) is not dict or type(record.get('path')) is not str \
                or type(record.get('narHash')) is not str \
                or type(record.get('narSize')) is not int \
                or type(record.get('references')) is not list \
                or any(type(ref) is not str for ref in record['references']):
            raise WorkerError('store-schema-unexpected')
        if record['path'] in seen or record['path'] not in expected:
            raise WorkerError('store-closure-mismatch')
        seen.add(record['path'])
        want = expected[record['path']]
        try:
            actual_hash = nar_hash_bytes(record['narHash'])
        except WorkerError:
            raise WorkerError('store-schema-unexpected') from None
        if actual_hash != want[0] \
                or record['narSize'] != want[1] \
                or sorted(record['references']) != want[2]:
            raise WorkerError('store-closure-mismatch')
    if seen != set(expected):
        raise WorkerError('store-closure-mismatch')
    paths = sorted(expected)
    for offset in range(0, len(paths), _VERIFY_BATCH):
        check = runner.run(
            ['nix-store', '--store', 'daemon', '--verify-path']
            + paths[offset:offset + _VERIFY_BATCH])
        if check.returncode != 0:
            raise WorkerError('store-verify-failed')


class SecurePaths:
    def _lstat(self, path):
        try:
            return self.fs.lstat(path)
        except FileNotFoundError:
            return None

    def _check_ancestors(self, path):
        current = ''
        for part in [p for p in path.split('/') if p][:-1]:
            current += '/' + part
            st = self._lstat(current)
            if st is None or not stat.S_ISDIR(st.st_mode) \
                    or stat.S_ISLNK(st.st_mode) or st.st_uid != 0:
                raise WorkerError('path-unsafe')
            mode = stat.S_IMODE(st.st_mode)
            if mode & 0o022 and not st.st_mode & stat.S_ISVTX:
                raise WorkerError('path-unsafe')

    def _ensure_dir(self, path, mode):
        current = ''
        for part in [p for p in path.split('/') if p]:
            current += '/' + part
            st = self._lstat(current)
            if st is None:
                self.fs.mkdir(current, mode)
                st = self._lstat(current)
                if st is None:
                    raise WorkerError('path-unsafe')
            else:
                if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) \
                        or st.st_uid != 0:
                    raise WorkerError('path-unsafe')
                pmode = stat.S_IMODE(st.st_mode)
                if current != path and pmode & 0o022 \
                        and not st.st_mode & stat.S_ISVTX:
                    raise WorkerError('path-unsafe')
        st = self._lstat(path)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 \
                or stat.S_IMODE(st.st_mode) != mode:
            raise WorkerError('path-unsafe')

    def _check_dir(self, path, uid=0, gid=0, mode=None):
        self._check_ancestors(path)
        st = self._lstat(path)
        if st is None or not stat.S_ISDIR(st.st_mode) \
                or stat.S_ISLNK(st.st_mode) or st.st_uid != uid \
                or st.st_gid != gid:
            raise WorkerError('path-unsafe')
        if mode is not None and stat.S_IMODE(st.st_mode) != mode:
            raise WorkerError('path-unsafe')

    def _check_file(self, path, mode):
        st = self._lstat(path)
        if st is None or not stat.S_ISREG(st.st_mode) or st.st_uid != 0 \
                or stat.S_IMODE(st.st_mode) != mode:
            raise WorkerError('path-unsafe')

    def _ensure_metadata_file(self, path):
        self._check_ancestors(path)
        st = self._lstat(path)
        if st is None:
            self.fs.create_file(path, 0o600)
            st = self._lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 \
                or stat.S_IMODE(st.st_mode) != 0o600:
            raise WorkerError('path-unsafe')
        for suffix in ('-wal', '-shm', '-journal'):
            sibling = self._lstat(path + suffix)
            if sibling is not None and (
                    not stat.S_ISREG(sibling.st_mode) or sibling.st_uid != 0
                    or stat.S_IMODE(sibling.st_mode) != 0o600):
                raise WorkerError('path-unsafe')


class Worker(SecurePaths):
    def __init__(self, config, *, runner=None, fs=None, clock=None, boot_id=None,
                 unit_dir='/run/systemd/system', secrets_runner=None):
        self.config = validate_config(config)
        self.runner = runner or Runner()
        self.secrets_runner = secrets_runner \
            if secrets_runner is not None else SecretsCliRunner()
        self.fs = fs or HostFilesystem()
        self.clock = clock or Clock()
        self.boot_id = boot_id if boot_id is not None else _host_boot_id()
        self.unit_dir = unit_dir
        state_dir = self.config['stateDir']
        self._ensure_dir(state_dir, 0o700)
        self._ensure_dir(os.path.join(state_dir, 'instances'), 0o700)
        self._db_path = os.path.join(state_dir, 'worker.db')
        self._lock_path = os.path.join(state_dir, 'worker.lock')
        self._ensure_metadata_file(self._db_path)
        self._ensure_metadata_file(self._lock_path)
        self.db = sqlite3.connect(self._db_path, check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript(_SCHEMA)
        columns = {row[1] for row in self.db.execute(
            'PRAGMA table_info(instances)')}
        if 'binding_json' not in columns:
            self.db.execute(
                'ALTER TABLE instances ADD COLUMN binding_json TEXT')
        if 'retired' not in columns:
            self.db.execute(
                'ALTER TABLE instances ADD COLUMN retired'
                ' INTEGER NOT NULL DEFAULT 0')
        if 'adopted' not in columns:
            self.db.execute(
                'ALTER TABLE instances ADD COLUMN adopted'
                ' INTEGER NOT NULL DEFAULT 0')
        self.db.commit()
        self._bundles = None

    def close(self):
        self.db.close()


    def _lock(self):
        handle = open(self._lock_path, 'r')
        fcntl.flock(handle, fcntl.LOCK_EX)
        return handle


    def _load_bundles(self):
        loaded = {}
        for bundle in self.config['approvedBundles']:
            try:
                raw_manifest = self.fs.read_bytes(
                    os.path.join(bundle, 'artifact.json'))
                manifest = artifacts.validate_manifest(load_json_bytes(raw_manifest))
                if raw_manifest != artifacts.canonical_bytes(manifest):
                    raise WorkerError('invalid-bundle')
                digest_file = self.fs.read_bytes(
                    os.path.join(bundle, 'artifact.sha256')).decode('utf-8').strip()
                if digest_file != artifacts.manifest_digest(manifest):
                    raise WorkerError('invalid-bundle')
                raw_definition = self.fs.read_bytes(
                    os.path.join(bundle, 'definition.json'))
                definition = catalog.validate_definition(
                    load_json_bytes(raw_definition))
                if raw_definition != artifacts.canonical_bytes(definition):
                    raise WorkerError('invalid-bundle')
            except WorkerError:
                raise
            except _INTERNAL_ERRORS:
                raise WorkerError('invalid-bundle') from None
            runtime = [a for a in definition['artifacts']
                       if a['id'] == definition['runtimeArtifactId']]
            if len(runtime) != 1 or runtime[0]['kind'] != 'nixos-closure' \
                    or runtime[0]['digest'] != artifacts.manifest_digest(manifest):
                raise WorkerError('invalid-bundle')
            if manifest['runtimeVersion'] != 'nspawn-v1':
                raise WorkerError('invalid-bundle')
            loaded[(definition['workloadId'], definition['revisionDigest'])] = (
                bundle, manifest, definition)
        return loaded

    def _bundles_by_revision(self):
        if self._bundles is None:
            self._bundles = self._load_bundles()
        return self._bundles

    def _resolve(self, workload_id, revision_digest):
        entry = self._bundles_by_revision().get((workload_id, revision_digest))
        if entry is None:
            raise WorkerError('unknown-workload')
        return entry

    def _check_bundle_host(self, manifest, definition):
        if manifest['architecture'] != self.config['architecture'] \
                or definition['architecture'] != self.config['architecture']:
            raise WorkerError('invalid-bundle')

    def _verify_mount(self):
        storage = self.config['storage']
        probe = storage['root']
        while not self.fs.exists(probe):
            parent = os.path.dirname(probe)
            if parent == probe:
                raise WorkerError('storage-not-mounted')
            probe = parent
        result = self.runner.run(
            ['findmnt', '--json', '--noheadings', '--output', 'TARGET,SOURCE,UUID',
             '--target', probe])
        if result.returncode != 0:
            raise WorkerError('storage-not-mounted')
        try:
            rows = json.loads(result.stdout)['filesystems']
        except (KeyError, ValueError):
            raise WorkerError('storage-schema-unexpected') from None
        if len(rows) != 1 or rows[0].get('target') != storage['mountPoint'] \
                or rows[0].get('uuid') != storage['uuid']:
            raise WorkerError('storage-mount-mismatch')
        return probe

    def _verify_closure(self, manifest):
        return verify_closure(manifest, self.runner)


    def _requirements_of(self, definition):
        req = definition['requirements']
        return {'memoryMiB': req['memoryMiB'], 'cpuMillis': req['cpuMillis'],
                'stateBytes': req['stateBytes']}

    def _reservation_map(self, exclude_instance=None):
        reserved = {'memoryMiB': 0, 'cpuMillis': 0, 'stateBytes': 0}
        held = {row[0] for row in self.db.execute(
            "SELECT instance_id FROM captures WHERE status='held'")}
        for instance_id, phase, raw in self.db.execute(
                'SELECT instance_id, phase, requirements FROM instances'):
            req = json.loads(raw)
            if phase in _RESERVE_PHASES or instance_id in held:
                for key in reserved:
                    reserved[key] += req.get(key, 0)
            else:
                reserved['stateBytes'] += req.get('stateBytes', 0)
        if exclude_instance is not None:
            rec = self._get_instance(exclude_instance)
            if rec is not None:
                req = json.loads(rec['requirements'])
                reserved['stateBytes'] = max(
                    0, reserved['stateBytes'] - req.get('stateBytes', 0))
                if rec['phase'] in _RESERVE_PHASES \
                        or rec['instance_id'] in held:
                    reserved['memoryMiB'] = max(
                        0, reserved['memoryMiB'] - req.get('memoryMiB', 0))
                    reserved['cpuMillis'] = max(
                        0, reserved['cpuMillis'] - req.get('cpuMillis', 0))
        return reserved

    def _admission(self, definition, exclude_instance=None, statvfs_path=None):
        meminfo = self.fs.read_text('/proc/meminfo')
        match = re.search(r'^MemAvailable:\s*(\d+) kB$', meminfo, re.M)
        if match is None:
            raise WorkerError('capacity-unavailable')
        memory = min(self.config['capacity']['memoryMiB'], int(match.group(1)) // 1024)
        cpu = min(self.config['capacity']['cpuMillis'], (os.cpu_count() or 0) * 1000)
        free = self.fs.statvfs(statvfs_path or self.config['storage']['root'])
        state = min(self.config['capacity']['stateBytes'], free.f_bavail * free.f_frsize)
        now = self.clock.time()
        host = {'schemaVersion': 2, 'hostId': self.config['hostId'],
                'architecture': self.config['architecture'],
                'capabilities': list(self.config['capabilities'])}
        observation = {'schemaVersion': 2, 'hostId': self.config['hostId'],
                       'observedAt': now,
                       'available': {'memoryMiB': memory, 'cpuMillis': cpu,
                                     'stateBytes': state}}
        decision = catalog.admit(definition, host, observation, now=now,
                                 reservations=self._reservation_map(exclude_instance))
        if not decision['eligible']:
            raise WorkerError('admission-' + decision['reasons'][0].split(':')[0])

    def _check_action_allowed(self, definition, action, request=None):
        """Category/allowedOperations gate shared by every action path.

        ``request`` is ``None`` only for internal control-plane-ordered
        callers — the permit guard and restore staging — which run
        inside a sequence the controller dispatched after verifying
        dependencies; there is no request to mark, so the dep gate must
        not re-block them (mirroring how the secrets gate lives outside
        this check). A request-bearing call is fail-closed the other
        way: a definition with non-empty ``dependencies`` is accepted
        only when the request carries the controller-emitted
        ``dependenciesResolved`` marker set to the exact JSON boolean
        true — anything else (absent, false, wrong type already
        rejected in ``validate_request``) fails
        ``dependency-not-resolved``."""
        needed = 'start' if action == 'prepare' else action
        if definition['category'] in ('archive', 'infrastructure'):
            raise WorkerError('workload-not-mutable')
        if needed not in definition['allowedOperations']:
            raise WorkerError('operation-not-allowed')
        if request is not None and definition['dependencies'] \
                and request.get('dependenciesResolved') is not True:
            raise WorkerError('dependency-not-resolved')

    # -- secret provisioning ------------------------------------------------

    def _secrets_ready(self):
        return all(key in self.config for key in _CONFIG_SECRETS)

    def _require_secrets_gate(self, definition):
        """A secrets-bearing definition is unusable without the full
        program/config/bundleDir trio — the same reject the old
        unconditional check produced, now gated on configuration."""
        if definition['secretSetRef'] is not None \
                and not self._secrets_ready():
            raise WorkerError('secret-provisioning-unavailable')

    def _secrets_names(self, definition):
        return _secrets_names(definition)

    def _check_secret_extra(self, name, path, slot, *, code,
                            strict_owner):
        """Shape rules for the worker's own secrets entries inside an
        instance dir: ``secrets/`` is an exactly-0700 non-symlink dir,
        ``.nexus-secrets`` a root-owned exactly-0600 regular file. With
        ``strict_owner`` (post-prepare invariants) the dir must be
        slot-owned; adopt/resume also accept root ownership — either a
        replica's original or a mid-provision residue."""
        st = self._lstat(path)
        if name == _SECRETS_DIR:
            uid_base = slot['uidBase']
            owners = {(uid_base, uid_base)} if strict_owner \
                else {(0, 0), (uid_base, uid_base)}
            if st is None or not stat.S_ISDIR(st.st_mode) \
                    or stat.S_ISLNK(st.st_mode) \
                    or stat.S_IMODE(st.st_mode) != 0o700 \
                    or (st.st_uid, st.st_gid) not in owners:
                raise WorkerError(code)
            return
        if st is None or not stat.S_ISREG(st.st_mode) \
                or stat.S_ISLNK(st.st_mode) or st.st_uid != 0 \
                or stat.S_IMODE(st.st_mode) != 0o600:
            raise WorkerError(code)

    def _load_secret_record(self, secret_set_ref):
        """Read and validate the host escrow record for a secret set.

        The store layout is ``<secretsBundleDir>/<ref>.json`` (escrow
        record: the returned seal envelope plus an optional pinned
        manifest binding) and ``<secretsBundleDir>/<ref>.blob`` (the
        sealed bytes ``nexus-secrets seal`` wrote) — both populated
        out-of-band by the controller/operator, both root-owned and
        never group/other writable, inside an exactly-0700 root dir.
        Returns ``(envelope, pinned, binding)`` where ``binding`` is the
        envelope's own manifest triple used for the marker."""
        bundle_dir = self.config['secretsBundleDir']
        self._check_dir(bundle_dir, mode=0o700)
        record_path = os.path.join(bundle_dir, secret_set_ref + '.json')
        blob_path = os.path.join(bundle_dir, secret_set_ref + '.blob')
        for path in (record_path, blob_path):
            st = self._lstat(path)
            if st is None:
                raise WorkerError('secrets-bundle-missing')
            if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) \
                    or st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
                raise WorkerError('path-unsafe')
        try:
            raw = self.fs.read_bounded(record_path, _SECRET_RECORD_MAX)
        except OSError:
            raise WorkerError('path-unavailable') from None
        if len(raw) > _SECRET_RECORD_MAX:
            raise WorkerError('secrets-bundle-invalid')
        try:
            record = load_json_bytes(raw)
            if type(record) is not dict \
                    or set(record) != _SECRET_RECORD_FIELDS \
                    or type(record['schemaVersion']) is not int \
                    or record['schemaVersion'] != 1:
                raise WorkerError('secrets-bundle-invalid')
            envelope = record['envelope']
            if type(envelope) is not dict \
                    or envelope.get('secretSetRef') != secret_set_ref:
                raise WorkerError('secrets-bundle-invalid')
            binding = {'secretSetRef': secret_set_ref}
            for key in ('versionDigest', 'bundleDigest'):
                _digest(envelope.get(key), 'secrets-bundle')
                binding[key] = envelope[key]
            pinned = record['binding']
            if pinned is not None:
                if type(pinned) is not dict \
                        or set(pinned) != _SECRET_BINDING_FIELDS \
                        or pinned['secretSetRef'] != secret_set_ref:
                    raise WorkerError('secrets-bundle-invalid')
                _digest(pinned['versionDigest'], 'secrets-bundle')
                _digest(pinned['bundleDigest'], 'secrets-bundle')
        except WorkerError as error:
            if error.code == 'secrets-bundle-invalid':
                raise
            raise WorkerError('secrets-bundle-invalid') from None
        return envelope, pinned, binding

    def _run_secrets_cli(self, secret_set_ref, envelope, binding,
                         target_dir):
        """One bounded ``nexus-secrets provision`` call. The sealed
        blob path and the escrowed envelope plus the optional pinned
        manifest binding go on stdin; the response's own digests must
        echo the envelope exactly — anything else is a transport
        failure, never a partial accept. Typed CLI blocks are surfaced
        as ``secrets-<code>``; opaque failures are uniform."""
        request = {'schemaVersion': 1, 'action': 'provision',
                   'envelope': envelope,
                   'bundleFile': os.path.join(
                       self.config['secretsBundleDir'],
                       secret_set_ref + '.blob'),
                   'targetDir': target_dir, 'binding': binding}
        result = self.secrets_runner.run(
            [self.config['secretsProgram'], '--config',
             self.config['secretsConfigFile'], 'provision'],
            artifacts.canonical_bytes(request))
        try:
            body = load_json_bytes(result.stdout)
        except WorkerError:
            raise WorkerError('secrets-provision-failed') from None
        if type(body) is not dict or type(body.get('status')) is not str:
            raise WorkerError('secrets-provision-failed')
        if body['status'] == 'blocked':
            error = body.get('error')
            if type(error) is str \
                    and _IDENTIFIER_RE.fullmatch(error) is not None:
                raise WorkerError('secrets-' + error)
            raise WorkerError('secrets-provision-failed')
        if result.returncode != 0 or body['status'] != 'completed' \
                or body.get('action') != 'provision' \
                or body.get('secretSetRef') != secret_set_ref \
                or body.get('versionDigest') != envelope['versionDigest'] \
                or body.get('bundleDigest') != envelope['bundleDigest'] \
                or type(body.get('fileCount')) is not int \
                or body['fileCount'] < 1:
            raise WorkerError('secrets-provision-failed')

    def _wipe_secrets_dir(self, secrets_dir):
        """Remove a provision-partial ``secrets/`` dir — only ever flat
        regular files, never silently a foreign tree — and the dir."""
        for name in self.fs.listdir(secrets_dir):
            path = os.path.join(secrets_dir, name)
            entry = self._lstat(path)
            if entry is None or not stat.S_ISREG(entry.st_mode) \
                    or stat.S_ISLNK(entry.st_mode):
                raise WorkerError('storage-state-conflict')
            self.fs.unlink(path)
        self.fs.rmdir(secrets_dir)

    def _provision_secrets(self, rec, definition, slot):
        """Unseal the escrowed bundle into ``<instanceDir>/secrets``.

        Idempotent boundary inside 'preparing': the instance row is
        already journaled, so a crash anywhere here replays. The
        ``.nexus-secrets`` marker (canonical binding triple, root 0600)
        lands only after the provisioned tree is durable and slot-owned
        — a marker matching the pinned escrow record means "done",
        anything else means the last attempt never completed and is
        torn down before a fresh provision. A populated dir without a
        valid marker is never trusted as secret material."""
        if definition['secretSetRef'] is None:
            return
        ref = definition['secretSetRef']
        if _SECRETS_DIR in {mount['id'] for mount
                            in definition['stateMounts']}:
            raise WorkerError('storage-state-conflict')
        instance_dir = self._instance_dir(rec)
        secrets_dir = os.path.join(instance_dir, _SECRETS_DIR)
        marker_path = os.path.join(instance_dir, _SECRETS_MARKER)
        uid_base = slot['uidBase']
        envelope, pinned, binding = self._load_secret_record(ref)
        expected = artifacts.canonical_bytes(binding)
        mst = self._lstat(marker_path)
        matched = False
        if mst is not None:
            if not stat.S_ISREG(mst.st_mode) or mst.st_uid != 0 \
                    or stat.S_IMODE(mst.st_mode) != 0o600:
                raise WorkerError('storage-state-conflict')
            try:
                matched = self.fs.read_bounded(
                    marker_path, _SECRET_MARKER_MAX) == expected
            except OSError:
                raise WorkerError('path-unavailable') from None
        dst = self._lstat(secrets_dir)
        if matched:
            # Resume path: the marker proves this dir was fully
            # provisioned from this exact envelope, but the tree itself
            # is re-verified — a marker without its slot-owned payload
            # is a conflict, never a silent skip.
            if dst is None or not stat.S_ISDIR(dst.st_mode) \
                    or stat.S_ISLNK(dst.st_mode) \
                    or stat.S_IMODE(dst.st_mode) != 0o700 \
                    or (dst.st_uid, dst.st_gid) != (uid_base, uid_base):
                raise WorkerError('storage-state-conflict')
            try:
                names = self.fs.listdir(secrets_dir)
            except OSError:
                raise WorkerError('path-unavailable') from None
            if not names:
                raise WorkerError('storage-state-conflict')
            for name in names:
                st = self._lstat(os.path.join(secrets_dir, name))
                if st is None or not stat.S_ISREG(st.st_mode) \
                        or stat.S_ISLNK(st.st_mode) \
                        or (st.st_uid, st.st_gid) != (uid_base, uid_base):
                    raise WorkerError('storage-state-conflict')
            return
        if rec['adopted']:
            # An adopted row may only ever reuse the replicated pair:
            # the marker is bound to exactly the escrowed envelope
            # ``_adopt_secrets`` validated before the row was journaled,
            # so a missing or mismatched pair on replay is a conflict —
            # never a reprovision over replicated state.
            raise WorkerError('adopt-state-conflict')
        if dst is not None:
            if not stat.S_ISDIR(dst.st_mode) \
                    or stat.S_ISLNK(dst.st_mode) \
                    or stat.S_IMODE(dst.st_mode) != 0o700 \
                    or (dst.st_uid, dst.st_gid) not in (
                        (0, 0), (uid_base, uid_base)):
                raise WorkerError('storage-state-conflict')
            self._wipe_secrets_dir(secrets_dir)
            self.fs.sync_dir(instance_dir)
        if mst is not None:
            self.fs.unlink(marker_path)
            self.fs.sync_dir(instance_dir)
        self._run_secrets_cli(ref, envelope, pinned, secrets_dir)
        dst = self._lstat(secrets_dir)
        if dst is None or not stat.S_ISDIR(dst.st_mode) \
                or stat.S_ISLNK(dst.st_mode) \
                or stat.S_IMODE(dst.st_mode) != 0o700 or dst.st_uid != 0:
            raise WorkerError('secrets-provision-failed')
        try:
            names = self.fs.listdir(secrets_dir)
        except OSError:
            raise WorkerError('path-unavailable') from None
        if not names:
            raise WorkerError('secrets-provision-failed')
        for name in names:
            path = os.path.join(secrets_dir, name)
            st = self._lstat(path)
            if st is None or not stat.S_ISREG(st.st_mode) \
                    or stat.S_ISLNK(st.st_mode) or st.st_uid != 0:
                raise WorkerError('secrets-provision-failed')
            self.fs.chown(path, uid_base, uid_base)
        self.fs.chown(secrets_dir, uid_base, uid_base)
        self.fs.sync_dir(secrets_dir)
        self.fs.write_file(marker_path, expected, 0o600)
        self.fs.sync_dir(instance_dir)
        self.fs.sync_dir(rec['binding']['storage']['root'])

    def _adopt_secrets(self, instance_dir, definition, slot):
        """Content validation for replicated secrets entries before an
        adopt is journaled. ``secrets/`` lives inside the replicated
        instance dir by design — a secrets-bearing definition's replica
        must carry the provisioned pair: absent means the replication
        set is incomplete (``adopt-secrets-missing``), and anything
        less than a slot-owned dir plus a marker bound to exactly the
        escrowed envelope this host pins is ``adopt-state-conflict``.
        Adoption never reprovisions over foreign or missing secret
        material; a rejected replica leaves no journal row."""
        if definition['secretSetRef'] is None:
            return
        secrets_dir = os.path.join(instance_dir, _SECRETS_DIR)
        marker_path = os.path.join(instance_dir, _SECRETS_MARKER)
        dst = self._lstat(secrets_dir)
        mst = self._lstat(marker_path)
        if dst is None or mst is None:
            raise WorkerError('adopt-secrets-missing')
        self._check_secret_extra(_SECRETS_DIR, secrets_dir, slot,
                                 code='adopt-state-conflict',
                                 strict_owner=True)
        self._check_secret_extra(_SECRETS_MARKER, marker_path, slot,
                                 code='adopt-state-conflict',
                                 strict_owner=True)
        try:
            names = self.fs.listdir(secrets_dir)
        except OSError:
            raise WorkerError('path-unavailable') from None
        if not names:
            raise WorkerError('adopt-state-conflict')
        for name in names:
            st = self._lstat(os.path.join(secrets_dir, name))
            uid_base = slot['uidBase']
            if st is None or not stat.S_ISREG(st.st_mode) \
                    or stat.S_ISLNK(st.st_mode) \
                    or (st.st_uid, st.st_gid) != (uid_base, uid_base):
                raise WorkerError('adopt-state-conflict')
        _envelope, _pinned, binding = self._load_secret_record(
            definition['secretSetRef'])
        try:
            marker = self.fs.read_bounded(marker_path,
                                          _SECRET_MARKER_MAX)
        except OSError:
            raise WorkerError('path-unavailable') from None
        if marker != artifacts.canonical_bytes(binding):
            raise WorkerError('adopt-state-conflict')

    def _instance_dir(self, rec):
        binding = rec.get('binding')
        if binding is None:
            raise WorkerError('binding-missing')
        return os.path.join(binding['storage']['root'], rec['instance_id'])

    def _binding_status(self, rec):
        binding = rec['binding']
        if binding is None:
            return False
        current_slot = None
        for slot in self.config['slots']:
            if slot['id'] == rec['slot_id']:
                current_slot = slot
        return binding.get('hostId') == self.config['hostId'] \
            and binding.get('architecture') == self.config['architecture'] \
            and binding.get('storage') == self.config['storage'] \
            and binding.get('slot') == current_slot

    def _require_binding_current(self, rec):
        if rec['binding'] is None:
            raise WorkerError('binding-missing')
        if not self._binding_status(rec):
            raise WorkerError('binding-changed')

    def _orphan_check(self):
        result = self.runner.run(
            ['systemctl', '--no-ask-password', 'list-units', '--all',
             '--type=service', '--plain', '--no-legend', '--no-pager',
             'nexus-workload@*.service'])
        if result.returncode != 0:
            raise WorkerError('runtime-observation-unavailable')
        tracked = {row[0] for row in self.db.execute(
            'SELECT machine_name FROM instances')}
        for line in result.stdout.splitlines():
            fields = line.split()
            if not fields:
                continue
            unit = fields[0]
            if not unit.startswith('nexus-workload@') \
                    or not unit.endswith('.service'):
                continue
            machine = unit[len('nexus-workload@'):-len('.service')]
            if machine in tracked:
                continue
            if _MACHINE_RE.fullmatch(machine) is None:
                raise WorkerError('unknown-runtime')
            if self._unit_drained(self._show(unit)) is not True:
                raise WorkerError('unknown-runtime')

    def _check_workload_drained(self, workload_id):
        for (machine,) in self.db.execute(
                'SELECT machine_name FROM instances WHERE workload_id=?',
                (workload_id,)):
            drained = self._unit_drained(
                self._show('nexus-workload@' + machine + '.service'))
            if drained is False:
                raise WorkerError('workload-not-stopped')
            if drained is not True:
                raise WorkerError('unknown-runtime')

    def _allocate_state_dirs(self, rec, definition, slot, resume):
        instance_dir = self._instance_dir(rec)
        leaf_ids = {mount['id'] for mount in definition['stateMounts']}
        exists = self._lstat(instance_dir)
        if exists is None:
            self._ensure_dir(instance_dir, 0o700)
        elif not stat.S_ISDIR(exists.st_mode) or stat.S_ISLNK(exists.st_mode):
            raise WorkerError('storage-state-conflict')
        else:
            if not resume:
                raise WorkerError('storage-state-conflict')
            self._check_dir(instance_dir, mode=0o700)
            names = set(self.fs.listdir(instance_dir))
            if not names <= leaf_ids | self._secrets_names(definition):
                raise WorkerError('storage-state-conflict')
            for name in names - leaf_ids:
                self._check_secret_extra(
                    name, os.path.join(instance_dir, name), slot,
                    code='storage-state-conflict', strict_owner=False)
        for mount in definition['stateMounts']:
            leaf = os.path.join(instance_dir, mount['id'])
            st = self._lstat(leaf)
            if st is None:
                self.fs.mkdir(leaf, 0o700)
            elif resume:
                if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) \
                        or st.st_uid not in (0, slot['uidBase'] + mount['ownerUid']) \
                        or stat.S_IMODE(st.st_mode) != 0o700 \
                        or self.fs.listdir(leaf):
                    raise WorkerError('storage-state-conflict')
            else:
                raise WorkerError('storage-state-conflict')
            self.fs.chown(leaf, slot['uidBase'] + mount['ownerUid'],
                          slot['uidBase'] + mount['ownerGid'])
            self.fs.sync_dir(leaf)
        self.fs.sync_dir(instance_dir)
        self.fs.sync_dir(rec['binding']['storage']['root'])

    def _check_state_dirs(self, rec, definition, slot):
        instance_dir = self._instance_dir(rec)
        self._check_dir(instance_dir, mode=0o700)
        leaf_ids = {mount['id'] for mount in definition['stateMounts']}
        extras = self._secrets_names(definition)
        if set(self.fs.listdir(instance_dir)) != leaf_ids | extras:
            raise WorkerError('storage-state-conflict')
        for mount in definition['stateMounts']:
            leaf = os.path.join(instance_dir, mount['id'])
            st = self._lstat(leaf)
            if st is None or not stat.S_ISDIR(st.st_mode) \
                    or stat.S_ISLNK(st.st_mode) \
                    or st.st_uid != slot['uidBase'] + mount['ownerUid'] \
                    or st.st_gid != slot['uidBase'] + mount['ownerGid']:
                raise WorkerError('storage-state-conflict')
        for name in extras:
            self._check_secret_extra(
                name, os.path.join(instance_dir, name), slot,
                code='storage-state-conflict', strict_owner=True)

    def _adopt_dirs(self, instance_dir, definition, slot, claimed):
        """Strictly validate a pre-existing replicated instance dir for
        adoption (M8). Returns True when the dir still carries the
        replica's uidBase ownership and must be claimed (chown to root)
        by the caller after the instance row is durably inserted.

        Contract for the provisioning side of a failover pair (uidBase
        is symmetric by design assumption — mismatched ownership means
        the replica needs the idmap restore path, not adoption):

        - the instance dir exists, is a real directory, mode 0700, and
          is owned exactly ``uidBase:uidBase`` — the provenance marker a
          peer never produces by local ``prepare`` (whose dirs are
          root-owned). Once ``claimed`` (row journaled) a root-owned dir
          is also accepted so a crash between claim and phase commit can
          resume without wedging the slot;
        - every declared ``stateMount`` id is present as a directory
          owned exactly ``uidBase + ownerUid : uidBase + ownerGid`` — the
          same ownership a peer worker set and ``_check_state_dirs``
          requires later (``uidBase:uidBase`` for the common
          zero-offset mounts);
        - nothing else at the top level except the worker's own files
          (restore sentinel, restore staging, and for secrets-bearing
          definitions the ``secrets`` dir plus ``.nexus-secrets``
          marker) which are re-validated and left in place — a
          replicated sentinel correctly blocks ``start`` with
          ``restore-incomplete`` and the secrets pair is content-bound
          to the local escrow by ``_adopt_secrets``.

        Rejections are typed and mutate nothing: ``adopt-state-absent``
        (use normal ``prepare``), ``adopt-ownership-conflict`` and
        ``adopt-state-conflict``.
        """
        self._check_ancestors(instance_dir)
        st = self._lstat(instance_dir)
        if st is None:
            raise WorkerError('adopt-state-absent')
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) \
                or stat.S_IMODE(st.st_mode) != 0o700:
            raise WorkerError('adopt-state-conflict')
        owner = (st.st_uid, st.st_gid)
        if owner == (slot['uidBase'], slot['uidBase']):
            claim = True
        elif claimed and owner == (0, 0):
            claim = False
        else:
            raise WorkerError('adopt-ownership-conflict')
        try:
            names = set(self.fs.listdir(instance_dir))
        except OSError:
            raise WorkerError('path-unavailable') from None
        leaf_ids = {mount['id'] for mount in definition['stateMounts']}
        own_files = _ADOPT_OWN_FILES | self._secrets_names(definition)
        if not leaf_ids <= names \
                or not names <= leaf_ids | own_files:
            raise WorkerError('adopt-state-conflict')
        for name in names - leaf_ids:
            own = self._lstat(os.path.join(instance_dir, name))
            if name in self._secrets_names(definition):
                self._check_secret_extra(
                    name, os.path.join(instance_dir, name), slot,
                    code='adopt-state-conflict', strict_owner=False)
            elif name == _RESTORE_SENTINEL:
                if own is None or not stat.S_ISREG(own.st_mode) \
                        or own.st_uid != 0:
                    raise WorkerError('adopt-state-conflict')
            elif own is None or not stat.S_ISDIR(own.st_mode) \
                    or stat.S_ISLNK(own.st_mode) or own.st_uid != 0:
                raise WorkerError('adopt-state-conflict')
        for mount in definition['stateMounts']:
            leaf = os.path.join(instance_dir, mount['id'])
            st = self._lstat(leaf)
            if st is None or not stat.S_ISDIR(st.st_mode) \
                    or stat.S_ISLNK(st.st_mode):
                raise WorkerError('adopt-state-conflict')
            if st.st_uid != slot['uidBase'] + mount['ownerUid'] \
                    or st.st_gid != slot['uidBase'] + mount['ownerGid']:
                raise WorkerError('adopt-ownership-conflict')
        return claim

    def _render_env(self, rec, definition, manifest, slot):
        instance_dir = self._instance_dir(rec)
        binds = []
        for mount in definition['stateMounts']:
            leaf = os.path.join(instance_dir, mount['id'])
            binds.append('--bind={}:{}'.format(leaf, mount['mountPoint']))
        if definition['secretSetRef'] is not None:
            # The provisioned secrets dir rides the same uid mapping as
            # the state leaves: slot-owned on the host, uidBase-mapped
            # in the container, read-only and never part of captures.
            binds.append('--bind-ro={}:{}'.format(
                os.path.join(instance_dir, _SECRETS_DIR),
                _SECRETS_MOUNT))
        flags = ['--ephemeral', '--link-journal=no', '--private-users-ownership=auto',
                 '--inaccessible=/nix/var/nix/daemon-socket',
                 '--rlimit=RLIMIT_NPROC=65535:65535'] + binds
        if 'nested-docker' in definition['requirements']['capabilities']:
            flags += ['--system-call-filter=keyctl', '--system-call-filter=bpf']
        return '\n'.join([
            'SYSTEM_PATH=' + manifest['root'],
            'PRIVATE_NETWORK=1',
            'PRIVATE_USERS=' + str(slot['uidBase']),
            'HOST_ADDRESS=' + slot['hostAddress'],
            'LOCAL_ADDRESS=' + slot['localAddress'],
            'EXTRA_NSPAWN_FLAGS="' + ' '.join(flags) + '"',
        ]) + '\n'

    def _render_dropin(self, rec, definition):
        req = definition['requirements']
        quota = '{}.{}'.format(req['cpuMillis'] // 10, req['cpuMillis'] % 10)
        return '[Unit]\nRequiresMountsFor={}\n[Service]\nMemoryMax={}M\n' \
               'CPUQuota={}%\n'.format(self.config['storage']['mountPoint'],
                                      req['memoryMiB'], quota)

    def _env_path(self, machine_name):
        return os.path.join(self.config['stateDir'], 'instances',
                            machine_name, 'nspawn.env')

    def _dropin_path(self, machine_name):
        return os.path.join(
            self.unit_dir, 'nexus-workload@{}.service.d'.format(machine_name),
            'nexus.conf')

    def _render_runtime_files(self, rec, definition, manifest, slot):
        env_dir = os.path.dirname(self._env_path(rec['machine_name']))
        self._ensure_dir(env_dir, 0o700)
        self.fs.write_file(self._env_path(rec['machine_name']),
                           self._render_env(rec, definition, manifest, slot), 0o600)
        dropin_dir = os.path.dirname(self._dropin_path(rec['machine_name']))
        self._ensure_dir(dropin_dir, 0o755)
        self.fs.write_file(self._dropin_path(rec['machine_name']),
                           self._render_dropin(rec, definition), 0o644)

    def _check_runtime_files(self, rec, definition, manifest, slot):
        self._check_dir(os.path.dirname(self._env_path(rec['machine_name'])),
                        mode=0o700)
        self._check_file(self._env_path(rec['machine_name']), 0o600)
        if self.fs.read_bytes(self._env_path(rec['machine_name'])) \
                != self._render_env(rec, definition, manifest, slot).encode('utf-8'):
            raise WorkerError('runtime-files-mismatch')
        self._check_dir(os.path.dirname(self._dropin_path(rec['machine_name'])),
                        mode=0o755)
        self._check_file(self._dropin_path(rec['machine_name']), 0o644)
        if self.fs.read_bytes(self._dropin_path(rec['machine_name'])) \
                != self._render_dropin(rec, definition).encode('utf-8'):
            raise WorkerError('runtime-files-mismatch')


    def _show(self, unit):
        try:
            result = self.runner.run(
                ['systemctl', '--no-ask-password', 'show', unit, '--property',
                 ','.join(_SHOW_PROPERTIES)])
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        values = {}
        for line in result.stdout.splitlines():
            if '=' in line:
                key, _, value = line.partition('=')
                values[key] = value
        if any(key not in values for key in _SHOW_PROPERTIES) \
                or not values['MainPID'].isdigit():
            return None
        return values

    def _cgroup_drained(self, control_group):
        if not control_group:
            return True
        if not control_group.startswith('/') or '//' in control_group \
                or '..' in control_group.split('/'):
            return None
        events = '/sys/fs/cgroup' + control_group + '/cgroup.events'
        try:
            body = self.fs.read_text(events)
        except FileNotFoundError:
            return True
        except OSError:
            return None
        populated = None
        for line in body.splitlines():
            key, _, value = line.partition(' ')
            if key == 'populated':
                populated = value.strip()
        if populated == '0':
            return True
        if populated == '1':
            return False
        return None

    def _unit_drained(self, show):
        if show is None:
            return None
        if show['ActiveState'] not in ('inactive', 'failed'):
            return False
        if show['MainPID'] != '0':
            return None if show['LoadState'] == 'not-found' else False
        return self._cgroup_drained(show['ControlGroup'])

    def _unit_of(self, rec):
        return 'nexus-workload@' + rec['machine_name'] + '.service'

    def _reconcile(self):
        pending = [self._get_instance(row[0]) for row in self.db.execute(
            "SELECT instance_id FROM instances"
            " WHERE phase IN ('starting','stopping','running','unknown')")]
        for rec in pending:
            show = self._show(self._unit_of(rec))
            if rec['phase'] == 'starting':
                if show is None:
                    continue
                if show['ActiveState'] == 'active':
                    self.db.execute(
                        'UPDATE instances SET phase=?, permit=0'
                        ' WHERE instance_id=?', ('running', rec['instance_id']))
                elif self._unit_drained(show) is True:
                    self.db.execute(
                        'UPDATE instances SET phase=?, permit=0'
                        ' WHERE instance_id=?', ('stopped', rec['instance_id']))
                elif rec['boot_id'] != self.boot_id \
                        or self.clock.monotonic() > (rec['permit_deadline'] or 0):
                    self.db.execute(
                        'UPDATE instances SET phase=?, permit=0'
                        ' WHERE instance_id=?', ('unknown', rec['instance_id']))
            elif rec['phase'] == 'stopping':
                drained = self._unit_drained(show)
                if drained is True:
                    self.db.execute(
                        'UPDATE instances SET phase=? WHERE instance_id=?',
                        ('stopped', rec['instance_id']))
                elif drained is not None:
                    self.db.execute(
                        'UPDATE instances SET phase=? WHERE instance_id=?',
                        ('unknown', rec['instance_id']))
            elif rec['phase'] == 'running':
                if show is None or show['ActiveState'] == 'active':
                    continue
                if self._unit_drained(show) is True:
                    self.db.execute(
                        'UPDATE instances SET phase=? WHERE instance_id=?',
                        ('stopped', rec['instance_id']))
                else:
                    self.db.execute(
                        'UPDATE instances SET phase=? WHERE instance_id=?',
                        ('unknown', rec['instance_id']))
            elif rec['phase'] == 'unknown':
                if show is None:
                    continue
                if show['ActiveState'] == 'active':
                    self.db.execute(
                        'UPDATE instances SET phase=?, permit=0'
                        ' WHERE instance_id=?', ('running', rec['instance_id']))
                elif self._unit_drained(show) is True:
                    self.db.execute(
                        'UPDATE instances SET phase=? WHERE instance_id=?',
                        ('stopped', rec['instance_id']))
        self.db.commit()


    def _receipt(self, request, status, phase):
        rec = self._get_instance(request['instanceId'])
        host_id = self.config['hostId']
        if rec is not None and rec['binding'] is not None:
            host_id = rec['binding']['hostId']
        response = {'schemaVersion': 1, 'operationId': request['operationId'],
                    'action': request['action'], 'workloadId': request['workloadId'],
                    'instanceId': request['instanceId'],
                    'generation': request['generation'], 'hostId': host_id,
                    'status': status, 'appliedPhase': phase}
        if request['action'] in ('freeze', 'thaw'):
            response['captureId'] = request['captureId']
        return response

    def _finish(self, request, status, phase, error=None):
        response = self._receipt(request, status, phase)
        if error is not None:
            response['error'] = error
        canonical = artifacts.canonical_bytes(response).decode('utf-8')
        cursor = self.db.execute(
            "UPDATE operations SET status=?, result=?"
            " WHERE operation_id=? AND status='pending'",
            (status, canonical, request['operationId']))
        if cursor.rowcount != 1:
            row = self.db.execute(
                'SELECT status, result FROM operations WHERE operation_id=?',
                (request['operationId'],)).fetchone()
            if row is not None and row[0] != 'pending' and row[1] == canonical:
                self.db.commit()
                return response
            self.db.rollback()
            raise WorkerError('operation-conflict')
        self.db.commit()
        return response

    def _uncertain(self, request, code='operation-uncertain'):
        rec = self._get_instance(request['instanceId'])
        response = self._receipt(request, 'uncertain',
                                 rec['phase'] if rec else 'unchanged')
        response['error'] = code
        return response

    def _run(self, request):
        try:
            if request['action'] == 'prepare':
                return self._prepare(request)
            if request['action'] == 'adopt':
                return self._prepare(request, adopt=True)
            if request['action'] == 'start':
                return self._start(request)
            if request['action'] == 'retire':
                return self._retire(request)
            if request['action'] == 'freeze':
                return self._freeze(request)
            if request['action'] == 'thaw':
                return self._thaw(request)
            return self._stop(request)
        except UncertainError as error:
            return self._uncertain(request, error.code)
        except WorkerError as error:
            return self._finish(request, 'failed', 'unchanged', error.code)
        except sqlite3.IntegrityError:
            self.db.rollback()
            return self._uncertain(request, 'internal-error')
        except _INTERNAL_ERRORS:
            return self._uncertain(request, 'internal-error')

    def _resume(self, request):
        try:
            if request['action'] == 'prepare':
                return self._prepare(request)
            if request['action'] == 'adopt':
                return self._prepare(request, adopt=True)
            if request['action'] == 'start':
                return self._resume_start(request)
            if request['action'] == 'retire':
                return self._resume_retire(request)
            if request['action'] == 'freeze':
                return self._resume_freeze(request)
            if request['action'] == 'thaw':
                return self._resume_thaw(request)
            return self._resume_stop(request)
        except UncertainError as error:
            return self._uncertain(request, error.code)
        except WorkerError as error:
            return self._finish(request, 'failed', 'unchanged', error.code)
        except sqlite3.IntegrityError:
            self.db.rollback()
            return self._uncertain(request, 'internal-error')
        except _INTERNAL_ERRORS:
            return self._uncertain(request, 'internal-error')

    def execute(self, request):
        action, request = validate_request(request)
        if action == 'observe':
            with self._lock():
                self._reconcile()
                return self._observe(request)
        canonical = artifacts.canonical_bytes(request).decode('utf-8')
        with self._lock():
            self._reconcile()
            row = self.db.execute(
                'SELECT status, request, result FROM operations'
                ' WHERE operation_id=?', (request['operationId'],)).fetchone()
            if row is not None:
                if row[1] != canonical:
                    raise WorkerError('operation-conflict')
                if row[0] == 'pending':
                    return self._resume(request)
                return json.loads(row[2])
            for (raw,) in self.db.execute(
                    "SELECT request FROM operations WHERE status='pending'"):
                pending = json.loads(raw)
                if pending.get('instanceId') == request['instanceId'] \
                        or pending.get('workloadId') == request['workloadId']:
                    outcome = self._resume(pending)
                    if outcome['status'] == 'uncertain':
                        return self._uncertain(request,
                                               'operation-in-progress')
            self.db.execute(
                "INSERT INTO operations(operation_id, request, status)"
                " VALUES(?,?,'pending')",
                (request['operationId'], canonical))
            self.db.commit()
            return self._run(request)


    def _get_instance(self, instance_id):
        row = self.db.execute(
            'SELECT instance_id, workload_id, revision_digest, generation, slot_id,'
            ' machine_name, phase, requirements, binding_json, boot_id,'
            ' permit_deadline, permit, retired, adopted'
            ' FROM instances WHERE instance_id=?', (instance_id,)).fetchone()
        if row is None:
            return None
        keys = ('instance_id', 'workload_id', 'revision_digest', 'generation',
                'slot_id', 'machine_name', 'phase', 'requirements', 'binding',
                'boot_id', 'permit_deadline', 'permit', 'retired', 'adopted')
        rec = dict(zip(keys, row))
        rec['binding'] = json.loads(rec['binding']) if rec['binding'] else None
        return rec

    def _check_identity(self, rec, request):
        if rec is None:
            raise WorkerError('unknown-instance')
        if (rec['workload_id'], rec['revision_digest'], rec['generation']) != (
                request['workloadId'], request['revisionDigest'],
                request['generation']):
            raise WorkerError('instance-conflict')

    def _check_generation_current(self, rec):
        known = self.db.execute(
            'SELECT generation FROM generations WHERE workload_id=?',
            (rec['workload_id'],)).fetchone()
        if known is None or rec['generation'] != known[0]:
            raise WorkerError('generation-stale')

    def _capture_row(self, capture_id):
        row = self.db.execute(
            'SELECT capture_id, instance_id, workload_id, revision_digest,'
            ' generation, status FROM captures WHERE capture_id=?',
            (capture_id,)).fetchone()
        if row is None:
            return None
        keys = ('capture_id', 'instance_id', 'workload_id', 'revision_digest',
                'generation', 'status')
        return dict(zip(keys, row))

    def _held_capture(self, workload_id):
        row = self.db.execute(
            'SELECT capture_id, instance_id, workload_id, revision_digest,'
            " generation, status FROM captures"
            " WHERE workload_id=? AND status='held'",
            (workload_id,)).fetchone()
        if row is None:
            return None
        keys = ('capture_id', 'instance_id', 'workload_id', 'revision_digest',
                'generation', 'status')
        return dict(zip(keys, row))

    def _capture_id_of(self, instance_id):
        row = self.db.execute(
            "SELECT capture_id FROM captures"
            " WHERE instance_id=? AND status='held'",
            (instance_id,)).fetchone()
        return row[0] if row else None

    def _restore_pending(self, rec):
        if rec['binding'] is None:
            return False
        path = os.path.join(self._instance_dir(rec), _RESTORE_SENTINEL)
        try:
            st = self._lstat(path)
        except OSError:
            raise WorkerError('path-unavailable') from None
        return st is not None

    def _capture_matches(self, row, rec):
        return (row['instance_id'], row['workload_id'],
                row['revision_digest'], row['generation']) == (
                    rec['instance_id'], rec['workload_id'],
                    rec['revision_digest'], rec['generation'])

    def _capture_context(self, request):
        rec = self._get_instance(request['instanceId'])
        self._check_identity(rec, request)
        self._require_binding_current(rec)
        bundle, manifest, definition = self._resolve(
            rec['workload_id'], rec['revision_digest'])
        self._check_action_allowed(definition, 'stop', request)
        if 'backup' not in definition['allowedOperations']:
            raise WorkerError('operation-not-allowed')
        self._check_bundle_host(manifest, definition)
        self._verify_mount()
        self._check_state_dirs(rec, definition, rec['binding']['slot'])
        return rec, definition

    def _set_highest_generation(self, workload_id, generation):
        self.db.execute(
            'INSERT INTO generations(workload_id, generation) VALUES(?,?)'
            ' ON CONFLICT(workload_id) DO UPDATE SET'
            ' generation=max(generation, excluded.generation)',
            (workload_id, generation))

    def _prepare(self, request, adopt=False):
        rec = self._get_instance(request['instanceId'])
        resume = rec is not None
        if resume:
            self._check_identity(rec, request)
            if rec['retired']:
                raise WorkerError('instance-retired')
            if rec['phase'] not in ('preparing', 'prepared'):
                raise WorkerError('phase-conflict')
            if bool(rec['adopted']) != adopt:
                raise WorkerError('instance-conflict')
            self._require_binding_current(rec)
            bundle, manifest, definition = self._resolve(
                rec['workload_id'], rec['revision_digest'])
        else:
            bundle, manifest, definition = self._resolve(
                request['workloadId'], request['revisionDigest'])
            known = self.db.execute(
                'SELECT generation FROM generations WHERE workload_id=?',
                (request['workloadId'],)).fetchone()
            if known is not None and request['generation'] <= known[0]:
                raise WorkerError('generation-stale')
        self._check_bundle_host(manifest, definition)
        self._check_action_allowed(definition, 'prepare', request)
        held = rec['workload_id'] if resume else request['workloadId']
        if self._held_capture(held) is not None:
            raise WorkerError('capture-held')
        self._require_secrets_gate(definition)
        probe = self._verify_mount()
        self._verify_closure(manifest)
        self._admission(definition,
                        exclude_instance=rec['instance_id'] if resume else None,
                        statvfs_path=probe)
        self._orphan_check()
        if not resume:
            self._check_workload_drained(request['workloadId'])
            slot = self._free_slot()
            instance_dir = os.path.join(self.config['storage']['root'],
                                        request['instanceId'])
            if adopt:
                # Fully validated BEFORE the instance row is journaled:
                # a rejected replica leaves no record, so a corrected
                # dir can be adopted under a fresh operationId and plain
                # prepare still fails the pre-existing dir as
                # storage-state-conflict.
                self._adopt_dirs(instance_dir, definition, slot,
                                 claimed=False)
                self._adopt_secrets(instance_dir, definition, slot)
            elif self._lstat(instance_dir) is not None:
                raise WorkerError('storage-state-conflict')
            machine = _machine_name(request['instanceId'])
            binding = {'hostId': self.config['hostId'],
                       'architecture': self.config['architecture'],
                       'storage': copy.deepcopy(self.config['storage']),
                       'slot': copy.deepcopy(slot)}
            try:
                self.db.execute(
                    'INSERT INTO instances(instance_id, workload_id,'
                    ' revision_digest, generation, slot_id, machine_name,'
                    ' phase, requirements, binding_json, adopted)'
                    ' VALUES(?,?,?,?,?,?,?,?,?,?)',
                    (request['instanceId'], request['workloadId'],
                     request['revisionDigest'], request['generation'],
                     slot['id'], machine, 'preparing',
                     artifacts.canonical_bytes(
                         self._requirements_of(definition)).decode('utf-8'),
                     artifacts.canonical_bytes(binding).decode('utf-8'),
                     1 if adopt else 0))
                self._set_highest_generation(
                    request['workloadId'], request['generation'])
                self.db.commit()
            except sqlite3.IntegrityError:
                self.db.rollback()
                raise WorkerError('instance-conflict') from None
            rec = self._get_instance(request['instanceId'])
        else:
            slot = rec['binding']['slot']
        if resume and rec['phase'] == 'prepared':
            self._check_state_dirs(rec, definition, slot)
            self._render_runtime_files(rec, definition, manifest, slot)
            return self._finish(request, 'completed', 'prepared')
        if adopt:
            # Re-validate, then claim: the uidBase-owned replica dir
            # becomes a normal root-owned instance dir, so every later
            # invariant (_check_state_dirs, restore leaf checks, guard)
            # sees exactly the layout a local prepare would have made —
            # except the leaves keep their replicated payload.
            instance_dir = self._instance_dir(rec)
            if self._adopt_dirs(instance_dir, definition, slot,
                                claimed=True):
                self.fs.chown(instance_dir, 0, 0)
                self.fs.sync_dir(instance_dir)
                self.fs.sync_dir(rec['binding']['storage']['root'])
        else:
            self._allocate_state_dirs(rec, definition, slot, resume)
        # Secret provisioning rides the same 'preparing' journal
        # boundary as state-dir allocation: a verified marker means an
        # already-populated replica dir (adopt) or a completed earlier
        # attempt is reused verbatim — adopt never reprovisions, and a
        # provision-partial crash is torn down and redone cleanly.
        self._provision_secrets(rec, definition, slot)
        self._render_runtime_files(rec, definition, manifest, slot)
        self.db.execute('UPDATE instances SET phase=? WHERE instance_id=?',
                        ('prepared', rec['instance_id']))
        self._set_highest_generation(rec['workload_id'], rec['generation'])
        self.db.commit()
        return self._finish(request, 'completed', 'prepared')

    def _issue_start(self, rec):
        unit = self._unit_of(rec)
        self.runner.run(['systemctl', '--no-ask-password', 'daemon-reload'])
        self.runner.run(['systemctl', '--no-ask-password', 'start', unit])
        return self._show(unit)

    def _settle_start(self, request, rec, show):
        if show is not None and show['ActiveState'] == 'active':
            self.db.execute(
                'UPDATE instances SET phase=?, permit=0 WHERE instance_id=?',
                ('running', rec['instance_id']))
            self.db.commit()
            return self._finish(request, 'completed', 'running')
        if show is not None and self._unit_drained(show) is True:
            self.db.execute(
                'UPDATE instances SET phase=?, permit=0 WHERE instance_id=?',
                ('stopped', rec['instance_id']))
            self.db.commit()
            return self._finish(request, 'failed', 'stopped', 'start-failed')
        self.db.execute(
            'UPDATE instances SET phase=?, permit=0 WHERE instance_id=?',
            ('unknown', rec['instance_id']))
        self.db.commit()
        raise UncertainError()

    def _start(self, request):
        rec = self._get_instance(request['instanceId'])
        self._check_identity(rec, request)
        if rec['retired']:
            raise WorkerError('instance-retired')
        self._require_binding_current(rec)
        # Runs inside the execute() flock: nexus-restore claims the
        # sentinel under this same lock atomically with its
        # prepared-and-never-started proof, so this gate can never be
        # bypassed by a raced stage.
        if self._restore_pending(rec):
            raise WorkerError('restore-incomplete')
        bundle, manifest, definition = self._resolve(
            rec['workload_id'], rec['revision_digest'])
        self._check_bundle_host(manifest, definition)
        self._check_action_allowed(definition, 'start', request)
        self._check_generation_current(rec)
        if self._held_capture(rec['workload_id']) is not None:
            raise WorkerError('capture-held')
        unit = self._unit_of(rec)
        if rec['phase'] == 'running':
            show = self._show(unit)
            if show is None:
                raise UncertainError()
            if show['ActiveState'] == 'active':
                return self._finish(request, 'completed', 'running')
            if self._unit_drained(show) is True:
                self.db.execute(
                    'UPDATE instances SET phase=? WHERE instance_id=?',
                    ('stopped', rec['instance_id']))
                self.db.commit()
                rec['phase'] = 'stopped'
            else:
                self.db.execute(
                    'UPDATE instances SET phase=? WHERE instance_id=?',
                    ('unknown', rec['instance_id']))
                self.db.commit()
                raise UncertainError()
        if rec['phase'] == 'starting':
            raise WorkerError('phase-conflict')
        if rec['phase'] not in ('prepared', 'stopped'):
            raise WorkerError('phase-conflict')
        slot = rec['binding']['slot']
        probe = self._verify_mount()
        self._verify_closure(manifest)
        self._admission(definition, exclude_instance=rec['instance_id'],
                        statvfs_path=probe)
        self._orphan_check()
        self._check_state_dirs(rec, definition, slot)
        self._render_runtime_files(rec, definition, manifest, slot)
        self.db.execute(
            'UPDATE instances SET phase=?, permit=1, boot_id=?, permit_deadline=?'
            ' WHERE instance_id=?',
            ('starting', self.boot_id, self.clock.monotonic() + _PERMIT_SECONDS,
             rec['instance_id']))
        self.db.commit()
        show = self._issue_start(rec)
        return self._settle_start(request, rec, show)

    def _resume_start(self, request):
        rec = self._get_instance(request['instanceId'])
        self._check_identity(rec, request)
        if rec['retired']:
            raise WorkerError('instance-retired')
        if self._held_capture(rec['workload_id']) is not None:
            raise WorkerError('capture-held')
        unit = self._unit_of(rec)
        if rec['phase'] == 'prepared':
            return self._start(request)
        if rec['phase'] in ('preparing', 'stopping'):
            raise WorkerError('phase-conflict')
        show = self._show(unit)
        if rec['phase'] == 'running':
            if show is None:
                raise UncertainError()
            if show['ActiveState'] == 'active':
                return self._finish(request, 'completed', 'running')
            if self._unit_drained(show) is True:
                self.db.execute(
                    'UPDATE instances SET phase=? WHERE instance_id=?',
                    ('stopped', rec['instance_id']))
                self.db.commit()
                return self._finish(request, 'failed', 'stopped', 'start-failed')
            raise UncertainError()
        if rec['phase'] == 'stopped':
            return self._finish(request, 'failed', 'stopped', 'start-failed')
        if rec['phase'] == 'unknown':
            if show is None or show['ActiveState'] == 'activating':
                raise UncertainError()
            if show['ActiveState'] == 'active':
                self.db.execute(
                    'UPDATE instances SET phase=?, permit=0 WHERE instance_id=?',
                    ('running', rec['instance_id']))
                self.db.commit()
                return self._finish(request, 'completed', 'running')
            if self._unit_drained(show) is True:
                self.db.execute(
                    'UPDATE instances SET phase=? WHERE instance_id=?',
                    ('stopped', rec['instance_id']))
                self.db.commit()
                return self._finish(request, 'failed', 'stopped', 'start-failed')
            raise UncertainError()
        if show is not None and show['ActiveState'] == 'active':
            self.db.execute(
                'UPDATE instances SET phase=?, permit=0 WHERE instance_id=?',
                ('running', rec['instance_id']))
            self.db.commit()
            return self._finish(request, 'completed', 'running')
        if show is None or show['ActiveState'] == 'activating':
            raise UncertainError()
        permit_live = rec['permit'] == 1 and rec['boot_id'] == self.boot_id \
            and self.clock.monotonic() < (rec['permit_deadline'] or 0)
        if permit_live:
            raise UncertainError()
        if self._unit_drained(show) is True:
            self.db.execute(
                'UPDATE instances SET phase=?, permit=0 WHERE instance_id=?',
                ('stopped', rec['instance_id']))
            self.db.commit()
            return self._finish(request, 'failed', 'stopped', 'start-failed')
        self.db.execute(
            'UPDATE instances SET phase=?, permit=0 WHERE instance_id=?',
            ('unknown', rec['instance_id']))
        self.db.commit()
        raise UncertainError()

    def _issue_stop(self, rec):
        unit = self._unit_of(rec)
        self.runner.run(['systemctl', '--no-ask-password', 'stop', unit])
        return self._show(unit)

    def _settle_stop(self, request, rec, show):
        if self._unit_drained(show) is True:
            self.db.execute(
                'UPDATE instances SET phase=?, permit=0 WHERE instance_id=?',
                ('stopped', rec['instance_id']))
            self.db.commit()
            return self._finish(request, 'completed', 'stopped')
        self.db.execute(
            'UPDATE instances SET phase=?, permit=0 WHERE instance_id=?',
            ('unknown', rec['instance_id']))
        self.db.commit()
        raise UncertainError()

    def _stop(self, request):
        rec = self._get_instance(request['instanceId'])
        self._check_identity(rec, request)
        definition = self._resolve(rec['workload_id'], rec['revision_digest'])[2]
        self._check_action_allowed(definition, 'stop', request)
        if rec['phase'] in ('preparing', 'starting'):
            raise WorkerError('phase-conflict')
        if rec['phase'] == 'stopped':
            show = self._show(self._unit_of(rec))
            if self._unit_drained(show) is True:
                return self._finish(request, 'completed', 'stopped')
        self.db.execute(
            'UPDATE instances SET phase=?, permit=0 WHERE instance_id=?',
            ('stopping', rec['instance_id']))
        self.db.commit()
        rec = self._get_instance(request['instanceId'])
        show = self._issue_stop(rec)
        return self._settle_stop(request, rec, show)

    def _resume_stop(self, request):
        rec = self._get_instance(request['instanceId'])
        self._check_identity(rec, request)
        if rec['phase'] in ('preparing', 'starting'):
            raise WorkerError('phase-conflict')
        show = self._show(self._unit_of(rec))
        if self._unit_drained(show) is True:
            self.db.execute(
                'UPDATE instances SET phase=?, permit=0 WHERE instance_id=?',
                ('stopped', rec['instance_id']))
            self.db.commit()
            return self._finish(request, 'completed', 'stopped')
        if show is None:
            raise UncertainError()
        self.db.execute(
            'UPDATE instances SET phase=?, permit=0 WHERE instance_id=?',
            ('stopping', rec['instance_id']))
        self.db.commit()
        show = self._issue_stop(rec)
        return self._settle_stop(request, rec, show)

    def _retire(self, request):
        rec = self._get_instance(request['instanceId'])
        self._check_identity(rec, request)
        definition = self._resolve(rec['workload_id'], rec['revision_digest'])[2]
        self._check_action_allowed(definition, 'stop', request)
        self.db.execute('UPDATE instances SET retired=1, permit=0, phase=?'
                        ' WHERE instance_id=?',
                        ('stopping', rec['instance_id']))
        self.db.commit()
        rec = self._get_instance(rec['instance_id'])
        return self._settle_stop(request, rec, self._issue_stop(rec))

    def _resume_retire(self, request):
        rec = self._get_instance(request['instanceId'])
        self._check_identity(rec, request)
        if not rec['retired']:
            return self._retire(request)
        return self._resume_stop(request)

    def _freeze(self, request):
        rec, definition = self._capture_context(request)
        self._check_generation_current(rec)
        row = self._capture_row(request['captureId'])
        if row is not None:
            if not self._capture_matches(row, rec):
                raise WorkerError('capture-conflict')
            if row['status'] == 'released':
                raise WorkerError('capture-released')
            return self._resume_freeze(request)
        if self._held_capture(rec['workload_id']) is not None:
            raise WorkerError('capture-conflict')
        if rec['phase'] not in ('running', 'stopped'):
            raise WorkerError('phase-conflict')
        self.db.execute(
            "INSERT INTO captures(capture_id, instance_id, workload_id,"
            " revision_digest, generation, status)"
            " VALUES(?,?,?,?,?,'held')",
            (request['captureId'], rec['instance_id'], rec['workload_id'],
             rec['revision_digest'], rec['generation']))
        self.db.execute(
            "UPDATE instances SET permit=0, phase='stopping'"
            " WHERE instance_id=?",
            (rec['instance_id'],))
        self.db.commit()
        rec = self._get_instance(request['instanceId'])
        return self._settle_stop(request, rec, self._issue_stop(rec))

    def _resume_freeze(self, request):
        rec, definition = self._capture_context(request)
        self._check_generation_current(rec)
        row = self._capture_row(request['captureId'])
        if row is None:
            return self._freeze(request)
        if not self._capture_matches(row, rec):
            raise WorkerError('capture-conflict')
        if row['status'] == 'released':
            raise WorkerError('capture-released')
        return self._resume_stop(request)

    def _thaw(self, request):
        rec, definition = self._capture_context(request)
        row = self._capture_row(request['captureId'])
        if row is None:
            raise WorkerError('capture-missing')
        if not self._capture_matches(row, rec):
            raise WorkerError('capture-conflict')
        if row['status'] == 'released':
            return self._finish(request, 'completed', rec['phase'])
        if rec['phase'] == 'unknown':
            raise UncertainError()
        if rec['phase'] != 'stopped' or rec['permit']:
            raise WorkerError('phase-conflict')
        drained = self._unit_drained(self._show(self._unit_of(rec)))
        if drained is False:
            raise WorkerError('phase-conflict')
        if drained is not True:
            raise UncertainError()
        self.db.execute(
            "UPDATE captures SET status='released' WHERE capture_id=?"
            " AND status='held'", (request['captureId'],))
        self.db.commit()
        return self._finish(request, 'completed', 'stopped')

    def _resume_thaw(self, request):
        return self._thaw(request)

    def _observe(self, request):
        rec = self._get_instance(request['instanceId'])
        if rec is None:
            raise WorkerError('unknown-instance')
        show = self._show(self._unit_of(rec))
        binding = rec['binding'] or {}
        slot = binding.get('slot')
        return {
            'schemaVersion': 1,
            'action': 'observe',
            'workloadId': rec['workload_id'],
            'revisionDigest': rec['revision_digest'],
            'instanceId': rec['instance_id'],
            'generation': rec['generation'],
            'hostId': binding.get('hostId', self.config['hostId']),
            'bindingCurrent': self._binding_status(rec),
            'machineName': rec['machine_name'],
            'slotId': rec['slot_id'],
            'unitActiveState': show['ActiveState'] if show else 'unknown',
            'unitSubState': show['SubState'] if show else 'unknown',
            'observedAt': self.clock.time(),
            'phase': rec['phase'],
            'retired': bool(rec['retired']),
            'adopted': bool(rec['adopted']),
            'unitDrained': self._unit_drained(show),
            'captureId': self._capture_id_of(rec['instance_id']),
            'restorePending': self._restore_pending(rec),
            'endpointAddress': slot['localAddress'] if slot else None,
        }

    def _slot(self, slot_id):
        for slot in self.config['slots']:
            if slot['id'] == slot_id:
                return slot
        raise WorkerError('slot-conflict')

    def _free_slot(self):
        used = {row[0] for row in self.db.execute('SELECT slot_id FROM instances')}
        for slot in self.config['slots']:
            if slot['id'] not in used:
                return slot
        raise WorkerError('slot-unavailable')


    def guard(self, machine_name):
        try:
            row = self.db.execute(
                'SELECT instance_id, phase, boot_id, permit_deadline, permit,'
                ' retired FROM instances WHERE machine_name=?',
                (machine_name,)).fetchone()
            if row is None:
                return 1
            instance_id, phase, boot_id, deadline, permit, retired = row
            if retired or phase != 'starting' or permit != 1:
                return 1
            if boot_id != self.boot_id or self.clock.monotonic() >= deadline:
                return 1
            rec = self._get_instance(instance_id)
            self._require_binding_current(rec)
            if self._held_capture(rec['workload_id']) is not None:
                return 1
            bundle, manifest, definition = self._resolve(
                rec['workload_id'], rec['revision_digest'])
            self._check_bundle_host(manifest, definition)
            self._check_action_allowed(definition, 'start')
            slot = rec['binding']['slot']
            self._verify_mount()
            self._check_state_dirs(rec, definition, slot)
            self._check_runtime_files(rec, definition, manifest, slot)
            consumed = self.db.execute(
                'UPDATE instances SET permit=0 WHERE instance_id=? AND permit=1'
                ' AND phase=? AND boot_id=? AND permit_deadline>?'
                ' AND generation=(SELECT generation FROM generations'
                '  WHERE workload_id=?)'
                " AND NOT EXISTS (SELECT 1 FROM captures WHERE workload_id=?"
                "   AND status='held')",
                (instance_id, 'starting', boot_id, self.clock.monotonic(),
                 rec['workload_id'], rec['workload_id']))
            self.db.commit()
            return 0 if consumed.rowcount == 1 else 1
        except Exception:
            return 1


def _response(response):
    sys.stdout.write(artifacts.canonical_bytes(response).decode('utf-8') + '\n')


def main(argv=None):
    parser = argparse.ArgumentParser(prog='nexus-worker')
    parser.add_argument('--config', required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('execute')
    guard_cmd = commands.add_parser('guard')
    guard_cmd.add_argument('--machine', required=True)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        _response({'schemaVersion': 1, 'status': 'error', 'error': 'requires-root'})
        return 1
    try:
        config = load_json_bytes(Path(args.config).read_bytes())
        instance = Worker(config)
    except (WorkerError, OSError, catalog.CatalogError, artifacts.ArtifactError,
            sqlite3.Error) as error:
        code = getattr(error, 'code', 'invalid-config')
        _response({'schemaVersion': 1, 'status': 'error', 'error': code})
        return 1
    if args.command == 'guard':
        return instance.guard(args.machine)
    raw = sys.stdin.buffer.read(_MAX_REQUEST_BYTES + 1)
    if len(raw) > _MAX_REQUEST_BYTES:
        _response({'schemaVersion': 1, 'status': 'error', 'error': 'request-too-large'})
        return 1
    try:
        request = load_json_bytes(raw)
        response = instance.execute(request)
    except WorkerError as error:
        _response({'schemaVersion': 1, 'status': 'error', 'error': error.code})
        return 1
    except _INTERNAL_ERRORS:
        _response({'schemaVersion': 1, 'status': 'error', 'error': 'internal-error'})
        return 1
    _response(response)
    return 0 if response.get('status', 'completed') == 'completed' else 1


if __name__ == '__main__':
    sys.exit(main())
