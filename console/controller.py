"""Durable controller for manual workload moves (M5).

``nexus-controller execute`` is a root-only, single-request JSON CLI in
the same conventions as ``nexus-backup``/``nexus-restore``: strict
bounded requests, typed error codes, private directories, one canonical
journal record per ``operationId`` under a private flock, and
replay-identical responses.

A ``plan`` request validates the move against the live registry and
persists an operation record::

    {operationId, workloadId, revisionDigest, fromInstanceId,
     fromHostId, toHostId, toSlotId, newInstanceId, generation,
     newGeneration, captureId, restoreId, repositoryId, snapshotId,
     phase, checkpoints[], ...}

``execute`` then walks the journaled phase list, journaling every
transition BEFORE the action it describes so a crash replays the same
worker operation ids, capture id, restore id and registry request ids:

    validate        registry evidence: current placement, fresh source
                    observation, generation match, live target session
    freeze          local worker ``freeze`` (derived captureId)
    capture         ``nexus-backup`` capture + upload subprocesses
    thaw            local worker ``thaw`` (release the barrier only)
    retire-source   local worker ``retire`` — irrevocable — then waits
                    for fresh retired+drained registry evidence
    assign          POST /v2/placements/assign successor (generation+1)
    install-target  prepare/restore-stage/restore-commit/start
    await-ready     fresh running observation with all routed services
    publish         POST /v2/placements/publish (route ownership moves)
    retain          durable marker; never deletes source data

The phase order differs from the informal spec order for one hard
reason: the registry refuses a successor ``assign`` until the old
instance shows fresh retired+drained evidence, so ``retire-source``
must precede ``assign``. That ordering is strictly safer — the source
can never run again once retired, so no overlap is possible.

M5 REMOTE DISPATCH: steps whose host is not local are executed through
the registry's pull-model operation queue. The controller POSTs a
bounded operation (requestId replay-safe, bound to the current
placement generation and its holding host), and the target host's
reporter claims it, executes the worker/backup/restore request locally
and posts a first-wins receipt. The controller re-reads the operation
status on each ``execute`` call: pending/claimed stays ``deferred``
(carrying the exact instruction for a manual fallback), ``completed``
advances the phase machine, ``failed`` is a typed blocked error. A dead
host can never complete a move — claimed-but-silent operations defer
forever; nothing is silently skipped.
"""

import argparse
import copy
import fcntl
import hashlib
import http.client
import ipaddress
import json
import math
import os
import re
import selectors
import signal
import ssl
import stat
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

import artifacts
import catalog
import registry
import statefiles
import worker


class ControllerError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class _Deferred(Exception):
    """A step cannot finish yet; carries the journal detail to store."""

    def __init__(self, detail):
        super().__init__('deferred')
        self.detail = detail


_MAX_REQUEST_BYTES = 16384
_MAX_CONFIG_BYTES = 2 * 1024 * 1024
_MAX_JOB_BYTES = 256 * 1024
_MAX_BODY = 65536
_CLI_MAX_OUTPUT = 1024 * 1024
_CLI_TIMEOUT = 120
_BULK_TIMEOUT = 3600
# Bounded receipt polling inside one execute call: at most this many
# status reads, this far apart, before the step journals 'deferred'.
_DISPATCH_POLLS = 6
_DISPATCH_POLL_DELAY = 2.0
_HEX32_RE = worker._HEX32_RE
_HEX64_RE = re.compile(r'[0-9a-f]{64}')
_HOSTNAME_RE = re.compile(
    r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
    r'(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*')
_INTERNAL_ERRORS = (OSError, ValueError, KeyError, TypeError,
                    AttributeError, RecursionError)
_lstat = os.lstat
_fstat = os.fstat

_CONFIG_FIELDS = {'schemaVersion', 'hostId', 'stateDir',
                  'workerConfigFile', 'registryUrl', 'registry',
                  'backupProgram', 'backupConfigFile', 'restoreProgram',
                  'restoreConfigFile', 'requestTimeoutSeconds'}
_PLAN_FIELDS = {'schemaVersion', 'action', 'operationId', 'workloadId',
                'revisionDigest', 'fromInstanceId', 'toHostId',
                'toSlotId', 'repositoryId'}
_ACTION_FIELDS = {'schemaVersion', 'action', 'operationId'}
_JOB_FIELDS = {'schemaVersion', 'request', 'configDigest',
               'operationId', 'workloadId', 'revisionDigest',
               'fromInstanceId', 'fromHostId', 'toHostId', 'toSlotId',
               'newInstanceId', 'generation', 'newGeneration',
               'captureId', 'restoreId', 'repositoryId', 'snapshotId',
               'phase', 'checkpoints', 'plan', 'createdAt', 'updatedAt',
               'completedAt'}
_STEP_ORDER = ('validate', 'freeze', 'capture', 'thaw', 'retire-source',
               'assign', 'install-target', 'await-ready', 'publish',
               'retain')
_PHASES = ('planned', 'completed', 'aborted') + _STEP_ORDER
_CHECKPOINT_FIELDS = {'step', 'state', 'at', 'detail'}
_CHECKPOINT_STATES = ('started', 'deferred', 'completed')
_STATE_FIELDS = {'schemaVersion', 'registryEpoch', 'version',
                 'workloads', 'fences'}
_FENCE_VIEW_FIELDS = {'workloadId', 'generation', 'hostId', 'evidence',
                      'attestedBy', 'requestId', 'recordedAt'}
_WORKLOAD_FIELDS = {'workloadId', 'generation', 'instanceId', 'hostId',
                    'revisionDigest', 'published', 'observedState',
                    'observation'}
_OBSERVED_STATES = ('unknown', 'stale', 'lost', 'running', 'stopped',
                    'prepared', 'preparing', 'starting', 'stopping',
                    'retired')
_OBSERVATION_FIELDS = registry._OBSERVATION_FIELDS | {'receivedAt'}
_RECEIPT_FIELDS = {'schemaVersion', 'repositoryId',
                   'repositoryIdentity', 'snapshotId', 'manifest'}
_OPERATION_VIEW_FIELDS = {'schemaVersion', 'operationId', 'requestId',
                          'workloadId', 'hostId', 'generation', 'step',
                          'status', 'result', 'errorCode'}


def _check(fn, *args):
    try:
        fn(*args)
    except worker.WorkerError as error:
        raise ControllerError(error.code) from None


def _paths(fn, *args):
    try:
        return fn(*args)
    except statefiles.PathError as error:
        raise ControllerError(error.code) from None


def _registry_url(url):
    if type(url) is not str or len(url) > 512 or '%' in url \
            or any(ord(char) < 0x21 for char in url):
        raise ControllerError('invalid-registryUrl')
    try:
        parts = urllib.parse.urlsplit(url)
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        raise ControllerError('invalid-registryUrl') from None
    if parts.scheme != 'https' or parts.username is not None \
            or parts.password is not None or parts.query \
            or parts.fragment or parts.path not in ('', '/'):
        raise ControllerError('invalid-registryUrl')
    if hostname is None:
        raise ControllerError('invalid-registryUrl')
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        if len(hostname) > 253 or not _HOSTNAME_RE.fullmatch(hostname):
            raise ControllerError('invalid-registryUrl')
    if port is not None and not 1 <= port <= 65535:
        raise ControllerError('invalid-registryUrl')
    return hostname, port or 443


def _derive(operation_id, label):
    """Deterministic per-step id: stable across replay, unique per
    operation and step, and collision-bound to the caller's
    operationId."""
    return hashlib.sha256(b'nexus-controller:' + label.encode('utf-8')
                          + b':' + operation_id.encode('utf-8')
                          ).hexdigest()[:32]


def _bounded_json(value, depth=0):
    """Journal detail must stay a small strict tree."""
    if depth > 8:
        raise ControllerError('journal-invalid')
    if type(value) is dict:
        if len(value) > 32:
            raise ControllerError('journal-invalid')
        for key, item in value.items():
            if type(key) is not str or len(key) > 64:
                raise ControllerError('journal-invalid')
            _bounded_json(item, depth + 1)
    elif type(value) is list:
        if len(value) > 32:
            raise ControllerError('journal-invalid')
        for item in value:
            _bounded_json(item, depth + 1)
    elif type(value) is str:
        if len(value) > 512:
            raise ControllerError('journal-invalid')
    elif type(value) is int:
        if not 0 <= value <= 2**53:
            raise ControllerError('journal-invalid')
    elif value is not None and type(value) is not bool:
        raise ControllerError('journal-invalid')


def validate_config(config):
    _check(worker._fields, config, _CONFIG_FIELDS, 'config')
    _check(worker._integer, config['schemaVersion'], 1, 1,
           'config-schemaVersion')
    _check(worker._identifier, config['hostId'], 'config-hostId')
    for key in ('stateDir', 'workerConfigFile', 'backupProgram',
                'backupConfigFile', 'restoreProgram',
                'restoreConfigFile'):
        _check(worker._path, config[key], 'config-' + key)
    _registry_url(config['registryUrl'])
    _check(worker._integer, config['requestTimeoutSeconds'], 1, 120,
           'config-requestTimeoutSeconds')
    try:
        registry_config = registry.validate_config(config['registry'])
    except registry.RegistryError:
        raise ControllerError('invalid-registry-config') from None
    if config['hostId'] not in {h['hostId']
                                for h in registry_config['hosts']}:
        raise ControllerError('invalid-config-hostId')
    return {'schemaVersion': 1, 'hostId': config['hostId'],
            'stateDir': config['stateDir'],
            'workerConfigFile': config['workerConfigFile'],
            'registryUrl': config['registryUrl'],
            'registry': registry_config,
            'backupProgram': config['backupProgram'],
            'backupConfigFile': config['backupConfigFile'],
            'restoreProgram': config['restoreProgram'],
            'restoreConfigFile': config['restoreConfigFile'],
            'requestTimeoutSeconds': config['requestTimeoutSeconds']}


# -- safe config reads (same rules as backup.py/restore.py) ---------------

def _check_ancestors(path, euid):
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
            raise ControllerError('path-unsafe')


def _check_config_path(path):
    _check_ancestors(path, os.geteuid())
    st = _lstat(path)
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) \
            or st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
        raise ControllerError('path-unsafe')


def _read_config_file(path):
    try:
        worker._path(path, 'config')
    except worker.WorkerError as error:
        raise ControllerError(error.code) from None
    _check_config_path(path)
    try:
        st = _lstat(path)
    except OSError:
        raise ControllerError('path-unavailable') from None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise ControllerError('path-unavailable') from None
    try:
        fst = _fstat(fd)
        if not stat.S_ISREG(fst.st_mode) \
                or fst.st_uid != 0 or stat.S_IMODE(fst.st_mode) & 0o022 \
                or (fst.st_ino, fst.st_dev) != (st.st_ino, st.st_dev):
            raise ControllerError('path-unsafe')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            raw = handle.read(_MAX_CONFIG_BYTES + 1)
    except OSError:
        raise ControllerError('path-unavailable') from None
    finally:
        os.close(fd)
    if len(raw) > _MAX_CONFIG_BYTES:
        raise ControllerError('invalid-config')
    return raw


def _load_worker_config(path):
    raw = _read_config_file(path)
    try:
        return worker.validate_config(worker.load_json_bytes(raw))
    except worker.WorkerError as error:
        raise ControllerError(error.code) from None
    except _INTERNAL_ERRORS:
        raise ControllerError('invalid-config') from None


def _fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise ControllerError('path-unavailable') from None
    try:
        os.fsync(fd)
    except OSError:
        raise ControllerError('path-unavailable') from None
    finally:
        os.close(fd)


def _ensure_private_dir(path):
    euid = os.geteuid()
    _check_ancestors(path, euid)
    try:
        st = _lstat(path)
    except FileNotFoundError:
        try:
            os.mkdir(path, 0o700)
        except OSError:
            raise ControllerError('path-unavailable') from None
    except OSError:
        raise ControllerError('path-unavailable') from None
    else:
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) \
                or st.st_uid != euid \
                or stat.S_IMODE(st.st_mode) != 0o700:
            raise ControllerError('path-unsafe')
    _fsync_dir(path)
    _fsync_dir(os.path.dirname(path))


# -- transports ------------------------------------------------------------

class CliRunner:
    """Bounded fixed-environment subprocess runner with a bounded
    stdin payload — the repository.BoundedRunner discipline (own
    process group, monotonic deadline, byte caps, whole-group reap)
    extended with a request body for the *-execute CLIs."""

    def __init__(self, env=None):
        self.env = dict(repository_env() if env is None else env)

    def run(self, argv, input_bytes, *, timeout=_CLI_TIMEOUT,
            max_bytes=_CLI_MAX_OUTPUT):
        if type(argv) is not list or not argv \
                or any(type(item) is not str or not item
                       for item in argv) or len(argv) > 32:
            raise ControllerError('cli-command-failed')
        if len(input_bytes) > _MAX_REQUEST_BYTES:
            raise ControllerError('request-too-large')
        try:
            proc = subprocess.Popen(
                argv, shell=False, env=self.env,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True)
        except OSError:
            raise ControllerError('cli-command-failed') from None
        deadline = time.monotonic() + timeout
        completed = None
        selector = None
        try:
            proc.stdin.write(input_bytes)
            proc.stdin.close()
            proc.stdin = None
            selector = selectors.DefaultSelector()
            streams = {}
            selector.register(proc.stdout, selectors.EVENT_READ,
                              ('out', bytearray(), max_bytes))
            selector.register(proc.stderr, selectors.EVENT_READ,
                              ('err', bytearray(), 64 * 1024))
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ControllerError('cli-timeout')
                events = selector.select(min(remaining, 1.0))
                for key, _mask in events:
                    which, buffer, cap = key.data
                    try:
                        chunk = os.read(key.fileobj.fileno(), 65536)
                    except OSError:
                        raise ControllerError(
                            'cli-output-invalid') from None
                    buffer += chunk
                    if len(buffer) > cap:
                        raise ControllerError('cli-output-too-large')
                    if not chunk:
                        selector.unregister(key.fileobj)
                    streams[which] = buffer
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ControllerError('cli-timeout')
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
            raise ControllerError('cli-command-failed') from None
        finally:
            if completed is None:
                self._reap(proc)
            else:
                for stream in (proc.stdout, proc.stderr):
                    try:
                        stream.close()
                    except OSError:
                        pass
            if proc.stdin is not None:
                try:
                    proc.stdin.close()
                except OSError:
                    pass
            if selector is not None:
                try:
                    selector.close()
                except OSError:
                    pass

    @staticmethod
    def _reap(proc):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            pass
        for stream in (proc.stdout, proc.stderr, proc.stdin):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass


def repository_env():
    return {'PATH': os.environ.get('PATH', os.defpath),
            'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}


class RegistryTransport:
    """One-shot JSON client over verified mutual TLS (controller role)."""

    def __init__(self, url, context, *, timeout=10):
        if context is None or context.verify_mode != ssl.CERT_REQUIRED \
                or not context.check_hostname \
                or context.minimum_version < ssl.TLSVersion.TLSv1_2:
            raise ControllerError('insecure-context')
        self._host, self._port = _registry_url(url)
        self._context = context
        self._timeout = timeout

    def request(self, method, path, payload=None):
        body = None
        if payload is not None:
            body = artifacts.canonical_bytes(payload)
            if len(body) > _MAX_BODY:
                raise ControllerError('request-too-large')
        conn = http.client.HTTPSConnection(
            self._host, self._port, context=self._context,
            timeout=self._timeout)
        try:
            conn.putrequest(method, path)
            if body is not None:
                conn.putheader('Content-Type', 'application/json')
                conn.putheader('Content-Length', str(len(body)))
            conn.endheaders()
            if body:
                conn.send(body)
            response = conn.getresponse()
            raw = response.read(_MAX_BODY + 1)
            status = response.status
        except (OSError, http.client.HTTPException, ValueError):
            raise ControllerError('registry-unreachable') from None
        finally:
            conn.close()
        if len(raw) > _MAX_BODY:
            raise ControllerError('registry-response-invalid')
        try:
            value = worker.load_json_bytes(raw)
        except worker.WorkerError:
            raise ControllerError('registry-response-invalid') from None
        if type(value) is not dict:
            raise ControllerError('registry-response-invalid')
        return status, value


# -- request validation ----------------------------------------------------

def _validate_plan_request(request, context='request'):
    if type(request) is not dict or set(request) != _PLAN_FIELDS:
        raise ControllerError('invalid-request')
    if request['schemaVersion'] != 1 or request['action'] != 'plan':
        raise ControllerError('invalid-request')
    try:
        worker._hex32(request['operationId'], context + ' operationId')
        catalog.identifier(request['workloadId'],
                           context + ' workloadId')
        worker._digest(request['revisionDigest'],
                       context + ' revisionDigest')
        worker._hex32(request['fromInstanceId'],
                      context + ' fromInstanceId')
        catalog.identifier(request['toHostId'], context + ' toHostId')
        catalog.identifier(request['repositoryId'],
                           context + ' repositoryId')
        slot = request['toSlotId']
        if slot is not None:
            catalog.identifier(slot, context + ' toSlotId')
    except worker.WorkerError as error:
        raise ControllerError(error.code) from None
    except catalog.CatalogError:
        raise ControllerError('invalid-request') from None


def _validate_action_request(request):
    if type(request) is not dict or set(request) != _ACTION_FIELDS:
        raise ControllerError('invalid-request')
    if request['schemaVersion'] != 1 \
            or request['action'] not in ('execute', 'status', 'abort'):
        raise ControllerError('invalid-request')
    try:
        worker._hex32(request['operationId'], 'request operationId')
    except worker.WorkerError as error:
        raise ControllerError(error.code) from None


def _validate_checkpoint(value):
    if type(value) is not dict or set(value) != _CHECKPOINT_FIELDS:
        raise ControllerError('journal-invalid')
    if value['step'] not in _STEP_ORDER \
            or value['state'] not in _CHECKPOINT_STATES:
        raise ControllerError('journal-invalid')
    if type(value['at']) is not int or not 0 <= value['at'] <= 2**53:
        raise ControllerError('journal-invalid')
    _bounded_json(value['detail'])


def _validate_job(value, operation_id):
    if type(value) is not dict or set(value) != _JOB_FIELDS:
        raise ControllerError('journal-invalid')
    if type(value['schemaVersion']) is not int \
            or value['schemaVersion'] != 1:
        raise ControllerError('journal-invalid')
    _validate_plan_request(value['request'], 'journal')
    if value['request']['operationId'] != operation_id \
            or value['operationId'] != operation_id:
        raise ControllerError('journal-invalid')
    if type(value['configDigest']) is not str \
            or _HEX64_RE.fullmatch(value['configDigest']) is None:
        raise ControllerError('journal-invalid')
    try:
        catalog.identifier(value['workloadId'], 'journal workloadId')
        worker._digest(value['revisionDigest'],
                       'journal revisionDigest')
        worker._hex32(value['fromInstanceId'], 'journal fromInstanceId')
        catalog.identifier(value['fromHostId'], 'journal fromHostId')
        catalog.identifier(value['toHostId'], 'journal toHostId')
        worker._hex32(value['newInstanceId'], 'journal newInstanceId')
        worker._hex32(value['captureId'], 'journal captureId')
        worker._hex32(value['restoreId'], 'journal restoreId')
        catalog.identifier(value['repositoryId'],
                           'journal repositoryId')
        worker._integer(value['generation'], 1, worker._MAX_I64,
                        'journal generation')
        worker._integer(value['newGeneration'], 2, worker._MAX_I64,
                        'journal newGeneration')
        worker._integer(value['createdAt'], 0, 2**53, 'journal')
        worker._integer(value['updatedAt'], 0, 2**53, 'journal')
    except worker.WorkerError:
        raise ControllerError('journal-invalid') from None
    except catalog.CatalogError:
        raise ControllerError('journal-invalid') from None
    if value['newGeneration'] != value['generation'] + 1:
        raise ControllerError('journal-invalid')
    if value['toSlotId'] is not None:
        try:
            catalog.identifier(value['toSlotId'], 'journal toSlotId')
        except catalog.CatalogError:
            raise ControllerError('journal-invalid') from None
    if value['snapshotId'] is not None \
            and (type(value['snapshotId']) is not str
                 or _HEX64_RE.fullmatch(value['snapshotId']) is None):
        raise ControllerError('journal-invalid')
    if value['phase'] not in _PHASES:
        raise ControllerError('journal-invalid')
    checkpoints = value['checkpoints']
    if type(checkpoints) is not list \
            or len(checkpoints) > len(_STEP_ORDER):
        raise ControllerError('journal-invalid')
    seen = []
    for entry in checkpoints:
        _validate_checkpoint(entry)
        if entry['step'] in seen:
            raise ControllerError('journal-invalid')
        seen.append(entry['step'])
    if [ _STEP_ORDER.index(s) for s in seen ] \
            != sorted(_STEP_ORDER.index(s) for s in seen):
        raise ControllerError('journal-invalid')
    plan = value['plan']
    if type(plan) is not dict or set(plan) != {'steps'}:
        raise ControllerError('journal-invalid')
    steps = plan['steps']
    if type(steps) is not list or len(steps) != len(_STEP_ORDER):
        raise ControllerError('journal-invalid')
    for index, item in enumerate(steps):
        if type(item) is not dict \
                or set(item) != {'step', 'disposition'} \
                or item['step'] != _STEP_ORDER[index] \
                or item['disposition'] not in ('local', 'remote'):
            raise ControllerError('journal-invalid')
    completed = value['completedAt']
    if completed is not None \
            and (type(completed) is not int
                 or not value['createdAt'] <= completed <= 2**53):
        raise ControllerError('journal-invalid')
    if value['updatedAt'] < value['createdAt']:
        raise ControllerError('journal-invalid')
    if value['phase'] == 'completed' and completed is None:
        raise ControllerError('journal-invalid')
    return value


# -- controller --------------------------------------------------------------

class Controller:
    """Journaled move executor. ``transport`` is the registry client,
    ``runner`` the bounded CLI runner, ``worker_factory`` builds the
    local worker handle."""

    def __init__(self, config, *, transport=None, context=None,
                 runner=None, worker_factory=worker.Worker,
                 clock=time.time, sleeper=time.sleep):
        self._config = validate_config(config)
        self.clock = clock
        self._sleeper = sleeper
        self.runner = runner or CliRunner()
        self._worker_config = _load_worker_config(
            self._config['workerConfigFile'])
        if self._worker_config['hostId'] != self._config['hostId']:
            raise ControllerError('invalid-config')
        self._check_config_boundaries()
        state_dir = self._config['stateDir']
        _ensure_private_dir(state_dir)
        self._jobs_dir = os.path.join(state_dir, 'operations')
        _ensure_private_dir(self._jobs_dir)
        self._retained_dir = os.path.join(state_dir, 'retained')
        _ensure_private_dir(self._retained_dir)
        self._config_digest = hashlib.sha256(
            artifacts.canonical_bytes(self._config)).hexdigest()
        self._lock_path = os.path.join(state_dir, 'controller.lock')
        try:
            statefiles.ensure_private_file(self._lock_path)
        except statefiles.PathError as error:
            raise ControllerError(error.code) from None
        self._definitions = {
            (d['workloadId'], d['revisionDigest']): d
            for d in self._config['registry']['definitions']}
        self._hosts = {h['hostId']: h
                       for h in self._config['registry']['hosts']}
        self._routed = {}
        for route in self._config['registry']['routes']:
            self._routed.setdefault(route['workloadId'], set()).add(
                route['serviceId'])
        if transport is not None:
            self._transport = transport
        else:
            self._transport = RegistryTransport(
                self._config['registryUrl'], context,
                timeout=self._config['requestTimeoutSeconds'])
        self._worker_factory = worker_factory
        self._worker = self._worker_factory(self._worker_config)
        self._lock_handle = None

    def close(self):
        if self._lock_handle is not None:
            os.close(self._lock_handle)
            self._lock_handle = None
        if self._worker is not None:
            self._worker.close()
            self._worker = None

    # -- journal ------------------------------------------------------

    def _acquire_lock(self):
        if self._lock_handle is not None:
            return
        try:
            self._lock_handle = os.open(self._lock_path,
                                        os.O_RDWR | os.O_NOFOLLOW)
        except OSError:
            raise ControllerError('path-unavailable') from None
        try:
            fcntl.flock(self._lock_handle,
                        fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self._lock_handle)
            self._lock_handle = None
            raise ControllerError('controller-busy') from None
        except OSError:
            os.close(self._lock_handle)
            self._lock_handle = None
            raise ControllerError('path-unavailable') from None

    def _release_lock(self):
        if self._lock_handle is not None:
            os.close(self._lock_handle)
            self._lock_handle = None

    def _job_path(self, operation_id):
        return os.path.join(self._jobs_dir, operation_id + '.json')

    def _load_job(self, operation_id):
        try:
            value = statefiles.read_json(self._job_path(operation_id),
                                         _MAX_JOB_BYTES)
        except statefiles.PathError as error:
            raise ControllerError(error.code) from None
        if value is None:
            return None
        return _validate_job(value, operation_id)

    def _save_job(self, job):
        _validate_job(job, job['operationId'])
        job['updatedAt'] = self._now()
        raw = artifacts.canonical_bytes(job)
        if len(raw) > _MAX_JOB_BYTES:
            raise ControllerError('journal-too-large')
        try:
            statefiles.write_json(self._job_path(job['operationId']),
                                  job)
        except statefiles.PathError as error:
            raise ControllerError(error.code) from None
        except OSError:
            raise ControllerError('path-unavailable') from None

    def _check_job_config(self, job):
        if job['configDigest'] != self._config_digest:
            raise ControllerError('controller-config-changed')

    def _now(self, minimum=0):
        value = self.clock()
        if type(value) is bool or type(value) not in (int, float) \
                or not math.isfinite(value):
            raise ControllerError('clock-invalid')
        now = int(value)
        if now < minimum or now < 0 or now > 2**53:
            raise ControllerError('clock-invalid')
        return now

    def _check_config_boundaries(self):
        worker_paths = [self._worker_config['storage']['root'],
                        self._worker_config['stateDir']]
        own = [self._config['stateDir']]
        for path in own:
            for other in worker_paths:
                if worker._within(path, other) \
                        or worker._within(other, path):
                    raise ControllerError('invalid-config')

    # -- registry client -------------------------------------------------

    def _registry_state(self):
        status, body = self._transport.request('GET', '/v2/state')
        if status != 200 or type(body) is not dict \
                or set(body) != _STATE_FIELDS:
            raise ControllerError(self._registry_code(status, body))
        if body['schemaVersion'] != 2 \
                or type(body['registryEpoch']) is not str \
                or type(body['version']) is not int \
                or type(body['workloads']) is not list \
                or len(body['workloads']) > 1024:
            raise ControllerError('registry-response-invalid')
        fences = body['fences']
        if type(fences) is not list or len(fences) > 4096:
            raise ControllerError('registry-response-invalid')
        for fence in fences:
            self._validate_fence(fence)
        for entry in body['workloads']:
            self._validate_entry(entry)
        return body

    @staticmethod
    def _validate_fence(fence):
        if type(fence) is not dict \
                or set(fence) != _FENCE_VIEW_FIELDS:
            raise ControllerError('registry-response-invalid')
        try:
            worker._identifier(fence['workloadId'], 'fence')
            worker._integer(fence['generation'], 1, worker._MAX_I64,
                            'fence')
            worker._identifier(fence['hostId'], 'fence')
            worker._hex32(fence['requestId'], 'fence')
        except worker.WorkerError:
            raise ControllerError('registry-response-invalid') from None
        if fence['evidence'] not in registry._FENCE_EVIDENCE \
                or type(fence['attestedBy']) is not str \
                or not fence['attestedBy'] \
                or len(fence['attestedBy']) > 512 \
                or type(fence['recordedAt']) not in (int, float):
            raise ControllerError('registry-response-invalid')

    def _validate_entry(self, entry):
        if type(entry) is not dict or set(entry) != _WORKLOAD_FIELDS:
            raise ControllerError('registry-response-invalid')
        try:
            catalog.identifier(entry['workloadId'], 'entry')
            worker._integer(entry['generation'], 0, worker._MAX_I64,
                            'entry')
        except (worker.WorkerError, catalog.CatalogError):
            raise ControllerError('registry-response-invalid') from None
        if type(entry['published']) is not bool \
                or entry['observedState'] not in _OBSERVED_STATES:
            raise ControllerError('registry-response-invalid')
        if entry['instanceId'] is None:
            if entry['hostId'] is not None \
                    or entry['revisionDigest'] is not None \
                    or entry['observation'] is not None:
                raise ControllerError('registry-response-invalid')
            return
        try:
            worker._hex32(entry['instanceId'], 'entry')
            catalog.identifier(entry['hostId'], 'entry')
            worker._digest(entry['revisionDigest'], 'entry')
        except (worker.WorkerError, catalog.CatalogError):
            raise ControllerError('registry-response-invalid') from None
        observation = entry['observation']
        if observation is None:
            return
        if type(observation) is not dict \
                or not set(observation) <= _OBSERVATION_FIELDS:
            raise ControllerError('registry-response-invalid')
        try:
            worker._identifier(observation['hostId'], 'observation')
            worker._hex32(observation['sessionId'], 'observation')
            worker._integer(observation['sequence'], 1,
                            worker._MAX_I64, 'observation')
            worker._hex32(observation['instanceId'], 'observation')
            worker._identifier(observation['workloadId'],
                               'observation')
            worker._digest(observation['revisionDigest'], 'observation')
            worker._integer(observation['generation'], 1,
                            worker._MAX_I64, 'observation')
            if observation['phase'] not in registry._PHASES \
                    or observation['unitActiveState'] \
                    not in registry._UNIT_STATES \
                    or (observation['unitDrained'] is not None
                        and type(observation['unitDrained']) is not bool) \
                    or type(observation['retired']) is not bool \
                    or type(observation['readyServices']) is not list \
                    or any(type(s) is not str
                           for s in observation['readyServices']) \
                    or type(observation['observedAt']) \
                    not in (int, float) \
                    or type(observation.get('receivedAt')) \
                    not in (int, float):
                raise ControllerError('registry-response-invalid')
        except (worker.WorkerError, KeyError):
            raise ControllerError('registry-response-invalid') from None

    @staticmethod
    def _registry_code(status, body):
        error = body.get('error') if type(body) is dict else None
        if type(error) is str and worker._IDENTIFIER_RE.fullmatch(
                error):
            return 'registry-' + error
        return 'registry-http-{}'.format(status)

    def _registry_post(self, path, payload):
        status, body = self._transport.request('POST', path, payload)
        if status != 200 or type(body) is not dict \
                or body.get('status') != 'completed':
            raise ControllerError(self._registry_code(status, body))
        return body

    def _workload_row(self, state, workload_id):
        for entry in state['workloads']:
            if entry['workloadId'] == workload_id:
                return entry
        return None

    # -- remote dispatch (pull-model operation queue) -----------------------

    def _dispatch_view(self, job, operation_id, request_id, host_id,
                       step, generation):
        """Read back one operation the controller posted. Strictly
        validated: any mismatch in the echoed identity is a registry
        protocol violation, not a result."""
        status, body = self._transport.request(
            'GET', '/v2/operations/{}?requestId={}'.format(
                operation_id, request_id))
        if status != 200 or type(body) is not dict:
            raise ControllerError(self._registry_code(status, body))
        if set(body) - _OPERATION_VIEW_FIELDS \
                or body.get('schemaVersion') != 2 \
                or body.get('operationId') != operation_id \
                or body.get('requestId') != request_id \
                or body.get('workloadId') != job['workloadId'] \
                or body.get('hostId') != host_id \
                or body.get('generation') != generation \
                or body.get('step') != step \
                or body.get('status') \
                not in registry._OPERATION_STATUSES:
            raise ControllerError('registry-response-invalid')
        if body['status'] == 'completed' \
                and type(body.get('result')) is not dict:
            raise ControllerError('registry-response-invalid')
        if body['status'] == 'failed' \
                and (type(body.get('errorCode')) is not str
                     or worker._IDENTIFIER_RE.fullmatch(
                         body['errorCode']) is None):
            raise ControllerError('registry-response-invalid')
        return body

    def _remote_step(self, job, label, host_id, step, generation,
                     payload):
        """Post one dispatch operation (requestId replay-safe) and read
        its receipt state once. Returns the view on 'completed';
        pending/claimed raises _Deferred carrying the full instruction
        so an operator can still perform the step manually; 'failed'
        raises a typed ControllerError."""
        operation_id = payload.get('operationId') \
            if type(payload) is dict else None
        if type(operation_id) is not str:
            operation_id = _derive(job['operationId'], 'op:' + label)
        request_id = _derive(job['operationId'], 'post:' + label)
        status, body = self._transport.request(
            'POST', '/v2/operations',
            {'schemaVersion': 2, 'requestId': request_id,
             'operationId': operation_id,
             'workloadId': job['workloadId'], 'hostId': host_id,
             'generation': generation, 'step': step,
             'payload': payload})
        if status != 200 or type(body) is not dict \
                or body.get('status') != 'accepted' \
                or body.get('operationId') != operation_id \
                or body.get('requestId') != request_id:
            raise ControllerError(self._registry_code(status, body))
        view = None
        for attempt in range(_DISPATCH_POLLS):
            view = self._dispatch_view(job, operation_id, request_id,
                                       host_id, step, generation)
            if view['status'] in ('completed', 'failed'):
                break
            if attempt + 1 < _DISPATCH_POLLS:
                self._sleeper(_DISPATCH_POLL_DELAY)
        if view['status'] == 'failed':
            code = view.get('errorCode')
            raise ControllerError(
                'remote-' + code if type(code) is str
                and worker._IDENTIFIER_RE.fullmatch(code)
                else 'remote-failed')
        if view['status'] != 'completed':
            raise _Deferred({'disposition': 'remote-dispatched',
                             'operationId': operation_id,
                             'requestId': request_id, 'step': step,
                             'hostId': host_id,
                             'operationStatus': view['status'],
                             'instruction': payload})
        return view

    @staticmethod
    def _fresh_observation(entry):
        """The registry already classifies staleness: 'stale'/'lost'
        mean no usable current-session observation; anything else with
        an attached observation is fresh."""
        if entry is None or entry['observation'] is None:
            return None
        if entry['observedState'] in ('stale', 'lost'):
            return None
        return entry['observation']

    def _retired_evidence(self, job):
        entry = self._workload_row(self._registry_state(),
                                 job['workloadId'])
        if entry is None or entry['instanceId'] \
                != job['fromInstanceId']:
            return False
        observation = self._fresh_observation(entry)
        return observation is not None \
            and observation['retired'] is True \
            and observation['unitDrained'] is True \
            and observation['phase'] == 'stopped' \
            and observation['unitActiveState'] in ('inactive', 'failed')

    def _ready_evidence(self, job):
        entry = self._workload_row(self._registry_state(),
                                 job['workloadId'])
        if entry is None or entry['instanceId'] != job['newInstanceId']:
            return None
        if entry['generation'] != job['newGeneration']:
            return None
        observation = self._fresh_observation(entry)
        if observation is None:
            return None
        return entry, observation

    # -- worker / CLI helpers ---------------------------------------------

    def _worker_request(self, job, action, label, instance_id,
                        generation, capture_id=None):
        request = {'schemaVersion': 1,
                   'operationId': _derive(job['operationId'], label),
                   'action': action, 'workloadId': job['workloadId'],
                   'revisionDigest': job['revisionDigest'],
                   'instanceId': instance_id,
                   'generation': generation}
        if capture_id is not None:
            request['captureId'] = capture_id
        return request

    def _worker_execute(self, request):
        try:
            receipt = self._worker.execute(request)
        except worker.WorkerError as error:
            raise ControllerError('worker-' + error.code) from None
        except Exception:
            raise ControllerError('worker-unavailable') from None
        if type(receipt) is not dict \
                or receipt.get('schemaVersion') != 1:
            raise ControllerError('worker-receipt-invalid')
        if receipt.get('status') != 'completed':
            error = receipt.get('error')
            code = 'worker-' + error \
                if type(error) is str \
                and worker._IDENTIFIER_RE.fullmatch(error) \
                else 'worker-failed'
            raise ControllerError(code)
        return receipt

    def _cli(self, program, config_path, request, prefix,
             timeout=_CLI_TIMEOUT):
        argv = [program, '--config', config_path, 'execute']
        payload = artifacts.canonical_bytes(request)
        result = self.runner.run(argv, payload, timeout=timeout,
                                 max_bytes=_CLI_MAX_OUTPUT)
        try:
            body = worker.load_json_bytes(result.stdout)
        except worker.WorkerError:
            body = None
        if type(body) is not dict or type(body.get('status')) is not str:
            raise ControllerError(prefix + '-failed')
        if body['status'] == 'blocked':
            error = body.get('error')
            code = prefix + '-' + error \
                if type(error) is str \
                and worker._IDENTIFIER_RE.fullmatch(error) \
                else prefix + '-failed'
            raise ControllerError(code)
        if result.returncode != 0 or body['status'] != 'completed':
            raise ControllerError(prefix + '-failed')
        return body

    # -- steps -----------------------------------------------------------

    def _checkpoint(self, job, step):
        for entry in job['checkpoints']:
            if entry['step'] == step:
                return entry
        entry = {'step': step, 'state': 'started',
                 'at': self._now(), 'detail': {}}
        job['checkpoints'].append(entry)
        return entry

    def _step_validate(self, job, entry):
        state = self._registry_state()
        row = self._workload_row(state, job['workloadId'])
        if row is None:
            raise ControllerError('unknown-workload')
        if row['instanceId'] != job['fromInstanceId'] \
                or row['revisionDigest'] != job['revisionDigest']:
            raise ControllerError('instance-mismatch')
        if row['generation'] != job['generation']:
            raise ControllerError('generation-conflict')
        if row['hostId'] != job['fromHostId']:
            raise ControllerError('instance-mismatch')
        if self._fresh_observation(row) is None:
            raise ControllerError('evidence-stale')
        # Target session currency: the registry keeps no public session
        # table, so the only honest evidence is a fresh observation from
        # some instance already bound to the target host. A host with
        # zero reported instances cannot be proven live — fail closed.
        if job['toHostId'] != job['fromHostId']:
            live = False
            for other in state['workloads']:
                if other['hostId'] == job['toHostId'] \
                        and self._fresh_observation(other) is not None:
                    live = True
                    break
            if not live:
                raise ControllerError('target-session-unproven')
        return {'registryVersion': state['version'],
                'registryEpoch': state['registryEpoch']}

    def _step_freeze(self, job, entry):
        request = self._worker_request(
            job, 'freeze', 'freeze', job['fromInstanceId'],
            job['generation'], capture_id=job['captureId'])
        if job['fromHostId'] != self._config['hostId']:
            view = self._remote_step(
                job, 'freeze', job['fromHostId'], 'freeze',
                job['generation'], request)
            result = view['result']
            if result.get('appliedPhase') != 'stopped' \
                    or result.get('captureId') != job['captureId']:
                raise ControllerError('remote-receipt-invalid')
            return {'disposition': 'remote',
                    'operationId': view['operationId'],
                    'captureId': job['captureId'],
                    'appliedPhase': 'stopped'}
        receipt = self._worker_execute(request)
        if receipt.get('appliedPhase') != 'stopped' \
                or receipt.get('captureId') != job['captureId']:
            raise ControllerError('worker-receipt-invalid')
        return {'captureId': job['captureId'],
                'appliedPhase': receipt['appliedPhase']}

    def _step_capture(self, job, entry):
        config = self._config
        capture_request = {'schemaVersion': 1, 'action': 'capture',
                           'captureId': job['captureId'],
                           'workloadId': job['workloadId'],
                           'revisionDigest': job['revisionDigest'],
                           'instanceId': job['fromInstanceId'],
                           'generation': job['generation']}
        upload_request = {'schemaVersion': 1, 'action': 'upload',
                          'captureId': job['captureId'],
                          'repositoryId': job['repositoryId']}
        if job['fromHostId'] != self._config['hostId']:
            view = self._remote_step(
                job, 'capture', job['fromHostId'], 'capture',
                job['generation'],
                {'capture': capture_request, 'upload': upload_request})
            result = view['result']
            if type(result.get('snapshotId')) is not str \
                    or _HEX64_RE.fullmatch(result['snapshotId']) is None \
                    or result.get('repositoryId') != job['repositoryId'] \
                    or type(result.get('verifiedAt')) is not int \
                    or not 0 <= result['verifiedAt'] <= 2**53:
                raise ControllerError('remote-receipt-invalid')
            job['snapshotId'] = result['snapshotId']
            return {'disposition': 'remote',
                    'operationId': view['operationId'],
                    'snapshotId': result['snapshotId'],
                    'repositoryId': result['repositoryId'],
                    'verifiedAt': result['verifiedAt']}
        capture = self._cli(
            config['backupProgram'], config['backupConfigFile'],
            capture_request, 'backup', timeout=_BULK_TIMEOUT)
        record = capture.get('record')
        if type(record) is not dict \
                or type(record.get('snapshotId')) is not str \
                or _HEX64_RE.fullmatch(record['snapshotId']) is None:
            raise ControllerError('backup-receipt-invalid')
        upload = self._cli(
            config['backupProgram'], config['backupConfigFile'],
            upload_request, 'backup', timeout=_BULK_TIMEOUT)
        uploaded = upload.get('record')
        if type(uploaded) is not dict \
                or type(uploaded.get('snapshotId')) is not str \
                or _HEX64_RE.fullmatch(uploaded['snapshotId']) is None \
                or uploaded.get('repositoryId') != job['repositoryId']:
            raise ControllerError('backup-receipt-invalid')
        verified = upload.get('verifiedAt')
        if type(verified) is not int or not 0 <= verified <= 2**53:
            raise ControllerError('backup-receipt-invalid')
        job['snapshotId'] = uploaded['snapshotId']
        return {'captureSnapshotId': record['snapshotId'],
                'snapshotId': uploaded['snapshotId'],
                'repositoryId': uploaded['repositoryId'],
                'verifiedAt': verified}

    def _step_thaw(self, job, entry):
        request = self._worker_request(
            job, 'thaw', 'thaw', job['fromInstanceId'],
            job['generation'], capture_id=job['captureId'])
        if job['fromHostId'] != self._config['hostId']:
            view = self._remote_step(
                job, 'thaw', job['fromHostId'], 'thaw',
                job['generation'], request)
            result = view['result']
            if result.get('appliedPhase') != 'stopped' \
                    or result.get('captureId') != job['captureId']:
                raise ControllerError('remote-receipt-invalid')
            return {'disposition': 'remote',
                    'operationId': view['operationId'],
                    'appliedPhase': 'stopped'}
        receipt = self._worker_execute(request)
        if receipt.get('appliedPhase') != 'stopped' \
                or receipt.get('captureId') != job['captureId']:
            raise ControllerError('worker-receipt-invalid')
        return {'appliedPhase': receipt['appliedPhase']}

    def _step_retire_source(self, job, entry):
        if job['fromHostId'] != self._config['hostId']:
            # Remote retire: dispatched through the reporter; the op is
            # replay-safe so re-posting while deferred is harmless.
            view = self._remote_step(
                job, 'retire', job['fromHostId'], 'retire',
                job['generation'],
                self._worker_request(
                    job, 'retire', 'retire', job['fromInstanceId'],
                    job['generation']))
            if view['result'].get('appliedPhase') != 'stopped':
                raise ControllerError('remote-receipt-invalid')
        elif entry['state'] != 'deferred':
            request = self._worker_request(
                job, 'retire', 'retire', job['fromInstanceId'],
                job['generation'])
            receipt = self._worker_execute(request)
            if receipt.get('appliedPhase') != 'stopped':
                raise ControllerError('worker-receipt-invalid')
        if self._retired_evidence(job):
            return {'appliedPhase': 'stopped'}
        raise _Deferred({'awaiting': 'retired-drained-evidence'})

    def _step_assign(self, job, entry):
        receipt = self._registry_post(
            '/v2/placements/assign',
            {'schemaVersion': 2,
             'requestId': _derive(job['operationId'], 'assign'),
             'workloadId': job['workloadId'],
             'revisionDigest': job['revisionDigest'],
             'hostId': job['toHostId'],
             'instanceId': job['newInstanceId'],
             'expectedGeneration': job['generation']})
        if receipt.get('generation') != job['newGeneration']:
            raise ControllerError('registry-response-invalid')
        return {'generation': receipt['generation']}

    def _remote_instruction(self, job):
        """The exact bounded requests a remote operator (or future
        dispatcher) must run on the target host. ``slotId`` is null
        unless the caller pinned it: the remote worker allocates the
        slot at prepare time and its observe reports the actual id."""
        target = {'workloadId': job['workloadId'],
                  'revisionDigest': job['revisionDigest'],
                  'instanceId': job['newInstanceId'],
                  'generation': job['newGeneration'],
                  'slotId': job['toSlotId']}
        return {
            'prepare': self._worker_request(
                job, 'prepare', 'prepare', job['newInstanceId'],
                job['newGeneration']),
            'restoreStage': {'schemaVersion': 1, 'action': 'stage',
                             'restoreId': job['restoreId'],
                             'repositoryId': job['repositoryId'],
                             'snapshotId': job['snapshotId'],
                             'target': target},
            'restoreCommit': {'schemaVersion': 1, 'action': 'commit',
                              'restoreId': job['restoreId']},
            'start': self._worker_request(
                job, 'start', 'start', job['newInstanceId'],
                job['newGeneration'])}

    def _target_slot(self, job):
        try:
            observed = self._worker.execute(
                {'schemaVersion': 1, 'action': 'observe',
                 'instanceId': job['newInstanceId']})
        except worker.WorkerError as error:
            raise ControllerError('worker-' + error.code) from None
        except Exception:
            raise ControllerError('worker-unavailable') from None
        if type(observed) is not dict \
                or observed.get('bindingCurrent') is not True:
            raise ControllerError('worker-observe-invalid')
        slot_id = observed.get('slotId')
        if type(slot_id) is not str:
            raise ControllerError('worker-observe-invalid')
        if job['toSlotId'] is not None and slot_id != job['toSlotId']:
            raise ControllerError('slot-mismatch')
        job['toSlotId'] = slot_id
        return slot_id

    def _step_install_target(self, job, entry):
        if job['toHostId'] != self._config['hostId']:
            # Remote install: four dispatch operations — prepare,
            # observe (to learn the worker-allocated slot), restore
            # stage + commit, start. Each is replay-safe; deferred
            # checkpoints resume without re-executing completed ops.
            instruction = self._remote_instruction(job)
            self._remote_step(
                job, 'prepare', job['toHostId'], 'prepare',
                job['newGeneration'], instruction['prepare'])
            observe = {'schemaVersion': 1, 'action': 'observe',
                       'instanceId': job['newInstanceId']}
            view = self._remote_step(
                job, 'observe', job['toHostId'], 'observe',
                job['newGeneration'], observe)
            observed = view['result']
            if observed.get('bindingCurrent') is not True:
                raise ControllerError('remote-receipt-invalid')
            slot_id = observed.get('slotId')
            if type(slot_id) is not str:
                raise ControllerError('remote-receipt-invalid')
            if job['toSlotId'] is not None and slot_id != job['toSlotId']:
                raise ControllerError('slot-mismatch')
            job['toSlotId'] = slot_id
            stage = dict(instruction['restoreStage'])
            stage['target'] = dict(stage['target'], slotId=slot_id)
            self._remote_step(
                job, 'restore-stage', job['toHostId'], 'restore-stage',
                job['newGeneration'], stage)
            self._remote_step(
                job, 'restore-commit', job['toHostId'],
                'restore-commit', job['newGeneration'],
                instruction['restoreCommit'])
            view = self._remote_step(
                job, 'start', job['toHostId'], 'start',
                job['newGeneration'], instruction['start'])
            if view['result'].get('appliedPhase') != 'running':
                raise ControllerError('remote-receipt-invalid')
            return {'disposition': 'remote', 'slotId': slot_id}
        self._worker_execute(self._worker_request(
            job, 'prepare', 'prepare', job['newInstanceId'],
            job['newGeneration']))
        slot_id = self._target_slot(job)
        target = {'workloadId': job['workloadId'],
                  'revisionDigest': job['revisionDigest'],
                  'instanceId': job['newInstanceId'],
                  'generation': job['newGeneration'],
                  'slotId': slot_id}
        self._cli(self._config['restoreProgram'],
                  self._config['restoreConfigFile'],
                  {'schemaVersion': 1, 'action': 'stage',
                   'restoreId': job['restoreId'],
                   'repositoryId': job['repositoryId'],
                   'snapshotId': job['snapshotId'],
                   'target': target}, 'restore', timeout=_BULK_TIMEOUT)
        self._cli(self._config['restoreProgram'],
                  self._config['restoreConfigFile'],
                  {'schemaVersion': 1, 'action': 'commit',
                   'restoreId': job['restoreId']}, 'restore')
        receipt = self._worker_execute(self._worker_request(
            job, 'start', 'start', job['newInstanceId'],
            job['newGeneration']))
        if receipt.get('appliedPhase') != 'running':
            raise ControllerError('worker-receipt-invalid')
        return {'disposition': 'local', 'slotId': slot_id}

    def _step_await_ready(self, job, entry):
        found = self._ready_evidence(job)
        if found is None:
            raise _Deferred({'awaiting': 'readiness-evidence'})
        entry_row, observation = found
        if entry_row['observedState'] != 'running' \
                or not self._routed.get(job['workloadId'], set()) \
                <= set(observation['readyServices']):
            raise _Deferred({'awaiting': 'readiness-evidence'})
        return {'readyServices': sorted(observation['readyServices'])}

    def _step_publish(self, job, entry):
        receipt = self._registry_post(
            '/v2/placements/publish',
            {'schemaVersion': 2,
             'requestId': _derive(job['operationId'], 'publish'),
             'workloadId': job['workloadId'],
             'expectedGeneration': job['newGeneration']})
        if receipt.get('generation') != job['newGeneration']:
            raise ControllerError('registry-response-invalid')
        return {'generation': receipt['generation']}

    def _step_retain(self, job, entry):
        marker_path = os.path.join(self._retained_dir,
                                   job['operationId'] + '.json')
        marker = {'schemaVersion': 1, 'marker': 'retain-source-state',
                  'operationId': job['operationId'],
                  'workloadId': job['workloadId'],
                  'fromInstanceId': job['fromInstanceId'],
                  'fromHostId': job['fromHostId'],
                  'recordedAt': self._now()}
        try:
            statefiles.write_json(marker_path, marker)
        except statefiles.PathError as error:
            raise ControllerError(error.code) from None
        except OSError:
            raise ControllerError('path-unavailable') from None
        return {'marker': marker_path}

    def _run_step(self, job, entry):
        impl = getattr(self, '_step_' + entry['step'].replace('-', '_'))
        detail = impl(job, entry)
        entry['detail'] = detail
        entry['state'] = 'completed'
        entry['at'] = self._now()

    # -- verbs -----------------------------------------------------------

    def _operation_view(self, job):
        return {key: copy.deepcopy(job[key]) for key in (
            'operationId', 'workloadId', 'revisionDigest',
            'fromInstanceId', 'fromHostId', 'toHostId', 'toSlotId',
            'newInstanceId', 'generation', 'newGeneration', 'captureId',
            'restoreId', 'repositoryId', 'snapshotId', 'phase',
            'checkpoints', 'plan', 'createdAt', 'updatedAt',
            'completedAt')}

    def _plan(self, request):
        self._acquire_lock()
        job = self._load_job(request['operationId'])
        if job is not None:
            if job['request'] != request:
                raise ControllerError('operation-conflict')
            self._check_job_config(job)
            return {'schemaVersion': 1, 'status': 'completed',
                    'action': 'plan',
                    'operationId': request['operationId'],
                    'operation': self._operation_view(job)}
        definition = self._definitions.get(
            (request['workloadId'], request['revisionDigest']))
        if definition is None:
            raise ControllerError('unknown-workload')
        state = self._registry_state()
        row = self._workload_row(state, request['workloadId'])
        if row is None or row['instanceId'] is None:
            raise ControllerError('workload-not-placed')
        if row['instanceId'] != request['fromInstanceId'] \
                or row['revisionDigest'] != request['revisionDigest']:
            raise ControllerError('instance-mismatch')
        if self._fresh_observation(row) is None:
            raise ControllerError('evidence-stale')
        target = self._hosts.get(request['toHostId'])
        if target is None:
            raise ControllerError('unknown-host')
        if target['architecture'] != definition['architecture']:
            raise ControllerError('architecture-mismatch')
        if request['toSlotId'] is not None \
                and request['toHostId'] == self._config['hostId'] \
                and request['toSlotId'] not in {
                    slot['id'] for slot in self._worker_config['slots']}:
            raise ControllerError('unknown-slot')
        host_id = self._config['hostId']
        local_source = row['hostId'] == host_id
        local_target = request['toHostId'] == host_id
        steps = []
        for step in _STEP_ORDER:
            if step in ('freeze', 'capture', 'thaw', 'retire-source'):
                disposition = 'local' if local_source else 'remote'
            elif step == 'install-target':
                disposition = 'local' if local_target else 'remote'
            else:
                disposition = 'local'
            steps.append({'step': step, 'disposition': disposition})
        now = self._now()
        job = {'schemaVersion': 1, 'request': dict(request),
               'configDigest': self._config_digest,
               'operationId': request['operationId'],
               'workloadId': request['workloadId'],
               'revisionDigest': request['revisionDigest'],
               'fromInstanceId': request['fromInstanceId'],
               'fromHostId': row['hostId'],
               'toHostId': request['toHostId'],
               'toSlotId': request['toSlotId'],
               'newInstanceId': _derive(request['operationId'],
                                        'instance'),
               'generation': row['generation'],
               'newGeneration': row['generation'] + 1,
               'captureId': _derive(request['operationId'], 'capture'),
               'restoreId': _derive(request['operationId'], 'restore'),
               'repositoryId': request['repositoryId'],
               'snapshotId': None,
               'phase': 'planned', 'checkpoints': [],
               'plan': {'steps': steps},
               'createdAt': now, 'updatedAt': now,
               'completedAt': None}
        self._save_job(job)
        return {'schemaVersion': 1, 'status': 'completed',
                'action': 'plan', 'operationId': request['operationId'],
                'operation': self._operation_view(job)}

    def _execute(self, request):
        self._acquire_lock()
        job = self._load_job(request['operationId'])
        if job is None:
            raise ControllerError('operation-missing')
        self._check_job_config(job)
        if job['phase'] == 'aborted':
            raise ControllerError('operation-aborted')
        if job['phase'] == 'completed':
            return {'schemaVersion': 1, 'status': 'completed',
                    'action': 'execute',
                    'operationId': request['operationId'],
                    'operation': self._operation_view(job)}
        if job['phase'] == 'planned':
            job['phase'] = _STEP_ORDER[0]
            self._save_job(job)
        while job['phase'] in _STEP_ORDER:
            step = job['phase']
            entry = self._checkpoint(job, step)
            if entry['state'] != 'completed':
                try:
                    self._run_step(job, entry)
                except _Deferred as deferred:
                    entry['state'] = 'deferred'
                    entry['detail'] = deferred.detail
                    self._save_job(job)
                    return {'schemaVersion': 1, 'status': 'deferred',
                            'action': 'execute',
                            'operationId': request['operationId'],
                            'operation': self._operation_view(job)}
                self._save_job(job)
            next_phase = self._advance(step)
            if next_phase == 'completed':
                # Do not persist a bare 'completed' phase; the final
                # block below writes it together with completedAt.
                break
            job['phase'] = next_phase
            self._save_job(job)
        job['phase'] = 'completed'
        job['completedAt'] = self._now()
        self._save_job(job)
        return {'schemaVersion': 1, 'status': 'completed',
                'action': 'execute',
                'operationId': request['operationId'],
                'operation': self._operation_view(job)}

    @staticmethod
    def _advance(step):
        index = _STEP_ORDER.index(step)
        if index + 1 >= len(_STEP_ORDER):
            return 'completed'
        return _STEP_ORDER[index + 1]

    def _status(self, request):
        self._acquire_lock()
        job = self._load_job(request['operationId'])
        if job is None:
            raise ControllerError('operation-missing')
        self._check_job_config(job)
        return {'schemaVersion': 1, 'status': 'completed',
                'action': 'status',
                'operationId': request['operationId'],
                'operation': self._operation_view(job)}

    def _abort(self, request):
        self._acquire_lock()
        job = self._load_job(request['operationId'])
        if job is None:
            raise ControllerError('operation-missing')
        self._check_job_config(job)
        if job['phase'] == 'aborted':
            return {'schemaVersion': 1, 'status': 'completed',
                    'action': 'abort',
                    'operationId': request['operationId'],
                    'operation': self._operation_view(job)}
        # Route ownership moved once publish completed; a completed
        # operation is also post-publish. Aborting earlier leaves any
        # already-applied local side effects (freeze, capture, retire,
        # registry assign) in place — this record is a stop marker,
        # never an undo and never a delete.
        published = any(
            entry['step'] == 'publish' and entry['state'] == 'completed'
            for entry in job['checkpoints'])
        if published or job['phase'] == 'completed':
            raise ControllerError('abort-forbidden')
        job['phase'] = 'aborted'
        self._save_job(job)
        return {'schemaVersion': 1, 'status': 'completed',
                'action': 'abort',
                'operationId': request['operationId'],
                'operation': self._operation_view(job)}

    # -- dispatch ---------------------------------------------------------

    def execute(self, request):
        try:
            return self._execute_request(request)
        finally:
            self._release_lock()

    def _execute_request(self, request):
        operation_id = request.get('operationId') \
            if type(request) is dict else None
        try:
            if type(request) is not dict \
                    or type(request.get('schemaVersion')) is not int \
                    or request['schemaVersion'] != 1:
                raise ControllerError('invalid-request')
            action = request.get('action')
            if action == 'plan':
                _validate_plan_request(request)
                return self._plan(request)
            if action == 'execute':
                _validate_action_request(request)
                return self._execute(request)
            if action == 'status':
                _validate_action_request(request)
                return self._status(request)
            if action == 'abort':
                _validate_action_request(request)
                return self._abort(request)
            raise ControllerError('invalid-request')
        except ControllerError as error:
            return {'schemaVersion': 1, 'status': 'blocked',
                    'error': error.code, 'operationId': operation_id}
        except worker.WorkerError as error:
            return {'schemaVersion': 1, 'status': 'blocked',
                    'error': error.code, 'operationId': operation_id}
        except registry.RegistryError as error:
            return {'schemaVersion': 1, 'status': 'blocked',
                    'error': error.code, 'operationId': operation_id}
        except statefiles.PathError as error:
            return {'schemaVersion': 1, 'status': 'blocked',
                    'error': error.code, 'operationId': operation_id}
        except _INTERNAL_ERRORS:
            return {'schemaVersion': 1, 'status': 'blocked',
                    'error': 'internal-error',
                    'operationId': operation_id}


def _response(response):
    sys.stdout.write(artifacts.canonical_bytes(response).decode('utf-8')
                     + '\n')


def main(argv=None):
    parser = argparse.ArgumentParser(prog='nexus-controller')
    parser.add_argument('--config', required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('execute')
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        _response({'schemaVersion': 1, 'status': 'error',
                   'error': 'requires-root'})
        return 1
    try:
        config = validate_config(
            worker.load_json_bytes(_read_config_file(args.config)))
        credentials = Path(os.environ['CREDENTIALS_DIRECTORY'])
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=credentials / 'ca')
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(credentials / 'cert',
                                credentials / 'key')
        instance = Controller(config, context=context)
    except (ControllerError, worker.WorkerError,
            registry.RegistryError, OSError, KeyError,
            ValueError) as error:
        code = getattr(error, 'code', 'invalid-config')
        _response({'schemaVersion': 1, 'status': 'error',
                   'error': code})
        return 1
    try:
        raw = sys.stdin.buffer.read(_MAX_REQUEST_BYTES + 1)
        if len(raw) > _MAX_REQUEST_BYTES:
            _response({'schemaVersion': 1, 'status': 'error',
                       'error': 'request-too-large'})
            return 1
        try:
            request = worker.load_json_bytes(raw)
        except worker.WorkerError as error:
            _response({'schemaVersion': 1, 'status': 'error',
                       'error': error.code})
            return 1
        response = instance.execute(request)
    finally:
        instance.close()
    _response(response)
    return 0 if response.get('status') in ('completed', 'deferred') else 1


if __name__ == '__main__':
    sys.exit(main())
