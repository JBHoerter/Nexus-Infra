"""Persistent host reporter daemon (M5).

Runs on every workload host, holding the host's own mTLS client
certificate (URI SAN ``urn:nexus:host:<hostId>``; the registry enforces
the host role). Each cycle it refreshes its registry session, fetches
``GET /v2/assignments``, runs a local worker ``observe`` for every
assigned instance — including retired ones, whose retired+drained
evidence the registry requires before a successor placement — and POSTs
``/v2/observations`` with a strictly increasing per-host ``sequence``
resumed from a private state file. A sequence is allocated and the next
value persisted BEFORE the POST leaves the host, so a crash can skip a
sequence but never reuse or regress one; on a new registry session the
sequence restarts at 1 under the new ``sessionId``.

Failures (unreachable registry, rejected sample, missing worker
instance) are logged as bounded JSON events carrying typed codes only —
no key material, bodies or paths are ever logged — and answered with
bounded exponential backoff plus jitter. The daemon never crashes the
worker: every call is isolated per instance and converts to a skipped
sample.

Beyond observation, the reporter is the host's pull-model executor
(M5): after posting observations it fetches ``GET /v2/operations`` —
pending operations the controller posted against this host's current
placement generation — and for each one durably journals the claim,
executes the step locally (worker ``execute`` for prepare/start/stop/
freeze/thaw/retire/observe, the pinned ``nexus-backup``/``nexus-restore``
executables for capture/restore-stage/restore-commit) and posts a
first-wins receipt back. The journal records ``claiming → claimed →
executed`` before each external effect so a crash replays the same
operationId rather than double-executing. An operation whose
workloadId/instanceId/generation does not match an assignment this host
currently holds is refused with an error receipt — the registry scopes
by hostId and generation, but the reporter re-verifies before touching
the worker. Nothing executes without an operation request.
"""

import argparse
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
import random
import re
import selectors
import signal
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path

import artifacts
import registry
import statefiles
import worker


class ReporterError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class SessionLost(Exception):
    """Internal signal: the registry rejected the current session."""


class _Refused(Exception):
    """A dispatched operation is refused locally: permanent, typed,
    becomes a 'failed' receipt — never retried blindly."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


_MAX_REQUEST_BYTES = 16384
_MAX_BODY = 65536
_MAX_CONFIG = 2 * 1024 * 1024
_MAX_ASSIGNMENTS = 256
_MAX_OPERATIONS = 64
_MAX_DISPATCH_JOURNAL = 256
_CLI_MAX_OUTPUT = 1024 * 1024
_CLI_TIMEOUT = 120
_BULK_TIMEOUT = 3600
_STATE_FIELDS = {'schemaVersion', 'hostId', 'sessionId', 'registryEpoch',
                 'nextSequence'}
_CONFIG_FIELDS = {'schemaVersion', 'hostId', 'registryUrl', 'registry',
                  'stateDir', 'workerConfigFile', 'observeIntervalSeconds',
                  'requestTimeoutSeconds', 'maxBackoffSeconds'}
# Optional dispatch CLIs: each pair is present together or absent
# together; absent pairs refuse the matching dispatch steps locally.
_OPTIONAL_CLIS = (('backupProgram', 'backupConfigFile'),
                  ('restoreProgram', 'restoreConfigFile'))
_OPTIONAL_KEYS = {key for pair in _OPTIONAL_CLIS for key in pair}
_SESSION_FIELDS = {'schemaVersion', 'hostId', 'sessionId', 'registryEpoch'}
_ASSIGNMENTS_FIELDS = {'schemaVersion', 'hostId', 'instances'}
_ASSIGNMENT_FIELDS = {'instanceId', 'workloadId', 'revisionDigest',
                      'hostId', 'generation'}
_OPERATIONS_FIELDS = {'schemaVersion', 'hostId', 'operations'}
_OPERATION_ROW_FIELDS = {'seq', 'operationId', 'workloadId',
                         'generation', 'step', 'payload'}
_DISPATCH_FIELDS = {'schemaVersion', 'operationId', 'seq', 'workloadId',
                    'generation', 'step', 'payload', 'claimRequestId',
                    'receiptRequestId', 'phase', 'result', 'errorCode'}
_DISPATCH_PHASES = ('claiming', 'claimed', 'executed')
_WORKER_STEPS = ('prepare', 'adopt', 'start', 'stop', 'freeze', 'thaw',
                 'retire')
_STAGE_FIELDS = {'schemaVersion', 'action', 'restoreId', 'repositoryId',
                 'snapshotId', 'target'}
_TARGET_FIELDS = {'workloadId', 'revisionDigest', 'instanceId',
                  'generation', 'slotId'}
_COMMIT_FIELDS = {'schemaVersion', 'action', 'restoreId'}
_CAPTURE_FIELDS = {'schemaVersion', 'action', 'captureId', 'workloadId',
                   'revisionDigest', 'instanceId', 'generation'}
_UPLOAD_FIELDS = {'schemaVersion', 'action', 'captureId', 'repositoryId'}
_CAPTURE_PAYLOAD_FIELDS = {'capture', 'upload'}
_HEX64_RE = re.compile(r'[0-9a-f]{64}')
_LOG_KEYS = {'event', 'at', 'code', 'type', 'instanceId', 'workloadId',
             'sequence', 'posted', 'skipped', 'dispatched',
             'operationId', 'step'}
_SKIP_CODES = {'instance-mismatch'}
_DROP_CODES = {'observation-stale', 'observation-future'}
_SESSION_CODES = {'session-mismatch', 'sequence-conflict'}
_RECEIPT_DROP_CODES = {'receipt-conflict', 'unknown-operation',
                       'host-mismatch'}
_PROBE_TIMEOUT = 1.0
_INTERNAL_ERRORS = (OSError, ValueError, KeyError, TypeError,
                    AttributeError)


def _check(fn, *args):
    try:
        fn(*args)
    except worker.WorkerError as error:
        raise ReporterError(error.code) from None


def _bounded_time(value, code):
    try:
        return registry._bounded_time(value, code)
    except registry.RegistryError as error:
        raise ReporterError(error.code) from None


def _paths(fn, *args):
    try:
        return fn(*args)
    except statefiles.PathError as error:
        raise ReporterError('reporter-' + error.code) from None


def _registry_url(url):
    if type(url) is not str or len(url) > 512 or '%' in url \
            or any(ord(char) < 0x21 for char in url):
        raise ReporterError('invalid-registryUrl')
    try:
        parts = urllib.parse.urlsplit(url)
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        raise ReporterError('invalid-registryUrl') from None
    if parts.scheme != 'https' or parts.username is not None \
            or parts.password is not None or parts.query \
            or parts.fragment or parts.path not in ('', '/'):
        raise ReporterError('invalid-registryUrl')
    if hostname is None:
        raise ReporterError('invalid-registryUrl')
    try:
        ip = ipaddress.ip_address(hostname)
        del ip
    except ValueError:
        if len(hostname) > 253 or not _HOSTNAME_RE.fullmatch(hostname):
            raise ReporterError('invalid-registryUrl')
    if port is not None and not 1 <= port <= 65535:
        raise ReporterError('invalid-registryUrl')
    return hostname, port or 443


_HOSTNAME_RE = re.compile(
    r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
    r'(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*')
_HEX32_RE = worker._HEX32_RE


def validate_config(config):
    if type(config) is not dict:
        raise ReporterError('invalid-config-fields')
    _check(worker._fields,
           {key: value for key, value in config.items()
            if key not in _OPTIONAL_KEYS}, _CONFIG_FIELDS, 'config')
    _check(worker._integer, config['schemaVersion'], 2, 2,
           'config-schemaVersion')
    _check(worker._identifier, config['hostId'], 'config-hostId')
    _registry_url(config['registryUrl'])
    _check(worker._path, config['stateDir'], 'config-stateDir')
    _check(worker._path, config['workerConfigFile'],
           'config-workerConfigFile')
    _check(worker._integer, config['observeIntervalSeconds'], 1, 300,
           'config-observeIntervalSeconds')
    _check(worker._integer, config['requestTimeoutSeconds'], 1, 120,
           'config-requestTimeoutSeconds')
    _check(worker._integer, config['maxBackoffSeconds'], 1, 3600,
           'config-maxBackoffSeconds')
    clis = {}
    for program_key, config_key in _OPTIONAL_CLIS:
        present = (program_key in config, config_key in config)
        if any(present) and not all(present):
            raise ReporterError('invalid-config')
        if all(present):
            _check(worker._path, config[program_key],
                   'config-' + program_key)
            _check(worker._path, config[config_key],
                   'config-' + config_key)
        clis[program_key] = config.get(program_key)
        clis[config_key] = config.get(config_key)
    try:
        registry_config = registry.validate_config(config['registry'])
    except registry.RegistryError as error:
        raise ReporterError('invalid-registry-config') from None
    if config['hostId'] not in {h['hostId']
                                for h in registry_config['hosts']}:
        raise ReporterError('invalid-config-hostId')
    normalized = {'schemaVersion': 2, 'hostId': config['hostId'],
                  'registryUrl': config['registryUrl'],
                  'registry': registry_config,
                  'stateDir': config['stateDir'],
                  'workerConfigFile': config['workerConfigFile'],
                  'observeIntervalSeconds': config['observeIntervalSeconds'],
                  'requestTimeoutSeconds': config['requestTimeoutSeconds'],
                  'maxBackoffSeconds': config['maxBackoffSeconds']}
    normalized.update(clis)
    return normalized


def _load_worker_config(path):
    """Bounded root/euid-owned config read for the local worker."""
    try:
        worker._path(path, 'config')
    except worker.WorkerError as error:
        raise ReporterError(error.code) from None
    try:
        st = os.lstat(path)
    except OSError:
        raise ReporterError('path-unavailable') from None
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) \
            or stat.S_IMODE(st.st_mode) & 0o022:
        raise ReporterError('path-unsafe')
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise ReporterError('path-unavailable') from None
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) \
                or stat.S_IMODE(fst.st_mode) & 0o022 \
                or (fst.st_ino, fst.st_dev) != (st.st_ino, st.st_dev):
            raise ReporterError('path-unsafe')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            raw = handle.read(_MAX_CONFIG + 1)
    except OSError:
        raise ReporterError('path-unavailable') from None
    finally:
        os.close(fd)
    if len(raw) > _MAX_CONFIG:
        raise ReporterError('invalid-config')
    try:
        return worker.validate_config(worker.load_json_bytes(raw))
    except worker.WorkerError as error:
        raise ReporterError(error.code) from None
    except _INTERNAL_ERRORS:
        raise ReporterError('invalid-config') from None


class TlsTransport:
    """One-shot JSON client over a verified mutual-TLS channel.

    A fresh ``http.client.HTTPSConnection`` per request; the context
    must already require a peer certificate, verify the hostname and
    bound TLS to >=1.2 — the same invariants ingress/registry_api
    enforce. Responses are bounded and strictly decoded.
    """

    def __init__(self, url, context, *, timeout=10):
        if context is None or context.verify_mode != ssl.CERT_REQUIRED \
                or not context.check_hostname \
                or context.minimum_version < ssl.TLSVersion.TLSv1_2:
            raise ReporterError('insecure-context')
        self._host, self._port = _registry_url(url)
        self._context = context
        self._timeout = timeout

    def request(self, method, path, payload=None):
        body = None
        if payload is not None:
            body = artifacts.canonical_bytes(payload)
            if len(body) > _MAX_BODY:
                raise ReporterError('request-too-large')
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
            raise ReporterError('registry-unreachable') from None
        finally:
            conn.close()
        if len(raw) > _MAX_BODY:
            raise ReporterError('registry-response-invalid')
        try:
            value = worker.load_json_bytes(raw)
        except worker.WorkerError:
            raise ReporterError('registry-response-invalid') from None
        if type(value) is not dict:
            raise ReporterError('registry-response-invalid')
        return status, value


class CliRunner:
    """Bounded fixed-environment subprocess runner for the pinned
    backup/restore executables — own process group, monotonic deadline,
    byte caps, whole-group reap; same discipline as the controller's."""

    def __init__(self, env=None):
        self.env = {'PATH': os.environ.get('PATH', os.defpath),
                    'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'} \
            if env is None else dict(env)

    def run(self, argv, input_bytes, *, timeout=_CLI_TIMEOUT,
            max_bytes=_CLI_MAX_OUTPUT):
        if type(argv) is not list or not argv \
                or any(type(item) is not str or not item
                       for item in argv) or len(argv) > 32:
            raise ReporterError('cli-command-failed')
        if len(input_bytes) > _MAX_REQUEST_BYTES:
            raise ReporterError('request-too-large')
        try:
            proc = subprocess.Popen(
                argv, shell=False, env=self.env,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True)
        except OSError:
            raise ReporterError('cli-command-failed') from None
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
                    raise ReporterError('cli-timeout')
                events = selector.select(min(remaining, 1.0))
                for key, _mask in events:
                    which, buffer, cap = key.data
                    try:
                        chunk = os.read(key.fileobj.fileno(), 65536)
                    except OSError:
                        raise ReporterError(
                            'cli-output-invalid') from None
                    buffer += chunk
                    if len(buffer) > cap:
                        raise ReporterError('cli-output-too-large')
                    if not chunk:
                        selector.unregister(key.fileobj)
                    streams[which] = buffer
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ReporterError('cli-timeout')
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
            raise ReporterError('cli-command-failed') from None
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


def _tcp_probe(address, port):
    """Honest liveness hint: a TCP connect to the slot address."""
    sock = None
    try:
        sock = socket.create_connection((address, port),
                                        timeout=_PROBE_TIMEOUT)
        return True
    except OSError:
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _validate_state(value, host_id):
    if type(value) is not dict or set(value) != _STATE_FIELDS:
        raise ReporterError('reporter-state-corrupt')
    if type(value['schemaVersion']) is not int \
            or value['schemaVersion'] != 1:
        raise ReporterError('reporter-state-corrupt')
    if value['hostId'] != host_id:
        raise ReporterError('reporter-state-mismatch')
    session = value['sessionId']
    epoch = value['registryEpoch']
    if (session is None) != (epoch is None):
        raise ReporterError('reporter-state-corrupt')
    if session is not None \
            and (_HEX32_RE.fullmatch(session) is None
                 or type(epoch) is not str
                 or _HEX32_RE.fullmatch(epoch) is None):
        raise ReporterError('reporter-state-corrupt')
    _check(worker._integer, value['nextSequence'], 1,
           worker._MAX_I64 - 1, 'nextSequence')
    return value


class Reporter:
    """The per-host reporting loop.

    ``transport`` is the registry client (TlsTransport in production,
    a double in tests); ``observer`` maps an instanceId to the worker's
    observe dict (default: the local worker's execute); ``prober``
    maps (address, port) to a liveness bool for readyServices.
    """

    def __init__(self, config, *, context=None, transport=None,
                 observer=None, prober=None, worker_factory=worker.Worker,
                 executor=None, runner=None, clock=time.time,
                 monotonic=time.monotonic,
                 sleeper=None, log=None, rand=None):
        self.config = validate_config(config)
        self.clock, self.monotonic = clock, monotonic
        self._rand = rand if rand is not None else random.random
        self._log_fn = log if log is not None else self._default_log
        self._sleeper = sleeper
        self._interval = self.config['observeIntervalSeconds']
        self._max_backoff = self.config['maxBackoffSeconds']
        self._prober = prober or _tcp_probe
        self._worker_config = _load_worker_config(
            self.config['workerConfigFile'])
        if self._worker_config['hostId'] != self.config['hostId']:
            raise ReporterError('invalid-config-hostId')
        self._worker_factory = worker_factory
        self._observer_fn = observer
        self._executor_fn = executor
        self._runner = runner if runner is not None else CliRunner()
        self._worker = None
        self._closed = False
        state_dir = self.config['stateDir']
        _paths(statefiles.check_private_dir, state_dir)
        self._dispatch_dir = os.path.join(state_dir, 'dispatch')
        self._ensure_dir(self._dispatch_dir)
        self._lock_path = os.path.join(state_dir, 'reporter.lock')
        self._state_path = os.path.join(state_dir, 'reporter-state.json')
        _paths(statefiles.ensure_private_file, self._lock_path)
        self._lock_handle = os.open(self._lock_path, os.O_RDWR
                                    | os.O_NOFOLLOW)
        try:
            fcntl.flock(self._lock_handle, fcntl.LOCK_EX
                        | fcntl.LOCK_NB)
            stored = _paths(statefiles.read_json, self._state_path,
                            4096)
            if stored is None:
                self._state = {'schemaVersion': 1,
                               'hostId': self.config['hostId'],
                               'sessionId': None, 'registryEpoch': None,
                               'nextSequence': 1}
                self._save_state()
            else:
                self._state = _validate_state(
                    stored, self.config['hostId'])
        except BlockingIOError:
            os.close(self._lock_handle)
            self._lock_handle = None
            raise ReporterError('reporter-in-use') from None
        except Exception:
            os.close(self._lock_handle)
            self._lock_handle = None
            raise
        self._session_id = self._state['sessionId']
        self._definitions = {
            (d['workloadId'], d['revisionDigest']): d
            for d in self.config['registry']['definitions']}
        self._hosts = {h['hostId']: h
                       for h in self.config['registry']['hosts']}
        self._addresses = set(
            self._hosts[self.config['hostId']]['addresses'])
        if transport is not None:
            self._transport = transport
        else:
            self._transport = TlsTransport(
                self.config['registryUrl'], context,
                timeout=self.config['requestTimeoutSeconds'])

    # -- internals -----------------------------------------------------

    @staticmethod
    def _default_log(record):
        sys.stdout.write(json.dumps(record, sort_keys=True,
                                    separators=(',', ':')) + '\n')
        sys.stdout.flush()

    def _log(self, event, **fields):
        record = {'event': event}
        record.update(fields)
        if set(record) <= _LOG_KEYS:
            self._log_fn(record)
        else:
            # Never let an unexpected field (or secret) reach the log.
            self._log_fn({'event': 'log-field-drop'})

    def _save_state(self):
        try:
            statefiles.write_json(self._state_path, self._state)
        except statefiles.PathError as error:
            raise ReporterError('reporter-' + error.code) from None
        except OSError:
            raise ReporterError('reporter-path-unavailable') from None

    def _allocate_sequence(self):
        """Reserve the next sequence under the current session and
        durably persist the successor BEFORE any POST uses it."""
        sequence = self._state['nextSequence']
        self._state['nextSequence'] = sequence + 1
        self._save_state()
        return sequence

    def _open_session(self):
        status, body = self._transport.request(
            'POST', '/v2/hosts/session',
            {'schemaVersion': 2, 'hostId': self.config['hostId']})
        if status != 200 or set(body) != _SESSION_FIELDS:
            raise ReporterError(self._registry_code(status, body))
        if body['schemaVersion'] != 2 \
                or body['hostId'] != self.config['hostId'] \
                or type(body['sessionId']) is not str \
                or _HEX32_RE.fullmatch(body['sessionId']) is None \
                or type(body['registryEpoch']) is not str \
                or _HEX32_RE.fullmatch(body['registryEpoch']) is None:
            raise ReporterError('registry-response-invalid')
        self._session_id = body['sessionId']
        self._state['sessionId'] = body['sessionId']
        self._state['registryEpoch'] = body['registryEpoch']
        self._state['nextSequence'] = 1
        self._save_state()
        self._log('session-opened')

    @staticmethod
    def _registry_code(status, body):
        error = body.get('error') if type(body) is dict else None
        if type(error) is str and worker._IDENTIFIER_RE.fullmatch(
                error):
            return 'registry-' + error
        return 'registry-http-{}'.format(status)

    def _fetch_assignments(self):
        status, body = self._transport.request('GET', '/v2/assignments')
        if status != 200 or type(body) is not dict \
                or set(body) != _ASSIGNMENTS_FIELDS:
            raise ReporterError(self._registry_code(status, body))
        if body['schemaVersion'] != 2 \
                or body['hostId'] != self.config['hostId']:
            raise ReporterError('registry-response-invalid')
        rows = body['instances']
        if type(rows) is not list or len(rows) > _MAX_ASSIGNMENTS:
            raise ReporterError('registry-response-invalid')
        instances = []
        for row in rows:
            if type(row) is not dict or set(row) != _ASSIGNMENT_FIELDS:
                raise ReporterError('registry-response-invalid')
            try:
                worker._hex32(row['instanceId'], 'instanceId')
                worker._identifier(row['workloadId'], 'workloadId')
                worker._digest(row['revisionDigest'], 'revisionDigest')
                worker._identifier(row['hostId'], 'hostId')
                worker._integer(row['generation'], 1, worker._MAX_I64,
                                'generation')
            except worker.WorkerError:
                raise ReporterError('registry-response-invalid') \
                    from None
            instances.append(row)
        return instances

    def _worker_handle(self):
        if self._worker is None:
            try:
                self._worker = self._worker_factory(self._worker_config)
            except Exception:
                raise ReporterError('worker-unavailable') from None
        return self._worker

    def _observer(self):
        if self._observer_fn is not None:
            return self._observer_fn
        worker_handle = self._worker_handle()

        def observe(instance_id):
            return worker_handle.execute(
                {'schemaVersion': 1, 'action': 'observe',
                 'instanceId': instance_id})

        return observe

    def _executor(self):
        if self._executor_fn is not None:
            return self._executor_fn
        return self._worker_handle().execute

    def _observe_instance(self, row):
        """Local worker observe, converted to a registry observation
        skeleton; None means the sample is skipped this cycle."""
        try:
            observed = self._observer()(row['instanceId'])
        except Exception as error:
            self._log('observe-skipped', instanceId=row['instanceId'],
                      code=getattr(error, 'code',
                                   type(error).__name__))
            return None
        if type(observed) is not dict:
            self._log('observe-skipped', instanceId=row['instanceId'],
                      code='observe-invalid')
            return None
        endpoint = observed.get('endpointAddress')
        if endpoint not in self._addresses:
            self._log('observe-skipped', instanceId=row['instanceId'],
                      code='endpoint-unapproved')
            return None
        phase = observed.get('phase')
        unit = observed.get('unitActiveState')
        drained = observed.get('unitDrained')
        retired = observed.get('retired')
        if phase not in registry._PHASES \
                or unit not in registry._UNIT_STATES \
                or (drained is not None and type(drained) is not bool) \
                or type(retired) is not bool:
            self._log('observe-skipped', instanceId=row['instanceId'],
                      code='observe-invalid')
            return None
        ready = []
        if phase == 'running' and unit == 'active' and drained is False \
                and retired is False:
            definition = self._definitions.get(
                (row['workloadId'], row['revisionDigest']))
            if definition is None:
                self._log('observe-skipped',
                          instanceId=row['instanceId'],
                          code='definition-unapproved')
                return None
            for service in definition['services']:
                try:
                    alive = self._prober(endpoint, service['port'])
                except Exception:
                    alive = False
                if alive is True:
                    ready.append(service['id'])
        now = _bounded_time(self.clock(), 'clock-unavailable')
        return {'schemaVersion': 2, 'hostId': self.config['hostId'],
                'sessionId': None, 'sequence': None,
                'instanceId': row['instanceId'],
                'workloadId': row['workloadId'],
                'revisionDigest': row['revisionDigest'],
                'generation': row['generation'], 'observedAt': now,
                'phase': phase, 'unitActiveState': unit,
                'unitDrained': drained, 'retired': retired,
                'endpointAddress': endpoint, 'readyServices': ready}

    def _post_observation(self, observation):
        """POST one observation. Returns 'accepted'/'drop'; raises
        SessionLost for session/sequence rejection, ReporterError
        otherwise."""
        status, body = self._transport.request(
            'POST', '/v2/observations', observation)
        if status == 200 and type(body) is dict \
                and body.get('status') == 'accepted':
            return 'accepted'
        code = body.get('error') if type(body) is dict else None
        if code in _SESSION_CODES:
            raise SessionLost(code)
        if code in _SKIP_CODES or code in _DROP_CODES:
            return 'drop'
        raise ReporterError(self._registry_code(status, body))

    # -- operation dispatch (M5) ------------------------------------------

    def _ensure_dir(self, path):
        """Create ``path`` as a private dir or verify it is one."""
        if os.path.isdir(path) and not os.path.islink(path):
            _paths(statefiles.check_private_dir, path)
            return
        if os.path.lexists(path):
            raise ReporterError('reporter-path-unsafe')
        _paths(statefiles.check_private_dir, os.path.dirname(path))
        try:
            os.mkdir(path, 0o700)
        except OSError:
            raise ReporterError('reporter-path-unavailable') from None
        self._fsync_dir(path)
        self._fsync_dir(os.path.dirname(path))

    @staticmethod
    def _fsync_dir(path):
        fd = None
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY
                         | os.O_NOFOLLOW)
            os.fsync(fd)
        except OSError:
            raise ReporterError('reporter-path-unavailable') from None
        finally:
            if fd is not None:
                os.close(fd)

    @staticmethod
    def _receipt_id(operation_id, kind):
        return hashlib.sha256(
            b'nexus-dispatch:' + kind.encode('utf-8') + b':'
            + operation_id.encode('utf-8')).hexdigest()[:32]

    def _dispatch_path(self, operation_id):
        return os.path.join(self._dispatch_dir, operation_id + '.json')

    def _validate_dispatch_entry(self, value):
        if type(value) is not dict or set(value) != _DISPATCH_FIELDS:
            raise ReporterError('dispatch-journal-invalid')
        if value['schemaVersion'] != 1 or value['phase'] \
                not in _DISPATCH_PHASES:
            raise ReporterError('dispatch-journal-invalid')
        try:
            worker._hex32(value['operationId'], 'operationId')
            worker._integer(value['seq'], 1, worker._MAX_I64, 'seq')
            worker._identifier(value['workloadId'], 'workloadId')
            worker._integer(value['generation'], 1, worker._MAX_I64,
                            'generation')
            worker._hex32(value['claimRequestId'], 'claimRequestId')
            worker._hex32(value['receiptRequestId'], 'receiptRequestId')
        except worker.WorkerError:
            raise ReporterError('dispatch-journal-invalid') from None
        if value['step'] not in registry._OPERATION_STEPS:
            raise ReporterError('dispatch-journal-invalid')
        try:
            registry._bounded_payload(value['payload'])
        except registry.RegistryError:
            raise ReporterError('dispatch-journal-invalid') from None
        result = value['result']
        if result is not None:
            try:
                registry._bounded_payload(result)
            except registry.RegistryError:
                raise ReporterError(
                    'dispatch-journal-invalid') from None
        error = value['errorCode']
        if error is not None and (type(error) is not str
                                  or worker._IDENTIFIER_RE.fullmatch(
                                      error) is None):
            raise ReporterError('dispatch-journal-invalid')
        return value

    def _save_dispatch(self, entry):
        self._validate_dispatch_entry(entry)
        try:
            statefiles.write_json(self._dispatch_path(
                entry['operationId']), entry)
        except statefiles.PathError as error:
            raise ReporterError('reporter-' + error.code) from None
        except OSError:
            raise ReporterError('reporter-path-unavailable') from None

    def _drop_dispatch(self, entry, event, **fields):
        path = self._dispatch_path(entry['operationId'])
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
        except OSError:
            raise ReporterError('reporter-path-unavailable') from None
        self._fsync_dir(self._dispatch_dir)
        self._log(event, operationId=entry['operationId'],
                  step=entry['step'], **fields)

    def _dispatch_journal(self):
        """Every unfinished operation claim, durable order by seq."""
        entries = []
        try:
            names = os.listdir(self._dispatch_dir)
        except OSError:
            raise ReporterError('reporter-path-unavailable') from None
        if len(names) > _MAX_DISPATCH_JOURNAL:
            raise ReporterError('dispatch-journal-invalid')
        for name in names:
            if not name.endswith('.json') or _HEX32_RE.fullmatch(
                    name[:-5]) is None:
                raise ReporterError('dispatch-journal-invalid')
            try:
                value = statefiles.read_json(
                    os.path.join(self._dispatch_dir, name),
                    _MAX_REQUEST_BYTES)
            except statefiles.PathError:
                raise ReporterError(
                    'dispatch-journal-invalid') from None
            if value is None:
                continue
            entries.append(self._validate_dispatch_entry(value))
        entries.sort(key=lambda entry: entry['seq'])
        return entries

    def _fetch_operations(self):
        status, body = self._transport.request(
            'GET', '/v2/operations?host={}&after=0'.format(
                self.config['hostId']))
        if status != 200 or type(body) is not dict \
                or set(body) != _OPERATIONS_FIELDS:
            raise ReporterError(self._registry_code(status, body))
        if body['schemaVersion'] != 2 \
                or body['hostId'] != self.config['hostId']:
            raise ReporterError('registry-response-invalid')
        rows = body['operations']
        if type(rows) is not list or len(rows) > _MAX_OPERATIONS:
            raise ReporterError('registry-response-invalid')
        operations = []
        seen = set()
        for row in rows:
            if type(row) is not dict \
                    or set(row) != _OPERATION_ROW_FIELDS:
                raise ReporterError('registry-response-invalid')
            try:
                worker._integer(row['seq'], 1, worker._MAX_I64, 'seq')
                worker._hex32(row['operationId'], 'operationId')
                worker._identifier(row['workloadId'], 'workloadId')
                worker._integer(row['generation'], 1,
                                worker._MAX_I64, 'generation')
            except worker.WorkerError:
                raise ReporterError(
                    'registry-response-invalid') from None
            if row['step'] not in registry._OPERATION_STEPS \
                    or type(row['payload']) is not dict:
                raise ReporterError('registry-response-invalid')
            if row['operationId'] in seen:
                raise ReporterError('registry-response-invalid')
            seen.add(row['operationId'])
            operations.append(row)
        operations.sort(key=lambda row: row['seq'])
        return operations

    def _held(self, entry, assignments):
        """Defense in depth: re-verify the operation's workload and
        generation against the assignments this host currently holds
        before any local effect. Returns the assignment row or None."""
        for row in assignments:
            if row['hostId'] == self.config['hostId'] \
                    and row['workloadId'] == entry['workloadId'] \
                    and row['generation'] == entry['generation']:
                return row
        return None

    def _post_receipt(self, entry, receipt):
        """POST one operation receipt. True when accepted; False when
        the registry says the transition is already decided (conflict,
        gone) — the caller drops the journal rather than fighting it."""
        status, body = self._transport.request(
            'POST', '/v2/operations/{}/receipt'.format(
                entry['operationId']), receipt)
        if status == 200 and type(body) is dict \
                and body.get('status') == 'accepted' \
                and body.get('operationId') == entry['operationId']:
            return True
        code = body.get('error') if type(body) is dict else None
        if code in _RECEIPT_DROP_CODES:
            return False
        raise ReporterError(self._registry_code(status, body))

    def _dispatch_entry(self, entry, assignments):
        """Advance one journaled operation as far as possible this
        cycle. Each phase is durably journaled BEFORE the effect it
        describes, so a restart replays rather than double-executing."""
        if entry['phase'] == 'claiming':
            if not self._post_receipt(
                    entry, {'schemaVersion': 2,
                            'requestId': entry['claimRequestId'],
                            'status': 'claimed'}):
                self._drop_dispatch(entry, 'dispatch-conflict')
                return
            entry['phase'] = 'claimed'
            self._save_dispatch(entry)
            self._log('dispatch-claimed',
                      operationId=entry['operationId'],
                      step=entry['step'])
        if entry['phase'] == 'claimed':
            try:
                entry['result'] = self._execute_entry(
                    entry, assignments)
            except _Refused as refusal:
                entry['result'] = None
                entry['errorCode'] = refusal.code
            entry['phase'] = 'executed'
            self._save_dispatch(entry)
        if entry['phase'] == 'executed':
            if entry['errorCode'] is not None:
                receipt = {'schemaVersion': 2,
                           'requestId': entry['receiptRequestId'],
                           'status': 'failed',
                           'errorCode': entry['errorCode']}
            else:
                receipt = {'schemaVersion': 2,
                           'requestId': entry['receiptRequestId'],
                           'status': 'completed',
                           'result': entry['result']}
            if not self._post_receipt(entry, receipt):
                self._drop_dispatch(entry, 'dispatch-conflict')
                return
            self._drop_dispatch(entry, 'dispatch-finished')

    def _dispatch_cycle(self, assignments):
        """Resume journaled claims, then pull and claim fresh pending
        operations for this host."""
        handled = 0
        journaled = set()
        for entry in self._dispatch_journal():
            journaled.add(entry['operationId'])
            self._dispatch_entry(entry, assignments)
            handled += 1
        for operation in self._fetch_operations():
            if operation['operationId'] in journaled:
                continue
            entry = {'schemaVersion': 1,
                     'operationId': operation['operationId'],
                     'seq': operation['seq'],
                     'workloadId': operation['workloadId'],
                     'generation': operation['generation'],
                     'step': operation['step'],
                     'payload': operation['payload'],
                     'claimRequestId': self._receipt_id(
                         operation['operationId'], 'claim'),
                     'receiptRequestId': self._receipt_id(
                         operation['operationId'], 'receipt'),
                     'phase': 'claiming', 'result': None,
                     'errorCode': None}
            self._save_dispatch(entry)
            self._dispatch_entry(entry, assignments)
            handled += 1
        return handled

    # -- per-step payload validation and execution -------------------------

    def _worker_payload(self, entry, held):
        payload = entry['payload']
        try:
            action, request = worker.validate_request(payload)
        except worker.WorkerError:
            raise _Refused('operation-invalid') from None
        if action != entry['step']:
            raise _Refused('operation-invalid')
        if request['operationId'] != entry['operationId'] \
                or request['workloadId'] != entry['workloadId'] \
                or request['generation'] != entry['generation'] \
                or request['instanceId'] != held['instanceId']:
            raise _Refused('operation-not-held')
        return request

    def _worker_result(self, request):
        try:
            receipt = self._executor()(request)
        except worker.WorkerError as error:
            raise _Refused('worker-' + error.code) from None
        if type(receipt) is not dict or receipt.get('schemaVersion') != 1 \
                or receipt.get('operationId') != request['operationId']:
            raise _Refused('worker-receipt-invalid')
        status = receipt.get('status')
        if status == 'completed':
            result = {'appliedPhase': receipt.get('appliedPhase')}
            if 'captureId' in receipt:
                result['captureId'] = receipt['captureId']
            return result
        if status == 'failed':
            error = receipt.get('error')
            raise _Refused('worker-' + error
                           if type(error) is str
                           and worker._IDENTIFIER_RE.fullmatch(error)
                           else 'worker-failed')
        # 'uncertain' (or anything unexpected): the worker may have
        # applied partially — keep the claim and retry next cycle.
        raise ReporterError('worker-uncertain')

    def _observe_payload(self, entry, held):
        payload = entry['payload']
        try:
            action, request = worker.validate_request(payload)
        except worker.WorkerError:
            raise _Refused('operation-invalid') from None
        if action != 'observe' \
                or request['instanceId'] != held['instanceId']:
            raise _Refused('operation-not-held')
        return request

    def _observe_result(self, request):
        try:
            observed = self._executor()(request)
        except worker.WorkerError as error:
            raise _Refused('worker-' + error.code) from None
        if type(observed) is not dict:
            raise _Refused('worker-receipt-invalid')
        result = {}
        for key in ('bindingCurrent', 'slotId', 'phase',
                    'unitActiveState', 'unitDrained', 'retired'):
            if key in observed:
                result[key] = observed[key]
        try:
            registry._bounded_payload(result)
        except registry.RegistryError:
            raise _Refused('worker-receipt-invalid') from None
        return result

    def _cli(self, program_key, config_key, request, timeout):
        program = self.config[program_key]
        config_path = self.config[config_key]
        if program is None or config_path is None:
            raise _Refused('dispatch-unavailable')
        try:
            completed = self._runner.run(
                [program, '--config', config_path, 'execute'],
                artifacts.canonical_bytes(request), timeout=timeout)
        except ReporterError as error:
            # A timeout may mean slow real work — keep the claim and
            # retry next cycle; anything else is a fixed failure.
            if error.code == 'cli-timeout':
                raise
            raise _Refused('cli-failed') from None
        try:
            body = worker.load_json_bytes(completed.stdout)
        except worker.WorkerError:
            raise _Refused('cli-response-invalid') from None
        if type(body) is not dict \
                or type(body.get('status')) is not str:
            raise _Refused('cli-response-invalid')
        if body['status'] == 'blocked':
            error = body.get('error')
            raise _Refused('cli-' + error
                           if type(error) is str
                           and worker._IDENTIFIER_RE.fullmatch(error)
                           else 'cli-failed')
        if completed.returncode != 0 or body['status'] != 'completed':
            raise _Refused('cli-failed')
        return body

    def _stage_payload(self, entry, held):
        payload = entry['payload']
        if set(payload) != _STAGE_FIELDS \
                or payload['schemaVersion'] != 1 \
                or payload['action'] != 'stage':
            raise _Refused('operation-invalid')
        try:
            worker._hex32(payload['restoreId'], 'restoreId')
            worker._identifier(payload['repositoryId'], 'repositoryId')
            if type(payload['snapshotId']) is not str \
                    or _HEX64_RE.fullmatch(payload['snapshotId']) is None:
                raise worker.WorkerError('snapshotId')
            target = payload['target']
            if type(target) is not dict \
                    or set(target) != _TARGET_FIELDS:
                raise worker.WorkerError('target')
            worker._identifier(target['workloadId'], 'workloadId')
            worker._digest(target['revisionDigest'], 'revisionDigest')
            worker._hex32(target['instanceId'], 'instanceId')
            worker._integer(target['generation'], 1, worker._MAX_I64,
                            'generation')
            worker._identifier(target['slotId'], 'slotId')
        except worker.WorkerError:
            raise _Refused('operation-invalid') from None
        target = payload['target']
        if target['workloadId'] != entry['workloadId'] \
                or target['generation'] != entry['generation'] \
                or target['instanceId'] != held['instanceId'] \
                or target['revisionDigest'] != held['revisionDigest']:
            raise _Refused('operation-not-held')
        return payload

    def _commit_payload(self, entry):
        payload = entry['payload']
        if set(payload) != _COMMIT_FIELDS \
                or payload['schemaVersion'] != 1 \
                or payload['action'] != 'commit':
            raise _Refused('operation-invalid')
        try:
            worker._hex32(payload['restoreId'], 'restoreId')
        except worker.WorkerError:
            raise _Refused('operation-invalid') from None
        return payload

    def _capture_payload(self, entry, held):
        payload = entry['payload']
        if set(payload) != _CAPTURE_PAYLOAD_FIELDS:
            raise _Refused('operation-invalid')
        capture = payload['capture']
        upload = payload['upload']
        if type(capture) is not dict or set(capture) != _CAPTURE_FIELDS \
                or type(upload) is not dict \
                or set(upload) != _UPLOAD_FIELDS \
                or capture['schemaVersion'] != 1 \
                or capture['action'] != 'capture' \
                or upload['schemaVersion'] != 1 \
                or upload['action'] != 'upload':
            raise _Refused('operation-invalid')
        try:
            worker._hex32(capture['captureId'], 'captureId')
            worker._identifier(capture['workloadId'], 'workloadId')
            worker._digest(capture['revisionDigest'], 'revisionDigest')
            worker._hex32(capture['instanceId'], 'instanceId')
            worker._integer(capture['generation'], 1,
                            worker._MAX_I64, 'generation')
            worker._identifier(upload['repositoryId'], 'repositoryId')
        except worker.WorkerError:
            raise _Refused('operation-invalid') from None
        if upload['captureId'] != capture['captureId'] \
                or capture['workloadId'] != entry['workloadId'] \
                or capture['generation'] != entry['generation'] \
                or capture['instanceId'] != held['instanceId']:
            raise _Refused('operation-not-held')
        return capture, upload

    def _execute_entry(self, entry, assignments):
        """Run the operation's step. ``_Refused`` becomes a permanent
        'failed' receipt; ReporterError propagates as transient and the
        claim survives for the next cycle."""
        held = self._held(entry, assignments)
        if held is None:
            raise _Refused('operation-not-held')
        step = entry['step']
        if step in _WORKER_STEPS:
            return self._worker_result(
                self._worker_payload(entry, held))
        if step == 'observe':
            return self._observe_result(
                self._observe_payload(entry, held))
        if step == 'restore-stage':
            request = self._stage_payload(entry, held)
            self._cli('restoreProgram', 'restoreConfigFile', request,
                      _BULK_TIMEOUT)
            return {'restoreId': request['restoreId'],
                    'action': 'stage', 'status': 'completed'}
        if step == 'restore-commit':
            request = self._commit_payload(entry)
            self._cli('restoreProgram', 'restoreConfigFile', request,
                      _CLI_TIMEOUT)
            return {'restoreId': request['restoreId'],
                    'action': 'commit', 'status': 'completed'}
        # capture: nexus-backup capture then upload; both are
        # replay-identical on captureId, so a mid-step crash simply
        # re-runs them.
        capture, upload = self._capture_payload(entry, held)
        self._cli('backupProgram', 'backupConfigFile', capture,
                  _BULK_TIMEOUT)
        body = self._cli('backupProgram', 'backupConfigFile', upload,
                         _BULK_TIMEOUT)
        record = body.get('record')
        if type(record) is not dict \
                or type(record.get('snapshotId')) is not str \
                or _HEX64_RE.fullmatch(record['snapshotId']) is None \
                or type(body.get('verifiedAt')) is not int \
                or record.get('repositoryId') != upload['repositoryId']:
            raise _Refused('cli-response-invalid')
        return {'snapshotId': record['snapshotId'],
                'repositoryId': record['repositoryId'],
                'verifiedAt': body['verifiedAt']}

    # -- public surface --------------------------------------------------

    def run_once(self):
        """One reporting cycle: session, assignments, observe+post per
        instance, then dispatch pending operations. Raises
        ReporterError for cycle-level failures."""
        if self._closed:
            raise ReporterError('reporter-closed')
        if self._session_id is None:
            self._open_session()
        assignments = self._fetch_assignments()
        posted = skipped = 0
        for row in assignments:
            observation = self._observe_instance(row)
            if observation is None:
                skipped += 1
                continue
            observation['sessionId'] = self._session_id
            observation['sequence'] = self._allocate_sequence()
            try:
                outcome = self._post_observation(observation)
            except SessionLost:
                # The registry discarded our session (restart, epoch
                # change or a conflicting reporter). Re-open once and
                # restart the sequence at 1 under the new session.
                self._open_session()
                observation['sessionId'] = self._session_id
                observation['sequence'] = self._allocate_sequence()
                outcome = self._post_observation(observation)
            if outcome == 'accepted':
                posted += 1
            else:
                skipped += 1
        dispatched = self._dispatch_cycle(assignments)
        self._log('cycle', posted=posted, skipped=skipped,
                  dispatched=dispatched)
        return posted, skipped

    def _backoff(self, failures):
        base = min(self._max_backoff,
                   self._interval * (2 ** min(failures - 1, 16)))
        jitter = self._rand()
        if type(jitter) is not float or not 0.0 <= jitter <= 1.0:
            jitter = 0.5
        return min(float(self._max_backoff), base * (0.5 + jitter))

    def run(self, stop=None):
        """Serve forever: cycle, then interval sleep or bounded backoff
        with jitter on failure. Never propagates cycle errors."""
        stop = stop or threading.Event()
        failures = 0
        while not stop.is_set():
            try:
                self.run_once()
                failures = 0
                delay = self._interval
            except Exception as error:
                failures = min(failures + 1, 17)
                delay = self._backoff(failures)
                code = getattr(error, 'code', None)
                self._log('cycle-error',
                          code=code if type(code) is str else None,
                          type=type(error).__name__)
            if self._sleeper is not None:
                self._sleeper(delay)
            else:
                stop.wait(delay)

    def close(self):
        self._closed = True
        if self._worker is not None:
            try:
                self._worker.close()
            except Exception:
                pass
            self._worker = None
        if self._lock_handle is not None:
            os.close(self._lock_handle)
            self._lock_handle = None


def _response(response):
    sys.stdout.write(artifacts.canonical_bytes(response).decode('utf-8')
                     + '\n')


def _read_config_file(path):
    try:
        worker._path(path, 'config')
    except worker.WorkerError as error:
        raise ReporterError(error.code) from None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise ReporterError('path-unavailable') from None
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            raise ReporterError('path-unsafe')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            raw = handle.read(_MAX_CONFIG + 1)
    except OSError:
        raise ReporterError('path-unavailable') from None
    finally:
        os.close(fd)
    if len(raw) > _MAX_CONFIG:
        raise ReporterError('config-too-large')
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(prog='nexus-reporter')
    parser.add_argument('--config', required=True)
    args = parser.parse_args(argv)
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
        instance = Reporter(config, context=context)
    except (ReporterError, worker.WorkerError, registry.RegistryError,
            OSError, KeyError, ValueError) as error:
        code = getattr(error, 'code', 'invalid-config')
        _response({'schemaVersion': 2, 'status': 'error',
                   'error': code})
        return 1
    try:
        instance.run()
    finally:
        instance.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
