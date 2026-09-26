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
bounded exponential backoff plus jitter. The daemon never mutates the
worker (``observe`` only) and never crashes it: every worker call is
isolated per instance and converts to a skipped sample.
"""

import argparse
import fcntl
import http.client
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import stat
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


_MAX_REQUEST_BYTES = 16384
_MAX_BODY = 65536
_MAX_CONFIG = 2 * 1024 * 1024
_MAX_ASSIGNMENTS = 256
_STATE_FIELDS = {'schemaVersion', 'hostId', 'sessionId', 'registryEpoch',
                 'nextSequence'}
_CONFIG_FIELDS = {'schemaVersion', 'hostId', 'registryUrl', 'registry',
                  'stateDir', 'workerConfigFile', 'observeIntervalSeconds',
                  'requestTimeoutSeconds', 'maxBackoffSeconds'}
_SESSION_FIELDS = {'schemaVersion', 'hostId', 'sessionId', 'registryEpoch'}
_ASSIGNMENTS_FIELDS = {'schemaVersion', 'hostId', 'instances'}
_ASSIGNMENT_FIELDS = {'instanceId', 'workloadId', 'revisionDigest',
                      'hostId', 'generation'}
_LOG_KEYS = {'event', 'at', 'code', 'type', 'instanceId', 'workloadId',
             'sequence', 'posted', 'skipped'}
_SKIP_CODES = {'instance-mismatch'}
_DROP_CODES = {'observation-stale', 'observation-future'}
_SESSION_CODES = {'session-mismatch', 'sequence-conflict'}
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
    _check(worker._fields, config, _CONFIG_FIELDS, 'config')
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
    try:
        registry_config = registry.validate_config(config['registry'])
    except registry.RegistryError as error:
        raise ReporterError('invalid-registry-config') from None
    if config['hostId'] not in {h['hostId']
                                for h in registry_config['hosts']}:
        raise ReporterError('invalid-config-hostId')
    return {'schemaVersion': 2, 'hostId': config['hostId'],
            'registryUrl': config['registryUrl'],
            'registry': registry_config, 'stateDir': config['stateDir'],
            'workerConfigFile': config['workerConfigFile'],
            'observeIntervalSeconds': config['observeIntervalSeconds'],
            'requestTimeoutSeconds': config['requestTimeoutSeconds'],
            'maxBackoffSeconds': config['maxBackoffSeconds']}


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
                 clock=time.time, monotonic=time.monotonic,
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
        self._worker = None
        self._closed = False
        state_dir = self.config['stateDir']
        _paths(statefiles.check_private_dir, state_dir)
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

    def _observer(self):
        if self._observer_fn is not None:
            return self._observer_fn
        if self._worker is None:
            try:
                self._worker = self._worker_factory(self._worker_config)
            except Exception:
                raise ReporterError('worker-unavailable') from None
        worker_handle = self._worker

        def observe(instance_id):
            return worker_handle.execute(
                {'schemaVersion': 1, 'action': 'observe',
                 'instanceId': instance_id})

        return observe

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

    # -- public surface --------------------------------------------------

    def run_once(self):
        """One reporting cycle: session, assignments, observe+post per
        instance. Raises ReporterError for cycle-level failures."""
        if self._closed:
            raise ReporterError('reporter-closed')
        if self._session_id is None:
            self._open_session()
        posted = skipped = 0
        for row in self._fetch_assignments():
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
        self._log('cycle', posted=posted, skipped=skipped)
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
