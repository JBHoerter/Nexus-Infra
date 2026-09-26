"""Durable registry core for workload placement and retirement (M3)
plus the pull-model operation-dispatch queue (M5).

Internal library only: callers pass a Principal constructed by a future
authenticated transport. Roles and identities are trusted caller inputs until
mTLS/ingress integration exists; there is no network listener here. Host
observations are self-reported evidence: a missing or stale sample is never
proof a host is down, and a reported retirement is not off-host fencing. A
successor placement requires a fresh, current-session observation proving the
old instance retired AND drained — OR a committed fence record (M8): a
durable, controller-posted attestation scoped to the incumbent's
(workloadId, generation) and bound to its hostId, recorded BEFORE the host
reports anything, for the case where a dead or partitioned host can never
report itself (docs/replication-failover-design.md). A fence record only
unblocks successor ``assign``; it never marks an observed-live instance
dead — routes, publish and observed state remain governed by fresh
observations alone, and withdraw rules are unchanged. A definition that
declares dependencies additionally requires, at the atomic ``assign`` and
``publish`` commit points, fresh ready evidence on every declared
dependency — the same /v2/state view the controller verifies at plan time —
so a dependency lost between the controller's check and the commit cannot
slip through. Nothing in this
module or anywhere in Nexus issues fence records automatically: posting one
is an explicit act of a future authorized failover component (DRBD
quorum-attested) or of an operator — there is no automatic failover
trigger here by design.

The operation queue is a rendezvous, not a control channel: a controller
POSTs a bounded operation bound to the CURRENT placement generation of a
workload and to the host holding that generation; the owning host polls
``operations`` for pending rows, claims each with a first-wins receipt,
executes it locally and posts a terminal receipt. Receipts are
exactly-once per requestId — identical replays are accepted, conflicting
ones rejected — and the registry never executes anything itself. A stale
generation or a generation bound to another host is rejected at post
time; this is control-plane trust, not fencing.
"""
import copy
import fcntl
import json
import math
import os
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass

import artifacts
import catalog
import statefiles
import worker


@dataclass(frozen=True)
class Principal:
    identity: str
    role: str  # controller, host, reader, ingress
    host_id: str | None = None


class RegistryError(Exception):
    def __init__(self, code, status=400):
        super().__init__(code)
        self.code, self.status = code, status


_MAX_I64 = 2**63 - 1
_OBSERVATION_MAX_AGE = 30.0
_LOST_AFTER = 300.0
_ROUTE_TTL = 10.0
_ROLES = ('controller', 'host', 'reader', 'ingress')
_ARCHITECTURES = ('x86_64-linux', 'aarch64-linux')
_PHASES = ('preparing', 'prepared', 'starting', 'running', 'stopping',
           'stopped', 'unknown')
_UNIT_STATES = ('active', 'inactive', 'failed', 'activating', 'deactivating',
                'unknown')
_HOSTNAME_LABEL_RE = re.compile(r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?')
_OBSERVATION_FIELDS = {'schemaVersion', 'hostId', 'sessionId', 'sequence',
                       'instanceId', 'workloadId', 'revisionDigest',
                       'generation', 'observedAt', 'phase', 'unitActiveState',
                       'unitDrained', 'retired', 'endpointAddress',
                       'readyServices'}
_OPERATION_FIELDS = {'schemaVersion', 'requestId', 'operationId',
                     'workloadId', 'hostId', 'generation', 'step', 'payload'}
_OPERATION_STEPS = ('prepare', 'adopt', 'restore-stage', 'restore-commit',
                    'start', 'stop', 'observe', 'freeze', 'capture', 'thaw',
                    'retire')
_FENCE_FIELDS = {'schemaVersion', 'requestId', 'workloadId', 'generation',
                 'hostId', 'evidence'}
_FENCE_EVIDENCE = ('quorum-attested', 'operator')
_OPERATION_STATUSES = ('pending', 'claimed', 'completed', 'failed')
_RECEIPT_BASE = {'schemaVersion', 'requestId', 'status'}
_OPERATION_PENDING_MAX = 256
_OPERATION_POLL_MAX = 64

_SCHEMA = '''
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value INTEGER NOT NULL);
INSERT OR IGNORE INTO meta VALUES('version',0);
CREATE TABLE IF NOT EXISTS placements(workload_id TEXT PRIMARY KEY,
    generation INTEGER NOT NULL,
    instance_id TEXT NOT NULL, published INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS instances(instance_id TEXT PRIMARY KEY,
    workload_id TEXT NOT NULL, revision_digest TEXT NOT NULL,
    host_id TEXT NOT NULL, generation INTEGER NOT NULL,
    UNIQUE(workload_id,generation));
CREATE TABLE IF NOT EXISTS sessions(host_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL, epoch TEXT NOT NULL, sequence INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS observations(instance_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL, session_id TEXT NOT NULL, epoch TEXT NOT NULL,
    received_at REAL NOT NULL, received_mono REAL NOT NULL);
CREATE TABLE IF NOT EXISTS requests(request_id TEXT PRIMARY KEY,
    principal TEXT NOT NULL, action TEXT NOT NULL, payload TEXT NOT NULL,
    receipt TEXT NOT NULL);
INSERT OR IGNORE INTO meta VALUES('operationSequence',0);
CREATE TABLE IF NOT EXISTS operations(operation_id TEXT PRIMARY KEY,
    seq INTEGER NOT NULL UNIQUE, host_id TEXT NOT NULL,
    workload_id TEXT NOT NULL, generation INTEGER NOT NULL,
    step TEXT NOT NULL, payload TEXT NOT NULL,
    request_id TEXT NOT NULL UNIQUE, principal TEXT NOT NULL,
    status TEXT NOT NULL, claim_request_id TEXT, claim_body TEXT,
    final_request_id TEXT, final_body TEXT);
CREATE TABLE IF NOT EXISTS fences(workload_id TEXT NOT NULL,
    generation INTEGER NOT NULL, host_id TEXT NOT NULL,
    evidence TEXT NOT NULL, attester TEXT NOT NULL,
    request_id TEXT NOT NULL, recorded_at REAL NOT NULL,
    PRIMARY KEY(workload_id, generation));
'''


def _check(fn, *args):
    try:
        fn(*args)
    except worker.WorkerError as error:
        raise RegistryError(error.code) from None


def _bounded_time(value, code, status=400):
    if type(value) is int:
        if not 0 <= value <= 2**53:
            raise RegistryError(code, status)
        return float(value)
    if type(value) is not float or not math.isfinite(value) \
            or not 0 <= value <= 2**53:
        raise RegistryError(code, status)
    return value


def _hostname(value):
    if type(value) is not str or not value or len(value) > 253:
        raise RegistryError('invalid-route-hostname')
    for label in value.split('.'):
        if _HOSTNAME_LABEL_RE.fullmatch(label) is None:
            raise RegistryError('invalid-route-hostname')


def validate_config(config):
    _check(worker._fields, config,
           {'schemaVersion', 'definitions', 'hosts', 'routes'}, 'config')
    _check(worker._integer, config['schemaVersion'], 2, 2,
           'config-schemaVersion')
    raw_definitions = config['definitions']
    if type(raw_definitions) is not list \
            or not 1 <= len(raw_definitions) <= 1024:
        raise RegistryError('invalid-config-definitions')
    definitions = {}
    revisions = {}
    for raw in raw_definitions:
        try:
            record = catalog.validate_definition(raw)
        except catalog.CatalogError:
            raise RegistryError('invalid-config-definitions') from None
        key = (record['workloadId'], record['revisionDigest'])
        if key in definitions:
            raise RegistryError('invalid-config-definitions')
        definitions[key] = record
        revisions.setdefault(record['workloadId'], []).append(record)
    raw_hosts = config['hosts']
    if type(raw_hosts) is not list or not 1 <= len(raw_hosts) <= 256:
        raise RegistryError('invalid-config-hosts')
    hosts = {}
    seen_addresses = set()
    for host in raw_hosts:
        _check(worker._fields, host, {'hostId', 'architecture', 'addresses'},
               'host')
        _check(worker._identifier, host['hostId'], 'host-hostId')
        if host['hostId'] in hosts:
            raise RegistryError('invalid-config-hosts')
        if type(host['architecture']) is not str \
                or host['architecture'] not in _ARCHITECTURES:
            raise RegistryError('invalid-config-hosts')
        addresses = host['addresses']
        if type(addresses) is not list or not 1 <= len(addresses) <= 64:
            raise RegistryError('invalid-config-hosts')
        for address in addresses:
            _check(worker._ipv4, address, 'host-addresses')
            if address in seen_addresses:
                raise RegistryError('invalid-config-hosts')
            seen_addresses.add(address)
        hosts[host['hostId']] = {'hostId': host['hostId'],
                                 'architecture': host['architecture'],
                                 'addresses': list(addresses)}
    raw_routes = config['routes']
    if type(raw_routes) is not list or len(raw_routes) > 1024:
        raise RegistryError('invalid-config-routes')
    routes = []
    seen_ids, seen_hostnames = set(), set()
    for route in raw_routes:
        _check(worker._fields, route,
               {'id', 'workloadId', 'serviceId', 'hostname'}, 'route')
        _check(worker._identifier, route['id'], 'route-id')
        _check(worker._identifier, route['workloadId'], 'route-workloadId')
        _check(worker._identifier, route['serviceId'], 'route-serviceId')
        if route['id'] in seen_ids:
            raise RegistryError('invalid-config-routes')
        seen_ids.add(route['id'])
        _hostname(route['hostname'])
        if route['hostname'] in seen_hostnames:
            raise RegistryError('invalid-config-routes')
        seen_hostnames.add(route['hostname'])
        versions = revisions.get(route['workloadId'])
        if not versions:
            raise RegistryError('invalid-config-routes')
        for definition in versions:
            if definition['category'] in ('archive', 'infrastructure'):
                raise RegistryError('invalid-config-routes')
            service = [s for s in definition['services']
                       if s['id'] == route['serviceId']]
            if len(service) != 1 or service[0]['protocol'] != 'http':
                raise RegistryError('invalid-config-routes')
        routes.append({'id': route['id'], 'workloadId': route['workloadId'],
                       'serviceId': route['serviceId'],
                       'hostname': route['hostname']})
    return {'schemaVersion': 2,
            'definitions': [definitions[key] for key in sorted(definitions)],
            'hosts': [hosts[key] for key in sorted(hosts)],
            'routes': sorted(routes, key=lambda route: route['id'])}


def _validate_assign(request):
    _check(worker._fields, request,
           {'schemaVersion', 'requestId', 'workloadId', 'revisionDigest',
            'hostId', 'instanceId', 'expectedGeneration'}, 'request')
    _check(worker._integer, request['schemaVersion'], 2, 2, 'schemaVersion')
    _check(worker._hex32, request['requestId'], 'requestId')
    _check(worker._identifier, request['workloadId'], 'workloadId')
    _check(worker._digest, request['revisionDigest'], 'revisionDigest')
    _check(worker._identifier, request['hostId'], 'hostId')
    _check(worker._hex32, request['instanceId'], 'instanceId')
    _check(worker._integer, request['expectedGeneration'], 0, _MAX_I64 - 1,
           'expectedGeneration')
    return request


def _validate_placement_request(request):
    _check(worker._fields, request,
           {'schemaVersion', 'requestId', 'workloadId', 'expectedGeneration'},
           'request')
    _check(worker._integer, request['schemaVersion'], 2, 2, 'schemaVersion')
    _check(worker._hex32, request['requestId'], 'requestId')
    _check(worker._identifier, request['workloadId'], 'workloadId')
    _check(worker._integer, request['expectedGeneration'], 0, _MAX_I64 - 1,
           'expectedGeneration')
    return request


def _validate_observation(request, now):
    _check(worker._fields, request, _OBSERVATION_FIELDS, 'request')
    _check(worker._integer, request['schemaVersion'], 2, 2, 'schemaVersion')
    _check(worker._identifier, request['hostId'], 'hostId')
    _check(worker._hex32, request['sessionId'], 'sessionId')
    _check(worker._integer, request['sequence'], 1, _MAX_I64, 'sequence')
    _check(worker._hex32, request['instanceId'], 'instanceId')
    _check(worker._identifier, request['workloadId'], 'workloadId')
    _check(worker._digest, request['revisionDigest'], 'revisionDigest')
    _check(worker._integer, request['generation'], 1, _MAX_I64, 'generation')
    observed_at = _bounded_time(request['observedAt'], 'invalid-observedAt')
    if observed_at > now:
        raise RegistryError('observation-future')
    if now - observed_at > _OBSERVATION_MAX_AGE:
        raise RegistryError('observation-stale')
    if request['phase'] not in _PHASES:
        raise RegistryError('invalid-phase')
    if request['unitActiveState'] not in _UNIT_STATES:
        raise RegistryError('invalid-unitActiveState')
    if request['unitDrained'] is not None \
            and type(request['unitDrained']) is not bool:
        raise RegistryError('invalid-unitDrained')
    if type(request['retired']) is not bool:
        raise RegistryError('invalid-retired')
    ready = request['readyServices']
    if type(ready) is not list or len(ready) > 64:
        raise RegistryError('invalid-readyServices')
    for service in ready:
        _check(worker._identifier, service, 'readyServices')
    if len(set(ready)) != len(ready):
        raise RegistryError('invalid-readyServices')
    if ready and (request['phase'] != 'running'
                  or request['unitActiveState'] != 'active'
                  or request['unitDrained'] is not False
                  or request['retired'] is not False):
        raise RegistryError('invalid-observation')
    return request


def _bounded_payload(value, depth=0):
    """Operation payloads and receipt results must stay small, strict
    JSON trees — the registry stores but never interprets them."""
    if depth > 8:
        raise RegistryError('invalid-payload')
    if type(value) is dict:
        if len(value) > 32:
            raise RegistryError('invalid-payload')
        for key, item in value.items():
            if type(key) is not str or not key or len(key) > 64:
                raise RegistryError('invalid-payload')
            _bounded_payload(item, depth + 1)
    elif type(value) is list:
        if len(value) > 64:
            raise RegistryError('invalid-payload')
        for item in value:
            _bounded_payload(item, depth + 1)
    elif type(value) is str:
        if len(value) > 512:
            raise RegistryError('invalid-payload')
    elif type(value) is int:
        if not 0 <= value <= 2**53:
            raise RegistryError('invalid-payload')
    elif value is not None and type(value) is not bool:
        raise RegistryError('invalid-payload')


def _validate_operation(request):
    _check(worker._fields, request, _OPERATION_FIELDS, 'request')
    _check(worker._integer, request['schemaVersion'], 2, 2,
           'schemaVersion')
    _check(worker._hex32, request['requestId'], 'requestId')
    _check(worker._hex32, request['operationId'], 'operationId')
    _check(worker._identifier, request['workloadId'], 'workloadId')
    _check(worker._identifier, request['hostId'], 'hostId')
    _check(worker._integer, request['generation'], 1, _MAX_I64,
           'generation')
    if request['step'] not in _OPERATION_STEPS:
        raise RegistryError('invalid-step')
    if type(request['payload']) is not dict:
        raise RegistryError('invalid-payload')
    _bounded_payload(request['payload'])
    return request


def _validate_receipt(request):
    if type(request) is not dict:
        raise RegistryError('invalid-request-fields')
    status = request.get('status')
    if status == 'claimed':
        expected = _RECEIPT_BASE
    elif status == 'completed':
        expected = _RECEIPT_BASE | {'result'}
    elif status == 'failed':
        expected = _RECEIPT_BASE | {'errorCode'}
    else:
        raise RegistryError('invalid-status')
    _check(worker._fields, request, expected, 'request')
    _check(worker._integer, request['schemaVersion'], 2, 2,
           'schemaVersion')
    _check(worker._hex32, request['requestId'], 'requestId')
    if status == 'completed':
        _bounded_payload(request['result'])
    elif status == 'failed':
        _check(worker._identifier, request['errorCode'], 'errorCode')
    return request


def _validate_fence(request):
    _check(worker._fields, request, _FENCE_FIELDS, 'request')
    _check(worker._integer, request['schemaVersion'], 2, 2,
           'schemaVersion')
    _check(worker._hex32, request['requestId'], 'requestId')
    _check(worker._identifier, request['workloadId'], 'workloadId')
    _check(worker._integer, request['generation'], 1, _MAX_I64,
           'generation')
    _check(worker._identifier, request['hostId'], 'hostId')
    if request['evidence'] not in _FENCE_EVIDENCE:
        raise RegistryError('invalid-evidence')
    return request


class Registry:
    def __init__(self, config, db_path, *, clock=time.time,
                 monotonic=time.monotonic, epoch=None):
        self.config = validate_config(config)
        self.clock = clock
        self.monotonic = monotonic
        self.epoch = epoch if epoch is not None else secrets.token_hex(16)
        _check(worker._path, db_path, 'db-path')
        self._mutex = threading.RLock()
        self._last_wall = None
        self._last_mono = None
        self._definitions = {
            (d['workloadId'], d['revisionDigest']): d
            for d in self.config['definitions']}
        self._revisions = {}
        for definition in self.config['definitions']:
            self._revisions.setdefault(definition['workloadId'], []).append(
                definition)
        self._hosts = {h['hostId']: h for h in self.config['hosts']}
        self._routes = list(self.config['routes'])
        self._route_services = {}
        for route in self._routes:
            self._route_services.setdefault(route['workloadId'], set()).add(
                route['serviceId'])
        self._lock_handle = None
        self.db = None
        try:
            self._open_db(db_path)
        except RegistryError:
            self._release()
            raise
        except (OSError, sqlite3.Error):
            self._release()
            raise RegistryError('registry-unavailable') from None

    def _release(self):
        if self.db is not None:
            try:
                self.db.close()
            except sqlite3.Error:
                pass
            self.db = None
        if self._lock_handle is not None:
            os.close(self._lock_handle)
            self._lock_handle = None

    def close(self):
        with self._mutex:
            if self.db is not None:
                try:
                    self.db.execute('ROLLBACK')
                except sqlite3.Error:
                    pass
            self._release()

    def _open_db(self, db_path):
        parent = os.path.dirname(db_path)
        try:
            statefiles.check_private_dir(parent)
            statefiles.ensure_private_file(db_path)
            statefiles.ensure_private_file(db_path + '.lock')
            for suffix in ('-wal', '-shm', '-journal'):
                statefiles.check_private_file(db_path + suffix)
        except statefiles.PathError as error:
            raise RegistryError('registry-' + error.code
                                if error.code == 'path-unsafe'
                                else 'registry-unavailable') from None
        lock_path = db_path + '.lock'
        self._lock_handle = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(self._lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RegistryError('registry-in-use', 409) from None
        self.db = sqlite3.connect(db_path, isolation_level=None,
                                  check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript(_SCHEMA)
        self._check_compat()

    def _check_compat(self):
        for workload_id, revision_digest, host_id in self.db.execute(
                'SELECT workload_id, revision_digest, host_id'
                ' FROM instances'):
            definition = self._definitions.get((workload_id,
                                                revision_digest))
            host = self._hosts.get(host_id)
            if definition is None or host is None \
                    or definition['architecture'] != host['architecture']:
                raise RegistryError('registry-config-incompatible', 409)
        known = {row[0] for row in self.db.execute(
            'SELECT instance_id FROM instances')}
        for (instance_id,) in self.db.execute(
                'SELECT instance_id FROM placements'):
            if instance_id not in known:
                raise RegistryError('registry-config-incompatible', 409)
        generations = {(row[0], row[1]) for row in self.db.execute(
            'SELECT workload_id, generation FROM instances')}
        for host_id, workload_id, generation in self.db.execute(
                'SELECT host_id, workload_id, generation'
                ' FROM operations'):
            if host_id not in self._hosts \
                    or (workload_id, generation) not in generations:
                raise RegistryError('registry-config-incompatible', 409)
        for host_id, workload_id, generation, evidence in self.db.execute(
                'SELECT host_id, workload_id, generation, evidence'
                ' FROM fences'):
            if host_id not in self._hosts \
                    or (workload_id, generation) not in generations \
                    or evidence not in _FENCE_EVIDENCE:
                raise RegistryError('registry-config-incompatible', 409)

    def _now(self):
        value = _bounded_time(self.clock(), 'clock-unavailable', 500)
        if self._last_wall is not None and value < self._last_wall:
            raise RegistryError('clock-unavailable', 500)
        self._last_wall = value
        return value

    def _mono(self):
        value = _bounded_time(self.monotonic(), 'clock-unavailable', 500)
        if self._last_mono is not None and value < self._last_mono:
            raise RegistryError('clock-unavailable', 500)
        self._last_mono = value
        return value

    def _principal(self, principal, roles):
        try:
            identity = principal.identity
            role = principal.role
            host_id = principal.host_id
        except AttributeError:
            raise RegistryError('invalid-principal', 403) from None
        if type(identity) is not str or not identity or len(identity) > 512 \
                or type(role) is not str or role not in _ROLES:
            raise RegistryError('invalid-principal', 403)
        if host_id is not None and (type(host_id) is not str
                                    or host_id not in self._hosts):
            raise RegistryError('invalid-principal', 403)
        if role not in roles:
            raise RegistryError('forbidden', 403)

    def _own_host(self, principal, host_id):
        if principal.host_id is None or principal.host_id != host_id:
            raise RegistryError('host-mismatch', 403)

    def _version(self):
        return self.db.execute(
            "SELECT value FROM meta WHERE key='version'").fetchone()[0]

    def _bump(self):
        self.db.execute(
            "UPDATE meta SET value=value+1 WHERE key='version'")

    @staticmethod
    def _principal_key(principal):
        return artifacts.canonical_bytes(
            {'hostId': principal.host_id, 'identity': principal.identity,
             'role': principal.role}).decode('utf-8')

    def _request_replay(self, principal, action, request):
        row = self.db.execute(
            'SELECT principal, action, payload, receipt FROM requests'
            ' WHERE request_id=?', (request['requestId'],)).fetchone()
        if row is None:
            return None
        if (row[0], row[1], row[2]) != (
                self._principal_key(principal), action,
                artifacts.canonical_bytes(request).decode('utf-8')):
            raise RegistryError('request-conflict', 409)
        return json.loads(row[3])

    def _record_request(self, principal, action, request, receipt):
        self.db.execute(
            'INSERT INTO requests(request_id, principal, action, payload,'
            ' receipt) VALUES(?,?,?,?,?)',
            (request['requestId'], self._principal_key(principal), action,
             artifacts.canonical_bytes(request).decode('utf-8'),
             artifacts.canonical_bytes(receipt).decode('utf-8')))

    def _commit(self):
        try:
            self.db.execute('COMMIT')
        except BaseException:
            try:
                self.db.execute('ROLLBACK')
            except sqlite3.Error:
                pass
            raise

    def _rollback(self):
        try:
            self.db.execute('ROLLBACK')
        except sqlite3.Error:
            pass

    def _fresh(self, observation, host_id, now, mono):
        if observation is None:
            return False
        payload_raw, session_id, epoch, _, received_mono = observation
        if epoch != self.epoch:
            return False
        session = self.db.execute(
            'SELECT session_id FROM sessions WHERE host_id=?',
            (host_id,)).fetchone()
        if session is None or session[0] != session_id:
            return False
        payload = json.loads(payload_raw)
        if not 0 <= now - payload['observedAt'] <= _OBSERVATION_MAX_AGE:
            return False
        if not 0 <= mono - received_mono <= _OBSERVATION_MAX_AGE:
            return False
        return True

    def _retired_drained(self, observation, host_id, now, mono):
        if not self._fresh(observation, host_id, now, mono):
            return False
        payload = json.loads(observation[0])
        return payload['retired'] is True and payload['unitDrained'] is True \
            and payload['phase'] == 'stopped' \
            and payload['unitActiveState'] in ('inactive', 'failed')

    def _ready(self, observation, host_id, workload_id, now, mono,
               service_ids=None):
        if not self._fresh(observation, host_id, now, mono):
            return False
        payload = json.loads(observation[0])
        if payload['phase'] != 'running' \
                or payload['unitActiveState'] != 'active' \
                or payload['unitDrained'] is not False \
                or payload['retired'] is not False:
            return False
        needed = self._route_services.get(workload_id, set()) \
            if service_ids is None else service_ids
        return needed <= set(payload['readyServices'])

    def _executable(self, definition):
        if definition['category'] in ('archive', 'infrastructure'):
            raise RegistryError('workload-not-mutable', 409)
        if 'start' not in definition['allowedOperations']:
            raise RegistryError('operation-not-allowed', 409)
        if definition['secretSetRef'] is not None:
            raise RegistryError('secret-provisioning-unavailable', 409)

    def _dependencies_ready(self, workload_id, revision_digest,
                            now, mono):
        """Dependency readiness enforced at commit points: every
        declared direct dependency of the workload's sealed revision
        must have a current placement carrying fresh ready evidence —
        the same /v2/state view the controller verifies at plan time —
        checked atomically here so a dependency lost between the
        controller's check and this write cannot slip through."""
        definition = self._definitions.get(
            (workload_id, revision_digest))
        if definition is None:
            return
        for dep_id in definition['dependencies']:
            dep_placement = self._placement(dep_id)
            if dep_placement is None:
                raise RegistryError('dependency-not-placed', 409)
            dep_instance = self._instance(dep_placement[1])
            if dep_instance is None or not self._ready(
                    self._observation_row(dep_placement[1]),
                    dep_instance[2], dep_id, now, mono):
                raise RegistryError('dependency-not-ready', 409)

    def _observation_row(self, instance_id):
        return self.db.execute(
            'SELECT payload, session_id, epoch, received_at, received_mono'
            ' FROM observations WHERE instance_id=?',
            (instance_id,)).fetchone()

    def _placement(self, workload_id):
        return self.db.execute(
            'SELECT generation, instance_id, published FROM placements'
            ' WHERE workload_id=?', (workload_id,)).fetchone()

    def _instance(self, instance_id):
        return self.db.execute(
            'SELECT workload_id, revision_digest, host_id, generation'
            ' FROM instances WHERE instance_id=?', (instance_id,)).fetchone()

    def open_session(self, principal, request):
        with self._mutex:
            self._principal(principal, ('host',))
            _check(worker._fields, request, {'schemaVersion', 'hostId'},
                   'request')
            _check(worker._integer, request['schemaVersion'], 2, 2,
                   'schemaVersion')
            _check(worker._identifier, request['hostId'], 'hostId')
            self._own_host(principal, request['hostId'])
            session_id = secrets.token_hex(16)
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self.db.execute(
                    'INSERT INTO sessions(host_id, session_id, epoch,'
                    ' sequence) VALUES(?,?,?,0)'
                    ' ON CONFLICT(host_id) DO UPDATE SET'
                    ' session_id=excluded.session_id, epoch=excluded.epoch,'
                    ' sequence=0',
                    (request['hostId'], session_id, self.epoch))
                self._bump()
                self._commit()
            except BaseException:
                self._rollback()
                raise
            return {'schemaVersion': 2, 'hostId': request['hostId'],
                    'sessionId': session_id, 'registryEpoch': self.epoch}

    def observe(self, principal, request):
        with self._mutex:
            self._principal(principal, ('host',))
            now = self._now()
            mono = self._mono()
            req = _validate_observation(request, now)
            self._own_host(principal, req['hostId'])
            host = self._hosts[req['hostId']]
            if req['endpointAddress'] not in host['addresses']:
                raise RegistryError('invalid-endpointAddress')
            record = self._instance(req['instanceId'])
            if record is None or (req['workloadId'], req['revisionDigest'],
                                  req['hostId'], req['generation']) \
                    != tuple(record):
                raise RegistryError('instance-mismatch', 403)
            definition = self._definitions[(record[0], record[1])]
            service_ids = {s['id'] for s in definition['services']}
            if any(s not in service_ids for s in req['readyServices']):
                raise RegistryError('invalid-readyServices')
            session = self.db.execute(
                'SELECT session_id, epoch, sequence FROM sessions'
                ' WHERE host_id=?', (req['hostId'],)).fetchone()
            if session is None or session[0] != req['sessionId'] \
                    or session[1] != self.epoch:
                raise RegistryError('session-mismatch', 403)
            if req['sequence'] <= session[2]:
                raise RegistryError('sequence-conflict', 409)
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self.db.execute(
                    'UPDATE sessions SET sequence=? WHERE host_id=?',
                    (req['sequence'], req['hostId']))
                self.db.execute(
                    'INSERT OR REPLACE INTO observations(instance_id,'
                    ' payload, session_id, epoch, received_at, received_mono)'
                    ' VALUES(?,?,?,?,?,?)',
                    (req['instanceId'],
                     artifacts.canonical_bytes(req).decode('utf-8'),
                     req['sessionId'], self.epoch, now, mono))
                self._bump()
                self._commit()
            except BaseException:
                self._rollback()
                raise
            return {'schemaVersion': 2, 'status': 'accepted',
                    'instanceId': req['instanceId'],
                    'sequence': req['sequence']}

    def assign(self, principal, request):
        with self._mutex:
            self._principal(principal, ('controller',))
            req = _validate_assign(request)
            now = self._now()
            mono = self._mono()
            self.db.execute('BEGIN IMMEDIATE')
            try:
                replay = self._request_replay(principal, 'assign', req)
                if replay is not None:
                    self._commit()
                    return replay
                definition = self._definitions.get(
                    (req['workloadId'], req['revisionDigest']))
                if definition is None:
                    raise RegistryError('unknown-workload', 404)
                self._executable(definition)
                host = self._hosts.get(req['hostId'])
                if host is None:
                    raise RegistryError('unknown-host', 404)
                if definition['architecture'] != host['architecture']:
                    raise RegistryError('architecture-mismatch', 409)
                placement = self._placement(req['workloadId'])
                current = placement[0] if placement is not None else 0
                if current != req['expectedGeneration']:
                    raise RegistryError('generation-conflict', 409)
                if placement is not None:
                    old = self._instance(placement[1])
                    observation = self._observation_row(placement[1])
                    if not self._retired_drained(
                            observation, old[2] if old else None,
                            now, mono) and not self._fenced(
                            req['workloadId'], current,
                            old[2] if old else None):
                        raise RegistryError('retirement-required', 409)
                self._dependencies_ready(
                    req['workloadId'], req['revisionDigest'], now, mono)
                if self._instance(req['instanceId']) is not None:
                    raise RegistryError('instance-conflict', 409)
                generation = current + 1
                self.db.execute(
                    'INSERT INTO instances(instance_id, workload_id,'
                    ' revision_digest, host_id, generation)'
                    ' VALUES(?,?,?,?,?)',
                    (req['instanceId'], req['workloadId'],
                     req['revisionDigest'], req['hostId'], generation))
                self.db.execute(
                    'INSERT INTO placements(workload_id, generation,'
                    ' instance_id, published) VALUES(?,?,?,0)'
                    ' ON CONFLICT(workload_id) DO UPDATE SET'
                    ' generation=excluded.generation,'
                    ' instance_id=excluded.instance_id, published=0',
                    (req['workloadId'], generation, req['instanceId']))
                receipt = {'schemaVersion': 2, 'status': 'completed',
                           'requestId': req['requestId'], 'action': 'assign',
                           'workloadId': req['workloadId'],
                           'generation': generation}
                self._record_request(principal, 'assign', req, receipt)
                self._bump()
                self._commit()
            except BaseException:
                self._rollback()
                raise
            return receipt

    def _publish_withdraw(self, principal, request, action):
        with self._mutex:
            self._principal(principal, ('controller',))
            req = _validate_placement_request(request)
            now = self._now()
            mono = self._mono()
            self.db.execute('BEGIN IMMEDIATE')
            try:
                replay = self._request_replay(principal, action, req)
                if replay is not None:
                    self._commit()
                    return replay
                if req['workloadId'] not in self._revisions:
                    raise RegistryError('unknown-workload', 404)
                placement = self._placement(req['workloadId'])
                current = placement[0] if placement is not None else 0
                if placement is None or req['expectedGeneration'] != current:
                    raise RegistryError('generation-conflict', 409)
                if action == 'publish':
                    instance = self._instance(placement[1])
                    observation = self._observation_row(placement[1])
                    if not self._ready(observation, instance[2],
                                       req['workloadId'], now, mono):
                        raise RegistryError('readiness-required', 409)
                    self._dependencies_ready(
                        req['workloadId'], instance[1], now, mono)
                    self.db.execute(
                        'UPDATE placements SET published=1'
                        ' WHERE workload_id=?', (req['workloadId'],))
                else:
                    self.db.execute(
                        'UPDATE placements SET published=0'
                        ' WHERE workload_id=?', (req['workloadId'],))
                receipt = {'schemaVersion': 2, 'status': 'completed',
                           'requestId': req['requestId'], 'action': action,
                           'workloadId': req['workloadId'],
                           'generation': current}
                self._record_request(principal, action, req, receipt)
                self._bump()
                self._commit()
            except BaseException:
                self._rollback()
                raise
            return receipt

    def publish(self, principal, request):
        return self._publish_withdraw(principal, request, 'publish')

    def withdraw(self, principal, request):
        return self._publish_withdraw(principal, request, 'withdraw')

    def _fenced(self, workload_id, generation, host_id):
        """True when a committed fence record covers exactly this
        incumbent (workloadId, generation, hostId). A fence never marks
        an observed-live instance dead — it only substitutes for the
        retired+drained self-report a dead host can never post."""
        if host_id is None:
            return False
        return self.db.execute(
            'SELECT 1 FROM fences WHERE workload_id=? AND generation=?'
            ' AND host_id=?',
            (workload_id, generation, host_id)).fetchone() is not None

    def fence(self, principal, request):
        """Controller-only durable fence attestation (M8).

        Commits a fence record bound to the CURRENT placement's
        (workloadId, generation) and the host holding it — the evidence
        a future authorized failover component (or an operator) posts
        before assigning a successor when the incumbent host is dead or
        partitioned and can never self-report retirement. The record is
        idempotent on requestId and survives restart; it is a permanent
        tombstone once the generation advances. A second, identical
        attestation for the same scope under a new requestId is accepted
        and recorded; a differing hostId/evidence for the same scope is
        a conflict. Nothing posts this record automatically — there is
        no automatic failover trigger in Nexus."""
        with self._mutex:
            self._principal(principal, ('controller',))
            req = _validate_fence(request)
            now = self._now()
            self.db.execute('BEGIN IMMEDIATE')
            try:
                replay = self._request_replay(principal, 'fence', req)
                if replay is not None:
                    self._commit()
                    return replay
                if req['workloadId'] not in self._revisions:
                    raise RegistryError('unknown-workload', 404)
                if req['hostId'] not in self._hosts:
                    raise RegistryError('unknown-host', 404)
                placement = self._placement(req['workloadId'])
                if placement is None \
                        or placement[0] != req['generation']:
                    raise RegistryError('generation-conflict', 409)
                instance = self._instance(placement[1])
                if instance is None or instance[2] != req['hostId']:
                    raise RegistryError('generation-conflict', 409)
                existing = self.db.execute(
                    'SELECT host_id, evidence FROM fences'
                    ' WHERE workload_id=? AND generation=?',
                    (req['workloadId'], req['generation'])).fetchone()
                if existing is not None:
                    if (existing[0], existing[1]) != (req['hostId'],
                                                    req['evidence']):
                        raise RegistryError('fence-conflict', 409)
                else:
                    self.db.execute(
                        'INSERT INTO fences(workload_id, generation,'
                        ' host_id, evidence, attester, request_id,'
                        ' recorded_at) VALUES(?,?,?,?,?,?,?)',
                        (req['workloadId'], req['generation'],
                         req['hostId'], req['evidence'],
                         principal.identity, req['requestId'], now))
                receipt = {'schemaVersion': 2, 'status': 'accepted',
                           'requestId': req['requestId'],
                           'workloadId': req['workloadId'],
                           'generation': req['generation'],
                           'hostId': req['hostId'],
                           'evidence': req['evidence']}
                self._record_request(principal, 'fence', req, receipt)
                self._bump()
                self._commit()
            except BaseException:
                self._rollback()
                raise
            return receipt

    def _fence_rows(self):
        return [{'workloadId': row[0], 'generation': row[1],
                 'hostId': row[2], 'evidence': row[3],
                 'attestedBy': row[4], 'requestId': row[5],
                 'recordedAt': row[6]}
                for row in self.db.execute(
                    'SELECT workload_id, generation, host_id, evidence,'
                    ' attester, request_id, recorded_at FROM fences'
                    ' ORDER BY workload_id, generation')]

    def assignments(self, principal):
        with self._mutex:
            self._principal(principal, ('host',))
            if principal.host_id is None:
                raise RegistryError('host-mismatch', 403)
            rows = self.db.execute(
                'SELECT instance_id, workload_id, revision_digest, host_id,'
                ' generation FROM instances WHERE host_id=?'
                ' ORDER BY generation, workload_id, instance_id',
                (principal.host_id,)).fetchall()
            return {'schemaVersion': 2, 'hostId': principal.host_id,
                    'instances': [
                        {'instanceId': row[0], 'workloadId': row[1],
                         'revisionDigest': row[2], 'hostId': row[3],
                         'generation': row[4]} for row in rows]}

    # -- operation dispatch queue (M5) -------------------------------------

    def post_operation(self, principal, request):
        """Controller-only enqueue. The operation binds to the CURRENT
        placement generation and to the host that holds it; replays on
        ``requestId`` return the recorded acceptance."""
        with self._mutex:
            self._principal(principal, ('controller',))
            req = _validate_operation(request)
            self.db.execute('BEGIN IMMEDIATE')
            try:
                replay = self._request_replay(principal, 'operation', req)
                if replay is not None:
                    self._commit()
                    return replay
                if req['workloadId'] not in self._revisions:
                    raise RegistryError('unknown-workload', 404)
                if req['hostId'] not in self._hosts:
                    raise RegistryError('unknown-host', 404)
                placement = self._placement(req['workloadId'])
                if placement is None \
                        or placement[0] != req['generation']:
                    raise RegistryError('generation-conflict', 409)
                instance = self._instance(placement[1])
                if instance is None or instance[2] != req['hostId']:
                    raise RegistryError('generation-conflict', 409)
                if self.db.execute(
                        'SELECT 1 FROM operations WHERE operation_id=?',
                        (req['operationId'],)).fetchone() is not None:
                    raise RegistryError('operation-conflict', 409)
                queued = self.db.execute(
                    "SELECT COUNT(*) FROM operations WHERE host_id=?"
                    " AND status IN ('pending','claimed')",
                    (req['hostId'],)).fetchone()[0]
                if queued >= _OPERATION_PENDING_MAX:
                    raise RegistryError('operation-queue-full', 409)
                self.db.execute(
                    "UPDATE meta SET value=value+1"
                    " WHERE key='operationSequence'")
                seq = self.db.execute(
                    "SELECT value FROM meta"
                    " WHERE key='operationSequence'").fetchone()[0]
                self.db.execute(
                    'INSERT INTO operations(operation_id, seq, host_id,'
                    ' workload_id, generation, step, payload, request_id,'
                    ' principal, status) VALUES(?,?,?,?,?,?,?,?,?,?)',
                    (req['operationId'], seq, req['hostId'],
                     req['workloadId'], req['generation'], req['step'],
                     artifacts.canonical_bytes(req['payload']).decode(
                         'utf-8'),
                     req['requestId'], self._principal_key(principal),
                     'pending'))
                receipt = {'schemaVersion': 2, 'status': 'accepted',
                           'requestId': req['requestId'],
                           'operationId': req['operationId'], 'seq': seq}
                self._record_request(principal, 'operation', req, receipt)
                self._bump()
                self._commit()
            except BaseException:
                self._rollback()
                raise
            return receipt

    def poll_operations(self, principal, host_id, after):
        """Host-only pull: pending operations addressed to the caller's
        own host, in durable sequence order, strictly after ``after``."""
        with self._mutex:
            self._principal(principal, ('host',))
            _check(worker._identifier, host_id, 'host')
            self._own_host(principal, host_id)
            _check(worker._integer, after, 0, _MAX_I64, 'after')
            rows = self.db.execute(
                "SELECT seq, operation_id, workload_id, generation, step,"
                " payload FROM operations WHERE host_id=? AND"
                " status='pending' AND seq>? ORDER BY seq LIMIT ?",
                (host_id, after, _OPERATION_POLL_MAX)).fetchall()
            return {'schemaVersion': 2, 'hostId': host_id,
                    'operations': [
                        {'seq': row[0], 'operationId': row[1],
                         'workloadId': row[2], 'generation': row[3],
                         'step': row[4], 'payload': json.loads(row[5])}
                        for row in rows]}

    def operation_receipt(self, principal, operation_id, request):
        """Host-only receipt write. Exactly-once per transition:
        pending -> claimed (first claim wins) -> completed|failed.
        Identical replays of a recorded receipt are accepted; conflicts
        are rejected."""
        with self._mutex:
            self._principal(principal, ('host',))
            _check(worker._hex32, operation_id, 'operationId')
            req = _validate_receipt(request)
            body = artifacts.canonical_bytes(req).decode('utf-8')
            response = {'schemaVersion': 2, 'status': 'accepted',
                        'operationId': operation_id,
                        'receipt': req['status']}
            self.db.execute('BEGIN IMMEDIATE')
            try:
                row = self.db.execute(
                    'SELECT host_id, status, claim_request_id, claim_body,'
                    ' final_request_id, final_body FROM operations'
                    ' WHERE operation_id=?', (operation_id,)).fetchone()
                if row is None:
                    raise RegistryError('unknown-operation', 404)
                self._own_host(principal, row[0])
                if req['status'] == 'claimed':
                    if row[1] == 'pending':
                        self.db.execute(
                            "UPDATE operations SET status='claimed',"
                            ' claim_request_id=?, claim_body=?'
                            ' WHERE operation_id=?',
                            (req['requestId'], body, operation_id))
                        self._bump()
                        self._commit()
                        return response
                    if row[2] == req['requestId'] and row[3] == body:
                        self._commit()
                        return response
                    raise RegistryError('receipt-conflict', 409)
                if row[1] == 'pending':
                    raise RegistryError('operation-not-claimed', 409)
                if row[4] == req['requestId'] and row[5] == body:
                    self._commit()
                    return response
                if row[1] == 'claimed' and row[4] is None:
                    self.db.execute(
                        'UPDATE operations SET status=?,'
                        ' final_request_id=?, final_body=?'
                        ' WHERE operation_id=?',
                        (req['status'], req['requestId'], body,
                         operation_id))
                    self._bump()
                    self._commit()
                    return response
                raise RegistryError('receipt-conflict', 409)
            except BaseException:
                self._rollback()
                raise

    def operation_status(self, principal, operation_id, request_id):
        """Controller-only read of one operation it posted. The stored
        ``requestId`` and posting principal must both match."""
        with self._mutex:
            self._principal(principal, ('controller',))
            _check(worker._hex32, operation_id, 'operationId')
            _check(worker._hex32, request_id, 'requestId')
            row = self.db.execute(
                'SELECT request_id, principal, workload_id, host_id,'
                ' generation, step, status, final_body FROM operations'
                ' WHERE operation_id=?', (operation_id,)).fetchone()
            if row is None:
                raise RegistryError('unknown-operation', 404)
            if row[0] != request_id \
                    or row[1] != self._principal_key(principal):
                raise RegistryError('forbidden', 403)
            view = {'schemaVersion': 2, 'operationId': operation_id,
                    'requestId': request_id, 'workloadId': row[2],
                    'hostId': row[3], 'generation': row[4],
                    'step': row[5], 'status': row[6]}
            if row[6] in ('completed', 'failed'):
                final = json.loads(row[7])
                if row[6] == 'completed':
                    view['result'] = final['result']
                else:
                    view['errorCode'] = final['errorCode']
            return view

    def _observed_state(self, observation, host_id, now, mono):
        if observation is None:
            return 'unknown', None
        payload = json.loads(observation[0])
        view = dict(payload, receivedAt=observation[3])
        wall_age = now - payload['observedAt']
        if wall_age < 0:
            return 'unknown', view
        if not self._fresh(observation, host_id, now, mono):
            return ('lost' if wall_age >= _LOST_AFTER else 'stale'), view
        unit = payload['unitActiveState']
        drained = payload['unitDrained']
        phase = payload['phase']
        quiet = drained is True and unit in ('inactive', 'failed')
        if unit == 'unknown':
            state = 'unknown'
        elif payload['retired'] is True:
            state = 'retired' if quiet else 'unknown'
        elif phase == 'running':
            state = 'running' if unit == 'active' and drained is False \
                else 'unknown'
        elif phase == 'stopped':
            state = 'stopped' if quiet else 'unknown'
        elif phase in ('preparing', 'prepared'):
            state = phase if quiet else 'unknown'
        elif phase == 'starting':
            state = 'starting' if quiet \
                or unit in ('activating', 'active') else 'unknown'
        elif phase == 'stopping':
            state = 'stopping' if quiet or unit in (
                'active', 'activating', 'deactivating') else 'unknown'
        else:
            state = 'unknown'
        return state, view

    def state(self, principal):
        with self._mutex:
            self._principal(principal, ('reader', 'controller'))
            now = self._now()
            mono = self._mono()
            workloads = []
            for workload_id in sorted(self._revisions):
                placement = self._placement(workload_id)
                if placement is None:
                    workloads.append({
                        'workloadId': workload_id, 'generation': 0,
                        'instanceId': None, 'hostId': None,
                        'revisionDigest': None, 'published': False,
                        'observedState': 'unknown', 'observation': None})
                    continue
                instance = self._instance(placement[1])
                observation = self._observation_row(placement[1])
                observed_state, view = self._observed_state(
                    observation, instance[2], now, mono)
                workloads.append({
                    'workloadId': workload_id, 'generation': placement[0],
                    'instanceId': placement[1], 'hostId': instance[2],
                    'revisionDigest': instance[1],
                    'published': bool(placement[2]),
                    'observedState': observed_state, 'observation': view})
            return {'schemaVersion': 2, 'registryEpoch': self.epoch,
                    'version': self._version(), 'workloads': workloads,
                    'fences': self._fence_rows()}

    def routes(self, principal, nonce):
        with self._mutex:
            self._principal(principal, ('ingress', 'controller'))
            _check(worker._hex32, nonce, 'nonce')
            now = self._now()
            mono = self._mono()
            expiries = [now + _ROUTE_TTL]
            routes = []
            for route in sorted(self._routes, key=lambda r: r['id']):
                backend = None
                placement = self._placement(route['workloadId'])
                if placement is not None and placement[2]:
                    instance = self._instance(placement[1])
                    observation = self._observation_row(placement[1])
                    if self._ready(observation, instance[2],
                                   route['workloadId'], now, mono,
                                   service_ids={route['serviceId']}):
                        payload = json.loads(observation[0])
                        definition = self._definitions[
                            (route['workloadId'], instance[1])]
                        port = next(s['port'] for s in definition['services']
                                    if s['id'] == route['serviceId'])
                        backend = {
                            'instanceId': placement[1],
                            'generation': placement[0], 'hostId': instance[2],
                            'revisionDigest': instance[1],
                            'address': payload['endpointAddress'],
                            'port': port, 'protocol': 'http'}
                        expiries.append(min(
                            payload['observedAt'] + _OBSERVATION_MAX_AGE,
                            now + max(0.0, _OBSERVATION_MAX_AGE
                                      - (mono - observation[4]))))
                routes.append({'id': route['id'], 'hostname': route['hostname'],
                               'workloadId': route['workloadId'],
                               'serviceId': route['serviceId'],
                               'backend': backend})
            return {'schemaVersion': 2, 'registryEpoch': self.epoch,
                    'version': self._version(), 'nonce': nonce,
                    'generatedAt': now, 'validUntil': min(expiries),
                    'routes': routes}
