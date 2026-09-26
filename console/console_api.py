"""Read-only workload-first console surface (M6 view + plan/explain).

A separate listener from ``server.py`` (the authenticated v1 VM console):
that service owns browser sessions, CSRF, host-agent polling and its audit
database. This module is a strictly read-only workload view served on a
configurable loopback/private bind — there is no login, no session state,
no POST/PUT/DELETE verb and no mutation path of any kind. Moves are
rendered as explainable plan previews only; handing an accepted plan to a
controller is future work and deliberately absent here.

Evidence sources, all consumed read-only:

- ``catalogFile`` — sealed schemaVersion-2 definitions (console/catalog.py);
  either a bare list or a ``catalog.Catalog.document()`` record.
- ``manifestsFile`` — sealed recovery-point manifests replayed through
  ``recovery.catalog_from_manifests`` (never repository internals).
- ``policiesFile`` — ``workload-backup-policy`` records evaluated through
  ``policy.evaluate`` with evidence derived only from backup journals.
- ``registry`` — ``GET /v2/state``, ``GET /v2/assignments`` and
  ``GET /v2/routes`` over mutual TLS with a configured client identity
  (see registry_api.py; a ``reader`` identity is only authorized for
  ``/v2/state`` — the other endpoints are rendered as denied, not hidden).
- Per-host ``workers`` state directories — ``worker.db`` opened read-only
  (SQLite ``mode=ro``, no WAL creation, per-table LIMIT queries).
- ``backupStateDir``/``restoreStateDir`` — ``jobs/<id>.json`` journals
  re-read through this module's own bounded readers below; nothing here
  imports or mutates worker/backup/restore internals, and only journal
  identifiers, phases, timestamps and digest metadata are surfaced —
  never filesystem paths, request payloads or secret material.

Every page is server-rendered with ``html.escape`` on all interpolated
values, capped rows, and the shared security headers from common.py.
"""

import argparse
import html
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import ssl
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import catalog
import common
import policy
import recovery


class ConsoleError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


_MAX_FILE_BYTES = 16 * 1024 * 1024
_MAX_REGISTRY_BYTES = 8 * 1024 * 1024
_MAX_CONFIG_BYTES = 2 * 1024 * 1024
_MAX_JOBS = 256
_MAX_OPERATIONS = 200
_MAX_ROWS = 256
_OBSERVATION_FRESH_SECONDS = 30.0
_ADMISSION_MAX_AGE = 60.0
_HEX32_RE = re.compile(r'[0-9a-f]{32}')
_JOB_FILE_RE = re.compile(r'[0-9a-f]{32}\.json')
_ID_RE = re.compile(r'[a-z][a-z0-9-]{0,62}')
_ARCHITECTURES = {'x86_64-linux', 'aarch64-linux'}
_CONFIG_FIELDS = {'schemaVersion', 'listenAddress', 'port', 'catalogFile',
                  'manifestsFile', 'policiesFile', 'hosts', 'registry',
                  'workers', 'backupStateDir', 'restoreStateDir'}
_HOST_FIELDS = {'hostId', 'architecture', 'capabilities', 'evidenceFile'}
_REGISTRY_FIELDS = {'url', 'caFile', 'certFile', 'keyFile',
                    'timeoutSeconds'}
_WORKER_FIELDS = {'hostId', 'stateDir'}
_RESOURCE_KEYS = ('memoryMiB', 'cpuMillis', 'stateBytes')


# -- bounded strict JSON ----------------------------------------------------

def _reject_constant(value):
    raise ConsoleError('invalid-json')


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConsoleError('invalid-json')
        result[key] = value
    return result


def load_json(raw):
    try:
        return json.loads(raw, parse_constant=_reject_constant,
                          object_pairs_hook=_no_duplicate_keys)
    except ConsoleError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise ConsoleError('invalid-json') from None


def read_json_file(path, limit=_MAX_FILE_BYTES):
    """Bounded read-only JSON document read; never writes, never follows
    a symlinked leaf. This is the console's only file read path."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with os.fdopen(fd, 'rb') as handle:
            data = handle.read(limit + 1)
    except OSError:
        raise ConsoleError('unavailable') from None
    if not data or len(data) > limit:
        raise ConsoleError('invalid-json')
    return load_json(data)


def _identifier(value):
    try:
        catalog.identifier(value, 'identifier')
    except catalog.CatalogError:
        raise ConsoleError('invalid-identifier') from None


def _abs_path(value, context):
    if type(value) is not str or not value.startswith('/') \
            or '\x00' in value:
        raise ConsoleError('invalid-' + context)
    return value


# -- configuration ----------------------------------------------------------

def _bind_address(value):
    """The console is a read-only evidence view with no browser auth of
    its own; it must never bind a public, unspecified or multicast
    address."""
    if type(value) is not str:
        raise ConsoleError('invalid-listenAddress')
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        raise ConsoleError('invalid-listenAddress') from None
    if str(parsed) != value or parsed.is_unspecified \
            or parsed.is_multicast or parsed.is_global:
        raise ConsoleError('invalid-listenAddress')
    return value


def _host_entry(value):
    if type(value) is not dict or not _HOST_FIELDS >= set(value) \
            or not {'hostId', 'architecture', 'capabilities'} <= set(value):
        raise ConsoleError('invalid-hosts')
    _identifier(value['hostId'])
    if value['architecture'] not in _ARCHITECTURES:
        raise ConsoleError('invalid-hosts')
    capabilities = value['capabilities']
    if type(capabilities) is not list or len(capabilities) > 64 \
            or len(set(capabilities)) != len(capabilities):
        raise ConsoleError('invalid-hosts')
    for capability in capabilities:
        _identifier(capability)
    entry = {'hostId': value['hostId'],
             'architecture': value['architecture'],
             'capabilities': list(capabilities),
             'evidenceFile': None}
    if 'evidenceFile' in value:
        entry['evidenceFile'] = _abs_path(value['evidenceFile'],
                                          'evidenceFile')
    return entry


def validate_config(config):
    # Required keys must all be present; only known optional keys may
    # appear alongside them.
    required = {'schemaVersion', 'listenAddress', 'port', 'catalogFile'}
    if type(config) is not dict or not required <= set(config) \
            or not set(config) <= _CONFIG_FIELDS:
        raise ConsoleError('invalid-config')
    if type(config['schemaVersion']) is not int \
            or config['schemaVersion'] != 1:
        raise ConsoleError('invalid-config')
    listen = _bind_address(config['listenAddress'])
    # Port 0 is an ephemeral bind and useful for tests.
    if type(config['port']) is not int \
            or not 0 <= config['port'] <= 65535:
        raise ConsoleError('invalid-config')
    out = {'schemaVersion': 1, 'listenAddress': listen,
           'port': config['port'],
           'catalogFile': _abs_path(config['catalogFile'], 'catalogFile'),
           'manifestsFile': None, 'policiesFile': None,
           'hosts': {}, 'registry': None, 'workers': {},
           'backupStateDir': None, 'restoreStateDir': None}
    for key in ('manifestsFile', 'policiesFile'):
        if key in config:
            out[key] = _abs_path(config[key], key)
    for key in ('backupStateDir', 'restoreStateDir'):
        if key in config:
            out[key] = _abs_path(config[key], key)
    hosts = config.get('hosts')
    if hosts is not None:
        if type(hosts) is not list or len(hosts) > 256:
            raise ConsoleError('invalid-hosts')
        for host in hosts:
            entry = _host_entry(host)
            if entry['hostId'] in out['hosts']:
                raise ConsoleError('invalid-hosts')
            out['hosts'][entry['hostId']] = entry
    workers = config.get('workers')
    if workers is not None:
        if type(workers) is not list or len(workers) > 256:
            raise ConsoleError('invalid-workers')
        for record in workers:
            if type(record) is not dict or set(record) != _WORKER_FIELDS:
                raise ConsoleError('invalid-workers')
            _identifier(record['hostId'])
            if record['hostId'] in out['workers']:
                raise ConsoleError('invalid-workers')
            out['workers'][record['hostId']] = _abs_path(
                record['stateDir'], 'stateDir')
    registry = config.get('registry')
    if registry is not None:
        if type(registry) is not dict or set(registry) != _REGISTRY_FIELDS:
            raise ConsoleError('invalid-registry')
        url = registry['url']
        if type(url) is not str:
            raise ConsoleError('invalid-registry')
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != 'https' or not parsed.hostname \
                or parsed.username or parsed.password \
                or parsed.path not in ('', '/') or parsed.query \
                or parsed.fragment:
            raise ConsoleError('invalid-registry')
        timeout = registry['timeoutSeconds']
        if type(timeout) not in (int, float) or isinstance(timeout, bool) \
                or not 0.5 <= timeout <= 10:
            raise ConsoleError('invalid-registry')
        out['registry'] = {
            'url': 'https://' + parsed.netloc,
            'caFile': _abs_path(registry['caFile'], 'caFile'),
            'certFile': _abs_path(registry['certFile'], 'certFile'),
            'keyFile': _abs_path(registry['keyFile'], 'keyFile'),
            'timeoutSeconds': timeout}
    return out


# -- registry mTLS reader ----------------------------------------------------

class RegistryReader:
    """Minimal GET client for the registry v2 surface over mutual TLS.

    Identity comes only from the configured certificate, exactly like
    registry_api.py's server-side mapping. Responses are bounded and
    strictly parsed; failures are returned as data, never raised."""

    def __init__(self, config):
        self._base = config['url']
        self._timeout = config['timeoutSeconds']
        context = ssl.create_default_context(cafile=config['caFile'])
        context.load_cert_chain(config['certFile'], config['keyFile'])
        self._context = context

    def get(self, path, nonce=None):
        request = urllib.request.Request(self._base + path)
        if nonce is not None:
            request.add_header('X-Nexus-Nonce', nonce)
        try:
            with urllib.request.urlopen(request, context=self._context,
                                        timeout=self._timeout) as response:
                if response.status != 200:
                    return {'available': False, 'error': 'unexpected-status'}
                raw = response.read(_MAX_REGISTRY_BYTES + 1)
        except urllib.error.HTTPError as error:
            code = 'denied' if error.code == 403 else \
                'http-%d' % error.code
            try:
                error.close()
            except (AttributeError, OSError):
                pass
            return {'available': False, 'error': code}
        except (OSError, ValueError):
            return {'available': False, 'error': 'unavailable'}
        if len(raw) > _MAX_REGISTRY_BYTES:
            return {'available': False, 'error': 'response-too-large'}
        try:
            value = load_json(raw)
        except ConsoleError:
            return {'available': False, 'error': 'invalid-response'}
        if type(value) is not dict:
            return {'available': False, 'error': 'invalid-response'}
        return {'available': True, 'data': value}


def _registry_snapshot(reader):
    """Fetch the three read endpoints; a reader identity is legitimately
    denied assignments/routes, so per-endpoint status is kept."""
    out = {}
    for name, path, nonce in (
            ('state', '/v2/state', None),
            ('assignments', '/v2/assignments', None),
            ('routes', '/v2/routes', secrets.token_hex(16))):
        if reader is None:
            out[name] = {'available': False, 'error': 'not-configured'}
        else:
            out[name] = reader.get(path, nonce=nonce)
    return out


# -- journal readers (read-only, this module's own documented read paths) ---

def read_worker_journal(state_dir):
    """Read-only projection of ``<stateDir>/worker.db``.

    The database is opened through SQLite ``mode=ro`` — no write, no WAL
    or shm file creation. Only identity/phase/status columns are read;
    ``binding_json`` (which carries slot addresses and storage paths) is
    deliberately not selected."""
    result = {'available': False, 'error': None, 'generations': {},
              'instances': [], 'operations': [], 'captures': []}
    db_path = os.path.join(state_dir, 'worker.db')
    try:
        st = os.lstat(db_path)
    except FileNotFoundError:
        result['error'] = 'missing'
        return result
    except OSError:
        result['error'] = 'unavailable'
        return result
    if not stat.S_ISREG(st.st_mode):
        result['error'] = 'unavailable'
        return result
    connection = None
    try:
        connection = sqlite3.connect(
            'file:' + urllib.parse.quote(db_path) + '?mode=ro', uri=True)
        for workload_id, generation in connection.execute(
                'SELECT workload_id, generation FROM generations'
                ' LIMIT 1024'):
            result['generations'][workload_id] = generation
        result['instances'] = [
            {'instanceId': row[0], 'workloadId': row[1],
             'revisionDigest': row[2], 'generation': row[3],
             'slotId': row[4], 'machineName': row[5], 'phase': row[6],
             'retired': bool(row[7])}
            for row in connection.execute(
                'SELECT instance_id, workload_id, revision_digest,'
                ' generation, slot_id, machine_name, phase, retired'
                ' FROM instances ORDER BY workload_id, generation'
                ' LIMIT 1024')]
        operations = []
        for row in connection.execute(
                'SELECT operation_id, request, status FROM operations'
                ' ORDER BY rowid DESC LIMIT ?', (_MAX_OPERATIONS,)):
            entry = {'operationId': row[0], 'status': row[2]}
            try:
                request = load_json(row[1].encode()
                                    if type(row[1]) is str else row[1])
            except ConsoleError:
                request = None
            if type(request) is dict:
                for key in ('action', 'workloadId', 'instanceId',
                            'generation', 'captureId'):
                    if key in request:
                        entry[key] = request[key]
            operations.append(entry)
        result['operations'] = operations
        result['captures'] = [
            {'captureId': row[0], 'instanceId': row[1],
             'workloadId': row[2], 'generation': row[3], 'status': row[4]}
            for row in connection.execute(
                'SELECT capture_id, instance_id, workload_id, generation,'
                ' status FROM captures LIMIT 1024')]
        result['available'] = True
    except sqlite3.Error:
        result['error'] = 'unavailable'
        result['instances'], result['operations'] = [], []
        result['captures'], result['generations'] = [], {}
    finally:
        if connection is not None:
            connection.close()
    return result


def _job_summaries(state_dir, extract):
    """Bounded read-only scan of ``<stateDir>/jobs/*.json`` journals.

    Entries are summarized to identifiers, phases, timestamps and digest
    metadata only. Malformed or unreadable files surface as ``invalid``
    markers; nothing is ever written."""
    result = {'available': False, 'error': None, 'jobs': []}
    jobs_dir = os.path.join(state_dir, 'jobs')
    try:
        names = sorted(os.listdir(jobs_dir))
    except FileNotFoundError:
        result['error'] = 'missing'
        return result
    except OSError:
        result['error'] = 'unavailable'
        return result
    for name in names:
        if len(result['jobs']) >= _MAX_JOBS:
            break
        if _JOB_FILE_RE.fullmatch(name) is None:
            continue
        try:
            value = read_json_file(os.path.join(jobs_dir, name),
                                   _MAX_FILE_BYTES)
            result['jobs'].append(extract(value))
        except (ConsoleError, OSError, KeyError, TypeError):
            result['jobs'].append({'id': name[:-5], 'invalid': True})
    result['available'] = True
    return result


def _copy_summary(entry):
    """Projection of one uploaded-copy journal record; repository and
    snapshot identifiers only."""
    record = entry['record']
    return {'repositoryId': record['repositoryId'],
            'snapshotId': record['snapshotId'],
            'verifiedAt': entry['verifiedAt'],
            'recoveryPointId': record['manifest']['recoveryPointId']}


def _backup_job(value):
    if type(value) is not dict or value.get('schemaVersion') != 1:
        raise ConsoleError('invalid-journal')
    request = value['request']
    capture = value['capture']
    cache = value.get('cache')
    copies = value.get('copies')
    if type(request) is not dict or type(capture) is not dict \
            or type(copies) is not dict \
            or value.get('phase') not in ('pending', 'captured'):
        raise ConsoleError('invalid-journal')
    summary = {'id': request['captureId'], 'phase': value['phase'],
               'workloadId': request['workloadId'],
               'instanceId': request['instanceId'],
               'generation': request['generation'],
               'captureStartedAt': capture['startedAt'],
               'captureCompletedAt': capture['completedAt'],
               'copies': [_copy_summary(copies[key])
                          for key in sorted(copies)]}
    if type(cache) is dict and type(cache.get('manifest')) is dict:
        summary['recoveryPointId'] = \
            cache['manifest']['recoveryPointId']
        summary['cacheSnapshotId'] = cache['snapshotId']
    else:
        summary['recoveryPointId'] = None
        summary['cacheSnapshotId'] = None
    return summary


def read_backup_jobs(state_dir):
    return _job_summaries(state_dir, _backup_job)


def _restore_job(value):
    if type(value) is not dict or value.get('schemaVersion') != 1 \
            or value.get('phase') not in ('pending', 'staged', 'committed'):
        raise ConsoleError('invalid-journal')
    request = value['request']
    record = value['record']
    target = request.get('target')
    if type(request) is not dict or type(target) is not dict \
            or type(record) is not dict \
            or type(record.get('manifest')) is not dict:
        raise ConsoleError('invalid-journal')
    return {'id': request['restoreId'], 'phase': value['phase'],
            'workloadId': target['workloadId'],
            'instanceId': target['instanceId'],
            'generation': target['generation'],
            'slotId': target['slotId'],
            'repositoryId': record['repositoryId'],
            'snapshotId': record['snapshotId'],
            'recoveryPointId': record['manifest']['recoveryPointId'],
            'stagedAt': value['stagedAt'],
            'committedAt': value['committedAt']}


def read_restore_jobs(state_dir):
    return _job_summaries(state_dir, _restore_job)


def _point_evidence(backup_jobs):
    """Caller-attested ``{verified, uploadedCopies}`` evidence per
    recovery point, derived only from durable upload journal records."""
    evidence = {}
    for job in backup_jobs:
        if job.get('invalid'):
            continue
        point_id = job['recoveryPointId']
        if point_id is None:
            continue
        entry = evidence.setdefault(
            point_id, {'uploadedCopies': 0, 'verified': True})
        entry['uploadedCopies'] += len(job['copies'])
        entry['verified'] = entry['verified'] and bool(job['copies']) \
            and all(copy['verifiedAt'] is not None
                    for copy in job['copies'])
    for point_id, entry in evidence.items():
        entry['uploadedCopies'] = min(entry['uploadedCopies'], 1024)
    return evidence


# -- snapshot ---------------------------------------------------------------

def _load_catalog(path):
    value = read_json_file(path)
    if type(value) is dict:
        if set(value) != {'schemaVersion', 'workloads'} \
                or value['schemaVersion'] != 2:
            raise ConsoleError('catalog-invalid')
        value = value['workloads']
    try:
        document = catalog.Catalog(value).document()
    except catalog.CatalogError:
        raise ConsoleError('catalog-invalid') from None
    return {record['workloadId']: record
            for record in document['workloads']}


def _load_manifests(path):
    if path is None:
        return []
    value = read_json_file(path)
    if type(value) is not list:
        raise ConsoleError('manifests-invalid')
    try:
        return recovery.catalog_from_manifests(value)
    except recovery.RecoveryError:
        raise ConsoleError('manifests-invalid') from None


def _load_policies(path):
    if path is None:
        return {}
    value = read_json_file(path)
    if type(value) is not list or len(value) > 1024:
        raise ConsoleError('policies-invalid')
    records = {}
    for entry in value:
        try:
            record = policy.validate_policy(entry)
        except policy.PolicyError:
            raise ConsoleError('policies-invalid') from None
        if record['workloadId'] in records:
            raise ConsoleError('policies-invalid')
        records[record['workloadId']] = record
    return records


def _load_evidence(host):
    """Optional host capacity observation for catalog.admit; an absent or
    unreadable file means ``observation-missing`` is rendered, not an
    error."""
    path = host['evidenceFile']
    if path is None:
        return None
    try:
        value = read_json_file(path)
    except (ConsoleError, OSError):
        return None
    if type(value) is not dict \
            or set(value) != {'schemaVersion', 'hostId', 'observedAt',
                              'available'} \
            or value.get('schemaVersion') != 2 \
            or value.get('hostId') != host['hostId']:
        return None
    available = value['available']
    if type(available) is not dict \
            or set(available) != set(_RESOURCE_KEYS) \
            or any(type(available[key]) is not int or available[key] < 0
                   for key in _RESOURCE_KEYS):
        return None
    if type(value['observedAt']) not in (int, float) \
            or isinstance(value['observedAt'], bool):
        return None
    return value


def collect(config, *, reader=None, now=None):
    """Gather every configured source into one immutable snapshot.

    A failed source degrades to an explicit status marker; it never
    aborts the view."""
    if now is None:
        now = time.time()
    snapshot = {'generatedAt': now, 'sources': {}, 'definitions': {},
                'manifests': [], 'policies': {}, 'hosts': {},
                'workers': {}, 'backupJobs': [], 'restoreJobs': [],
                'registry': _registry_snapshot(reader)}
    try:
        snapshot['definitions'] = _load_catalog(config['catalogFile'])
        snapshot['sources']['catalog'] = {'status': 'ok'}
    except (ConsoleError, OSError) as error:
        snapshot['sources']['catalog'] = {
            'status': 'error',
            'error': getattr(error, 'code', 'unavailable')}
    try:
        snapshot['manifests'] = _load_manifests(config['manifestsFile'])
        snapshot['sources']['manifests'] = {'status': 'ok'}
    except (ConsoleError, OSError) as error:
        snapshot['sources']['manifests'] = {
            'status': 'error',
            'error': getattr(error, 'code', 'unavailable')}
    try:
        snapshot['policies'] = _load_policies(config['policiesFile'])
        snapshot['sources']['policies'] = {'status': 'ok'}
    except (ConsoleError, OSError) as error:
        snapshot['sources']['policies'] = {
            'status': 'error',
            'error': getattr(error, 'code', 'unavailable')}
    for host_id, host in config['hosts'].items():
        evidence = _load_evidence(host)
        snapshot['hosts'][host_id] = {
            'hostId': host_id, 'architecture': host['architecture'],
            'capabilities': list(host['capabilities']),
            'evidence': evidence}
    for host_id, state_dir in config['workers'].items():
        snapshot['workers'][host_id] = read_worker_journal(state_dir)
        snapshot['hosts'].setdefault(host_id, {
            'hostId': host_id, 'architecture': None,
            'capabilities': [], 'evidence': None})
    if config['backupStateDir'] is not None:
        jobs = read_backup_jobs(config['backupStateDir'])
        snapshot['backupJobs'] = jobs['jobs']
        snapshot['sources']['backup'] = {
            'status': 'ok' if jobs['available'] else 'error',
            'error': jobs['error']}
    if config['restoreStateDir'] is not None:
        jobs = read_restore_jobs(config['restoreStateDir'])
        snapshot['restoreJobs'] = jobs['jobs']
        snapshot['sources']['restore'] = {
            'status': 'ok' if jobs['available'] else 'error',
            'error': jobs['error']}
    state = snapshot['registry']['state']
    if state['available']:
        for item in state['data'].get('workloads', []):
            host_id = item.get('hostId')
            if host_id is not None and host_id not in snapshot['hosts']:
                snapshot['hosts'][host_id] = {
                    'hostId': host_id, 'architecture': None,
                    'capabilities': [], 'evidence': None}
    return snapshot


# -- view models --------------------------------------------------------------

def _placements(snapshot):
    """workloadId -> current registry placement view, when available."""
    state = snapshot['registry']['state']
    placements = {}
    if state['available']:
        for item in state['data'].get('workloads', []):
            if type(item) is dict and type(item.get('workloadId')) is str:
                placements[item['workloadId']] = item
    return placements


def _requirements(definition):
    requirements = definition['requirements']
    return {key: requirements[key] for key in _RESOURCE_KEYS}


def _reservations(snapshot, host_id, exclude_workload=None):
    """Requirements already placed on ``host_id`` per registry state."""
    reserved = {key: 0 for key in _RESOURCE_KEYS}
    for workload_id, item in _placements(snapshot).items():
        if workload_id == exclude_workload or item.get('hostId') != host_id:
            continue
        definition = snapshot['definitions'].get(workload_id)
        if definition is None:
            continue
        for key, value in _requirements(definition).items():
            reserved[key] += value
    return reserved


def _admission(snapshot, definition, host_id, now, exclude=None):
    """catalog.admit against a configured host record; result carries an
    explicit status when the host or its evidence cannot be checked."""
    host = snapshot['hosts'].get(host_id)
    if host is None or host['architecture'] is None:
        return {'status': 'host-unconfigured', 'eligible': None,
                'reasons': []}
    record = {'schemaVersion': 2, 'hostId': host['hostId'],
              'architecture': host['architecture'],
              'capabilities': host['capabilities']}
    try:
        result = catalog.admit(
            definition, record, host['evidence'], now=now,
            reservations=_reservations(snapshot, host_id,
                                       exclude_workload=exclude),
            max_age_seconds=_ADMISSION_MAX_AGE)
    except catalog.CatalogError:
        return {'status': 'check-failed', 'eligible': None, 'reasons': []}
    result['status'] = 'checked'
    return result


def _evaluation(snapshot, workload_id, now):
    """policy.evaluate for one workload with journal-derived evidence;
    ``None`` when the workload has no configured policy record."""
    record = snapshot['policies'].get(workload_id)
    if record is None:
        return None
    manifests = [m for m in snapshot['manifests']
                 if m['definition']['workloadId'] == workload_id]
    evidence = _point_evidence(snapshot['backupJobs'])
    points = []
    for manifest in manifests:
        attached = evidence.get(manifest['recoveryPointId'])
        points.append({'manifest': manifest,
                       'record': dict(attached) if attached else None})
    last_completed = None
    for job in snapshot['backupJobs']:
        if job.get('invalid') or job['workloadId'] != workload_id:
            continue
        completed = job['captureCompletedAt']
        if type(completed) is int:
            last_completed = completed if last_completed is None \
                else max(last_completed, completed)
    try:
        return policy.evaluate(record, points, int(now),
                               last_capture_completed_at=last_completed)
    except policy.PolicyError:
        return {'error': 'evaluation-failed'}


def workload_rows(snapshot):
    """The workload list view model: identity, placement, evidence
    freshness, recovery-point status and admission on the current host."""
    now = snapshot['generatedAt']
    placements = _placements(snapshot)
    workload_ids = set(snapshot['definitions']) | set(placements)
    workload_ids |= {m['definition']['workloadId']
                     for m in snapshot['manifests']}
    rows = []
    for workload_id in sorted(workload_ids):
        definition = snapshot['definitions'].get(workload_id)
        placement = placements.get(workload_id, {})
        observation = placement.get('observation')
        observed_at = observation.get('observedAt') \
            if type(observation) is dict else None
        age = now - observed_at \
            if type(observed_at) in (int, float) else None
        evaluation = _evaluation(snapshot, workload_id, now)
        host_id = placement.get('hostId')
        admission = None
        if definition is not None and host_id is not None:
            admission = _admission(snapshot, definition, host_id, now,
                                   exclude=workload_id)
        rows.append({
            'workloadId': workload_id,
            'displayName': definition['displayName']
            if definition else workload_id,
            'category': definition['category'] if definition else None,
            'definitionKnown': definition is not None,
            'revisionDigest': definition['revisionDigest']
            if definition else placement.get('revisionDigest'),
            'hostId': host_id,
            'instanceId': placement.get('instanceId'),
            'generation': placement.get('generation', 0),
            'published': bool(placement.get('published')),
            'observedState': placement.get('observedState', 'unknown'),
            'observedAt': observed_at,
            'observationFresh': age is not None
                and 0 <= age <= _OBSERVATION_FRESH_SECONDS,
            'readyServices': observation.get('readyServices')
                if type(observation) is dict else None,
            'admission': admission,
            'evaluation': evaluation})
    return rows


def workload_detail(snapshot, workload_id):
    """Detail model: definition, recovery-point classifications and the
    known placement/instance history from registry plus worker journals."""
    now = snapshot['generatedAt']
    rows = {row['workloadId']: row for row in workload_rows(snapshot)}
    row = rows.get(workload_id)
    if row is None:
        return None
    definition = snapshot['definitions'].get(workload_id)
    evaluation = row['evaluation']
    classified = {}
    if type(evaluation) is dict and 'points' in evaluation:
        classified = {point['recoveryPointId']: point
                      for point in evaluation['points']}
    points = []
    for manifest in snapshot['manifests']:
        if manifest['definition']['workloadId'] != workload_id:
            continue
        entry = classified.get(manifest['recoveryPointId'], {})
        points.append({
            'recoveryPointId': manifest['recoveryPointId'],
            'schemaVersion': manifest['schemaVersion'],
            'sourceHostId': manifest['source']['hostId'],
            'instanceId': manifest['source']['instanceId'],
            'generation': manifest['source']['generation'],
            'captureStartedAt': manifest['capture']['startedAt'],
            'captureCompletedAt': manifest['capture']['completedAt'],
            'classification': entry.get('classification'),
            'reasons': entry.get('reasons', [])})
    instances = []
    for host_id, journal in sorted(snapshot['workers'].items()):
        for instance in journal['instances']:
            if instance['workloadId'] == workload_id:
                instances.append(dict(instance, hostId=host_id))
        for capture in journal['captures']:
            if capture['workloadId'] == workload_id:
                instances.append({'hostId': host_id, 'capture': capture})
    operations = []
    for host_id, journal in sorted(snapshot['workers'].items()):
        for operation in journal['operations']:
            if operation.get('workloadId') == workload_id:
                operations.append(dict(operation, hostId=host_id,
                                       source='worker'))
    for job in snapshot['backupJobs']:
        if not job.get('invalid') and job['workloadId'] == workload_id:
            operations.append({'source': 'backup', 'id': job['id'],
                               'phase': job['phase'],
                               'completedAt': job['captureCompletedAt']})
    for job in snapshot['restoreJobs']:
        if not job.get('invalid') and job['workloadId'] == workload_id:
            operations.append({'source': 'restore', 'id': job['id'],
                               'phase': job['phase'],
                               'committedAt': job['committedAt']})
    return {'row': row, 'definition': definition, 'points': points,
            'instances': instances, 'operations': operations,
            'stateMounts': definition['stateMounts'] if definition else [],
            'services': definition['services'] if definition else [],
            'allowedOperations': definition['allowedOperations']
                if definition else []}


def host_rows(snapshot):
    """Host view model: configured capabilities, capacity-evidence
    freshness, observed instances and worker-journal state."""
    now = snapshot['generatedAt']
    placements = _placements(snapshot)
    rows = []
    for host_id, host in sorted(snapshot['hosts'].items()):
        evidence = host['evidence']
        evidence_age = None
        if type(evidence) is dict:
            value = evidence['observedAt']
            if type(value) in (int, float):
                evidence_age = now - value
        observed = [item for item in placements.values()
                    if item.get('hostId') == host_id]
        freshest = None
        for item in observed:
            observation = item.get('observation')
            if type(observation) is dict:
                observed_at = observation.get('observedAt')
                if type(observed_at) in (int, float) and (
                        freshest is None or observed_at > freshest):
                    freshest = observed_at
        journal = snapshot['workers'].get(host_id)
        rows.append({
            'hostId': host_id,
            'architecture': host['architecture'],
            'capabilities': host['capabilities'],
            'configured': host['architecture'] is not None,
            'evidenceObservedAt': evidence['observedAt']
                if type(evidence) is dict else None,
            'evidenceFresh': evidence_age is not None
                and 0 <= evidence_age <= _ADMISSION_MAX_AGE,
            'available': evidence['available'] if evidence else None,
            'observedInstances': len(observed),
            'latestObservationAt': freshest,
            'journal': {'available': journal['available'],
                        'error': journal['error'],
                        'instances': len(journal['instances']),
                        'heldCaptures': sum(
                            1 for c in journal['captures']
                            if c['status'] == 'held')}
                if journal else None})
    return rows


def operations_rows(snapshot):
    """Operations view: worker receipts plus backup/restore job phases."""
    sections = []
    for host_id, journal in sorted(snapshot['workers'].items()):
        sections.append({
            'source': 'worker', 'hostId': host_id,
            'available': journal['available'], 'error': journal['error'],
            'operations': journal['operations'][:_MAX_ROWS]})
    sections.append({
        'source': 'backup', 'hostId': None,
        'available': True, 'error': None,
        'operations': [
            {'id': job.get('id'), 'workloadId': job.get('workloadId'),
             'phase': job.get('phase'), 'invalid': job.get('invalid'),
             'copies': len(job.get('copies') or []),
             'completedAt': job.get('captureCompletedAt')}
            for job in snapshot['backupJobs'][:_MAX_ROWS]]})
    sections.append({
        'source': 'restore', 'hostId': None,
        'available': True, 'error': None,
        'operations': [
            {'id': job.get('id'), 'workloadId': job.get('workloadId'),
             'phase': job.get('phase'), 'invalid': job.get('invalid'),
             'stagedAt': job.get('stagedAt'),
             'committedAt': job.get('committedAt')}
            for job in snapshot['restoreJobs'][:_MAX_ROWS]]})
    return sections


def move_check(snapshot, workload_id, host_id):
    """Explainable plan preview: every reason a workload cannot move to a
    host, layered by source. Executes nothing."""
    now = snapshot['generatedAt']
    reasons = []

    def blocker(code, source):
        reasons.append({'code': code, 'source': source,
                        'severity': 'blocker'})

    def warning(code, source):
        reasons.append({'code': code, 'source': source,
                        'severity': 'warning'})

    definition = snapshot['definitions'].get(workload_id)
    host = snapshot['hosts'].get(host_id)
    if definition is None:
        blocker('unknown-workload', 'catalog')
    else:
        if definition['category'] == 'archive':
            blocker('workload-archived', 'definition')
        if definition['category'] == 'infrastructure':
            blocker('workload-not-mutable', 'definition')
        for operation in ('move', 'start', 'stop', 'backup', 'restore'):
            if operation not in definition['allowedOperations']:
                blocker('operation-not-allowed:' + operation,
                        'definition')
        if definition['secretSetRef'] is not None:
            blocker('secret-provisioning-unavailable', 'definition')
        if definition['dependencies']:
            blocker('dependency-readiness-unavailable', 'definition')
    if host is None:
        blocker('unknown-host', 'catalog')
    if not snapshot['registry']['state']['available']:
        warning('registry-state-unavailable', 'placement')
    placement = _placements(snapshot).get(workload_id)
    if placement is not None and placement.get('hostId') is not None:
        if placement['hostId'] == host_id:
            blocker('already-on-target', 'placement')
        elif placement.get('observedState') != 'retired':
            blocker('retirement-required', 'placement')
    admission = None
    if definition is not None and host is not None \
            and host['architecture'] is not None:
        admission = _admission(snapshot, definition, host_id, now,
                               exclude=workload_id)
        if admission['status'] == 'checked':
            for reason in admission['reasons']:
                blocker(reason, 'admission')
        else:
            blocker(admission['status'], 'admission')
    elif definition is not None and host is not None:
        blocker('host-unconfigured', 'admission')
    if definition is not None and definition['stateMounts']:
        evaluation = _evaluation(snapshot, workload_id, now)
        protected = type(evaluation) is dict \
            and evaluation.get('freshestProtected')
        if not protected:
            warning('no-protected-recovery-point', 'protection')
    eligible = not any(r['severity'] == 'blocker' for r in reasons)
    return {'workloadId': workload_id, 'hostId': host_id,
            'checkedAt': now, 'eligible': eligible, 'reasons': reasons,
            'admission': admission}


# -- HTML rendering -----------------------------------------------------------

def esc(value):
    return html.escape('—' if value is None else str(value), quote=True)


_CSS = """
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#0c0f14;color:#dbe2ea;font-size:14px}
a{color:#7cb3ff;text-decoration:none}
a:hover{text-decoration:underline}
header{display:flex;gap:24px;align-items:center;padding:14px 28px;border-bottom:1px solid #232a35;background:#10141b}
header .brand{font-weight:700;letter-spacing:.12em}
nav{display:flex;gap:16px}
nav a{color:#9aa7b4}
nav a.active{color:#dbe2ea}
main{max-width:1180px;margin:0 auto;padding:28px}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:15px;margin:0 0 10px}
.sub{color:#8b96a2;margin:0 0 22px}
.panel{background:#12161d;border:1px solid #232a35;border-radius:10px;padding:18px;margin-bottom:18px}
table{width:100%;border-collapse:collapse}
th{text-align:left;color:#8b96a2;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em;padding:8px 10px;border-bottom:1px solid #232a35}
td{padding:9px 10px;border-bottom:1px solid #1a2029;vertical-align:top}
tr:last-child td{border-bottom:none}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;border:1px solid #2e3846;background:#1a212b;color:#b7c1cc}
.badge.ok{border-color:#2f6b45;background:#12271b;color:#7fd6a4}
.badge.warn{border-color:#7a5b22;background:#2a2110;color:#ecc76b}
.badge.bad{border-color:#7c3131;background:#2a1414;color:#f08b8b}
.mono,code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
.muted{color:#8b96a2}
.reasons{margin:4px 0 0;padding:0;list-style:none}
.reasons li{display:inline-block;margin:2px 4px 2px 0;padding:1px 8px;border-radius:6px;background:#241a2b;border:1px solid #463052;color:#d5aef0;font-size:12px}
.reasons li.warn{background:#2a2110;border-color:#7a5b22;color:#ecc76b}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:18px}
.kv{display:flex;justify-content:space-between;gap:12px;padding:5px 0;border-bottom:1px solid #1a2029}
.kv span:first-child{color:#8b96a2}
.note{color:#6f7a86;font-size:12px;margin-top:8px}
select,button{background:#1a212b;color:#dbe2ea;border:1px solid #2e3846;border-radius:6px;padding:6px 10px;font:inherit}
footer{color:#5d6874;font-size:12px;text-align:center;padding:22px}
"""


def _badge(text, tone=''):
    return '<span class="badge %s">%s</span>' % (tone, esc(text))


def _age(value, now):
    if type(value) not in (int, float):
        return '—'
    delta = now - value
    if delta < 0:
        return 'in future'
    if delta < 90:
        return '%ds ago' % delta
    if delta < 5400:
        return '%dm ago' % (delta // 60)
    if delta < 129600:
        return '%dh ago' % (delta // 3600)
    return '%dd ago' % (delta // 86400)


def _stamp(value):
    if type(value) not in (int, float):
        return '—'
    return time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(value))


def _digest(value):
    if type(value) is not str:
        return '—'
    if len(value) > 19:
        return '<code title="%s">%s…</code>' % (esc(value), esc(value[:19]))
    return '<code>%s</code>' % esc(value)


def _table(headers, rows):
    head = ''.join('<th>%s</th>' % esc(h) for h in headers)
    body = ''.join('<tr>%s</tr>' % ''.join('<td>%s</td>' % cell
                                           for cell in row)
                   for row in rows)
    if not rows:
        body = '<tr><td colspan="%d" class="muted">None recorded.</td></tr>' \
            % len(headers)
    return '<table><thead><tr>%s</tr></thead><tbody>%s</tbody></table>' \
        % (head, body)


def _page(title, body, generated_at):
    nav = ''.join('<a href="%s"%s>%s</a>'
                  % (href,
                     ' class="active"' if text == title.split(' ')[0]
                     else '', text)
                  for href, text in (
                      ('/workloads', 'Workloads'),
                      ('/hosts', 'Hosts'),
                      ('/operations', 'Operations')))
    html_doc = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,'
        ' initial-scale=1"><title>Nexus workloads · %s</title>'
        '<style>%s</style></head><body>'
        '<header><span class="brand">NEXUS</span><nav>%s</nav></header>'
        '<main>%s</main>'
        '<footer>Read-only workload view · generated %s · no mutations '
        'are possible from this surface</footer></body></html>'
        % (esc(title), _CSS, nav, body, esc(_stamp(generated_at))))
    return html_doc.encode('utf-8')


def _reason_list(reasons):
    items = ''.join(
        '<li%s>%s</li>'
        % (' class="warn"' if r.get('severity') == 'warning' else '',
           esc(r['code'] if type(r) is dict else r))
        for r in reasons)
    return '<ul class="reasons">%s</ul>' % items if items else ''


def _source_notes(snapshot):
    notes = []
    for name, source in sorted(snapshot['sources'].items()):
        if source['status'] != 'ok':
            notes.append('%s: %s' % (name, esc(source.get('error'))))
    for name, result in sorted(snapshot['registry'].items()):
        if not result['available']:
            notes.append('registry %s: %s' % (name, esc(result['error'])))
    if not notes:
        return ''
    return '<p class="note">Degraded sources — %s.</p>' % '; '.join(notes)


def workloads_page(snapshot):
    now = snapshot['generatedAt']
    rows = workload_rows(snapshot)[:_MAX_ROWS]
    table_rows = []
    for row in rows:
        evaluation = row['evaluation']
        if evaluation is None:
            protection = _badge('no policy', 'warn')
        elif 'error' in evaluation:
            protection = _badge('evaluation failed', 'bad')
        else:
            status = evaluation['protectionStatus']
            freshest = evaluation['freshestProtected']
            protection = _badge(
                'protected' if status['healthy'] else 'at risk',
                '' if status['healthy'] else 'bad')
            if freshest is not None:
                protection += ' <span class="muted">%s</span>' % esc(
                    _age(now - freshest['ageSeconds'], now))
            if status['reasons']:
                protection += _reason_list(
                    [{'code': r} for r in status['reasons']])
        admission = row['admission']
        if admission is None:
            admitted = '<span class="muted">not placed</span>'
        elif admission['status'] != 'checked':
            admitted = _badge(admission['status'], 'warn')
        elif admission['eligible']:
            admitted = _badge('admitted', 'ok')
        else:
            admitted = _badge('rejected', 'bad') \
                + _reason_list([{'code': r}
                                for r in admission['reasons']])
        state_tone = '' if row['observedState'] == 'running' \
            and row['observationFresh'] else 'warn'
        state = _badge(row['observedState'],
                       'bad' if row['observedState'] in ('lost',)
                       else state_tone)
        state += ' <span class="muted">%s</span>' % esc(
            _age(row['observedAt'], now))
        table_rows.append([
            '<a href="/workloads/%s"><strong>%s</strong></a>'
            '<br><span class="muted">%s · %s</span>'
            % (esc(row['workloadId']), esc(row['displayName']),
               esc(row['workloadId']), esc(row['category'])),
            '%s<br><span class="muted mono">gen %s · %s</span>'
            % (esc(row['hostId']), esc(row['generation']),
               esc(row['instanceId'])),
            state,
            protection,
            admitted])
    body = ('<h1>Workloads</h1><p class="sub">Catalog identity, current '
            'placement, observation freshness and recovery protection.</p>'
            '<div class="panel">'
            + _table(('Workload', 'Placement', 'Observed state',
                      'Protection', 'Admission on current host'),
                     table_rows)
            + '</div>' + _source_notes(snapshot))
    return _page('Workloads', body, now)


def workload_detail_page(snapshot, workload_id):
    now = snapshot['generatedAt']
    detail = workload_detail(snapshot, workload_id)
    if detail is None:
        return None
    row, definition = detail['row'], detail['definition']
    fields = []
    for label, value in (
            ('Workload', row['workloadId']),
            ('Display name', row['displayName']),
            ('Category', row['category']),
            ('Revision', None),
            ('Placed host', row['hostId']),
            ('Instance', row['instanceId']),
            ('Generation', row['generation']),
            ('Published', 'yes' if row['published'] else 'no')):
        rendered = _digest(row['revisionDigest']) if label == 'Revision' \
            else esc(value)
        fields.append('<div class="kv"><span>%s</span>'
                      '<span>%s</span></div>' % (esc(label), rendered))
    move_form = ''
    if definition is not None and snapshot['hosts']:
        options = ''.join('<option value="%s">%s</option>'
                          % (esc(h), esc(h))
                          for h in sorted(snapshot['hosts']))
        move_form = (
            '<form method="get" action="/move-check">'
            '<input type="hidden" name="workloadId" value="%s">'
            '<label class="muted">Check move to</label> '
            '<select name="hostId">%s</select> '
            '<button type="submit">Explain</button></form>'
            % (esc(workload_id), options))
    mounts = _table(
        ('Mount id', 'Guest path', 'Owner', 'Consistency'),
        [[esc(m['id']), '<code>%s</code>' % esc(m['mountPoint']),
          esc('%s:%s' % (m['ownerUid'], m['ownerGid'])),
          esc(m['consistencyAdapter'])]
         for m in detail['stateMounts'][:_MAX_ROWS]])
    points = _table(
        ('Recovery point', 'Captured', 'Source', 'Classification'),
        [[_digest(p['recoveryPointId']),
          esc(_stamp(p['captureStartedAt'])),
          esc('%s · gen %s' % (p['sourceHostId'], p['generation'])),
          (_badge(p['classification'],
                  'ok' if p['classification'] == 'current-protected'
                  else 'warn') if p['classification']
           else '<span class="muted">unevaluated</span>')
          + _reason_list([{'code': r} for r in p['reasons']])]
         for p in detail['points'][:_MAX_ROWS]])
    placements = _table(
        ('Host', 'Instance', 'Generation', 'Phase', 'Detail'),
        [[esc(i['hostId']),
          '<code>%s</code>' % esc(i.get('instanceId') or
                                  i.get('capture', {}).get('captureId')),
          esc(i.get('generation')),
          esc(i.get('phase') or i.get('capture', {}).get('status')),
          esc('retired' if i.get('retired') else
              ('capture barrier' if 'capture' in i else ''))]
         for i in detail['instances'][:_MAX_ROWS]])
    operations = _table(
        ('Source', 'Operation', 'Workload', 'Status'),
        [[esc('%s:%s' % (o.get('source'), o.get('hostId') or '')),
          esc(o.get('action') or o.get('id')),
          esc(o.get('workloadId') or ''),
          esc(o.get('status') or o.get('phase'))]
         for o in detail['operations'][:_MAX_ROWS]])
    body = ('<h1>%s</h1><p class="sub">%s · %s</p>'
            '<div class="grid"><div class="panel"><h2>Identity and '
            'placement</h2>%s</div>'
            '<div class="panel"><h2>Move check</h2><p class="muted">'
            'Explainable preview only — nothing is planned or executed.'
            '</p>%s</div></div>'
            '<div class="panel"><h2>State mounts</h2>%s</div>'
            '<div class="panel"><h2>Recovery points</h2>%s</div>'
            '<div class="panel"><h2>Known placements and captures</h2>%s</div>'
            '<div class="panel"><h2>Operations</h2>%s</div>'
            % (esc(row['displayName']), esc(row['workloadId']),
               esc(row['category']), ''.join(fields), move_form,
               mounts, points, placements, operations))
    return _page('Workloads', body, now)


def hosts_page(snapshot):
    now = snapshot['generatedAt']
    cards = []
    for row in host_rows(snapshot)[:_MAX_ROWS]:
        evidence = _badge('fresh', 'ok') if row['evidenceFresh'] else \
            _badge('stale' if row['evidenceObservedAt'] is not None
                   else 'no evidence', 'warn')
        available = row['available']
        capacity = ('<div class="kv"><span>Available</span><span>'
                    '%s MiB · %s cpu-millis · %s B</span></div>'
                    % (esc(available['memoryMiB']),
                       esc(available['cpuMillis']),
                       esc(available['stateBytes']))) if available else ''
        journal = row['journal']
        journal_line = ''
        if journal is not None:
            journal_line = (
                '<div class="kv"><span>Worker journal</span><span>%s'
                '</span></div>'
                % esc('%s — %d instances, %d held captures'
                      % ('readable' if journal['available']
                         else 'unavailable (%s)' % journal['error'],
                         journal['instances'], journal['heldCaptures'])))
        cards.append(
            '<div class="panel"><h2>%s %s</h2>'
            '<div class="kv"><span>Architecture</span><span>%s</span></div>'
            '<div class="kv"><span>Capabilities</span><span>%s</span></div>'
            '<div class="kv"><span>Capacity evidence</span><span>%s %s'
            '</span></div>%s'
            '<div class="kv"><span>Registry instances</span><span>%d</span>'
            '</div><div class="kv"><span>Latest observation</span><span>%s'
            '</span></div>%s</div>'
            % (esc(row['hostId']),
               '' if row['configured'] else _badge('unconfigured', 'warn'),
               esc(row['architecture']),
               esc(', '.join(row['capabilities']) or '—'),
               evidence, esc(_age(row['evidenceObservedAt'], now)),
               capacity, row['observedInstances'],
               esc(_stamp(row['latestObservationAt'])), journal_line))
    body = ('<h1>Hosts</h1><p class="sub">Admission capability records, '
            'capacity-evidence freshness and observed instances.</p>'
            '<div class="grid">%s</div>%s'
            % (''.join(cards), _source_notes(snapshot)))
    return _page('Hosts', body, now)


def operations_page(snapshot):
    now = snapshot['generatedAt']
    parts = []
    for section in operations_rows(snapshot):
        label = section['source'] + (
            ' on ' + section['hostId'] if section['hostId'] else '')
        status = '' if section['available'] else ' ' + _badge(
            'unavailable: %s' % (section['error'] or 'not configured'),
            'warn')
        rows = []
        for op in section['operations']:
            rows.append([
                '<code>%s</code>' % esc(op.get('operationId')
                                        or op.get('id')),
                esc(op.get('action') or op.get('phase') or ''),
                esc(op.get('workloadId') or ''),
                esc(op.get('status') or
                    ('invalid' if op.get('invalid') else '') or
                    op.get('phase') or '')])
        parts.append('<div class="panel"><h2>%s%s</h2>%s</div>'
                     % (esc(label), status,
                        _table(('Id', 'Operation', 'Workload', 'Status'),
                               rows)))
    body = ('<h1>Operations</h1><p class="sub">Recorded worker receipts '
            'and backup/restore journal phases. Nothing can be triggered '
            'from here.</p>%s%s'
            % (''.join(parts), _source_notes(snapshot)))
    return _page('Operations', body, now)


def move_check_page(snapshot, workload_id, host_id):
    now = snapshot['generatedAt']
    result = move_check(snapshot, workload_id, host_id)
    verdict = _badge('compatible — plan preview only',
                     'ok') if result['eligible'] else \
        _badge('not movable as recorded', 'bad')
    rows = [[_badge(r['severity'],
                    'bad' if r['severity'] == 'blocker' else 'warn'),
             esc(r['code']), esc(r['source'])]
            for r in result['reasons']]
    body = ('<h1>Move check</h1><p class="sub">%s → %s · explainable '
            'preflight, nothing executed.</p>'
            '<div class="panel"><h2>Verdict %s</h2>%s</div>%s'
            % (esc(workload_id), esc(host_id), verdict,
               _table(('Severity', 'Reason', 'Source'), rows),
               _source_notes(snapshot)))
    return _page('Move check', body, now)


# -- HTTP surface ------------------------------------------------------------

def _json_ready(value):
    """JSON-safe projection: policy/catalog outputs are already plain
    dicts; this is a defensive pass that also bounds size."""
    raw = json.dumps(value, allow_nan=False)
    if len(raw) > _MAX_REGISTRY_BYTES:
        raise common.HTTPError(500, 'Response too large')
    return value


def make_handler(config, reader):
    class API(common.Handler):
        def _snapshot(self):
            return collect(config, reader=reader)

        def _query(self, parsed):
            if len(parsed.query) > 512:
                raise common.HTTPError(400, 'Query too large')
            try:
                fields = urllib.parse.parse_qs(parsed.query,
                                               max_num_fields=8)
            except ValueError:
                raise common.HTTPError(400, 'Invalid query') from None
            return {key: values[0] for key, values in fields.items()
                    if len(values) == 1 and len(values[0]) <= 256}

        def route(self, method):
            if method != 'GET':
                raise common.HTTPError(404, 'Unknown endpoint')
            try:
                parsed = urllib.parse.urlsplit(self.path)
            except ValueError:
                raise common.HTTPError(404, 'Unknown endpoint') from None
            if parsed.scheme or parsed.netloc:
                raise common.HTTPError(404, 'Unknown endpoint')
            path = parsed.path
            query = self._query(parsed)
            if path == '/healthz':
                return self.send(200, {'status': 'ok'})
            if path == '/':
                return self.send(302, b'', 'text/plain',
                                 {'Location': '/workloads'})
            detail = re.fullmatch(r'/(?:api/v1/)?workloads/'
                                  r'([a-z][a-z0-9-]{0,62})', path)
            known = path in ('/workloads', '/hosts', '/operations',
                             '/move-check', '/api/v1/workloads',
                             '/api/v1/hosts', '/api/v1/operations',
                             '/api/v1/sources', '/api/v1/move-check') \
                or detail is not None
            if not known:
                raise common.HTTPError(404, 'Unknown endpoint')
            snapshot = self._snapshot()
            if path == '/workloads':
                return self.send(200, workloads_page(snapshot),
                                 'text/html; charset=utf-8')
            if detail is not None:
                if path.startswith('/api/'):
                    model = workload_detail(snapshot, detail[1])
                    if model is None:
                        raise common.HTTPError(404, 'Unknown workload')
                    return self.send(200, _json_ready(
                        {'schemaVersion': 1, 'workload': model}))
                page = workload_detail_page(snapshot, detail[1])
                if page is None:
                    raise common.HTTPError(404, 'Unknown workload')
                return self.send(200, page, 'text/html; charset=utf-8')
            if path == '/hosts':
                return self.send(200, hosts_page(snapshot),
                                 'text/html; charset=utf-8')
            if path == '/operations':
                return self.send(200, operations_page(snapshot),
                                 'text/html; charset=utf-8')
            if path == '/move-check':
                for key in ('workloadId', 'hostId'):
                    value = query.get(key)
                    if value is None or _ID_RE.fullmatch(value) is None:
                        raise common.HTTPError(400, 'Invalid ' + key)
                return self.send(200, move_check_page(
                    snapshot, query['workloadId'], query['hostId']),
                    'text/html; charset=utf-8')
            if path == '/api/v1/workloads':
                return self.send(200, _json_ready(
                    {'schemaVersion': 1,
                     'generatedAt': snapshot['generatedAt'],
                     'workloads': workload_rows(snapshot)}))
            if path == '/api/v1/hosts':
                return self.send(200, _json_ready(
                    {'schemaVersion': 1, 'hosts': host_rows(snapshot)}))
            if path == '/api/v1/operations':
                return self.send(200, _json_ready(
                    {'schemaVersion': 1,
                     'operations': operations_rows(snapshot)}))
            if path == '/api/v1/sources':
                return self.send(200, _json_ready(
                    {'schemaVersion': 1, 'sources': snapshot['sources'],
                     'registry': {k: {'available': v['available'],
                                      'error': v.get('error')}
                                  for k, v in
                                  snapshot['registry'].items()}}))
            if path == '/api/v1/move-check':
                for key in ('workloadId', 'hostId'):
                    value = query.get(key)
                    if value is None or _ID_RE.fullmatch(value) is None:
                        raise common.HTTPError(400, 'Invalid ' + key)
                return self.send(200, _json_ready(move_check(
                    snapshot, query['workloadId'], query['hostId'])))
            raise common.HTTPError(404, 'Unknown endpoint')

    for verb in ('POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'):
        setattr(API, 'do_' + verb,
                lambda self, _verb=verb: self.dispatch(_verb))
    return API


def make_server(config):
    try:
        family = socket.AF_INET6 \
            if ipaddress.ip_address(config['listenAddress']).version == 6 \
            else socket.AF_INET
    except ValueError:
        raise ConsoleError('invalid-listenAddress') from None

    class Listener(common.Server):
        address_family = family

    reader = RegistryReader(config['registry']) \
        if config['registry'] is not None else None
    return Listener((config['listenAddress'], config['port']),
                    make_handler(config, reader))


def _response(value):
    sys.stdout.write(json.dumps(value, sort_keys=True,
                                separators=(',', ':')) + '\n')


def main(argv=None):
    parser = argparse.ArgumentParser(prog='nexus-workloads-console')
    parser.add_argument('--config', required=True)
    args = parser.parse_args(argv)
    try:
        with open(args.config, 'rb') as handle:
            raw = handle.read(_MAX_CONFIG_BYTES + 1)
        if len(raw) > _MAX_CONFIG_BYTES:
            raise ConsoleError('config-too-large')
        config = validate_config(load_json(raw))
        server = make_server(config)
    except (ConsoleError, OSError, ssl.SSLError) as error:
        _response({'schemaVersion': 1, 'status': 'error',
                   'error': getattr(error, 'code',
                                    'invalid-config')})
        return 1
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
