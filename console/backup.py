"""Durable root-only capture/upload worker (trusted-caller library).

``nexus-backup execute`` consumes one bounded JSON request and turns a
caller-held worker capture barrier into a durable encrypted recovery
point in a local restic cache, or copies a completed cached point to a
bound destination repository. It never freezes, thaws, starts or stops
workloads: the caller must already hold the worker's durable
``captureId`` barrier, keeping lifecycle intent with the future
controller. A completed ``capture`` is a durable LOCAL encrypted point
only — off-host protection requires a separate ``upload`` to a
repository the caller operates off-host; nothing here labels points
protected or recoverable.

Capture reads the frozen source through a read-only bind mount inside
a private mount namespace and stores directly into an already
initialized local restic cache — no plaintext copy tree, no mode
rewriting, no archive format of its own. Scratch space contains only
the mount point and the sealed manifest metadata; journal entries are
canonical atomically-written root-only files under a private flock.
"""

import argparse
import copy
import fcntl
import hashlib
import math
import os
import re
import sqlite3
import stat
import sys
import time

import artifacts
import catalog
import recovery
import repository
import statefiles
import worker


class BackupError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


_MAX_REQUEST_BYTES = 16384
_MAX_CONFIG_BYTES = 2 * 1024 * 1024
_MAX_JOB_BYTES = 16 * 1024 * 1024
_MAX_BINDINGS = 1024
_HEX32_RE = worker._HEX32_RE
_CONFIG_FIELDS = {'schemaVersion', 'stateDir', 'workerConfigFile',
                  'cache', 'repositories', 'bindings'}
_CAPTURE_FIELDS = {'schemaVersion', 'action', 'captureId', 'workloadId',
                   'revisionDigest', 'instanceId', 'generation'}
_UPLOAD_FIELDS = {'schemaVersion', 'action', 'captureId', 'repositoryId'}
_STATUS_FIELDS = {'schemaVersion', 'action', 'captureId'}
_JOB_FIELDS = {'schemaVersion', 'request', 'configDigest',
               'sourceBinding', 'definition', 'source', 'secretBundle',
               'capture', 'phase', 'cache', 'copies'}
_RECEIPT_FIELDS = {'schemaVersion', 'repositoryId', 'repositoryIdentity',
                   'snapshotId', 'manifest'}
_INTERNAL_ERRORS = (OSError, ValueError, KeyError, TypeError,
                    AttributeError, sqlite3.Error)
_lstat = os.lstat
_fstat = os.fstat


def _response(response):
    sys.stdout.write(artifacts.canonical_bytes(response).decode('utf-8')
                     + '\n')


def _within(path, ancestor):
    return path == ancestor or path.startswith(ancestor + '/')


def _capture_tag(capture_id):
    return repository._DRAFT_TAG + ':' + capture_id


def _hex32(value, context='request'):
    try:
        worker._hex32(value, context)
    except worker.WorkerError as error:
        raise BackupError(error.code) from None


def _validate_binding(value):
    try:
        worker._fields(value, {'workloadId', 'revisionDigest',
                               'repositoryIds'}, 'binding')
        catalog.identifier(value['workloadId'], 'binding workloadId')
        worker._digest(value['revisionDigest'], 'binding revisionDigest')
        ids = value['repositoryIds']
        if type(ids) is not list or not 0 < len(ids) <= 64:
            raise worker.WorkerError('invalid-binding')
        for repo_id in ids:
            catalog.identifier(repo_id, 'binding repositoryId')
        if len(set(ids)) != len(ids):
            raise worker.WorkerError('invalid-binding')
    except worker.WorkerError as error:
        raise BackupError('invalid-config') from None
    except catalog.CatalogError:
        raise BackupError('invalid-config') from None


def _validate_config(config):
    try:
        worker._fields(config, _CONFIG_FIELDS, 'config')
        worker._integer(config['schemaVersion'], 1, 1,
                        'config-schemaVersion')
        worker._path(config['stateDir'], 'config-stateDir')
        worker._path(config['workerConfigFile'],
                     'config-workerConfigFile')
    except worker.WorkerError as error:
        raise BackupError(error.code) from None
    try:
        cache = repository._validate_config(config['cache'])
    except (repository.RepositoryError, TypeError):
        raise BackupError('invalid-config') from None
    if cache['transport']['kind'] != 'local':
        raise BackupError('invalid-config')
    repositories = config['repositories']
    if type(repositories) is not list or len(repositories) > 1024:
        raise BackupError('invalid-config')
    validated_repos = []
    seen = set()
    for repo_config in repositories:
        try:
            validated = repository._validate_config(repo_config)
        except (repository.RepositoryError, TypeError):
            raise BackupError('invalid-config') from None
        if validated['id'] in seen or validated['id'] == cache['id']:
            raise BackupError('invalid-config')
        seen.add(validated['id'])
        validated_repos.append(validated)
    bindings = config['bindings']
    if type(bindings) is not list or len(bindings) > _MAX_BINDINGS:
        raise BackupError('invalid-config')
    seen_keys = set()
    workload_of_repo = {}
    for binding in bindings:
        _validate_binding(binding)
        key = (binding['workloadId'], binding['revisionDigest'])
        if key in seen_keys:
            raise BackupError('invalid-config')
        seen_keys.add(key)
        for repo_id in binding['repositoryIds']:
            if repo_id not in seen:
                raise BackupError('invalid-config')
            if workload_of_repo.setdefault(
                    repo_id, binding['workloadId']) \
                    != binding['workloadId']:
                raise BackupError('invalid-config')
    result = copy.deepcopy(config)
    result['cache'] = cache
    result['repositories'] = validated_repos
    return result


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
            raise BackupError('path-unsafe')


def _check_config_path(path):
    """Root-owned non-symlink regular file under safe ancestors
    (Nix-store 0444 root files are allowed)."""
    _check_ancestors(path, os.geteuid())
    st = _lstat(path)
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) \
            or st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
        raise BackupError('path-unsafe')


def _read_config_file(path):
    """Bounded root-owned config read: safe path, O_NOFOLLOW open,
    fstat confirmation of the same regular file, limit+1 bytes."""
    try:
        worker._path(path, 'config')
    except worker.WorkerError as error:
        raise BackupError(error.code) from None
    _check_config_path(path)
    try:
        st = _lstat(path)
    except OSError:
        raise BackupError('path-unavailable') from None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise BackupError('path-unavailable') from None
    try:
        fst = _fstat(fd)
        if not stat.S_ISREG(fst.st_mode) \
                or fst.st_uid != 0 or stat.S_IMODE(fst.st_mode) & 0o022 \
                or (fst.st_ino, fst.st_dev) != (st.st_ino, st.st_dev):
            raise BackupError('path-unsafe')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            raw = handle.read(_MAX_CONFIG_BYTES + 1)
    except OSError:
        raise BackupError('path-unavailable') from None
    finally:
        os.close(fd)
    if len(raw) > _MAX_CONFIG_BYTES:
        raise BackupError('invalid-config')
    return raw


def _load_worker_config(path):
    raw = _read_config_file(path)
    try:
        config = worker.load_json_bytes(raw)
        return worker.validate_config(config)
    except worker.WorkerError as error:
        raise BackupError(error.code) from None
    except _INTERNAL_ERRORS:
        raise BackupError('invalid-config') from None


def _fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise BackupError('path-unavailable') from None
    try:
        os.fsync(fd)
    except OSError:
        raise BackupError('path-unavailable') from None
    finally:
        os.close(fd)


def _ensure_private_dir(path):
    """Ensure an exactly-0700 euid-owned non-symlink directory with
    durable dir+parent fsync; ancestors must be safe root/euid-owned
    non-symlink non-group/other-writable directories (root sticky
    allowed) and are never repaired."""
    euid = os.geteuid()
    _check_ancestors(path, euid)
    try:
        st = _lstat(path)
    except FileNotFoundError:
        try:
            os.mkdir(path, 0o700)
        except OSError:
            raise BackupError('path-unavailable') from None
    except OSError:
        raise BackupError('path-unavailable') from None
    else:
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) \
                or st.st_uid != euid \
                or stat.S_IMODE(st.st_mode) != 0o700:
            raise BackupError('path-unsafe')
    # Directory and parent durability are (re)established on every
    # call so a retry after an earlier fsync failure completes.
    _fsync_dir(path)
    _fsync_dir(os.path.dirname(path))


class RealMounts:
    """Read-only bind mounts inside an already-private mount
    namespace (the CLI wrapper unshares; asserted before use)."""

    def __init__(self, runner):
        self._runner = runner
        self.mounted = []

    def _check_namespace(self):
        try:
            own = os.readlink('/proc/self/ns/mnt')
            init = os.readlink('/proc/1/ns/mnt')
        except OSError:
            raise BackupError('path-unavailable') from None
        if own == init:
            raise BackupError('mount-namespace-shared')

    def mount(self, source, target):
        self._check_namespace()
        # A different namespace is not enough: private propagation
        # keeps every bind strictly inside this process view.
        self._run(['mount', '--make-rprivate', '/'])
        self._run(['mount', '--bind', source, target])
        try:
            self._run(['mount', '-o', 'remount,bind,ro', target])
        except BackupError:
            try:
                self._run(['umount', target])
            except BackupError:
                pass
            raise
        self.mounted.append(target)

    def unmount(self, target):
        self._run(['umount', target])
        if target in self.mounted:
            self.mounted.remove(target)

    def _run(self, argv):
        result = self._runner.run(argv, timeout=60)
        if result.returncode != 0:
            raise BackupError('mount-failed')


def _validate_capture_request(request, context='request'):
    if type(request) is not dict or set(request) != _CAPTURE_FIELDS:
        raise BackupError('invalid-request')
    if type(request['schemaVersion']) is not int \
            or request['schemaVersion'] != 1 \
            or request['action'] != 'capture':
        raise BackupError('invalid-request')
    try:
        catalog.identifier(request['workloadId'],
                           context + ' workloadId')
        worker._digest(request['revisionDigest'],
                       context + ' revisionDigest')
        worker._hex32(request['captureId'], context + ' captureId')
        worker._hex32(request['instanceId'], context + ' instanceId')
        worker._integer(request['generation'], 1, worker._MAX_I64,
                        context + ' generation')
    except worker.WorkerError as error:
        raise BackupError(error.code) from None
    except catalog.CatalogError:
        raise BackupError('invalid-request') from None


def _validate_source_binding(binding, source, definition):
    """The exact published worker binding record, cross-checked
    against the manifest's source/definition provenance."""
    if type(binding) is not dict or set(binding) != {
            'hostId', 'architecture', 'storage', 'slot'}:
        raise BackupError('journal-invalid')
    try:
        catalog.identifier(binding['hostId'], 'binding hostId')
    except catalog.CatalogError:
        raise BackupError('journal-invalid') from None
    if type(binding['architecture']) is not str \
            or binding['architecture'] not in (
                'x86_64-linux', 'aarch64-linux'):
        raise BackupError('journal-invalid')
    storage = binding['storage']
    if type(storage) is not dict \
            or set(storage) != {'root', 'mountPoint', 'uuid'}:
        raise BackupError('journal-invalid')
    try:
        worker._path(storage['root'], 'binding storage root')
        worker._path(storage['mountPoint'],
                     'binding storage mountPoint')
    except worker.WorkerError:
        raise BackupError('journal-invalid') from None
    if storage['mountPoint'] == '/' or (
            storage['root'] != storage['mountPoint']
            and not worker._within(storage['root'],
                                   storage['mountPoint'])):
        raise BackupError('journal-invalid')
    if type(storage['uuid']) is not str \
            or re.fullmatch(r'[0-9A-Fa-f-]{8,64}',
                            storage['uuid']) is None:
        raise BackupError('journal-invalid')
    slot = binding['slot']
    if type(slot) is not dict or set(slot) != {
            'id', 'uidBase', 'hostAddress', 'localAddress'}:
        raise BackupError('journal-invalid')
    try:
        catalog.identifier(slot['id'], 'binding slot id')
    except catalog.CatalogError:
        raise BackupError('journal-invalid') from None
    if type(slot['uidBase']) is not int or slot['uidBase'] <= 0 \
            or slot['uidBase'] % 65536 != 0 \
            or slot['uidBase'] > 2**32 - 131072:
        raise BackupError('journal-invalid')
    try:
        worker._ipv4(slot['hostAddress'], 'binding slot hostAddress')
        worker._ipv4(slot['localAddress'], 'binding slot localAddress')
    except worker.WorkerError:
        raise BackupError('journal-invalid') from None
    if slot['hostAddress'] == slot['localAddress']:
        raise BackupError('journal-invalid')
    if binding['hostId'] != source['hostId'] \
            or slot['uidBase'] != source['uidBase'] \
            or binding['architecture'] != definition['architecture']:
        raise BackupError('journal-invalid')


def _validated_receipt(value, job):
    if type(value) is not dict or set(value) != _RECEIPT_FIELDS:
        raise BackupError('journal-invalid')
    if type(value['schemaVersion']) is not int \
            or value['schemaVersion'] != 1:
        raise BackupError('journal-invalid')
    try:
        catalog.identifier(value['repositoryId'],
                           'receipt repositoryId')
    except catalog.CatalogError:
        raise BackupError('journal-invalid') from None
    for key in ('repositoryIdentity', 'snapshotId'):
        if type(value[key]) is not str \
                or repository._HEX64_RE.fullmatch(value[key]) is None:
            raise BackupError('journal-invalid')
    try:
        raw = artifacts.canonical_bytes(value['manifest'])
        manifest = recovery.decode_manifest(raw)
    except (recovery.RecoveryError, ValueError):
        raise BackupError('journal-invalid') from None
    if manifest != value['manifest'] \
            or manifest['definition'] != job['definition'] \
            or manifest['source'] != job['source'] \
            or manifest['capture'] != job['capture']:
        raise BackupError('journal-invalid')
    return value


def _validate_job(value, capture_id):
    if type(value) is not dict or set(value) != _JOB_FIELDS:
        raise BackupError('journal-invalid')
    if type(value['schemaVersion']) is not int \
            or value['schemaVersion'] != 1:
        raise BackupError('journal-invalid')
    _validate_capture_request(value['request'], 'journal')
    if value['request']['captureId'] != capture_id:
        raise BackupError('journal-invalid')
    if type(value['configDigest']) is not str \
            or repository._HEX64_RE.fullmatch(
                value['configDigest']) is None:
        raise BackupError('journal-invalid')
    definition = value['definition']
    source = value['source']
    capture = value['capture']
    if type(definition) is not dict or type(source) is not dict \
            or type(capture) is not dict:
        raise BackupError('journal-invalid')
    if set(capture) != {'adapter', 'consistency', 'startedAt',
                       'completedAt'}:
        raise BackupError('journal-invalid')
    if type(capture['startedAt']) is not int \
            or not 0 <= capture['startedAt'] <= 2**53:
        raise BackupError('journal-invalid')
    completed = capture['completedAt']
    if completed is not None \
            and (type(completed) is not int
                 or not capture['startedAt'] <= completed <= 2**53):
        raise BackupError('journal-invalid')
    # Validation probe only: placeholder digests prove the sealed
    # definition/source/capture can build a manifest; a pending job
    # borrows startedAt for the probe and never stores it.
    probe_capture = dict(capture)
    if completed is None:
        probe_capture['completedAt'] = capture['startedAt']
    try:
        placeholder = {mount['id']: 'sha256:' + '0' * 64
                       for mount in definition['stateMounts']}
        probe = recovery.build_manifest(
            definition, source, probe_capture,
            state_tree_digests=placeholder,
            state_set_digest='sha256:' + '0' * 64,
            secret_bundle=value['secretBundle'])
    except (recovery.RecoveryError, KeyError, TypeError):
        raise BackupError('journal-invalid') from None
    if probe['secretBundle'] != value['secretBundle']:
        raise BackupError('journal-invalid')
    definition = probe['definition']
    source = probe['source']
    if definition['workloadId'] != value['request']['workloadId'] \
            or definition['revisionDigest'] \
            != value['request']['revisionDigest'] \
            or source['instanceId'] != value['request']['instanceId'] \
            or source['generation'] != value['request']['generation']:
        raise BackupError('journal-invalid')
    _validate_source_binding(value['sourceBinding'], source,
                             definition)
    phase = value['phase']
    if phase not in ('pending', 'captured'):
        raise BackupError('journal-invalid')
    copies = value['copies']
    if type(copies) is not dict:
        raise BackupError('journal-invalid')
    for repo_id, entry in copies.items():
        try:
            catalog.identifier(repo_id, 'copies repositoryId')
        except catalog.CatalogError:
            raise BackupError('journal-invalid') from None
        if type(entry) is not dict \
                or set(entry) != {'record', 'verifiedAt'} \
                or type(entry['verifiedAt']) is not int \
                or not 0 <= entry['verifiedAt'] <= 2**53:
            raise BackupError('journal-invalid')
        record = _validated_receipt(entry['record'], value)
        if record['repositoryId'] != repo_id:
            raise BackupError('journal-invalid')
        if completed is not None \
                and entry['verifiedAt'] < completed:
            raise BackupError('journal-invalid')
    if phase == 'pending':
        if value['cache'] is not None or copies:
            raise BackupError('journal-invalid')
    else:
        if completed is None:
            raise BackupError('journal-invalid')
        _validated_receipt(value['cache'], value)
        if any(entry['record']['manifest'] != value['cache']['manifest']
               for entry in copies.values()):
            raise BackupError('journal-invalid')
    return value


class BackupWorker:
    """Root-only capture/upload worker around a local restic cache.

    ``execute`` accepts exactly ``capture``/``upload``/``status``
    requests; every request is a bounded dict whose ``captureId`` is
    the immutable job key."""

    def __init__(self, config, *, worker_factory=worker.Worker,
                 repo_factory=repository.ResticRepository,
                 runner=None, clock=time.time, mounts=None):
        self._config = _validate_config(config)
        self.clock = clock
        self.runner = runner or repository.BoundedRunner()
        self._repo_factory = repo_factory
        self._mounts = mounts or RealMounts(self.runner)
        self._worker_config = _load_worker_config(
            self._config['workerConfigFile'])
        # No filesystem metadata may be created before the configured
        # paths are proven disjoint from worker storage and from each
        # other.
        self._check_config_boundaries()
        state_dir = self._config['stateDir']
        _ensure_private_dir(state_dir)
        self._jobs_dir = os.path.join(state_dir, 'jobs')
        self._scratch_dir = os.path.join(state_dir, 'scratch')
        _ensure_private_dir(self._jobs_dir)
        _ensure_private_dir(self._scratch_dir)
        self._config_digest = hashlib.sha256(
            artifacts.canonical_bytes(self._config)).hexdigest()
        self._lock_path = os.path.join(state_dir, 'backup.lock')
        try:
            statefiles.ensure_private_file(self._lock_path)
        except statefiles.PathError as error:
            raise BackupError(error.code) from None
        # The worker handle is opened last: nothing below can fail
        # while it is held.
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

    # -- journal --------------------------------------------------------

    def _acquire_lock(self):
        if self._lock_handle is not None:
            return
        try:
            self._lock_handle = os.open(self._lock_path,
                                        os.O_RDWR | os.O_NOFOLLOW)
        except OSError:
            raise BackupError('path-unavailable') from None
        try:
            fcntl.flock(self._lock_handle,
                        fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self._lock_handle)
            self._lock_handle = None
            raise BackupError('backup-busy') from None
        except OSError:
            os.close(self._lock_handle)
            self._lock_handle = None
            raise BackupError('path-unavailable') from None

    def _release_lock(self):
        if self._lock_handle is not None:
            os.close(self._lock_handle)
            self._lock_handle = None

    def _job_path(self, capture_id):
        return os.path.join(self._jobs_dir, capture_id + '.json')

    def _load_job(self, capture_id):
        try:
            value = statefiles.read_json(self._job_path(capture_id),
                                         _MAX_JOB_BYTES)
        except statefiles.PathError as error:
            raise BackupError(error.code) from None
        if value is None:
            return None
        return _validate_job(value, capture_id)

    def _save_job(self, job):
        _validate_job(job, job['request']['captureId'])
        raw = artifacts.canonical_bytes(job)
        if len(raw) > _MAX_JOB_BYTES:
            raise BackupError('journal-too-large')
        try:
            statefiles.write_json(
                self._job_path(job['request']['captureId']), job)
        except statefiles.PathError as error:
            raise BackupError(error.code) from None
        except OSError:
            raise BackupError('path-unavailable') from None

    def _check_job_request(self, job, request):
        if job['request'] != request:
            raise BackupError('capture-conflict')

    def _check_job_config(self, job):
        if job['configDigest'] != self._config_digest:
            raise BackupError('backup-config-changed')

    def _binding_for(self, request):
        for binding in self._config['bindings']:
            if binding['workloadId'] == request['workloadId'] \
                    and binding['revisionDigest'] \
                    == request['revisionDigest']:
                return binding
        raise BackupError('binding-unapproved')

    # -- worker snapshot --------------------------------------------------

    def _worker_snapshot(self, request):
        """Consistent frozen-source snapshot under the worker lock.

        Never calls ``worker.execute`` while holding its lock: record
        rows are read here, then ``observe`` is issued separately."""
        lock = self._worker._lock()
        try:
            rec, definition = self._worker._capture_context(request)
            self._worker._check_generation_current(rec)
            held = self._worker._held_capture(rec['workload_id'])
            if held is None \
                    or held['capture_id'] != request['captureId'] \
                    or not self._worker._capture_matches(held, rec):
                raise BackupError('capture-required')
            source_dir = self._worker._instance_dir(rec)
            binding = copy.deepcopy(rec['binding'])
        finally:
            lock.close()
        observed = self._worker.execute({
            'schemaVersion': 1, 'action': 'observe',
            'instanceId': request['instanceId']})
        if observed.get('bindingCurrent') is not True \
                or observed.get('captureId') != request['captureId'] \
                or observed.get('phase') != 'stopped' \
                or observed.get('unitActiveState') \
                not in ('inactive', 'failed') \
                or observed.get('unitDrained') is not True:
            raise BackupError('capture-required')
        source = {'hostId': binding['hostId'],
                  'instanceId': rec['instance_id'],
                  'generation': rec['generation'],
                  'uidBase': binding['slot']['uidBase']}
        secret_bundle = None
        if definition['secretSetRef'] is not None:
            # The worker's durable marker is exactly the canonical
            # binding triple the recovery manifest must carry — the
            # frozen instance's provisioned secrets, not the escrow
            # record, are what the point binds. A missing or malformed
            # marker means the instance was never fully provisioned.
            marker = os.path.join(source_dir, worker._SECRETS_MARKER)
            try:
                secret_bundle = statefiles.read_json(
                    marker, _MAX_JOB_BYTES)
            except statefiles.PathError as error:
                raise BackupError(error.code) from None
            if secret_bundle is None:
                raise BackupError('secrets-missing')
        return {'rec': rec, 'definition': definition,
                'sourceBinding': binding, 'source': source,
                'sourceDir': source_dir, 'secretBundle': secret_bundle}

    def _local_repo_paths(self):
        paths = [self._config['stateDir'],
                 self._config['cache']['transport']['path']]
        for repo in self._config['repositories']:
            if repo['transport']['kind'] == 'local':
                paths.append(repo['transport']['path'])
        return paths

    def _check_config_boundaries(self):
        """Configured journal/cache/local-destination paths must not
        overlap the worker's storage root or state dir, and must be
        mutually disjoint — before any metadata is created."""
        worker_paths = [self._worker_config['storage']['root'],
                        self._worker_config['stateDir']]
        own = self._local_repo_paths()
        for path in own:
            for other in worker_paths:
                if _within(path, other) or _within(other, path):
                    raise BackupError('invalid-config')
        for i in range(len(own)):
            for j in range(i + 1, len(own)):
                if _within(own[i], own[j]) or _within(own[j], own[i]):
                    raise BackupError('invalid-config')

    def _check_source_boundaries(self, source_dir):
        for path in self._local_repo_paths():
            if _within(source_dir, path) or _within(path, source_dir):
                raise BackupError('path-unsafe')

    def _check_source_mounts(self, source_dir):
        """A non-recursive bind hides nested mounts: any existing
        mount at or under the source root means the capture could
        silently read underlying empty directories instead of the
        declared mounted data."""
        result = self.runner.run(
            ['findmnt', '--json', '--list', '--output', 'TARGET'],
            timeout=60)
        if result.returncode != 0:
            raise BackupError('source-mounts-unknown')
        try:
            value = worker.load_json_bytes(result.stdout)
            if type(value) is not dict \
                    or type(value.get('filesystems')) is not list \
                    or not value['filesystems']:
                raise BackupError('source-mounts-unknown')
            targets = []
            for entry in value['filesystems']:
                if type(entry) is not dict:
                    raise BackupError('source-mounts-unknown')
                target = entry.get('target')
                if type(target) is not str or not target.startswith('/') \
                        or '\x00' in target:
                    raise BackupError('source-mounts-unknown')
                targets.append(target)
        except (worker.WorkerError, RecursionError, ValueError, TypeError):
            raise BackupError('source-mounts-unknown') from None
        for target in targets:
            if _within(target, source_dir):
                raise BackupError('source-state-mounted')

    # -- repository helpers -----------------------------------------------

    def _cache(self):
        return self._repo_factory(self._config['cache'])

    def _repository(self, repository_id):
        for repo in self._config['repositories']:
            if repo['id'] == repository_id:
                return self._repo_factory(repo)
        raise BackupError('binding-unapproved')

    def _check_receipt_repo(self, receipt, repo_config):
        if receipt['repositoryId'] != repo_config['id'] \
                or receipt['repositoryIdentity'] \
                != repo_config['repositoryIdentity']:
            raise BackupError('capture-conflict')

    def _find_cached_point(self, job):
        """Final cache snapshots under this capture tag whose manifest
        binds exactly the journal's definition/source/capture. Full
        identity verification and check run before the pending job may
        be marked captured."""
        cache = self._cache()
        try:
            cache.verify_identity()
        except repository.RepositoryError as error:
            raise BackupError(error.code) from None
        capture_tag = _capture_tag(job['request']['captureId'])
        tag_filter = repository._FINAL_TAG + ',' + capture_tag
        try:
            result = cache._run(
                ['snapshots', '--json', '--tag', tag_filter],
                max_bytes=repository._METADATA_MAX)
            ids = cache._snapshot_ids(result.stdout)
        except repository.RepositoryError as error:
            raise BackupError(error.code) from None
        found = []
        for snapshot_id in ids:
            try:
                record = cache._receipt(
                    snapshot_id,
                    cache._inspect_final(snapshot_id, capture_tag))
            except repository.RepositoryError as error:
                raise BackupError(error.code) from None
            manifest = record['manifest']
            if manifest['definition'] != job['definition'] \
                    or manifest['source'] != job['source'] \
                    or manifest['capture'] != job['capture']:
                raise BackupError('capture-conflict')
            self._check_receipt_repo(record, self._config['cache'])
            found.append(record)
        if not found:
            return None
        try:
            cache.check()
        except repository.RepositoryError as error:
            raise BackupError(error.code) from None
        found.sort(key=lambda record: record['snapshotId'])
        return found[0]

    # -- clock --------------------------------------------------------------

    def _now(self, minimum=0):
        value = self.clock()
        if type(value) is bool or type(value) not in (int, float) \
                or not math.isfinite(value):
            raise BackupError('clock-invalid')
        now = int(value)
        if now < minimum or now < 0 or now > 2**53:
            raise BackupError('clock-invalid')
        return now

    # -- capture ----------------------------------------------------------

    def _persist_completed(self, job):
        """Callback inside the cache store: re-verify the barrier and
        the still-identical binding/definition/source, durably save
        completedAt once, and hand back the capture dict the sealed
        manifest must bind."""
        context = self._worker_snapshot(job['request'])
        if context['definition'] != job['definition'] \
                or context['source'] != job['source'] \
                or context['sourceBinding'] != job['sourceBinding'] \
                or context['secretBundle'] != job['secretBundle']:
            raise BackupError('capture-conflict')
        self._check_source_mounts(context['sourceDir'])
        if job['capture']['completedAt'] is None:
            job['capture']['completedAt'] = self._now(
                job['capture']['startedAt'])
            self._save_job(job)
        return dict(job['capture'])

    def _capture(self, request):
        self._acquire_lock()
        job = self._load_job(request['captureId'])
        if job is not None:
            self._check_job_request(job, request)
            self._check_job_config(job)
            if job['phase'] == 'captured':
                self._check_receipt_repo(job['cache'],
                                         self._config['cache'])
                receipt = self._verified_cached(job['cache'])
                return {'schemaVersion': 1, 'status': 'completed',
                        'action': 'capture',
                        'captureId': request['captureId'],
                        'record': receipt}
            if job['capture']['completedAt'] is not None:
                record = self._find_cached_point(job)
                if record is not None:
                    job['cache'] = record
                    job['phase'] = 'captured'
                    self._save_job(job)
                    return {'schemaVersion': 1, 'status': 'completed',
                            'action': 'capture',
                            'captureId': request['captureId'],
                            'record': record}
        else:
            self._binding_for(request)
            context = self._worker_snapshot(request)
            job = {
                'schemaVersion': 1,
                'request': dict(request),
                'configDigest': self._config_digest,
                'sourceBinding': context['sourceBinding'],
                'definition': context['definition'],
                'source': context['source'],
                'secretBundle': context['secretBundle'],
                'capture': {'adapter': 'quiesce-v1',
                            'consistency': 'quiesced',
                            'startedAt': self._now(),
                            'completedAt': None},
                'phase': 'pending', 'cache': None, 'copies': {},
            }
            # Reject an unbuildable capture (missing secret bundle,
            # malformed provenance) before the first journal write or
            # any mount; journal validation repeats the same probe.
            provisional = dict(job['capture'])
            provisional['completedAt'] = job['capture']['startedAt']
            try:
                placeholder = {mount['id']: 'sha256:' + '0' * 64
                               for mount in
                               job['definition']['stateMounts']}
                recovery.build_manifest(
                    job['definition'], job['source'], provisional,
                    state_tree_digests=placeholder,
                    state_set_digest='sha256:' + '0' * 64,
                    secret_bundle=job['secretBundle'])
            except (recovery.RecoveryError, KeyError, TypeError):
                raise BackupError('invalid-capture') from None
            self._save_job(job)
        context = self._worker_snapshot(request)
        if context['definition'] != job['definition'] \
                or context['source'] != job['source'] \
                or context['sourceBinding'] != job['sourceBinding'] \
                or context['secretBundle'] != job['secretBundle']:
            raise BackupError('capture-conflict')
        self._check_source_boundaries(context['sourceDir'])
        # The provisional completedAt (= startedAt) only proves the
        # capture shape; when the checkpoint callback is supplied its
        # returned dict is what the sealed manifest binds.
        provisional = dict(job['capture'])
        provisional['completedAt'] = job['capture']['startedAt']
        scratch = self._prepare_scratch(request['captureId'],
                                        job['definition'])
        mounted = []
        try:
            self._check_source_mounts(context['sourceDir'])
            # Exactly the declared stateMount leaves are bound into the
            # staging tree — never the whole instance dir, so worker
            # metadata (restore sentinel, staging area, provisioned
            # secrets and their marker) can never leak into a capture.
            for mount in job['definition']['stateMounts']:
                target = os.path.join(scratch, 'state', mount['id'])
                self._mounts.mount(
                    os.path.join(context['sourceDir'], mount['id']),
                    target)
                mounted.append(target)
            result = self.runner.run(
                ['sync', '-f', context['sourceDir']], timeout=60)
            if result.returncode != 0:
                raise BackupError('path-unavailable')
            # Final barrier confirmation inside store: the callback
            # re-observes and persists completedAt before the sealed
            # manifest is written.
            self._worker_snapshot(request)
            try:
                receipt = self._cache().store(
                    scratch, job['definition'], job['source'],
                    provisional,
                    capture_id=request['captureId'],
                    secret_bundle=job['secretBundle'],
                    capture_finished=lambda: self._persist_completed(job))
            except repository.RepositoryError as error:
                raise BackupError(error.code) from None
            manifest = receipt['manifest']
            if manifest['definition'] != job['definition'] \
                    or manifest['source'] != job['source'] \
                    or manifest['capture'] != job['capture']:
                raise BackupError('repository-point-invalid')
            self._check_receipt_repo(receipt, self._config['cache'])
            try:
                self._cache().check()
            except repository.RepositoryError as error:
                raise BackupError(error.code) from None
            job['cache'] = receipt
            job['phase'] = 'captured'
            self._save_job(job)
        finally:
            for target in reversed(mounted):
                self._mounts.unmount(target)
        return {'schemaVersion': 1, 'status': 'completed',
                'action': 'capture',
                'captureId': request['captureId'], 'record': receipt}

    def _verified_cached(self, record):
        cache = self._cache()
        try:
            cache.verify_identity()
            receipt = cache.inspect(record['snapshotId'])
        except repository.RepositoryError as error:
            raise BackupError(error.code) from None
        if receipt != record:
            raise BackupError('capture-conflict')
        try:
            cache.check()
        except repository.RepositoryError as error:
            raise BackupError(error.code) from None
        return receipt

    def _prepare_scratch(self, capture_id, definition):
        scratch = os.path.join(self._scratch_dir, capture_id)
        _ensure_private_dir(scratch)
        try:
            names = set(os.listdir(scratch))
        except OSError:
            raise BackupError('path-unavailable') from None
        if not names <= {'state', 'manifest.json'}:
            raise BackupError('path-unsafe')
        state = os.path.join(scratch, 'state')
        _ensure_private_dir(state)
        # One private mount target per declared leaf, created before
        # the binds land; a leftover from a crashed attempt is only
        # acceptable as an empty same-shaped dir.
        mounts = {mount['id'] for mount in definition['stateMounts']}
        try:
            children = set(os.listdir(state))
        except OSError:
            raise BackupError('path-unavailable') from None
        if not children <= mounts:
            raise BackupError('path-unsafe')
        for name in children:
            st = _lstat(os.path.join(state, name))
            if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) \
                    or st.st_uid != os.geteuid() \
                    or stat.S_IMODE(st.st_mode) != 0o700:
                raise BackupError('path-unsafe')
            try:
                if os.listdir(os.path.join(state, name)):
                    raise BackupError('path-unsafe')
            except OSError:
                raise BackupError('path-unavailable') from None
        for name in mounts - children:
            try:
                os.mkdir(os.path.join(state, name), 0o700)
            except OSError:
                raise BackupError('path-unavailable') from None
        _fsync_dir(state)
        return scratch

    # -- upload -----------------------------------------------------------

    def _upload(self, request):
        self._acquire_lock()
        job = self._load_job(request['captureId'])
        if job is None:
            raise BackupError('capture-missing')
        self._check_job_config(job)
        if job['phase'] != 'captured':
            raise BackupError('capture-pending')
        binding = self._binding_for(job['request'])
        if request['repositoryId'] not in binding['repositoryIds']:
            raise BackupError('binding-unapproved')
        repo_config = next(
            repo for repo in self._config['repositories']
            if repo['id'] == request['repositoryId'])
        target = self._repo_factory(repo_config)
        existing = job['copies'].get(request['repositoryId'])
        if existing is not None:
            self._check_receipt_repo(existing['record'], repo_config)
            if existing['record']['manifest'] \
                    != job['cache']['manifest']:
                raise BackupError('capture-conflict')
            try:
                receipt = target.inspect(
                    existing['record']['snapshotId'])
            except repository.RepositoryError as error:
                raise BackupError(error.code) from None
            if receipt != existing['record']:
                raise BackupError('capture-conflict')
            try:
                target.check()
            except repository.RepositoryError as error:
                raise BackupError(error.code) from None
            return {'schemaVersion': 1, 'status': 'completed',
                    'action': 'upload',
                    'captureId': request['captureId'],
                    'repositoryId': request['repositoryId'],
                    'record': receipt,
                    'verifiedAt': existing['verifiedAt']}
        # The cached source point must still be exactly the journal's
        # record before it may seed a destination copy.
        cached = self._verified_cached(job['cache'])
        if cached['manifest'] != job['cache']['manifest'] \
                or cached != job['cache']:
            raise BackupError('capture-conflict')
        try:
            receipt = target.copy_from(self._cache(),
                                       job['cache']['snapshotId'])
        except repository.RepositoryError as error:
            raise BackupError(error.code) from None
        self._check_receipt_repo(receipt, repo_config)
        if receipt['manifest'] != job['cache']['manifest']:
            raise BackupError('repository-point-invalid')
        verified_at = self._now(job['capture']['completedAt'])
        job['copies'][request['repositoryId']] = {
            'record': receipt, 'verifiedAt': verified_at}
        self._save_job(job)
        return {'schemaVersion': 1, 'status': 'completed',
                'action': 'upload',
                'captureId': request['captureId'],
                'repositoryId': request['repositoryId'],
                'record': receipt, 'verifiedAt': verified_at}

    # -- status -----------------------------------------------------------

    def _status(self, request):
        self._acquire_lock()
        job = self._load_job(request['captureId'])
        if job is None:
            raise BackupError('capture-missing')
        copies = [dict({'repositoryId': repo_id}, **entry)
                  for repo_id, entry in sorted(job['copies'].items())]
        return {'schemaVersion': 1, 'status': 'completed',
                'action': 'status',
                'captureId': request['captureId'],
                'phase': job['phase'], 'record': job['cache'],
                'copies': copies}

    # -- dispatch ---------------------------------------------------------

    def execute(self, request):
        try:
            return self._execute(request)
        finally:
            # The global journal flock serializes one operation;
            # it is never held across calls or by leaked handles.
            self._release_lock()

    def _execute(self, request):
        capture_id = request.get('captureId') if type(request) is dict \
            else None
        try:
            if type(request) is not dict \
                    or type(request.get('schemaVersion')) is not int \
                    or request['schemaVersion'] != 1:
                raise BackupError('invalid-request')
            action = request.get('action')
            if action == 'capture':
                _validate_capture_request(request)
                return self._capture(request)
            if action == 'upload':
                if set(request) != _UPLOAD_FIELDS:
                    raise BackupError('invalid-request')
                _hex32(request['captureId'], 'request captureId')
                try:
                    catalog.identifier(request['repositoryId'],
                                       'request repositoryId')
                except catalog.CatalogError:
                    raise BackupError('invalid-request') from None
                return self._upload(request)
            if action == 'status':
                if set(request) != _STATUS_FIELDS:
                    raise BackupError('invalid-request')
                _hex32(request['captureId'], 'request captureId')
                return self._status(request)
            raise BackupError('invalid-request')
        except BackupError as error:
            return {'schemaVersion': 1, 'status': 'blocked',
                    'error': error.code, 'captureId': capture_id}
        except worker.WorkerError as error:
            return {'schemaVersion': 1, 'status': 'blocked',
                    'error': error.code, 'captureId': capture_id}
        except repository.RepositoryError as error:
            return {'schemaVersion': 1, 'status': 'blocked',
                    'error': error.code, 'captureId': capture_id}
        except statefiles.PathError as error:
            return {'schemaVersion': 1, 'status': 'blocked',
                    'error': error.code, 'captureId': capture_id}
        except _INTERNAL_ERRORS:
            return {'schemaVersion': 1, 'status': 'blocked',
                    'error': 'internal-error', 'captureId': capture_id}


def main(argv=None):
    parser = argparse.ArgumentParser(prog='nexus-backup')
    parser.add_argument('--config', required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('execute')
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        _response({'schemaVersion': 1, 'status': 'error',
                   'error': 'requires-root'})
        return 1
    try:
        raw_config = _read_config_file(args.config)
        config = worker.load_json_bytes(raw_config)
        instance = BackupWorker(config)
    except (BackupError, worker.WorkerError) as error:
        _response({'schemaVersion': 1, 'status': 'error',
                   'error': error.code})
        return 1
    except _INTERNAL_ERRORS:
        _response({'schemaVersion': 1, 'status': 'error',
                   'error': 'invalid-config'})
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
    return 0 if response.get('status') == 'completed' else 1


if __name__ == '__main__':
    sys.exit(main())
