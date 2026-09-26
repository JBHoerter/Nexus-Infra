"""Durable root-only restore-installation worker (trusted-caller library).

``nexus-restore execute`` consumes one bounded JSON request and installs
a verified repository recovery point into a prepared-but-never-started
worker instance's state directory, translating numeric ownership from
the sealed manifest's ``source.uidBase`` onto the target slot's uidBase
through a kernel idmapped bind view (``X-mount.idmap``) plus
``cp --archive`` — modes, mtimes, hardlinks, symlinks, ACLs and
``security.capability`` rootids land translated while the
repository-extracted source tree is never modified. The idmap mount
lives only inside the private mount namespace the CLI wrapper unshares.

``stage`` claims the ``.nexus-restore-pending`` sentinel under the
worker's own flock in the same critical section that proves the target
prepared-and-never-started — a raced ``start`` either fails its
``_restore_pending`` gate on the durable sentinel or has already moved
the phase off ``prepared`` before the lock was taken — then extracts
the exact bound snapshot into private scratch, verifies the sealed
manifest (schemaVersion 3 / restic-posix-v2 only — legacy v2 carries
no state-set anchor and is never installable), copies the translated
tree into a durable staging area inside the instance directory and
records the journal only after the copy is durable. ``commit``
re-verifies the instance is still prepared-not-started, moves each
translated mount leaf into place, removes the sentinel and marks the
journal committed.
A crash before commit leaves the sentinel in place — the worker refuses
``start`` with ``restore-incomplete`` — and the interrupted job is
resumed by replay; a crash after commit replays as completed. This
worker never starts, stops, freezes or thaws the instance and asserts
no readiness, consistency or fencing.
"""

import argparse
import copy
import fcntl
import hashlib
import math
import os
import shutil
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


class RestoreError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


_MAX_REQUEST_BYTES = 16384
_MAX_CONFIG_BYTES = 2 * 1024 * 1024
_MAX_JOB_BYTES = 16 * 1024 * 1024
_MAX_SENTINEL_BYTES = 4096
_BULK_TIMEOUT = 3600
_SENTINEL = worker._RESTORE_SENTINEL
_STAGING = '.nexus-restore-staging'
_CONFIG_FIELDS = {'schemaVersion', 'stateDir', 'workerConfigFile',
                  'repositories'}
_STAGE_FIELDS = {'schemaVersion', 'action', 'restoreId', 'repositoryId',
                 'snapshotId', 'target'}
_TARGET_FIELDS = {'workloadId', 'revisionDigest', 'instanceId',
                  'generation', 'slotId'}
_COMMIT_FIELDS = {'schemaVersion', 'action', 'restoreId'}
_STATUS_FIELDS = {'schemaVersion', 'action', 'restoreId'}
_JOB_FIELDS = {'schemaVersion', 'request', 'configDigest', 'record',
               'translation', 'phase', 'stagedAt', 'committedAt'}
_RECEIPT_FIELDS = {'schemaVersion', 'repositoryId', 'repositoryIdentity',
                   'snapshotId', 'manifest'}
_INTERNAL_ERRORS = (OSError, ValueError, KeyError, TypeError,
                    AttributeError, RecursionError, sqlite3.Error)
_lstat = os.lstat
_fstat = os.fstat


def _response(response):
    sys.stdout.write(artifacts.canonical_bytes(response).decode('utf-8')
                     + '\n')


def _within(path, ancestor):
    return path == ancestor or path.startswith(ancestor + '/')


def _uid_base(value):
    return type(value) is int and value > 0 and value % 65536 == 0 \
        and value <= 2**32 - 131072


def _hex32(value, context='request'):
    try:
        worker._hex32(value, context)
    except worker.WorkerError as error:
        raise RestoreError(error.code) from None


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
            raise RestoreError('path-unsafe')


def _check_config_path(path):
    """Root-owned non-symlink regular file under safe ancestors
    (Nix-store 0444 root files are allowed)."""
    _check_ancestors(path, os.geteuid())
    st = _lstat(path)
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) \
            or st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
        raise RestoreError('path-unsafe')


def _read_config_file(path):
    """Bounded root-owned config read: safe path, O_NOFOLLOW open,
    fstat confirmation of the same regular file, limit+1 bytes."""
    try:
        worker._path(path, 'config')
    except worker.WorkerError as error:
        raise RestoreError(error.code) from None
    _check_config_path(path)
    try:
        st = _lstat(path)
    except OSError:
        raise RestoreError('path-unavailable') from None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise RestoreError('path-unavailable') from None
    try:
        fst = _fstat(fd)
        if not stat.S_ISREG(fst.st_mode) \
                or fst.st_uid != 0 or stat.S_IMODE(fst.st_mode) & 0o022 \
                or (fst.st_ino, fst.st_dev) != (st.st_ino, st.st_dev):
            raise RestoreError('path-unsafe')
        with os.fdopen(fd, 'rb', closefd=False) as handle:
            raw = handle.read(_MAX_CONFIG_BYTES + 1)
    except OSError:
        raise RestoreError('path-unavailable') from None
    finally:
        os.close(fd)
    if len(raw) > _MAX_CONFIG_BYTES:
        raise RestoreError('invalid-config')
    return raw


def _load_worker_config(path):
    raw = _read_config_file(path)
    try:
        config = worker.load_json_bytes(raw)
        return worker.validate_config(config)
    except worker.WorkerError as error:
        raise RestoreError(error.code) from None
    except _INTERNAL_ERRORS:
        raise RestoreError('invalid-config') from None


def _fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError:
        raise RestoreError('path-unavailable') from None
    try:
        os.fsync(fd)
    except OSError:
        raise RestoreError('path-unavailable') from None
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
            raise RestoreError('path-unavailable') from None
    except OSError:
        raise RestoreError('path-unavailable') from None
    else:
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) \
                or st.st_uid != euid \
                or stat.S_IMODE(st.st_mode) != 0o700:
            raise RestoreError('path-unsafe')
    # Directory and parent durability are (re)established on every
    # call so a retry after an earlier fsync failure completes.
    _fsync_dir(path)
    _fsync_dir(os.path.dirname(path))


def _lstat_or_none(path):
    try:
        return _lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        raise RestoreError('path-unavailable') from None


def _remove_tree(path):
    """Remove a private scratch/staging subtree; never follows the
    top-level symlink and refuses anything outside what was created."""
    st = _lstat_or_none(path)
    if st is None:
        return
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise RestoreError('path-unsafe')
    try:
        shutil.rmtree(path)
    except OSError:
        raise RestoreError('path-unavailable') from None
    _fsync_dir(os.path.dirname(path))


class RealMounts:
    """Idmapped read-only bind mounts inside an already-private mount
    namespace (the CLI wrapper unshares; asserted before use)."""

    def __init__(self, runner):
        self._runner = runner
        self.mounted = []

    def _check_namespace(self):
        try:
            own = os.readlink('/proc/self/ns/mnt')
            init = os.readlink('/proc/1/ns/mnt')
        except OSError:
            raise RestoreError('path-unavailable') from None
        if own == init:
            raise RestoreError('mount-namespace-shared')

    def mount(self, source, target, idmap):
        self._check_namespace()
        # A different namespace is not enough: private propagation
        # keeps every bind strictly inside this process view.
        self._run(['mount', '--make-rprivate', '/'])
        self._run(['mount', '--bind', '-o', 'X-mount.idmap=' + idmap,
                   source, target])
        try:
            self._run(['mount', '-o', 'remount,bind,ro', target])
        except (RestoreError, repository.RepositoryError):
            try:
                self._run(['umount', target])
            except (RestoreError, repository.RepositoryError):
                pass
            raise
        self.mounted.append(target)

    def unmount(self, target):
        self._run(['umount', target])
        if target in self.mounted:
            self.mounted.remove(target)

    def _run(self, argv):
        try:
            result = self._runner.run(argv, timeout=60)
        except repository.RepositoryError:
            raise RestoreError('mount-failed') from None
        if result.returncode != 0:
            raise RestoreError('mount-failed')


def _validate_stage_request(request, context='request'):
    if type(request) is not dict or set(request) != _STAGE_FIELDS:
        raise RestoreError('invalid-request')
    if type(request['schemaVersion']) is not int \
            or request['schemaVersion'] != 1 \
            or request['action'] != 'stage':
        raise RestoreError('invalid-request')
    try:
        worker._hex32(request['restoreId'], context + ' restoreId')
        catalog.identifier(request['repositoryId'],
                           context + ' repositoryId')
        repository._hex64(request['snapshotId'], context + ' snapshotId')
        target = request['target']
        worker._fields(target, _TARGET_FIELDS, 'target')
        catalog.identifier(target['workloadId'], context + ' workloadId')
        worker._digest(target['revisionDigest'],
                       context + ' revisionDigest')
        worker._hex32(target['instanceId'], context + ' instanceId')
        worker._integer(target['generation'], 1, worker._MAX_I64,
                        context + ' generation')
        catalog.identifier(target['slotId'], context + ' slotId')
    except worker.WorkerError as error:
        raise RestoreError(error.code) from None
    except (catalog.CatalogError, repository.RepositoryError):
        raise RestoreError('invalid-request') from None


def _validate_receipt(value):
    if type(value) is not dict or set(value) != _RECEIPT_FIELDS:
        raise RestoreError('journal-invalid')
    if type(value['schemaVersion']) is not int \
            or value['schemaVersion'] != 1:
        raise RestoreError('journal-invalid')
    try:
        catalog.identifier(value['repositoryId'],
                           'receipt repositoryId')
    except catalog.CatalogError:
        raise RestoreError('journal-invalid') from None
    try:
        repository._hex64(value['repositoryIdentity'], 'receipt')
        repository._hex64(value['snapshotId'], 'receipt')
    except repository.RepositoryError:
        raise RestoreError('journal-invalid') from None
    try:
        raw = artifacts.canonical_bytes(value['manifest'])
        manifest = recovery.decode_manifest(raw)
    except (recovery.RecoveryError, ValueError):
        raise RestoreError('journal-invalid') from None
    # Legacy schema-2 points carry no state-set anchor and are never
    # installable; only restic-posix-v2 manifests may be journaled.
    if manifest != value['manifest'] \
            or manifest['schemaVersion'] != recovery._SCHEMA_VERSION:
        raise RestoreError('journal-invalid')
    return value


def _validate_job(value, restore_id):
    if type(value) is not dict or set(value) != _JOB_FIELDS:
        raise RestoreError('journal-invalid')
    if type(value['schemaVersion']) is not int \
            or value['schemaVersion'] != 1:
        raise RestoreError('journal-invalid')
    _validate_stage_request(value['request'], 'journal')
    if value['request']['restoreId'] != restore_id:
        raise RestoreError('journal-invalid')
    try:
        repository._hex64(value['configDigest'], 'journal')
    except repository.RepositoryError:
        raise RestoreError('journal-invalid') from None
    record = _validate_receipt(value['record'])
    request = value['request']
    manifest = record['manifest']
    if record['snapshotId'] != request['snapshotId'] \
            or record['repositoryId'] != request['repositoryId'] \
            or manifest['definition']['workloadId'] \
            != request['target']['workloadId'] \
            or manifest['definition']['revisionDigest'] \
            != request['target']['revisionDigest']:
        raise RestoreError('journal-invalid')
    translation = value['translation']
    if type(translation) is not dict \
            or set(translation) != {'sourceUidBase', 'targetUidBase'} \
            or not _uid_base(translation['sourceUidBase']) \
            or not _uid_base(translation['targetUidBase']) \
            or translation['sourceUidBase'] \
            == translation['targetUidBase'] \
            or translation['sourceUidBase'] != manifest['source']['uidBase']:
        raise RestoreError('journal-invalid')
    phase = value['phase']
    if phase not in ('pending', 'staged', 'committed'):
        raise RestoreError('journal-invalid')
    for key in ('stagedAt', 'committedAt'):
        moment = value[key]
        if moment is not None and (type(moment) is not int
                                   or not 0 <= moment <= 2**53):
            raise RestoreError('journal-invalid')
    if phase == 'pending' and (value['stagedAt'] is not None
                             or value['committedAt'] is not None):
        raise RestoreError('journal-invalid')
    if phase == 'staged' and (type(value['stagedAt']) is not int
                            or value['committedAt'] is not None):
        raise RestoreError('journal-invalid')
    if phase == 'committed' \
            and (type(value['stagedAt']) is not int
                 or type(value['committedAt']) is not int
                 or value['committedAt'] < value['stagedAt']):
        raise RestoreError('journal-invalid')
    return value


def _validate_config(config):
    try:
        worker._fields(config, _CONFIG_FIELDS, 'config')
        worker._integer(config['schemaVersion'], 1, 1,
                        'config-schemaVersion')
        worker._path(config['stateDir'], 'config-stateDir')
        worker._path(config['workerConfigFile'],
                     'config-workerConfigFile')
    except worker.WorkerError as error:
        raise RestoreError(error.code) from None
    repositories = config['repositories']
    if type(repositories) is not list or len(repositories) > 1024:
        raise RestoreError('invalid-config')
    validated = []
    seen = set()
    for repo_config in repositories:
        try:
            checked = repository._validate_config(repo_config)
        except (repository.RepositoryError, TypeError):
            raise RestoreError('invalid-config') from None
        if checked['id'] in seen:
            raise RestoreError('invalid-config')
        seen.add(checked['id'])
        validated.append(checked)
    result = copy.deepcopy(config)
    result['repositories'] = validated
    return result


class RestoreWorker:
    """Root-only stage/commit installer for verified recovery points.

    ``execute`` accepts exactly ``stage``/``commit``/``status``
    requests; every request is a bounded dict whose ``restoreId`` is
    the immutable job key. The target instance must exist on this host,
    be bound to the request's workload/revision/generation/slot, and be
    ``prepared`` — a phase reachable only before any start."""

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
        # paths are proven disjoint from worker storage and each other.
        self._check_config_boundaries()
        state_dir = self._config['stateDir']
        _ensure_private_dir(state_dir)
        self._jobs_dir = os.path.join(state_dir, 'jobs')
        self._scratch_dir = os.path.join(state_dir, 'scratch')
        _ensure_private_dir(self._jobs_dir)
        _ensure_private_dir(self._scratch_dir)
        self._config_digest = hashlib.sha256(
            artifacts.canonical_bytes(self._config)).hexdigest()
        self._lock_path = os.path.join(state_dir, 'restore.lock')
        try:
            statefiles.ensure_private_file(self._lock_path)
        except statefiles.PathError as error:
            raise RestoreError(error.code) from None
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
            raise RestoreError('path-unavailable') from None
        try:
            fcntl.flock(self._lock_handle,
                        fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self._lock_handle)
            self._lock_handle = None
            raise RestoreError('restore-busy') from None
        except OSError:
            os.close(self._lock_handle)
            self._lock_handle = None
            raise RestoreError('path-unavailable') from None

    def _release_lock(self):
        if self._lock_handle is not None:
            os.close(self._lock_handle)
            self._lock_handle = None

    def _job_path(self, restore_id):
        return os.path.join(self._jobs_dir, restore_id + '.json')

    def _load_job(self, restore_id):
        try:
            value = statefiles.read_json(self._job_path(restore_id),
                                         _MAX_JOB_BYTES)
        except statefiles.PathError as error:
            raise RestoreError(error.code) from None
        if value is None:
            return None
        return _validate_job(value, restore_id)

    def _save_job(self, job):
        _validate_job(job, job['request']['restoreId'])
        raw = artifacts.canonical_bytes(job)
        if len(raw) > _MAX_JOB_BYTES:
            raise RestoreError('journal-too-large')
        try:
            statefiles.write_json(
                self._job_path(job['request']['restoreId']), job)
        except statefiles.PathError as error:
            raise RestoreError(error.code) from None
        except OSError:
            raise RestoreError('path-unavailable') from None

    def _check_job_request(self, job, request):
        if job['request'] != request:
            raise RestoreError('restore-conflict')

    def _check_job_config(self, job):
        if job['configDigest'] != self._config_digest:
            raise RestoreError('restore-config-changed')

    # -- config boundaries ----------------------------------------------

    def _local_repo_paths(self):
        paths = [self._config['stateDir']]
        for repo in self._config['repositories']:
            if repo['transport']['kind'] == 'local':
                paths.append(repo['transport']['path'])
        return paths

    def _check_config_boundaries(self):
        """Configured journal/local-repository paths must not overlap
        the worker's storage root or state dir, and must be mutually
        disjoint — before any metadata is created."""
        worker_paths = [self._worker_config['storage']['root'],
                        self._worker_config['stateDir']]
        own = self._local_repo_paths()
        for path in own:
            for other in worker_paths:
                if _within(path, other) or _within(other, path):
                    raise RestoreError('invalid-config')
        for i in range(len(own)):
            for j in range(i + 1, len(own)):
                if _within(own[i], own[j]) or _within(own[j], own[i]):
                    raise RestoreError('invalid-config')

    # -- worker snapshot --------------------------------------------------

    def _target_context(self, request, claim=None, journaled=False):
        """Prepared-not-started target snapshot under the worker lock.

        Never calls ``worker.execute`` while holding its lock: the
        record row is read here, then ``observe`` is issued separately.
        When ``claim`` is a restoreId the sentinel claim runs in the
        same critical section as the freshness proof: the sentinel is
        durable before the lock is released, so a ``start`` racing in
        afterwards always trips the worker's ``_restore_pending`` gate
        and one that already passed has moved the phase off
        ``prepared`` before this lock was taken.
        """
        target = request['target']
        lock = self._worker._lock()
        try:
            rec = self._worker._get_instance(target['instanceId'])
            if rec is None:
                raise RestoreError('unknown-instance')
            if (rec['workload_id'], rec['revision_digest'],
                    rec['generation']) != (
                    target['workloadId'], target['revisionDigest'],
                    target['generation']):
                raise RestoreError('instance-conflict')
            if rec['retired']:
                raise RestoreError('instance-retired')
            # 'prepared' is the only phase reachable without a start;
            # anything else means this incarnation already ran.
            if rec['phase'] != 'prepared':
                raise RestoreError('instance-not-fresh')
            if rec['slot_id'] != target['slotId']:
                raise RestoreError('instance-conflict')
            try:
                self._worker._require_binding_current(rec)
            except worker.WorkerError as error:
                raise RestoreError(error.code) from None
            slot = rec['binding']['slot']
            if slot['id'] != target['slotId']:
                raise RestoreError('instance-conflict')
            definition = self._worker._resolve(
                rec['workload_id'], rec['revision_digest'])[2]
            try:
                self._worker._check_action_allowed(definition, 'restore')
                self._worker._verify_mount()
            except worker.WorkerError as error:
                raise RestoreError(error.code) from None
            instance_dir = self._worker._instance_dir(rec)
            context = {'rec': rec, 'definition': definition, 'slot': slot,
                       'instanceDir': instance_dir}
            if claim is not None:
                self._claim_sentinel(context, claim, journaled)
        finally:
            lock.close()
        observed = self._worker.execute({
            'schemaVersion': 1, 'action': 'observe',
            'instanceId': target['instanceId']})
        if observed.get('phase') != 'prepared' \
                or observed.get('bindingCurrent') is not True \
                or observed.get('retired') is not False \
                or observed.get('unitActiveState') != 'inactive' \
                or observed.get('unitDrained') is not True:
            raise RestoreError('instance-not-fresh')
        return context

    # -- repository helpers -----------------------------------------------

    def _repository(self, repository_id):
        for repo in self._config['repositories']:
            if repo['id'] == repository_id:
                return repo
        raise RestoreError('repository-unapproved')

    def _verify_point(self, request, job):
        """Inspect the bound snapshot and prove it is an installable
        v3 point bound to the request's workload and revision."""
        repo_config = self._repository(request['repositoryId'])
        repo = self._repo_factory(repo_config)
        try:
            record = repo.inspect(request['snapshotId'])
        except repository.RepositoryError as error:
            raise RestoreError(error.code) from None
        if record['repositoryId'] != repo_config['id'] \
                or record['repositoryIdentity'] \
                != repo_config['repositoryIdentity']:
            raise RestoreError('point-mismatch')
        manifest = record['manifest']
        if manifest['schemaVersion'] != recovery._SCHEMA_VERSION \
                or manifest['stateFormat'] != recovery._STATE_FORMAT:
            raise RestoreError('manifest-unsupported')
        target = request['target']
        if manifest['definition']['workloadId'] != target['workloadId'] \
                or manifest['definition']['revisionDigest'] \
                != target['revisionDigest']:
            raise RestoreError('point-mismatch')
        try:
            digest = repo._snapshot_state_digest(
                request['snapshotId'], repository._FINAL_TAG)
        except repository.RepositoryError as error:
            raise RestoreError(error.code) from None
        if digest != manifest['stateSetDigest']:
            raise RestoreError('point-mismatch')
        if job is not None and job['record'] != record:
            raise RestoreError('restore-conflict')
        return repo, record

    # -- sentinel and staging --------------------------------------------

    def _sentinel_path(self, instance_dir):
        return os.path.join(instance_dir, _SENTINEL)

    def _staging_path(self, instance_dir):
        return os.path.join(instance_dir, _STAGING)

    def _read_sentinel(self, instance_dir):
        try:
            value = statefiles.read_json(
                self._sentinel_path(instance_dir), _MAX_SENTINEL_BYTES)
        except statefiles.PathError as error:
            raise RestoreError(error.code) from None
        if value is None:
            return None
        if type(value) is not dict \
                or set(value) != {'schemaVersion', 'restoreId'} \
                or value['schemaVersion'] != 1 \
                or type(value['restoreId']) is not str \
                or worker._HEX32_RE.fullmatch(
                    value['restoreId']) is None:
            raise RestoreError('path-unsafe')
        return value['restoreId']

    def _write_sentinel(self, instance_dir, restore_id):
        try:
            statefiles.write_json(
                self._sentinel_path(instance_dir),
                {'schemaVersion': 1, 'restoreId': restore_id})
        except statefiles.PathError as error:
            raise RestoreError(error.code) from None
        except OSError:
            raise RestoreError('path-unavailable') from None
        _fsync_dir(instance_dir)

    def _claim_sentinel(self, context, restore_id, journaled):
        """Verify or establish the restore sentinel. Always called with
        the worker flock held so the claim is atomic with the
        prepared/never-started proof above it: a journaled job must
        already own the sentinel, a foreign one conflicts, and a fresh
        claim first requires exactly the prepared empty mount leaves
        before the sentinel lands durably."""
        instance_dir = context['instanceDir']
        sentinel = self._read_sentinel(instance_dir)
        if sentinel is not None and sentinel != restore_id:
            raise RestoreError('restore-incomplete')
        if sentinel is None:
            if journaled:
                # A recorded job without its sentinel means an earlier
                # commit already ran the removal step.
                raise RestoreError('restore-incomplete')
            self._check_fresh_leaves(context)
        self._write_sentinel(instance_dir, restore_id)

    def _unwind_claim(self, instance_dir, restore_id):
        """Best-effort unwind of a fresh sentinel claim whose stage
        failed before its state became resumable: the sentinel is
        released only when no journal landed — a recorded job keeps
        its claim so replay can resume — and only our own restoreId is
        ever removed. A crash or failure here still leaves the
        same-restoreId adoption path, so the sentinel can never wedge
        the slot permanently."""
        try:
            if self._load_job(restore_id) is not None:
                return
        except RestoreError:
            return
        try:
            if self._read_sentinel(instance_dir) != restore_id:
                return
            os.unlink(self._sentinel_path(instance_dir))
            _fsync_dir(instance_dir)
        except (OSError, RestoreError):
            pass

    def _check_fresh_leaves(self, context):
        """A fresh claim requires exactly the prepared empty mount
        leaves — the sentinel and staging area are only ever added by
        this worker itself."""
        instance_dir = context['instanceDir']
        slot = context['slot']
        st = _lstat_or_none(instance_dir)
        if st is None or not stat.S_ISDIR(st.st_mode) \
                or stat.S_ISLNK(st.st_mode) or st.st_uid != os.geteuid() \
                or stat.S_IMODE(st.st_mode) != 0o700:
            raise RestoreError('storage-state-conflict')
        try:
            names = set(os.listdir(instance_dir))
        except OSError:
            raise RestoreError('path-unavailable') from None
        mounts = {mount['id']: mount
                  for mount in context['definition']['stateMounts']}
        if names != set(mounts):
            raise RestoreError('storage-state-conflict')
        for mount_id, mount in mounts.items():
            leaf = os.path.join(instance_dir, mount_id)
            st = _lstat_or_none(leaf)
            if st is None or not stat.S_ISDIR(st.st_mode) \
                    or stat.S_ISLNK(st.st_mode) \
                    or st.st_uid != slot['uidBase'] + mount['ownerUid'] \
                    or st.st_gid != slot['uidBase'] + mount['ownerGid']:
                raise RestoreError('storage-state-conflict')
            try:
                if os.listdir(leaf):
                    raise RestoreError('storage-state-conflict')
            except OSError:
                raise RestoreError('path-unavailable') from None

    def _check_staged(self, context, translation):
        """The durable staging area must hold exactly the manifest's
        mount set with fully translated mount-root ownership."""
        staging = self._staging_path(context['instanceDir'])
        st = _lstat_or_none(staging)
        if st is None or not stat.S_ISDIR(st.st_mode) \
                or stat.S_ISLNK(st.st_mode) \
                or st.st_uid != os.geteuid():
            raise RestoreError('restore-incomplete')
        mounts = {mount['id']: mount
                  for mount in context['definition']['stateMounts']}
        try:
            names = set(os.listdir(staging))
        except OSError:
            raise RestoreError('path-unavailable') from None
        if names != set(mounts):
            raise RestoreError('restore-incomplete')
        base = translation['targetUidBase']
        for mount_id, mount in mounts.items():
            st = _lstat_or_none(os.path.join(staging, mount_id))
            if st is None or not stat.S_ISDIR(st.st_mode) \
                    or stat.S_ISLNK(st.st_mode) \
                    or st.st_uid != base + mount['ownerUid'] \
                    or st.st_gid != base + mount['ownerGid']:
                raise RestoreError('restore-incomplete')

    # -- stage ------------------------------------------------------------

    def _translate(self, job, context):
        """Extract the bound snapshot and copy its state tree through
        the idmapped view into the durable staging area."""
        request = job['request']
        scratch = os.path.join(self._scratch_dir, request['restoreId'])
        _ensure_private_dir(scratch)
        extract = os.path.join(scratch, 'extract')
        view = os.path.join(scratch, 'view')
        staging = self._staging_path(context['instanceDir'])
        translation = job['translation']
        idmap = 'b:0:0:1 b:{}:{}:65536'.format(
            translation['sourceUidBase'], translation['targetUidBase'])
        repo, _record = self._verify_point(request, job)
        _remove_tree(extract)
        _remove_tree(staging)
        _ensure_private_dir(view)
        try:
            if os.listdir(view):
                raise RestoreError('path-unsafe')
        except OSError:
            raise RestoreError('path-unavailable') from None
        _ensure_private_dir(staging)
        mounted = False
        try:
            repo.restore(request['snapshotId'], extract)
            self._mounts.mount(os.path.join(extract, 'state'),
                               view, idmap)
            mounted = True
            result = self.runner.run(
                ['cp', '--archive', '--reflink=auto',
                 '--no-target-directory', view, staging],
                timeout=_BULK_TIMEOUT)
            if result.returncode != 0:
                raise RestoreError('translation-failed')
        except repository.RepositoryError as error:
            raise RestoreError(error.code) from None
        finally:
            if mounted:
                self._mounts.unmount(view)
        # The verbatim repository extract is scratch only — once the
        # translated copy is durable it is removed; a crashed attempt
        # is cleaned by the next run's _remove_tree above.
        _remove_tree(extract)
        self._check_staged(context, translation)
        try:
            result = self.runner.run(['sync', '-f', staging], timeout=60)
        except repository.RepositoryError:
            raise RestoreError('path-unavailable') from None
        if result.returncode != 0:
            raise RestoreError('path-unavailable')
        _fsync_dir(staging)
        _fsync_dir(context['instanceDir'])

    def _stage(self, request):
        self._acquire_lock()
        job = self._load_job(request['restoreId'])
        if job is not None:
            self._check_job_request(job, request)
            self._check_job_config(job)
            if job['phase'] == 'committed':
                return {'schemaVersion': 1, 'status': 'completed',
                        'action': 'stage',
                        'restoreId': request['restoreId'],
                        'record': job['record']}
        # The sentinel claim rides inside the target freshness check:
        # both run under the worker flock, so a raced ``start`` either
        # already moved the phase off ``prepared`` before the lock was
        # taken or fails its own ``_restore_pending`` gate once the
        # lock passes to it. A crash between the durable claim and the
        # journal write below is adopted by the same restoreId replay.
        context = self._target_context(
            request, claim=request['restoreId'],
            journaled=job is not None)
        slot = context['slot']
        if job is not None \
                and job['translation']['targetUidBase'] \
                != slot['uidBase']:
            raise RestoreError('restore-conflict')
        fresh = job is None
        try:
            _repo, record = self._verify_point(request, job)
            if fresh:
                job = {
                    'schemaVersion': 1, 'request': dict(request),
                    'configDigest': self._config_digest,
                    'record': record,
                    'translation': {
                        'sourceUidBase': record['manifest']['source']
                        ['uidBase'],
                        'targetUidBase': slot['uidBase']},
                    'phase': 'pending',
                    'stagedAt': None, 'committedAt': None,
                }
                self._save_job(job)
        except Exception:
            if fresh:
                # A clean failure must not wedge the slot: release the
                # claim unless the journal already landed, in which
                # case the sentinel stays and replay resumes it. The
                # unwind is best-effort and never masks the original
                # error — the adoption path always remains.
                try:
                    self._unwind_claim(context['instanceDir'],
                                       request['restoreId'])
                except Exception:
                    pass
            raise
        if job['phase'] == 'pending':
            self._translate(job, context)
            job['phase'] = 'staged'
            job['stagedAt'] = self._now()
            self._save_job(job)
        else:
            # The in-lock claim already re-proved and refreshed the
            # sentinel; staged replay still verifies the translated
            # tree is intact before reporting completion.
            self._check_staged(context, job['translation'])
        return {'schemaVersion': 1, 'status': 'completed',
                'action': 'stage', 'restoreId': request['restoreId'],
                'record': job['record']}

    # -- commit -----------------------------------------------------------

    def _commit(self, request):
        self._acquire_lock()
        job = self._load_job(request['restoreId'])
        if job is None:
            raise RestoreError('restore-missing')
        self._check_job_config(job)
        if job['phase'] == 'committed':
            return {'schemaVersion': 1, 'status': 'completed',
                    'action': 'commit', 'restoreId': request['restoreId'],
                    'record': job['record'],
                    'committedAt': job['committedAt']}
        if job['phase'] != 'staged':
            raise RestoreError('restore-not-staged')
        context = self._target_context(job['request'])
        slot = context['slot']
        if slot['uidBase'] != job['translation']['targetUidBase']:
            raise RestoreError('restore-conflict')
        staging = self._staging_path(context['instanceDir'])
        staging_st = _lstat_or_none(staging)
        if staging_st is not None and (
                not stat.S_ISDIR(staging_st.st_mode)
                or stat.S_ISLNK(staging_st.st_mode)
                or staging_st.st_uid != os.geteuid()):
            raise RestoreError('restore-incomplete')
        instance_dir = context['instanceDir']
        # A foreign sentinel means a different pending restore owns
        # this instance; a missing one means an earlier commit already
        # passed the removal step — replay converges below.
        sentinel = self._read_sentinel(instance_dir)
        if sentinel is not None and sentinel != request['restoreId']:
            raise RestoreError('restore-incomplete')
        mounts = {mount['id']: mount
                  for mount in context['definition']['stateMounts']}
        base = job['translation']['targetUidBase']
        for mount_id in sorted(mounts):
            mount = mounts[mount_id]
            source = os.path.join(staging, mount_id)
            leaf = os.path.join(instance_dir, mount_id)
            st = _lstat_or_none(source)
            if st is None:
                # Already moved by an interrupted commit: the leaf
                # must carry the translated mount-root ownership.
                leaf_st = _lstat_or_none(leaf)
                if leaf_st is None \
                        or not stat.S_ISDIR(leaf_st.st_mode) \
                        or stat.S_ISLNK(leaf_st.st_mode) \
                        or leaf_st.st_uid != base + mount['ownerUid'] \
                        or leaf_st.st_gid != base + mount['ownerGid']:
                    raise RestoreError('restore-incomplete')
                continue
            if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) \
                    or st.st_uid != base + mount['ownerUid'] \
                    or st.st_gid != base + mount['ownerGid']:
                raise RestoreError('restore-incomplete')
            leaf_st = _lstat_or_none(leaf)
            if leaf_st is not None:
                if not stat.S_ISDIR(leaf_st.st_mode) \
                        or stat.S_ISLNK(leaf_st.st_mode):
                    raise RestoreError('storage-state-conflict')
                try:
                    if os.listdir(leaf):
                        raise RestoreError('storage-state-conflict')
                    os.rmdir(leaf)
                except OSError:
                    raise RestoreError('path-unavailable') from None
            try:
                os.rename(source, leaf)
            except OSError:
                raise RestoreError('path-unavailable') from None
            _fsync_dir(instance_dir)
        # The sentinel is removed only after every mount leaf is in
        # place; a crash before this point replays the move above.
        if staging_st is not None:
            try:
                os.rmdir(staging)
            except OSError:
                raise RestoreError('restore-incomplete') from None
        _fsync_dir(instance_dir)
        try:
            os.unlink(self._sentinel_path(instance_dir))
        except FileNotFoundError:
            pass
        except OSError:
            raise RestoreError('path-unavailable') from None
        _fsync_dir(instance_dir)
        _fsync_dir(context['rec']['binding']['storage']['root'])
        job['phase'] = 'committed'
        job['committedAt'] = self._now(job['stagedAt'])
        self._save_job(job)
        return {'schemaVersion': 1, 'status': 'completed',
                'action': 'commit', 'restoreId': request['restoreId'],
                'record': job['record'], 'committedAt': job['committedAt']}

    # -- status -----------------------------------------------------------

    def _status(self, request):
        self._acquire_lock()
        job = self._load_job(request['restoreId'])
        if job is None:
            raise RestoreError('restore-missing')
        return {'schemaVersion': 1, 'status': 'completed',
                'action': 'status', 'restoreId': request['restoreId'],
                'phase': job['phase'], 'record': job['record'],
                'stagedAt': job['stagedAt'],
                'committedAt': job['committedAt']}

    # -- clock --------------------------------------------------------------

    def _now(self, minimum=0):
        value = self.clock()
        if type(value) is bool or type(value) not in (int, float) \
                or not math.isfinite(value):
            raise RestoreError('clock-invalid')
        now = int(value)
        if now < minimum or now < 0 or now > 2**53:
            raise RestoreError('clock-invalid')
        return now

    # -- dispatch ---------------------------------------------------------

    def execute(self, request):
        try:
            return self._execute(request)
        finally:
            # The global journal flock serializes one operation;
            # it is never held across calls or by leaked handles.
            self._release_lock()

    def _execute(self, request):
        restore_id = request.get('restoreId') if type(request) is dict \
            else None
        try:
            if type(request) is not dict \
                    or type(request.get('schemaVersion')) is not int \
                    or request['schemaVersion'] != 1:
                raise RestoreError('invalid-request')
            action = request.get('action')
            if action == 'stage':
                _validate_stage_request(request)
                return self._stage(request)
            if action == 'commit':
                if set(request) != _COMMIT_FIELDS:
                    raise RestoreError('invalid-request')
                _hex32(request['restoreId'], 'request restoreId')
                return self._commit(request)
            if action == 'status':
                if set(request) != _STATUS_FIELDS:
                    raise RestoreError('invalid-request')
                _hex32(request['restoreId'], 'request restoreId')
                return self._status(request)
            raise RestoreError('invalid-request')
        except RestoreError as error:
            return {'schemaVersion': 1, 'status': 'blocked',
                    'error': error.code, 'restoreId': restore_id}
        except worker.WorkerError as error:
            return {'schemaVersion': 1, 'status': 'blocked',
                    'error': error.code, 'restoreId': restore_id}
        except repository.RepositoryError as error:
            return {'schemaVersion': 1, 'status': 'blocked',
                    'error': error.code, 'restoreId': restore_id}
        except statefiles.PathError as error:
            return {'schemaVersion': 1, 'status': 'blocked',
                    'error': error.code, 'restoreId': restore_id}
        except _INTERNAL_ERRORS:
            return {'schemaVersion': 1, 'status': 'blocked',
                    'error': 'internal-error', 'restoreId': restore_id}


def main(argv=None):
    parser = argparse.ArgumentParser(prog='nexus-restore')
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
        instance = RestoreWorker(config)
    except (RestoreError, worker.WorkerError) as error:
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
