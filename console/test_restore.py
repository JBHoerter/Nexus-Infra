import copy
import fcntl
import hashlib
import json
import os
import shutil
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import artifacts
import catalog
import recovery
import repository
import restore
import statefiles
import worker
from test_catalog import sealed
from test_repository import (Completed, legacy_v2_manifest,
                             make_private_dir, write_private_file)


INSTANCE = 'ab' * 16
SOURCE_INSTANCE = 'cd' * 16
RESTORE_ID = 'd5' * 16
SNAPSHOT = 'e' * 64
REPO_IDENTITY = 'f' * 64
REVISION = sealed()['revisionDigest']
SRC_BASE = 65536
DST_BASE = 262144
SENTINEL = worker._RESTORE_SENTINEL


def stage_request(**overrides):
    request = {'schemaVersion': 1, 'action': 'stage',
               'restoreId': RESTORE_ID, 'repositoryId': 'repo-a',
               'snapshotId': SNAPSHOT,
               'target': {'workloadId': 'demo', 'revisionDigest': REVISION,
                          'instanceId': INSTANCE, 'generation': 2,
                          'slotId': 's1'}}
    request.update(overrides)
    return request


def commit_request(**overrides):
    request = {'schemaVersion': 1, 'action': 'commit',
               'restoreId': RESTORE_ID}
    request.update(overrides)
    return request


def status_request(**overrides):
    request = {'schemaVersion': 1, 'action': 'status',
               'restoreId': RESTORE_ID}
    request.update(overrides)
    return request


class OwnerMap:
    """Inode-keyed fake ownership: registration survives rename, so a
    translated staging leaf keeps its fake owner after os.rename."""

    def __init__(self):
        self.by_ino = {}

    def claim(self, path, uid, gid):
        st = os.lstat(path)
        self.by_ino[(st.st_dev, st.st_ino)] = (uid, gid)

    def lookup(self, path):
        st = os.lstat(path)
        return self.by_ino.get((st.st_dev, st.st_ino),
                               (st.st_uid, st.st_gid))

    def lookup_stat(self, st):
        return self.by_ino.get((st.st_dev, st.st_ino),
                               (st.st_uid, st.st_gid))


def clone_tree(source, destination, owners, translate):
    """`cp --archive`-like copy of ``source``'s children into an
    existing ``destination``, registering translated ownership per
    inode (the idmapped view the real mount would expose)."""
    for dirpath, dirnames, filenames in os.walk(source):
        rel = os.path.relpath(dirpath, source)
        target_dir = destination if rel == '.' \
            else os.path.join(destination, rel)
        for name in dirnames:
            src = os.path.join(dirpath, name)
            dst = os.path.join(target_dir, name)
            if os.path.islink(src):
                os.symlink(os.readlink(src), dst)
            else:
                os.mkdir(dst)
                shutil.copystat(src, dst)
            uid, gid = owners.lookup(src)
            owners.claim(dst, *translate(uid, gid))
        for name in filenames:
            src = os.path.join(dirpath, name)
            dst = os.path.join(target_dir, name)
            if os.path.islink(src):
                os.symlink(os.readlink(src), dst)
            else:
                shutil.copy2(src, dst)
            uid, gid = owners.lookup(src)
            owners.claim(dst, *translate(uid, gid))


class FakeMounts:
    """Idmapped bind-view double: copies the extracted tree into the
    view target applying the declared ``b:src:dst:65536`` shift to the
    registered owners, and removes only its own copies on unmount."""

    def __init__(self, owners):
        self.owners = owners
        self.mounted = []
        self.unmounted = []
        self.idmaps = []
        self.fail_mount = False
        self._views = {}

    def mount(self, source, target, idmap):
        if self.fail_mount:
            raise restore.RestoreError('mount-failed')
        self.mounted.append((source, target))
        self.idmaps.append(idmap)
        shift = {}
        for entry in idmap.split():
            _kind, src, dst, count = entry.split(':')
            shift[(int(src), int(src) + int(count))] = int(dst)

        def translate(uid, gid):
            for (low, high), base in shift.items():
                if low <= uid < high:
                    return base + (uid - low), base + (gid - low)
            return uid, gid
        clone_tree(source, target, self.owners, translate)
        self._views[target] = list(os.listdir(target))

    def unmount(self, target):
        self.unmounted.append(target)
        for name in self._views.pop(target, []):
            path = os.path.join(target, name)
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                os.unlink(path)


class FakeShell:
    """Runner seam for translate/copy/fsync utilities."""

    def __init__(self, owners):
        self.owners = owners
        self.calls = []
        self.rc = 0
        self.copy_owner_shift = None
        self.fail_cp = False

    def run(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv[0] == 'cp':
            if self.fail_cp:
                return Completed(1, b'', b'cp failed')
            source, dest = argv[-2], argv[-1]

            def keep(uid, gid):
                if self.copy_owner_shift is not None:
                    return uid + self.copy_owner_shift, \
                        gid + self.copy_owner_shift
                return uid, gid
            clone_tree(source, dest, self.owners, keep)
            return Completed(0, b'', b'')
        if argv[0] == 'sync':
            return Completed(self.rc, b'', b'forced failure')
        return Completed(self.rc, b'', b'forced failure')


class FakeRepo:
    """Repository adapter double: a pinned snapshot map whose restore
    materializes trees and registers source-base ownership."""

    def __init__(self, owners):
        self.owners = owners
        self.points = {}
        self.fail_inspect = None
        self.fail_restore = False
        self.restored = []

    def add_point(self, snapshot_id, manifest, state_digest, trees):
        self.points[snapshot_id] = {
            'manifest': copy.deepcopy(manifest),
            'stateDigest': state_digest, 'trees': trees}

    def _receipt(self, snapshot_id, manifest):
        return {'schemaVersion': 1, 'repositoryId': 'repo-a',
                'repositoryIdentity': REPO_IDENTITY,
                'snapshotId': snapshot_id, 'manifest': manifest}

    def inspect(self, snapshot_id):
        if self.fail_inspect is not None:
            raise repository.RepositoryError(self.fail_inspect)
        point = self.points.get(snapshot_id)
        if point is None:
            raise repository.RepositoryError('repository-point-invalid')
        return self._receipt(snapshot_id, copy.deepcopy(
            point['manifest']))

    def _snapshot_state_digest(self, snapshot_id, tag):
        point = self.points.get(snapshot_id)
        if point is None:
            raise repository.RepositoryError('repository-point-invalid')
        return point['stateDigest']

    def restore(self, snapshot_id, destination):
        if self.fail_restore:
            raise repository.RepositoryError('repository-command-failed')
        point = self.points.get(snapshot_id)
        if point is None:
            raise repository.RepositoryError('repository-point-invalid')
        manifest = point['manifest']
        uid_base = manifest['source']['uidBase']
        mounts = {mount['id']: mount
                  for mount in manifest['definition']['stateMounts']}
        os.mkdir(destination, 0o700)
        state = os.path.join(destination, 'state')
        os.mkdir(state, 0o700)
        for mount_id, files in point['trees'].items():
            mount = mounts[mount_id]
            leaf = os.path.join(state, mount_id)
            os.mkdir(leaf, 0o700)
            self.owners.claim(leaf, uid_base + mount['ownerUid'],
                              uid_base + mount['ownerGid'])
            for name, data in files.items():
                path = os.path.join(leaf, name)
                with open(path, 'wb') as handle:
                    handle.write(data)
                self.owners.claim(path, uid_base + mount['ownerUid'],
                                  uid_base + mount['ownerGid'])
        raw = recovery.encode_manifest(manifest)
        with open(os.path.join(destination, 'manifest.json'),
                  'wb') as handle:
            handle.write(raw)
        self.restored.append((snapshot_id, destination))
        return self._receipt(snapshot_id, copy.deepcopy(manifest))


class LockStub:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class FakeWorker:
    """Worker double covering the private interface RestoreWorker uses:
    record snapshot under its lock plus observe."""

    def __init__(self, config):
        self.config = config
        self.recs = {}
        self.definitions = {}
        self.state_dirs = {}
        self.observe = None
        self.mount_ok = True
        self.executed = []
        self.closed = False

    def _lock(self):
        return LockStub()

    def _get_instance(self, instance_id):
        return self.recs.get(instance_id)

    def _require_binding_current(self, rec):
        if rec['binding'] is None:
            raise worker.WorkerError('binding-missing')
        if rec['binding']['storage'] != self.config['storage']:
            raise worker.WorkerError('binding-changed')

    def _resolve(self, workload_id, revision_digest):
        return None, None, self.definitions[
            (workload_id, revision_digest)]

    def _check_action_allowed(self, definition, action):
        if action not in definition['allowedOperations']:
            raise worker.WorkerError('operation-not-allowed')

    def _verify_mount(self):
        if not self.mount_ok:
            raise worker.WorkerError('storage-not-mounted')
        return self.config['storage']['root']

    def _instance_dir(self, rec):
        return self.state_dirs[rec['instance_id']]

    def execute(self, request):
        self.executed.append(dict(request))
        if request['action'] == 'observe':
            observed = dict(self.observe)
            directory = self.state_dirs.get(request['instanceId'])
            observed['restorePending'] = directory is not None \
                and os.path.lexists(
                    os.path.join(directory, SENTINEL))
            return observed
        raise AssertionError('restore worker must never drive lifecycle')

    def start(self, instance_id):
        """Mirror of Worker._start's restore gate: inside the worker
        flock a prepared instance carrying the sentinel is refused and
        only a sentinel-free prepared instance may boot."""
        rec = self.recs[instance_id]
        if rec['phase'] != 'prepared':
            return 'phase-conflict'
        sentinel = os.path.join(self.state_dirs[instance_id], SENTINEL)
        if os.path.lexists(sentinel):
            return 'restore-incomplete'
        rec['phase'] = 'running'
        self.observe['phase'] = 'running'
        self.observe['unitActiveState'] = 'active'
        self.observe['unitDrained'] = False
        return 'completed'

    def close(self):
        self.closed = True


def worker_record(state_dir, slot, **overrides):
    rec = {'instance_id': INSTANCE, 'workload_id': 'demo',
           'revision_digest': REVISION, 'generation': 2,
           'slot_id': slot['id'], 'phase': 'prepared', 'retired': 0,
           'binding': {'hostId': 'host-b',
                       'architecture': 'x86_64-linux',
                       'storage': {'root': state_dir,
                                   'mountPoint': state_dir,
                                   'uuid': '9f013958-f0b2-48cd'},
                       'slot': copy.deepcopy(slot)}}
    rec.update(overrides)
    return rec


def observe_record(**overrides):
    record = {'schemaVersion': 1, 'action': 'observe',
              'instanceId': INSTANCE, 'hostId': 'host-b',
              'revisionDigest': REVISION, 'generation': 2,
              'phase': 'prepared', 'bindingCurrent': True,
              'retired': False, 'captureId': None,
              'unitActiveState': 'inactive', 'unitDrained': True}
    record.update(overrides)
    return record


def make_manifest(definition=None, secret_bundle=None,
                  **source_overrides):
    source = {'hostId': 'host-a', 'instanceId': SOURCE_INSTANCE,
              'generation': 1, 'uidBase': SRC_BASE}
    source.update(source_overrides)
    return recovery.build_manifest(
        definition or catalog.validate_definition(sealed()), source,
        {'adapter': 'quiesce-v1', 'consistency': 'quiesced',
         'startedAt': 1000, 'completedAt': 1010},
        state_tree_digests={'data': 'sha256:' + '2' * 64},
        state_set_digest='sha256:' + '3' * 64,
        secret_bundle=secret_bundle)


class RestoreFixture(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        self.owners = OwnerMap()
        self.private = make_private_dir(self.root, 'private')
        self.restore_dir = make_private_dir(self.root, 'restore-state')
        self.worker_dir = make_private_dir(self.root, 'worker-state')
        self.storage = make_private_dir(self.root, 'storage')
        self.repo_dir = make_private_dir(self.root, 'repo')
        self.repo_pw = write_private_file(
            os.path.join(self.private, 'repo-pass'), b'repo-key')
        self.slot = {'id': 's1', 'uidBase': DST_BASE,
                     'hostAddress': '10.10.1.2',
                     'localAddress': '10.10.1.3'}
        self.worker_config_path = os.path.join(
            self.private, 'worker.json')
        self._write_worker_config()
        # The pinned admin worker config is modelled root-owned, as
        # the real validator requires.
        self.owners.claim(self.worker_config_path, 0, 0)
        self.instance_dir = os.path.join(self.storage, INSTANCE)
        os.mkdir(self.instance_dir, 0o700)
        leaf = os.path.join(self.instance_dir, 'data')
        os.mkdir(leaf, 0o700)
        self.owners.claim(leaf, DST_BASE, DST_BASE)
        self.definition = catalog.validate_definition(sealed())
        self.manifest = make_manifest(self.definition)
        self.fake_repo = FakeRepo(self.owners)
        self.fake_repo.add_point(SNAPSHOT, self.manifest,
                                 'sha256:' + '3' * 64,
                                 {'data': {'value': b'restored-marker'}})
        self.fake_worker = FakeWorker(self._worker_config_dict())
        self.fake_worker.recs[INSTANCE] = worker_record(
            self.storage, self.slot)
        self.fake_worker.definitions[('demo', REVISION)] = \
            self.definition
        self.fake_worker.state_dirs[INSTANCE] = self.instance_dir
        self.fake_worker.observe = observe_record()
        self.fake_mounts = FakeMounts(self.owners)
        self.fake_shell = FakeShell(self.owners)
        self.now = 2000.0
        self.addCleanup(mock.patch.stopall)
        real_lstat = os.lstat
        owners = self.owners

        def fake_lstat(path):
            result = real_lstat(path)
            uid, gid = owners.lookup_stat(result)
            return SimpleNamespace(st_mode=result.st_mode, st_uid=uid,
                                   st_gid=gid, st_ino=result.st_ino,
                                   st_dev=result.st_dev)
        mock.patch.object(restore, '_lstat', fake_lstat).start()
        real_fstat = os.fstat

        def fake_fstat(fd):
            result = real_fstat(fd)
            uid, gid = owners.lookup_stat(result)
            return SimpleNamespace(st_mode=result.st_mode, st_uid=uid,
                                   st_gid=gid, st_ino=result.st_ino,
                                   st_dev=result.st_dev)
        mock.patch.object(restore, '_fstat', fake_fstat).start()

    def _worker_config_dict(self):
        return {'schemaVersion': 1, 'hostId': 'host-b',
                'architecture': 'x86_64-linux',
                'stateDir': self.worker_dir,
                'storage': {'root': self.storage,
                            'mountPoint': self.storage,
                            'uuid': '9f013958-f0b2-48cd'},
                'capacity': {'memoryMiB': 256, 'cpuMillis': 1000,
                             'stateBytes': 1048576},
                'capabilities': ['nspawn-v1'],
                'approvedBundles': ['/nix/store/' + 'a' * 32 + '-b'],
                'slots': [{'id': 's0', 'uidBase': SRC_BASE,
                           'hostAddress': '10.10.0.2',
                           'localAddress': '10.10.0.3'},
                          self.slot]}

    def _write_worker_config(self):
        raw = artifacts.canonical_bytes(self._worker_config_dict())
        with open(self.worker_config_path, 'wb') as handle:
            handle.write(raw)
        os.chmod(self.worker_config_path, 0o600)

    def repo_config(self, repo_id='repo-a', identity=REPO_IDENTITY,
                    path=None):
        return {'schemaVersion': 1, 'id': repo_id,
                'repositoryIdentity': identity,
                'passwordFile': self.repo_pw,
                'transport': {'kind': 'local',
                              'path': path or self.repo_dir}}

    def restore_config(self, **overrides):
        config = {'schemaVersion': 1,
                  'stateDir': self.restore_dir,
                  'workerConfigFile': self.worker_config_path,
                  'repositories': [self.repo_config()]}
        config.update(overrides)
        return config

    def make(self, config=None, **kwargs):
        kwargs.setdefault('worker_factory',
                          lambda cfg: self.fake_worker)
        kwargs.setdefault('repo_factory', lambda cfg: self.fake_repo)
        kwargs.setdefault('runner', self.fake_shell)
        kwargs.setdefault('clock', lambda: self.now)
        kwargs.setdefault('mounts', self.fake_mounts)
        return restore.RestoreWorker(config or self.restore_config(),
                                     **kwargs)

    def job_path(self, restore_id=RESTORE_ID):
        return os.path.join(self.restore_dir, 'jobs',
                            restore_id + '.json')

    def read_job(self, restore_id=RESTORE_ID):
        return statefiles.read_json(self.job_path(restore_id),
                                    restore._MAX_JOB_BYTES)

    def sentinel_path(self):
        return os.path.join(self.instance_dir, SENTINEL)

    def expect_blocked(self, response, code):
        self.assertEqual(response['status'], 'blocked')
        self.assertEqual(response['error'], code)
        self.assertEqual(response['schemaVersion'], 1)
        self.assertIn('restoreId', response)


class ConfigTests(RestoreFixture):

    def expect_bad(self, config):
        with self.assertRaises(restore.RestoreError):
            self.make(config)

    def test_exact_fields(self):
        config = self.restore_config()
        config['extra'] = True
        self.expect_bad(config)
        for field in ('stateDir', 'workerConfigFile', 'repositories'):
            bad = self.restore_config()
            del bad[field]
            self.expect_bad(bad)
        self.expect_bad(self.restore_config(schemaVersion=2))

    def test_repository_ids_unique(self):
        repos = self.restore_config()['repositories']
        self.expect_bad(self.restore_config(repositories=repos + repos))
        bad = self.restore_config()
        bad['repositories'] = [dict(bad['repositories'][0],
                                    repositoryIdentity='not-hex')]
        self.expect_bad(bad)

    def test_config_deep_copy(self):
        config = self.restore_config()
        instance = self.make(config)
        try:
            config['repositories'][0]['transport']['path'] = '/nowhere'
            self.assertEqual(instance._config['repositories'][0]
                             ['transport']['path'], self.repo_dir)
        finally:
            instance.close()

    def test_state_dirs_created_private(self):
        instance = self.make()
        try:
            for name in (self.restore_dir,
                         os.path.join(self.restore_dir, 'jobs'),
                         os.path.join(self.restore_dir, 'scratch')):
                st = os.lstat(name)
                self.assertTrue(stat.S_ISDIR(st.st_mode))
                self.assertEqual(stat.S_IMODE(st.st_mode), 0o700)
        finally:
            instance.close()

    def test_state_dir_must_not_overlap_worker_paths(self):
        bad = self.restore_config(
            stateDir=os.path.join(self.storage, 'restore'))
        self.expect_bad(bad)
        bad = self.restore_config(
            stateDir=os.path.join(self.worker_dir, 'restore'))
        self.expect_bad(bad)
        repo = self.repo_config(path=self.storage)
        self.expect_bad(self.restore_config(repositories=[repo]))


class RequestTests(RestoreFixture):

    def test_request_shape(self):
        instance = self.make()
        try:
            bad = stage_request(extra=1)
            self.expect_blocked(instance.execute(bad), 'invalid-request')
            bad = stage_request()
            del bad['target']
            self.expect_blocked(instance.execute(bad), 'invalid-request')
            bad = stage_request(schemaVersion=2)
            self.expect_blocked(instance.execute(bad), 'invalid-request')
            bad = stage_request(action='commit', restoreId=RESTORE_ID,
                                extra=1)
            self.expect_blocked(instance.execute(bad), 'invalid-request')
            bad = stage_request(restoreId='xyz')
            self.expect_blocked(instance.execute(bad),
                                'invalid-request restoreId')
            bad = stage_request(snapshotId='0' * 63)
            self.expect_blocked(instance.execute(bad),
                                'invalid-request')
            target = dict(stage_request()['target'])
            target['generation'] = 0
            self.expect_blocked(
                instance.execute(stage_request(target=target)),
                'invalid-request generation')
            target = dict(stage_request()['target'])
            target['slotId'] = 'Bad Slot'
            self.expect_blocked(
                instance.execute(stage_request(target=target)),
                'invalid-request')
            self.expect_blocked(instance.execute(42), 'invalid-request')
            self.expect_blocked(
                instance.execute(commit_request(restoreId='nope')),
                'invalid-request restoreId')
        finally:
            instance.close()

    def test_bool_fields_rejected(self):
        instance = self.make()
        try:
            bad = stage_request(schemaVersion=True)
            self.expect_blocked(instance.execute(bad), 'invalid-request')
            target = dict(stage_request()['target'])
            target['generation'] = True
            self.expect_blocked(
                instance.execute(stage_request(target=target)),
                'invalid-request generation')
        finally:
            instance.close()


class StageTests(RestoreFixture):

    def stage(self, **kwargs):
        return self.make(**kwargs).execute(stage_request())

    def test_stage_translates_ownership_and_marks_pending(self):
        response = self.stage()
        self.assertEqual(response['status'], 'completed', response)
        self.assertEqual(response['record']['snapshotId'], SNAPSHOT)
        self.assertEqual(response['record']['manifest'], self.manifest)
        # The durable journal records stage completion only after the
        # translated copy exists and the sentinel is written.
        job = self.read_job()
        self.assertEqual(job['phase'], 'staged')
        self.assertEqual(job['translation'],
                         {'sourceUidBase': SRC_BASE,
                          'targetUidBase': DST_BASE})
        self.assertEqual(job['stagedAt'], 2000)
        sentinel = statefiles.read_json(self.sentinel_path(),
                                        restore._MAX_SENTINEL_BYTES)
        self.assertEqual(sentinel, {'schemaVersion': 1,
                                    'restoreId': RESTORE_ID})
        staging = os.path.join(self.instance_dir, '.nexus-restore-staging')
        self.assertEqual(sorted(os.listdir(staging)), ['data'])
        leaf = os.path.join(staging, 'data')
        self.assertEqual(self.owners.lookup(leaf),
                         (DST_BASE, DST_BASE))
        value = os.path.join(staging, 'data', 'value')
        self.assertEqual(self.owners.lookup(value),
                         (DST_BASE, DST_BASE))
        with open(value, 'rb') as handle:
            self.assertEqual(handle.read(), b'restored-marker')
        # The proven idmap order (filesystem id first, then the
        # mount-view id) is what reached the mount call.
        self.assertEqual(self.fake_mounts.idmaps,
                         ['b:0:0:1 b:{}:{}:65536'.format(
                             SRC_BASE, DST_BASE)])
        self.assertEqual(len(self.fake_mounts.unmounted), 1)
        # The prepared leaves stay untouched until commit.
        self.assertTrue(os.path.isdir(
            os.path.join(self.instance_dir, 'data')))
        self.assertEqual(os.listdir(
            os.path.join(self.instance_dir, 'data')), [])

    def test_stage_replay_returns_identical_record(self):
        first = self.stage()
        again = self.make().execute(stage_request())
        self.assertEqual(again, first)
        self.assertEqual(self.read_job()['phase'], 'staged')

    def test_stage_pending_replay_redoes_translation(self):
        self.fake_shell.fail_cp = True
        response = self.stage()
        self.expect_blocked(response, 'translation-failed')
        self.assertEqual(self.read_job()['phase'], 'pending')
        self.assertTrue(os.path.exists(self.sentinel_path()))
        self.fake_shell.fail_cp = False
        response = self.make().execute(stage_request())
        self.assertEqual(response['status'], 'completed', response)
        self.assertEqual(self.read_job()['phase'], 'staged')

    def test_stage_claims_sentinel_inside_worker_lock(self):
        # The claim must be durable before the worker flock is
        # released — ahead of the journal write and any repository
        # I/O — or a raced ``start`` could slip between the freshness
        # check and the sentinel write.
        probe = []
        fixture = self

        class ProbedLock(LockStub):
            def close(self):
                probe.append((
                    os.path.lexists(fixture.sentinel_path()),
                    os.path.exists(fixture.job_path())))
                super().close()

        self.fake_worker._lock = lambda: ProbedLock()
        response = self.stage()
        self.assertEqual(response['status'], 'completed', response)
        self.assertEqual(probe, [(True, False)])

    def test_stage_sentinel_blocks_racing_start(self):
        # A ``start`` racing into the window between the flock-held
        # claim and the staging work must fail the worker's
        # ``_restore_pending`` gate and leave the instance prepared.
        raced = []
        real_inspect = self.fake_repo.inspect

        def inspect_during_race(snapshot_id):
            sentinel = statefiles.read_json(
                self.sentinel_path(), restore._MAX_SENTINEL_BYTES)
            self.assertEqual(sentinel, {'schemaVersion': 1,
                                        'restoreId': RESTORE_ID})
            raced.append(self.fake_worker.start(INSTANCE))
            return real_inspect(snapshot_id)

        self.fake_repo.inspect = inspect_during_race
        response = self.stage()
        self.assertEqual(response['status'], 'completed', response)
        self.assertEqual(set(raced), {'restore-incomplete'})
        self.assertEqual(self.fake_worker.recs[INSTANCE]['phase'],
                         'prepared')

    def test_stage_start_wins_flock_race(self):
        # A ``start`` whose critical section completed just before the
        # claim has already flipped the phase: the freshness check
        # inside the lock must see it and no sentinel may be left.
        real_lock = self.fake_worker._lock
        worker = self.fake_worker

        def lock_after_start():
            worker.recs[INSTANCE]['phase'] = 'starting'
            return real_lock()

        self.fake_worker._lock = lock_after_start
        self.expect_blocked(self.stage(), 'instance-not-fresh')
        self.assertIsNone(self.read_job())
        self.assertFalse(os.path.exists(self.sentinel_path()))

    def test_stage_verify_failure_releases_claim(self):
        self.fake_repo.fail_inspect = 'repository-command-failed'
        self.expect_blocked(self.stage(), 'repository-command-failed')
        self.assertIsNone(self.read_job())
        # A fresh claim whose stage fails before the journal lands is
        # released: the slot is neither wedged nor fenced against a
        # raced start, and the same restoreId may retry.
        self.assertFalse(os.path.exists(self.sentinel_path()))
        self.fake_repo.fail_inspect = None
        response = self.make().execute(stage_request())
        self.assertEqual(response['status'], 'completed', response)
        self.assertEqual(self.read_job()['phase'], 'staged')

    def test_stage_verify_failure_frees_other_restore_id(self):
        self.fake_repo.fail_inspect = 'repository-command-failed'
        self.expect_blocked(self.stage(), 'repository-command-failed')
        self.fake_repo.fail_inspect = None
        other = stage_request(restoreId='9e' * 16)
        response = self.make().execute(other)
        self.assertEqual(response['status'], 'completed', response)
        self.assertEqual(self.read_job('9e' * 16)['phase'], 'staged')

    def test_stage_journal_write_failure_releases_claim(self):
        real_write = statefiles.write_json
        fail = {'on': True}

        def flaky_write(path, value):
            if fail['on'] and path == self.job_path():
                raise OSError(28, 'simulated journal failure')
            return real_write(path, value)

        mock.patch.object(statefiles, 'write_json', flaky_write).start()
        self.expect_blocked(self.stage(), 'path-unavailable')
        self.assertIsNone(self.read_job())
        self.assertFalse(os.path.exists(self.sentinel_path()))
        fail['on'] = False
        response = self.make().execute(stage_request())
        self.assertEqual(response['status'], 'completed', response)
        self.assertEqual(self.read_job()['phase'], 'staged')

    def test_stage_pending_conflicts_other_restore_id(self):
        self.fake_shell.fail_cp = True
        self.expect_blocked(self.stage(), 'translation-failed')
        self.assertEqual(self.read_job()['phase'], 'pending')
        # While the claim is held a different restoreId conflicts and
        # a raced start stays refused; the same restoreId resumes.
        other = stage_request(restoreId='9e' * 16)
        self.expect_blocked(self.make().execute(other),
                            'restore-incomplete')
        self.assertEqual(self.fake_worker.start(INSTANCE),
                         'restore-incomplete')
        self.fake_shell.fail_cp = False
        response = self.make().execute(stage_request())
        self.assertEqual(response['status'], 'completed', response)

    def test_stage_adopts_orphaned_claim(self):
        # A crash between the flock-held claim and the journal write
        # leaves a sentinel with no job: the same restoreId adopts it.
        statefiles.write_json(
            self.sentinel_path(),
            {'schemaVersion': 1, 'restoreId': RESTORE_ID})
        response = self.make().execute(stage_request())
        self.assertEqual(response['status'], 'completed', response)
        self.assertEqual(self.read_job()['phase'], 'staged')

    def test_stage_rejects_unknown_instance(self):
        self.fake_worker.recs.clear()
        self.expect_blocked(self.stage(), 'unknown-instance')
        self.assertIsNone(self.read_job())
        self.assertFalse(os.path.exists(self.sentinel_path()))

    def test_stage_rejects_started_instance(self):
        for phase in ('stopped', 'running', 'starting', 'stopping'):
            self.fake_worker.recs[INSTANCE]['phase'] = phase
            self.fake_worker.observe['phase'] = phase
            response = self.stage()
            self.expect_blocked(response, 'instance-not-fresh')
            self.assertIsNone(self.read_job())
            self.assertFalse(os.path.exists(self.sentinel_path()))
            self.fake_worker.recs[INSTANCE]['phase'] = 'prepared'
            self.fake_worker.observe['phase'] = 'prepared'

    def test_stage_rejects_retired_instance(self):
        self.fake_worker.recs[INSTANCE]['retired'] = 1
        self.expect_blocked(self.stage(), 'instance-retired')

    def test_stage_rejects_wrong_identity(self):
        bad = stage_request()
        bad['target']['generation'] = 3
        self.expect_blocked(self.make().execute(bad),
                            'instance-conflict')
        bad = stage_request()
        bad['target']['slotId'] = 's0'
        self.expect_blocked(self.make().execute(bad),
                            'instance-conflict')
        bad = stage_request()
        bad['target']['workloadId'] = 'other'
        self.expect_blocked(self.make().execute(bad),
                            'instance-conflict')

    def test_stage_rejects_unknown_repository(self):
        bad = stage_request(repositoryId='repo-missing')
        self.expect_blocked(self.make().execute(bad),
                            'repository-unapproved')

    def test_stage_rejects_legacy_manifest(self):
        legacy = legacy_v2_manifest(self.manifest)
        self.fake_repo.add_point('a' * 64, legacy, 'sha256:' + '3' * 64,
                                 {'data': {'value': b'x'}})
        bad = stage_request(snapshotId='a' * 64)
        self.expect_blocked(self.make().execute(bad),
                            'manifest-unsupported')
        self.assertIsNone(self.read_job())
        self.assertFalse(os.path.exists(self.sentinel_path()))

    def test_stage_rejects_revision_mismatch(self):
        other = catalog.validate_definition(
            sealed(displayName='Other'))
        manifest = make_manifest(other)
        self.fake_repo.add_point('b' * 64, manifest,
                                 'sha256:' + '3' * 64,
                                 {'data': {'value': b'x'}})
        bad = stage_request(snapshotId='b' * 64)
        self.expect_blocked(self.make().execute(bad), 'point-mismatch')
        self.assertIsNone(self.read_job())

    def test_stage_rejects_state_digest_mismatch(self):
        self.fake_repo.points[SNAPSHOT]['stateDigest'] = \
            'sha256:' + '9' * 64
        self.expect_blocked(self.stage(), 'point-mismatch')
        self.assertIsNone(self.read_job())

    def test_stage_rejects_foreign_sentinel(self):
        statefiles.write_json(
            self.sentinel_path(),
            {'schemaVersion': 1, 'restoreId': '9e' * 16})
        self.expect_blocked(self.stage(), 'restore-incomplete')
        self.assertIsNone(self.read_job())

    def test_stage_rejects_nonempty_leaf(self):
        stray = os.path.join(self.instance_dir, 'data', 'stray')
        with open(stray, 'wb') as handle:
            handle.write(b'x')
        self.expect_blocked(self.stage(), 'storage-state-conflict')

    def test_stage_rejects_extra_state_dir_entry(self):
        os.mkdir(os.path.join(self.instance_dir, 'stray'), 0o700)
        self.expect_blocked(self.stage(), 'storage-state-conflict')

    def test_stage_rejects_wrong_leaf_ownership(self):
        leaf = os.path.join(self.instance_dir, 'data')
        self.owners.claim(leaf, SRC_BASE, SRC_BASE)
        self.expect_blocked(self.stage(), 'storage-state-conflict')

    def _secrets_target(self):
        """Rewire the fixture to a secrets-bearing target: a distinct
        revision, the provisioned ``secrets/`` dir and the worker's
        marker inside the prepared instance dir, and a recovery point
        carrying the bound ``secretBundle`` triple."""
        secrets_def = catalog.validate_definition(
            sealed(secretSetRef='lab-secrets'))
        revision = secrets_def['revisionDigest']
        bundle = {'secretSetRef': 'lab-secrets',
                  'versionDigest': 'sha256:' + '5' * 64,
                  'bundleDigest': 'sha256:' + '6' * 64}
        manifest = make_manifest(definition=secrets_def,
                                 secret_bundle=bundle)
        self.fake_repo.add_point(
            '7' * 64, manifest, 'sha256:' + '3' * 64,
            {'data': {'value': b'restored-marker'}})
        self.fake_worker.definitions[('demo', revision)] = secrets_def
        self.fake_worker.recs[INSTANCE] = worker_record(
            self.storage, self.slot, revision_digest=revision)
        secrets_dir = os.path.join(self.instance_dir,
                                   worker._SECRETS_DIR)
        os.mkdir(secrets_dir, 0o700)
        self.owners.claim(secrets_dir, DST_BASE, DST_BASE)
        secret = os.path.join(secrets_dir, 'app.env')
        write_private_file(secret, b'A=1\n')
        self.owners.claim(secret, DST_BASE, DST_BASE)
        marker = os.path.join(self.instance_dir,
                              worker._SECRETS_MARKER)
        write_private_file(marker, artifacts.canonical_bytes(bundle))
        return revision

    def _secrets_request(self, revision):
        target = {'workloadId': 'demo', 'revisionDigest': revision,
                  'instanceId': INSTANCE, 'generation': 2,
                  'slotId': 's1'}
        return stage_request(target=target, snapshotId='7' * 64)

    def test_stage_secrets_bound_marker_accepts(self):
        revision = self._secrets_target()
        response = self.make().execute(
            self._secrets_request(revision))
        self.assertEqual(response['status'], 'completed', response)
        self.assertEqual(
            response['record']['manifest']['secretBundle'],
            {'secretSetRef': 'lab-secrets',
             'versionDigest': 'sha256:' + '5' * 64,
             'bundleDigest': 'sha256:' + '6' * 64})
        # The provisioned pair survives staging untouched.
        secrets_dir = os.path.join(self.instance_dir,
                                   worker._SECRETS_DIR)
        self.assertTrue(os.path.isdir(secrets_dir))
        self.assertTrue(os.path.exists(
            os.path.join(self.instance_dir, worker._SECRETS_MARKER)))

    def test_stage_secrets_marker_manifest_mismatch(self):
        # The point pins a different bundle than the provisioned
        # marker — restore refuses rather than run new state against
        # stale secrets.
        revision = self._secrets_target()
        bad = {'secretSetRef': 'lab-secrets',
               'versionDigest': 'sha256:' + '5' * 64,
               'bundleDigest': 'sha256:' + '9' * 64}
        marker = os.path.join(self.instance_dir,
                              worker._SECRETS_MARKER)
        write_private_file(marker, artifacts.canonical_bytes(bad))
        response = self.make().execute(
            self._secrets_request(revision))
        self.expect_blocked(response, 'secrets-conflict')

    def test_stage_secrets_missing_pair(self):
        secrets_def = catalog.validate_definition(
            sealed(secretSetRef='lab-secrets'))
        revision = secrets_def['revisionDigest']
        bundle = {'secretSetRef': 'lab-secrets',
                  'versionDigest': 'sha256:' + '5' * 64,
                  'bundleDigest': 'sha256:' + '6' * 64}
        self.fake_repo.add_point(
            '7' * 64, make_manifest(definition=secrets_def,
                                    secret_bundle=bundle),
            'sha256:' + '3' * 64,
            {'data': {'value': b'restored-marker'}})
        self.fake_worker.definitions[('demo', revision)] = secrets_def
        self.fake_worker.recs[INSTANCE] = worker_record(
            self.storage, self.slot, revision_digest=revision)
        response = self.make().execute(
            self._secrets_request(revision))
        self.expect_blocked(response, 'storage-state-conflict')

    def test_stage_busy(self):
        instance = self.make()
        try:
            handle = os.open(instance._lock_path, os.O_RDWR)
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                self.expect_blocked(
                    instance.execute(stage_request()), 'restore-busy')
            finally:
                os.close(handle)
        finally:
            instance.close()

    def test_stage_mount_failure_unmounts_nothing(self):
        self.fake_mounts.fail_mount = True
        self.expect_blocked(self.stage(), 'mount-failed')
        self.assertEqual(self.read_job()['phase'], 'pending')
        self.assertFalse(self.fake_mounts.unmounted)

    def test_stage_journal_binds_request(self):
        self.stage()
        job = self.read_job()
        self.assertEqual(job['request'], stage_request())
        bad = stage_request()
        bad['target']['generation'] = 5
        self.expect_blocked(self.make().execute(bad),
                            'restore-conflict')


class CommitTests(RestoreFixture):

    def stage(self):
        return self.make().execute(stage_request())

    def test_commit_moves_translated_state(self):
        self.stage()
        response = self.make().execute(commit_request())
        self.assertEqual(response['status'], 'completed', response)
        self.assertEqual(response['committedAt'], 2000)
        self.assertFalse(os.path.exists(self.sentinel_path()))
        self.assertFalse(os.path.exists(
            os.path.join(self.instance_dir, '.nexus-restore-staging')))
        leaf = os.path.join(self.instance_dir, 'data')
        self.assertEqual(self.owners.lookup(leaf),
                         (DST_BASE, DST_BASE))
        self.assertEqual(sorted(os.listdir(leaf)), ['value'])
        with open(os.path.join(leaf, 'value'), 'rb') as handle:
            self.assertEqual(handle.read(), b'restored-marker')
        job = self.read_job()
        self.assertEqual(job['phase'], 'committed')
        self.assertEqual(sorted(os.listdir(self.instance_dir)),
                         ['data'])

    def test_commit_replay_is_idempotent(self):
        self.stage()
        first = self.make().execute(commit_request())
        again = self.make().execute(commit_request())
        self.assertEqual(again, first)
        self.assertEqual(self.read_job()['phase'], 'committed')

    def test_commit_partial_replay_continues(self):
        self.stage()
        instance_dir = self.instance_dir
        staging = os.path.join(instance_dir, '.nexus-restore-staging')
        # Simulate a crash between leaf removal and rename: leaf
        # missing, staged tree still present, sentinel in place.
        os.rmdir(os.path.join(instance_dir, 'data'))
        response = self.make().execute(commit_request())
        self.assertEqual(response['status'], 'completed', response)
        self.assertTrue(os.path.isfile(
            os.path.join(instance_dir, 'data', 'value')))
        self.assertFalse(os.path.exists(self.sentinel_path()))

    def test_commit_replay_after_sentinel_removal_crash(self):
        self.stage()
        first = self.make().execute(commit_request())
        # A commit that crashed after removing the sentinel but before
        # the journal flipped must converge on replay.
        job = self.read_job()
        job['phase'] = 'staged'
        job['committedAt'] = None
        statefiles.write_json(self.job_path(), job)
        replay = self.make().execute(commit_request())
        self.assertEqual(replay, first)
        self.assertEqual(self.read_job()['phase'], 'committed')

    def test_commit_requires_staged_job(self):
        self.expect_blocked(self.make().execute(commit_request()),
                            'restore-missing')
        self.fake_shell.fail_cp = True
        self.make().execute(stage_request())
        self.expect_blocked(self.make().execute(commit_request()),
                            'restore-not-staged')

    def test_commit_rechecks_fresh_target(self):
        self.stage()
        self.fake_worker.recs[INSTANCE]['phase'] = 'stopped'
        self.fake_worker.observe['phase'] = 'stopped'
        self.expect_blocked(self.make().execute(commit_request()),
                            'instance-not-fresh')
        self.assertTrue(os.path.exists(self.sentinel_path()))
        self.assertEqual(self.read_job()['phase'], 'staged')

    def test_commit_rejects_slot_change(self):
        self.stage()
        self.fake_worker.recs[INSTANCE]['binding']['slot'] = dict(
            self.slot, uidBase=SRC_BASE)
        self.expect_blocked(self.make().execute(commit_request()),
                            'restore-conflict')


class StatusTests(RestoreFixture):

    def test_status_reports_phases(self):
        self.expect_blocked(self.make().execute(status_request()),
                            'restore-missing')
        self.fake_shell.fail_cp = True
        self.make().execute(stage_request())
        response = self.make().execute(status_request())
        self.assertEqual(response['phase'], 'pending')
        self.assertIsNone(response['stagedAt'])
        self.fake_shell.fail_cp = False
        self.make().execute(stage_request())
        response = self.make().execute(status_request())
        self.assertEqual(response['phase'], 'staged')
        self.assertEqual(response['record']['snapshotId'], SNAPSHOT)
        self.make().execute(commit_request())
        response = self.make().execute(status_request())
        self.assertEqual(response['phase'], 'committed')
        self.assertEqual(response['committedAt'], 2000)


class JournalTests(RestoreFixture):

    def test_journal_rejects_tampering(self):
        self.make().execute(stage_request())
        job = self.read_job()
        for mutate in (
            lambda j: j.update(phase='committed'),
            lambda j: j.update(stagedAt=None),
            lambda j: j['request'].update(
                target=dict(j['request']['target'],
                            workloadId='other')),
            lambda j: j['translation'].update(targetUidBase=SRC_BASE),
            lambda j: j.update(extra='x'),
        ):
            candidate = copy.deepcopy(job)
            mutate(candidate)
            statefiles.write_json(self.job_path(), candidate)
            response = self.make().execute(status_request())
            self.assertEqual(response['status'], 'blocked', candidate)
            self.assertEqual(response['error'], 'journal-invalid',
                             candidate)
            statefiles.write_json(self.job_path(), job)

    def test_journal_rejects_config_change(self):
        self.make().execute(stage_request())
        config = self.restore_config(
            repositories=[self.repo_config(
                repo_id='repo-b', path=self.repo_dir)])
        response = self.make(config).execute(status_request())
        self.assertEqual(response['status'], 'completed')
        response = self.make(config).execute(stage_request())
        self.assertEqual(response['error'], 'restore-config-changed')


if __name__ == '__main__':
    unittest.main()
