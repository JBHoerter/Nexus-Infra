import copy
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import artifacts
import backup
import catalog
import recovery
import repository
import statefiles
import worker
from test_catalog import sealed
from test_repository import (CAPTURE_ID, Completed, FakeRestic,
                             make_private_dir, write_private_file)


INSTANCE = 'ab' * 16
REVISION = sealed()['revisionDigest']
CACHE_REPO_ID = 'a' * 64
DEST_REPO_ID = 'd' * 64
UID_BASE = 65536
OWNER_UID = 65536 + 0
FINAL_TAG = repository._FINAL_TAG
DRAFT_TAG = repository._DRAFT_TAG + ':' + CAPTURE_ID


def capture_request(**overrides):
    request = {'schemaVersion': 1, 'action': 'capture',
               'captureId': CAPTURE_ID, 'workloadId': 'demo',
               'revisionDigest': REVISION, 'instanceId': INSTANCE,
               'generation': 1}
    request.update(overrides)
    return request


def upload_request(**overrides):
    request = {'schemaVersion': 1, 'action': 'upload',
               'captureId': CAPTURE_ID, 'repositoryId': 'dest'}
    request.update(overrides)
    return request


def status_request(**overrides):
    request = {'schemaVersion': 1, 'action': 'status',
               'captureId': CAPTURE_ID}
    request.update(overrides)
    return request


class FakeShell:
    """Runner seam for backup-adjacent commands (sync, findmnt)."""

    def __init__(self):
        self.calls = []
        self.rc = 0
        self.mount_targets = ['/']
        self.findmnt_rc = 0
        self.findmnt_stdout = None

    def run(self, argv, **kwargs):
        self.calls.append(list(argv))
        if argv[0] == 'findmnt':
            if self.findmnt_rc != 0:
                return Completed(self.findmnt_rc, b'', b'forced failure')
            if self.findmnt_stdout is not None:
                return Completed(0, self.findmnt_stdout)
            body = {'filesystems': [{'target': target}
                                    for target in self.mount_targets]}
            return Completed(0, json.dumps(body).encode())
        return Completed(self.rc, b'', b'forced failure')


class FakeMounts:
    """Read-only bind-mount double: copies the frozen source tree into
    the scratch mount target the way a bind mount would expose it, and
    on unmount removes only the view it created — never preexisting
    or unrelated content."""

    def __init__(self):
        self.mounted = []
        self.unmounted = []
        self.owned = {}
        self.fail_mount = False
        self._views = {}

    def mount(self, source, target):
        if self.fail_mount:
            raise backup.BackupError('mount-failed')
        self.mounted.append((source, target))
        shutil.copytree(source, target, dirs_exist_ok=True)
        self._views[target] = list(os.listdir(target))
        for name in os.listdir(target):
            self.owned[os.path.join(target, name)] = (UID_BASE, UID_BASE)

    def unmount(self, target):
        self.unmounted.append(target)
        for name in self._views.pop(target, []):
            path = os.path.join(target, name)
            self.owned.pop(path, None)
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                os.unlink(path)


class LockStub:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class FakeWorker:
    """Worker double covering the private interface BackupWorker uses:
    frozen-record snapshot under its lock plus observe."""

    def __init__(self, config):
        self.config = config
        self.recs = {}
        self.definitions = {}
        self.state_dirs = {}
        self.held = {}
        self.observe = None
        self.context_error = None
        self.executed = []
        self.closed = False

    def _lock(self):
        return LockStub()

    def _capture_context(self, request):
        if self.context_error is not None:
            raise self.context_error
        rec = self.recs.get(request['instanceId'])
        if rec is None:
            raise worker.WorkerError('unknown-instance')
        if rec['workload_id'] != request['workloadId'] \
                or rec['revision_digest'] != request['revisionDigest'] \
                or rec['generation'] != request['generation']:
            raise worker.WorkerError('instance-conflict')
        return rec, self.definitions[
            (rec['workload_id'], rec['revision_digest'])]

    def _check_generation_current(self, rec):
        return None

    def _held_capture(self, workload_id):
        return self.held.get(workload_id)

    def _capture_matches(self, row, rec):
        return row.get('instance_id') == rec['instance_id'] \
            and row.get('generation') == rec['generation']

    def _instance_dir(self, rec):
        return self.state_dirs[rec['instance_id']]

    def execute(self, request):
        self.executed.append(dict(request))
        if request['action'] == 'observe':
            assert self.observe is not None
            return dict(self.observe)
        raise AssertionError('backup worker must never drive lifecycle')

    def close(self):
        self.closed = True


def worker_record(state_dir):
    return {'instance_id': INSTANCE, 'workload_id': 'demo',
            'revision_digest': REVISION, 'generation': 1,
            'binding': {'hostId': 'host-a',
                        'architecture': 'x86_64-linux',
                        'storage': {'root': state_dir,
                                    'mountPoint': state_dir,
                                    'uuid': '9f013958-f0b2-48cd'},
                        'slot': {'id': 's0', 'uidBase': UID_BASE,
                                 'hostAddress': '10.10.0.2',
                                 'localAddress': '10.10.0.3'}}}


def observe_record(**overrides):
    record = {'schemaVersion': 1, 'action': 'observe',
              'instanceId': INSTANCE, 'hostId': 'host-a',
              'revisionDigest': REVISION, 'generation': 1,
              'phase': 'stopped', 'bindingCurrent': True,
              'captureId': CAPTURE_ID, 'unitActiveState': 'inactive',
              'unitDrained': True}
    record.update(overrides)
    return record


def held_row(**overrides):
    row = {'capture_id': CAPTURE_ID, 'instance_id': INSTANCE,
           'workload_id': 'demo', 'generation': 1,
           'revision_digest': REVISION, 'observedAt': 1000,
           'unit_active_state': 'inactive', 'unit_drained': True}
    row.update(overrides)
    return row


class BackupFixture(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        self.private = make_private_dir(self.root, 'private')
        self.backup_dir = make_private_dir(self.root, 'backup-state')
        self.cache_dir = make_private_dir(self.root, 'cache-repo')
        self.dest_dir = make_private_dir(self.root, 'dest-repo')
        self.worker_dir = make_private_dir(self.root, 'worker-state')
        self.storage = make_private_dir(self.root, 'storage')
        self.cache_pw = write_private_file(
            os.path.join(self.private, 'cache-pass'), b'cache-key')
        self.dest_pw = write_private_file(
            os.path.join(self.private, 'dest-pass'), b'dest-key')
        self.worker_config_path = os.path.join(
            self.private, 'worker.json')
        self._write_worker_config()
        self.src_dir = os.path.join(self.storage, INSTANCE)
        os.mkdir(self.src_dir, 0o700)
        data = os.path.join(self.src_dir, 'data')
        os.mkdir(data, 0o700)
        with open(os.path.join(data, 'value'), 'wb') as handle:
            handle.write(b'frozen-marker-bytes')
        os.chmod(os.path.join(data, 'value'), 0o600)
        self.cache_fake = FakeRestic(repo_id=CACHE_REPO_ID)
        self.cache_fake.password_content = b'cache-key'
        self.dest_fake = FakeRestic(repo_id=DEST_REPO_ID)
        self.dest_fake.sources = {self.cache_dir: self.cache_fake}
        self.fake_worker = FakeWorker({})
        self.fake_worker.recs[INSTANCE] = worker_record(self.storage)
        self.fake_worker.definitions[('demo', REVISION)] = \
            catalog.validate_definition(sealed())
        self.fake_worker.state_dirs[INSTANCE] = self.src_dir
        self.fake_worker.held['demo'] = held_row()
        self.fake_worker.observe = observe_record()
        self.fake_mounts = FakeMounts()
        self.fake_shell = FakeShell()
        self.now = 1000.0
        self.addCleanup(mock.patch.stopall)
        real_lstat = os.lstat
        owned = self.fake_mounts.owned
        worker_config = self.worker_config_path

        def fake_lstat(path):
            result = real_lstat(path)
            if path == worker_config:
                # The pinned admin config is modelled root-owned,
                # as the real validator requires.
                return SimpleNamespace(st_mode=result.st_mode,
                                       st_uid=0, st_gid=result.st_gid,
                                       st_ino=result.st_ino,
                                       st_dev=result.st_dev)
            if path in owned:
                uid_value, gid_value = owned[path]
                return SimpleNamespace(st_mode=result.st_mode,
                                       st_uid=uid_value,
                                       st_gid=gid_value)
            return result
        mock.patch.object(repository, '_lstat', fake_lstat).start()
        mock.patch.object(backup, '_lstat', fake_lstat).start()
        real_fstat = os.fstat

        def fake_fstat(fd):
            result = real_fstat(fd)
            config_stat = real_lstat(worker_config)
            if (result.st_dev, result.st_ino) == (
                    config_stat.st_dev, config_stat.st_ino):
                return SimpleNamespace(st_mode=result.st_mode,
                                       st_uid=0, st_gid=result.st_gid,
                                       st_ino=result.st_ino,
                                       st_dev=result.st_dev)
            return result
        mock.patch.object(backup, '_fstat', fake_fstat).start()

    def _write_worker_config(self):
        config = {'schemaVersion': 1, 'hostId': 'host-a',
                  'architecture': 'x86_64-linux',
                  'stateDir': self.worker_dir,
                  'storage': {'root': self.storage,
                              'mountPoint': self.storage,
                              'uuid': '9f013958-f0b2-48cd'},
                  'capacity': {'memoryMiB': 256, 'cpuMillis': 1000,
                               'stateBytes': 1048576},
                  'capabilities': ['nspawn-v1'],
                  'approvedBundles': ['/nix/store/' + 'a' * 32 + '-b'],
                  'slots': [{'id': 's0', 'uidBase': UID_BASE,
                             'hostAddress': '10.10.0.2',
                             'localAddress': '10.10.0.3'}]}
        raw = artifacts.canonical_bytes(config)
        with open(self.worker_config_path, 'wb') as handle:
            handle.write(raw)
        os.chmod(self.worker_config_path, 0o600)

    def repo_factory(self, config):
        fakes = {'cache': self.cache_fake, 'dest': self.dest_fake}
        return repository.ResticRepository(
            config, runner=fakes[config['id']])

    def backup_config(self, **overrides):
        config = {
            'schemaVersion': 1,
            'stateDir': self.backup_dir,
            'workerConfigFile': self.worker_config_path,
            'cache': {'schemaVersion': 1, 'id': 'cache',
                      'repositoryIdentity': CACHE_REPO_ID,
                      'passwordFile': self.cache_pw,
                      'transport': {'kind': 'local',
                                    'path': self.cache_dir}},
            'repositories': [
                {'schemaVersion': 1, 'id': 'dest',
                 'repositoryIdentity': DEST_REPO_ID,
                 'passwordFile': self.dest_pw,
                 'transport': {'kind': 'local',
                               'path': self.dest_dir}}],
            'bindings': [{'workloadId': 'demo',
                          'revisionDigest': REVISION,
                          'repositoryIds': ['dest']}]}
        config.update(overrides)
        return config

    def make(self, config=None, **kwargs):
        kwargs.setdefault('worker_factory',
                          lambda cfg: self.fake_worker)
        kwargs.setdefault('repo_factory', self.repo_factory)
        kwargs.setdefault('runner', self.fake_shell)
        kwargs.setdefault('clock', lambda: self.now)
        kwargs.setdefault('mounts', self.fake_mounts)
        return backup.BackupWorker(config or self.backup_config(),
                                   **kwargs)

    def job_path(self, capture_id=CAPTURE_ID):
        return os.path.join(self.backup_dir, 'jobs',
                            capture_id + '.json')

    def read_job(self, capture_id=CAPTURE_ID):
        return statefiles.read_json(self.job_path(capture_id),
                                    backup._MAX_JOB_BYTES)

    def capture(self, **kwargs):
        return self.make(**kwargs).execute(capture_request())

    def expect_blocked(self, response, code):
        self.assertEqual(response['status'], 'blocked')
        self.assertEqual(response['error'], code)
        self.assertEqual(response['schemaVersion'], 1)


class ConfigTests(BackupFixture):

    def expect_bad(self, config):
        with self.assertRaises(backup.BackupError):
            self.make(config)

    def test_exact_fields(self):
        config = self.backup_config()
        config['extra'] = True
        self.expect_bad(config)
        for field in ('stateDir', 'workerConfigFile', 'cache',
                      'repositories', 'bindings'):
            bad = self.backup_config()
            del bad[field]
            self.expect_bad(bad)
        self.expect_bad(self.backup_config(schemaVersion=2))

    def test_repository_ids(self):
        # Duplicate repository id.
        repos = self.backup_config()['repositories']
        dup = self.backup_config(repositories=repos + repos)
        self.expect_bad(dup)
        # Cache id collision.
        cache = self.backup_config()['cache']
        cache['id'] = 'dest'
        self.expect_bad(self.backup_config(cache=cache))
        # Binding references unknown repository.
        bad = self.backup_config()
        bad['bindings'] = [{'workloadId': 'demo',
                            'revisionDigest': REVISION,
                            'repositoryIds': ['missing']}]
        self.expect_bad(bad)
        # One repository bound to two workloads.
        bad = self.backup_config()
        bad['bindings'] = [
            {'workloadId': 'demo', 'revisionDigest': REVISION,
             'repositoryIds': ['dest']},
            {'workloadId': 'other', 'revisionDigest': REVISION,
             'repositoryIds': ['dest']}]
        self.expect_bad(bad)
        # Duplicate binding entries.
        bad['bindings'] = [bad['bindings'][0], bad['bindings'][0]]
        self.expect_bad(bad)

    def test_cache_must_be_local(self):
        sftp = {'kind': 'sftp', 'host': 'repo', 'port': 22,
                'user': 'b', 'path': '/r',
                'identityFile': self.cache_pw,
                'knownHostsFile': self.cache_pw}
        cache = self.backup_config()['cache']
        cache['transport'] = sftp
        self.expect_bad(self.backup_config(cache=cache))

    def test_binding_shape(self):
        bad = self.backup_config()
        bad['bindings'] = [{'workloadId': 'demo',
                            'revisionDigest': 'deadbeef',
                            'repositoryIds': ['dest']}]
        self.expect_bad(bad)
        bad['bindings'] = [{'workloadId': 'demo',
                            'revisionDigest': REVISION,
                            'repositoryIds': []}]
        self.expect_bad(bad)
        bad['bindings'] = [{'workloadId': 'Bad Id',
                            'revisionDigest': REVISION,
                            'repositoryIds': ['dest']}]
        self.expect_bad(bad)
        bad['bindings'] = [{'workloadId': 'demo',
                            'revisionDigest': REVISION,
                            'repositoryIds': ['dest', 'dest']}]
        self.expect_bad(bad)

    def test_config_deep_copy(self):
        config = self.backup_config()
        instance = self.make(config)
        try:
            config['cache']['transport']['path'] = '/nowhere'
            config['bindings'][0]['repositoryIds'].append('x')
            self.assertEqual(instance._config['cache']['transport']
                             ['path'], self.cache_dir)
        finally:
            instance.close()

    def test_state_dirs_created_private(self):
        instance = self.make()
        try:
            for name in (self.backup_dir,
                         os.path.join(self.backup_dir, 'jobs'),
                         os.path.join(self.backup_dir, 'scratch')):
                st = os.lstat(name)
                self.assertTrue(stat.S_ISDIR(st.st_mode))
                self.assertEqual(stat.S_IMODE(st.st_mode), 0o700)
        finally:
            instance.close()


class RequestTests(BackupFixture):

    def test_request_shape(self):
        instance = self.make()
        try:
            bad = capture_request(extra=1)
            self.expect_blocked(instance.execute(bad), 'invalid-request')
            bad = capture_request()
            del bad['workloadId']
            self.expect_blocked(instance.execute(bad), 'invalid-request')
            bad = capture_request(schemaVersion=2)
            self.expect_blocked(instance.execute(bad), 'invalid-request')
            bad = capture_request(action='thaw')
            self.expect_blocked(instance.execute(bad), 'invalid-request')
            bad = capture_request(captureId='xyz')
            self.expect_blocked(instance.execute(bad),
                                'invalid-request captureId')
            bad = capture_request(generation=0)
            self.expect_blocked(instance.execute(bad),
                                'invalid-request generation')
            bad = capture_request(generation='1')
            self.expect_blocked(instance.execute(bad),
                                'invalid-request generation')
            self.expect_blocked(instance.execute(42), 'invalid-request')
            self.expect_blocked(
                instance.execute(upload_request(repositoryId='x' * 65)),
                'invalid-request')
        finally:
            instance.close()

    def test_bool_fields_rejected(self):
        instance = self.make()
        try:
            bad = capture_request(schemaVersion=True)
            self.expect_blocked(instance.execute(bad), 'invalid-request')
            bad = capture_request(generation=True)
            self.expect_blocked(instance.execute(bad),
                                'invalid-request generation')
        finally:
            instance.close()


class CaptureTests(BackupFixture):

    def test_capture_requires_held_barrier(self):
        self.fake_worker.held.clear()
        response = self.capture()
        self.expect_blocked(response, 'capture-required')
        self.assertFalse(self.fake_mounts.mounted)
        self.assertIsNone(self.read_job())

    def test_capture_wrong_capture_id_barrier(self):
        self.fake_worker.held['demo'] = held_row(
            capture_id='f' * 32)
        response = self.capture()
        self.expect_blocked(response, 'capture-required')

    def test_capture_binding_unapproved(self):
        bad = self.backup_config()
        bad['bindings'] = []
        response = self.make(bad).execute(capture_request())
        self.expect_blocked(response, 'binding-unapproved')

    def test_capture_unknown_instance(self):
        self.fake_worker.recs.clear()
        response = self.capture()
        self.expect_blocked(response, 'unknown-instance')

    def test_capture_binding_drift(self):
        # Frozen worker record carries a different revision than the
        # request/bindings approve.
        rec = worker_record(self.storage)
        rec['revision_digest'] = 'sha256:' + '9' * 64
        self.fake_worker.recs[INSTANCE] = rec
        response = self.capture()
        self.expect_blocked(response, 'instance-conflict')

    def test_capture_happy_path(self):
        response = self.capture()
        self.assertEqual(response['status'], 'completed')
        self.assertEqual(response['action'], 'capture')
        self.assertEqual(response['captureId'], CAPTURE_ID)
        record = response['record']
        self.assertEqual(record['repositoryId'], 'cache')
        manifest = record['manifest']
        self.assertEqual(manifest['source']['uidBase'], UID_BASE)
        self.assertEqual(manifest['capture']['adapter'], 'quiesce-v1')
        job = self.read_job()
        self.assertEqual(job['phase'], 'captured')
        self.assertEqual(job['cache'], record)
        self.assertEqual(job['capture']['completedAt'],
                         manifest['capture']['completedAt'])
        # Bind mount mounted and released inside the run.
        self.assertEqual(len(self.fake_mounts.mounted), 1)
        self.assertEqual(len(self.fake_mounts.unmounted), 1)
        # The barrier stays held; no lifecycle action was driven.
        self.assertIn('demo', self.fake_worker.held)
        actions = {call['action'] for call in self.fake_worker.executed}
        self.assertEqual(actions, {'observe'})
        # Source modes/bytes untouched.
        data = os.path.join(self.src_dir, 'data')
        st = os.lstat(os.path.join(data, 'value'))
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.lstat(data).st_mode), 0o700)

    def test_capture_replay_identical(self):
        first = self.capture()
        self.assertEqual(first['status'], 'completed')
        checks_before = self.cache_fake.checks
        replay = self.capture()
        self.assertEqual(replay, first)
        # Replay re-inspects the cache point and re-checks the repo.
        self.assertGreater(self.cache_fake.checks, checks_before)

    def test_capture_request_conflict(self):
        self.assertEqual(self.capture()['status'], 'completed')
        bad = capture_request(generation=2)
        response = self.make().execute(bad)
        self.expect_blocked(response, 'capture-conflict')

    def test_capture_config_changed(self):
        self.assertEqual(self.capture()['status'], 'completed')
        # The binding still approves the request; only the admin
        # config changed (a second revision binding), so the stored
        # configDigest no longer matches.
        changed = self.backup_config()
        changed['bindings'] = changed['bindings'] + [
            {'workloadId': 'demo',
             'revisionDigest': 'sha256:' + '7' * 64,
             'repositoryIds': ['dest']}]
        instance = self.make(changed)
        response = instance.execute(capture_request())
        self.expect_blocked(response, 'backup-config-changed')
        # Status still returns the historical record even when the
        # admin config changed underneath it.
        status = instance.execute(status_request())
        self.assertEqual(status['status'], 'completed')
        self.assertEqual(status['phase'], 'captured')

    def test_capture_secret_bundle_missing_fails_before_mount(self):
        definition = catalog.validate_definition(
            sealed(secretSetRef='secrets'))
        self.fake_worker.definitions[('demo', REVISION)] = definition
        response = self.capture()
        self.expect_blocked(response, 'invalid-capture')
        self.assertFalse(self.fake_mounts.mounted)
        backup_calls = [call for call in self.cache_fake.calls
                        if 'backup' in call]
        self.assertFalse(backup_calls)

    def test_capture_mount_failure_keeps_pending(self):
        self.fake_mounts.fail_mount = True
        response = self.capture()
        self.expect_blocked(response, 'mount-failed')
        self.assertEqual(self.read_job()['phase'], 'pending')
        # The same captureId resumes and completes — a pending journal
        # with no completedAt performs the full live capture.
        self.fake_mounts.fail_mount = False
        resumed = self.capture()
        self.assertEqual(resumed['status'], 'completed')

    def test_capture_mount_cleanup_on_store_failure(self):
        self.cache_fake.rc['backup'] = 1
        response = self.capture()
        self.expect_blocked(response, 'repository-command-failed')
        self.assertEqual(len(self.fake_mounts.unmounted), 1)
        self.assertEqual(self.read_job()['phase'], 'pending')

    def test_cache_write_failure_leaves_barrier(self):
        self.cache_fake.rc['backup'] = 11
        response = self.capture()
        self.expect_blocked(response, 'repository-locked')
        self.assertEqual(self.read_job()['phase'], 'pending')
        self.assertIn('demo', self.fake_worker.held)
        self.assertFalse(any(FINAL_TAG in s['tags']
                             for s in self.cache_fake.snapshots))

    def test_capture_child_mount_under_source_rejected(self):
        # A non-recursive bind would hide nested state mounts and the
        # capture could silently read underlying empty directories.
        self.fake_shell.mount_targets = [
            '/', os.path.join(self.src_dir, 'nested-state')]
        response = self.capture()
        self.expect_blocked(response, 'source-state-mounted')
        self.assertFalse(self.fake_mounts.mounted)
        # A mount exactly at the source root is also refused.
        self.fake_shell.mount_targets = ['/', self.src_dir]
        response = self.capture()
        self.expect_blocked(response, 'source-state-mounted')
        self.assertFalse(self.fake_mounts.mounted)

    def test_capture_findmnt_unknown_rejected(self):
        self.fake_shell.findmnt_rc = 1
        response = self.capture()
        self.expect_blocked(response, 'source-mounts-unknown')
        self.assertFalse(self.fake_mounts.mounted)
        self.fake_shell.findmnt_rc = 0
        self.fake_shell.findmnt_stdout = b'this is not json'
        response = self.capture()
        self.expect_blocked(response, 'source-mounts-unknown')
        self.assertFalse(self.fake_mounts.mounted)

    def test_capture_findmnt_requires_nonempty_valid_mount_list(self):
        for raw in (
                b'{"filesystems":{}}',
                b'{"filesystems":[]}',
                b'{"filesystems":[null]}',
                b'{"filesystems":[{"target":"relative"}]}',
                b'{"filesystems":[{"target":"/bad\\u0000path"}]}',
                b'{"filesystems":[{"target":"/","target":"/other"}]}',
                b'{"filesystems":[{"target":NaN}]}'):
            with self.subTest(raw=raw):
                self.fake_shell.findmnt_stdout = raw
                self.expect_blocked(
                    self.capture(), 'source-mounts-unknown')
                self.assertFalse(self.fake_mounts.mounted)
                self.assertFalse(self.cache_fake.snapshots)

    def test_capture_second_worker_reports_busy(self):
        first = self.make()
        first._acquire_lock()
        try:
            response = self.make().execute(capture_request())
            self.expect_blocked(response, 'backup-busy')
            # No lifecycle operation and no mount on contention.
            self.assertFalse(self.fake_mounts.mounted)
            self.assertEqual(self.fake_worker.executed, [])
        finally:
            first._release_lock()
            first.close()
        self.assertEqual(self.capture()['status'], 'completed')

    def test_checkpoint_late_binding_change_blocks(self):
        # If the frozen worker binding changes between the journal
        # snapshot and the checkpoint callback, the store must abort
        # before the final tag.
        original = self.fake_mounts.mount

        def mutate(source, target):
            original(source, target)
            self.fake_worker.recs[INSTANCE]['binding']['slot'][
                'uidBase'] += 65536
        self.fake_mounts.mount = mutate
        response = self.capture()
        self.expect_blocked(response, 'capture-checkpoint-failed')
        self.assertFalse(any(FINAL_TAG in s['tags']
                             for s in self.cache_fake.snapshots))

    def test_capture_path_containment_refused(self):
        # Instance source inside the cache repo path.
        inside = os.path.join(self.cache_dir, 'inner', INSTANCE)
        os.makedirs(os.path.join(inside, 'data'))
        self.fake_worker.state_dirs[INSTANCE] = inside
        response = self.capture()
        self.expect_blocked(response, 'path-unsafe')
        self.assertFalse(self.fake_mounts.mounted)

    def test_capture_scratch_stray_entry_refused(self):
        instance = self.make()
        scratch = os.path.join(self.backup_dir, 'scratch', CAPTURE_ID)
        os.mkdir(scratch)
        with open(os.path.join(scratch, 'stray'), 'wb') as handle:
            handle.write(b'x')
        response = instance.execute(capture_request())
        self.expect_blocked(response, 'path-unsafe')

    def test_capture_scratch_symlink_refused(self):
        instance = self.make()
        target = os.path.join(self.private, 'scratch-real')
        os.mkdir(target)
        link = os.path.join(self.backup_dir, 'scratch', CAPTURE_ID)
        os.symlink(target, link)
        response = instance.execute(capture_request())
        self.expect_blocked(response, 'path-unsafe')

    def test_capture_barrier_lost_after_draft(self):
        # The barrier is released inside the checkpoint callback:
        # the draft already exists but no final tag may be written.
        real = self.fake_worker._held_capture
        released = []

        def drop(workload_id):
            released.append(True)
            return None

        # Simulate barrier loss inside the callback by hooking the
        # worker's observe path: once the draft backup call ran, drop.
        original_run = self.cache_fake.run

        def run(argv, **kwargs):
            result = original_run(argv, **kwargs)
            if 'backup' in argv and not released:
                self.fake_worker.held.clear()
            return result
        self.cache_fake.run = run
        response = self.capture()
        self.expect_blocked(response, 'capture-checkpoint-failed')
        self.assertEqual(self.read_job()['phase'], 'pending')
        self.assertFalse(any(FINAL_TAG in s['tags']
                             for s in self.cache_fake.snapshots))
        self.assertEqual(len(self.fake_mounts.unmounted), 1)

    def test_capture_clock_backwards_refused(self):
        clocks = iter([2000.0, 1000.0])
        response = self.make(clock=lambda: next(clocks))\
            .execute(capture_request())
        self.expect_blocked(response, 'capture-checkpoint-failed')
        self.assertFalse(any(FINAL_TAG in s['tags']
                             for s in self.cache_fake.snapshots))

    def test_capture_invalid_clock_blocked(self):
        for bad in (float('nan'), float('inf'), -1.0, 2**53 + 1,
                    'now', True):
            if os.path.exists(self.job_path()):
                os.unlink(self.job_path())
            instance = self.make(clock=lambda value=bad: value)
            response = instance.execute(capture_request())
            self.expect_blocked(response, 'clock-invalid')
            instance.close()
        # No journal or mount effect was left behind.
        self.assertIsNone(self.read_job())
        self.assertFalse(self.fake_mounts.mounted)
        # A bad clock inside the checkpoint also aborts the store.
        self.now = 1000.0
        original = self.fake_mounts.mount

        def turn_bad(source, target):
            original(source, target)
            self.now = float('nan')
        self.fake_mounts.mount = turn_bad
        response = self.capture()
        self.expect_blocked(response, 'capture-checkpoint-failed')
        self.assertFalse(any(FINAL_TAG in s['tags']
                             for s in self.cache_fake.snapshots))

    def test_completed_timestamp_durable_and_reused(self):
        self.now = 5000.0
        response = self.capture()
        self.assertEqual(response['status'], 'completed')
        saved = self.read_job()['capture']['completedAt']
        self.assertEqual(saved,
                         response['record']['manifest']['capture']
                         ['completedAt'])
        self.assertGreater(saved, 0)
        # Crash-simulation: pending journal + completedAt already
        # saved + no final point -> live path must reuse the saved
        # timestamp rather than take a new one.
        job = self.read_job()
        self.assertIsNotNone(job['capture']['completedAt'])

    def test_crash_after_completed_before_final_reuses_timestamp(self):
        self.now = 7000.0
        # Drive a capture that crashes between completedAt persistence
        # and final tag: force the final backup to fail once.
        calls = {'n': 0}
        original_run = self.cache_fake.run

        def run(argv, **kwargs):
            if 'backup' in argv:
                calls['n'] += 1
                if calls['n'] == 2:
                    return Completed(1, b'', b'crash after draft')
            return original_run(argv, **kwargs)
        self.cache_fake.run = run
        first = self.capture()
        self.expect_blocked(first, 'repository-command-failed')
        saved = self.read_job()['capture']['completedAt']
        self.assertIsNotNone(saved)
        self.cache_fake.run = original_run
        self.now = 9999.0
        second = self.capture()
        self.assertEqual(second['status'], 'completed')
        self.assertEqual(second['record']['manifest']['capture']
                         ['completedAt'], saved)

    def test_crash_after_final_before_ledger_recovers(self):
        first = self.capture()
        self.assertEqual(first['status'], 'completed')
        # Simulate crash between restic finalization and journal
        # update: rewind the journal to pending with completedAt set.
        job = self.read_job()
        job['phase'] = 'pending'
        job['cache'] = None
        statefiles.write_json(self.job_path(), job)
        mounts_before = list(self.fake_mounts.mounted)
        # The worker must not be contacted at all: recovery is from
        # the cache and journal only.
        self.fake_worker.observe = None
        self.fake_worker.context_error = worker.WorkerError('gone')
        self.fake_mounts.mount = \
            lambda *args: self.fail('source must not be remounted')
        second = self.capture()
        self.assertEqual(second['status'], 'completed')
        self.assertEqual(second['record'], first['record'])
        self.assertEqual(self.fake_mounts.mounted, mounts_before)

    def test_rediscovery_wrong_cache_identity_blocked(self):
        first = self.capture()
        self.assertEqual(first['status'], 'completed')
        job = self.read_job()
        job['phase'] = 'pending'
        job['cache'] = None
        statefiles.write_json(self.job_path(), job)
        self.cache_fake.repo_id = 'f' * 64
        response = self.capture()
        self.expect_blocked(response, 'repository-identity-mismatch')
        self.assertEqual(self.read_job()['phase'], 'pending')
        self.assertIsNone(self.read_job()['cache'])

    def test_rediscovery_cache_check_failure_blocked(self):
        first = self.capture()
        self.assertEqual(first['status'], 'completed')
        job = self.read_job()
        job['phase'] = 'pending'
        job['cache'] = None
        statefiles.write_json(self.job_path(), job)
        self.cache_fake.rc['check'] = 1
        response = self.capture()
        self.expect_blocked(response, 'repository-command-failed')
        self.assertEqual(self.read_job()['phase'], 'pending')
        self.assertIsNone(self.read_job()['cache'])

    def _capture_and_mutate(self, mutator):
        self.assertEqual(self.capture()['status'], 'completed')
        job = self.read_job()
        mutator(job)
        statefiles.write_json(self.job_path(), job)
        return self.make().execute(status_request())

    def test_journal_swapped_cache_point_rejected(self):
        def mutate(job):
            capture = dict(job['cache']['manifest']['capture'])
            capture['completedAt'] += 1
            job['cache']['manifest'] = dict(job['cache']['manifest'],
                                          capture=capture)
        self.expect_blocked(self._capture_and_mutate(mutate),
                            'journal-invalid')

    def test_journal_mismatched_definition_rejected(self):
        def mutate(job):
            job['definition'] = dict(job['definition'],
                                     workloadId='other')
        self.expect_blocked(self._capture_and_mutate(mutate),
                            'journal-invalid')

    def test_journal_mismatched_source_rejected(self):
        def mutate(job):
            job['source'] = dict(job['source'], generation=99)
        self.expect_blocked(self._capture_and_mutate(mutate),
                            'journal-invalid')

    def test_journal_mismatched_binding_rejected(self):
        def mutate(job):
            job['sourceBinding']['slot']['uidBase'] += 65536
        self.expect_blocked(self._capture_and_mutate(mutate),
                            'journal-invalid')

    def test_journal_bool_schema_rejected(self):
        self.expect_blocked(
            self._capture_and_mutate(
                lambda job: job.update(schemaVersion=True)),
            'journal-invalid')

    def test_journal_bool_request_schema_rejected(self):
        # The same typed check applies inside the stored request.
        self.assertEqual(self.capture()['status'], 'completed')
        job = self.read_job()
        job['request']['schemaVersion'] = True
        statefiles.write_json(self.job_path(), job)
        self.expect_blocked(self.make().execute(status_request()),
                            'invalid-request')

    def test_journal_pending_with_copies_rejected(self):
        self.assertEqual(self.capture()['status'], 'completed')
        self.assertEqual(
            self.make().execute(upload_request())['status'],
            'completed')
        job = self.read_job()
        job['phase'] = 'pending'
        job['cache'] = None
        job['capture']['completedAt'] = None
        statefiles.write_json(self.job_path(), job)
        self.expect_blocked(self.make().execute(status_request()),
                            'journal-invalid')

    def test_journal_malformed_copy_record_rejected(self):
        self.assertEqual(self.capture()['status'], 'completed')
        self.assertEqual(
            self.make().execute(upload_request())['status'],
            'completed')
        job = self.read_job()
        job['copies']['dest']['record'] = {'bogus': True}
        statefiles.write_json(self.job_path(), job)
        self.expect_blocked(self.make().execute(status_request()),
                            'journal-invalid')

    def test_journal_copy_key_must_match_record(self):
        self.assertEqual(self.capture()['status'], 'completed')
        self.assertEqual(
            self.make().execute(upload_request())['status'],
            'completed')
        job = self.read_job()
        job['copies']['other'] = job['copies'].pop('dest')
        statefiles.write_json(self.job_path(), job)
        self.expect_blocked(self.make().execute(status_request()),
                            'journal-invalid')

    def test_journal_copy_must_bind_exact_cached_data(self):
        self.assertEqual(self.capture()['status'], 'completed')
        self.assertEqual(self.make().execute(upload_request())['status'],
                         'completed')
        job = self.read_job()
        cached = job['cache']['manifest']
        # This is a valid independently sealed manifest with identical
        # provenance and timestamps, but it describes different data.
        foreign = recovery.build_manifest(
            cached['definition'], cached['source'], cached['capture'],
            state_tree_digests={
                entry['id']: 'sha256:' + 'f' * 64
                for entry in cached['state']})
        self.assertNotEqual(foreign['recoveryPointId'],
                            cached['recoveryPointId'])
        job['copies']['dest']['record']['manifest'] = foreign
        statefiles.write_json(self.job_path(), job)
        self.expect_blocked(self.make().execute(status_request()),
                            'journal-invalid')

    def test_oversized_journal_preserves_old_record(self):
        self.capture()
        with open(self.job_path(), 'rb') as handle:
            before = handle.read()
        instance = self.make()
        job = self.read_job()
        with mock.patch.object(backup, '_MAX_JOB_BYTES', 64):
            with self.assertRaises(backup.BackupError) as ctx:
                instance._save_job(job)
        self.assertEqual(ctx.exception.code, 'journal-too-large')
        with open(self.job_path(), 'rb') as handle:
            self.assertEqual(handle.read(), before)

    def test_corrupted_journal_blocked(self):
        self.assertEqual(self.capture()['status'], 'completed')
        with open(self.job_path(), 'wb') as handle:
            handle.write(b'{"corrupted"')
        os.chmod(self.job_path(), 0o600)
        response = self.make().execute(status_request())
        self.expect_blocked(response, 'path-unsafe')

    def test_corrupted_journal_schema_blocked(self):
        self.assertEqual(self.capture()['status'], 'completed')
        statefiles.write_json(self.job_path(),
                              {'schemaVersion': 1, 'bogus': True})
        response = self.make().execute(status_request())
        self.expect_blocked(response, 'journal-invalid')

    def test_journal_symlink_refused(self):
        instance = self.make()
        target = os.path.join(self.private, 'elsewhere.json')
        write_private_file(target, b'{"schemaVersion": 1}')
        os.symlink(target, self.job_path())
        response = instance.execute(status_request())
        self.expect_blocked(response, 'path-unsafe')

    def test_no_implicit_lifecycle(self):
        self.capture()
        for call in self.fake_worker.executed:
            self.assertEqual(call['action'], 'observe')

    def test_status_reports_phase_and_copies(self):
        response = self.make().execute(status_request())
        self.expect_blocked(response, 'capture-missing')
        self.capture()
        status = self.make().execute(status_request())
        self.assertEqual(status['status'], 'completed')
        self.assertEqual(status['phase'], 'captured')
        self.assertEqual(status['record']['repositoryId'], 'cache')
        self.assertEqual(status['copies'], [])


class UploadTests(BackupFixture):

    def test_upload_requires_completed_capture(self):
        response = self.make().execute(upload_request())
        self.expect_blocked(response, 'capture-missing')
        # A pending job (crashed before capture finished) cannot
        # upload either.
        self.fake_mounts.fail_mount = True
        self.capture()
        self.fake_mounts.fail_mount = False
        response = self.make().execute(upload_request())
        self.expect_blocked(response, 'capture-pending')

    def test_upload_requires_approved_target(self):
        self.capture()
        response = self.make().execute(
            upload_request(repositoryId='unbound'))
        self.expect_blocked(response, 'binding-unapproved')

    def test_upload_happy_path(self):
        self.capture()
        response = self.make().execute(upload_request())
        self.assertEqual(response['status'], 'completed')
        self.assertEqual(response['action'], 'upload')
        self.assertEqual(response['repositoryId'], 'dest')
        self.assertEqual(response['record']['repositoryId'], 'dest')
        self.assertIsInstance(response['verifiedAt'], int)
        job = self.read_job()
        self.assertIn('dest', job['copies'])
        # No source mount or worker contact during upload.
        self.assertEqual(len(self.fake_mounts.mounted), 1)

    def test_upload_replay_verifies_current_copy(self):
        self.capture()
        first = self.make().execute(upload_request())
        checks = self.dest_fake.checks
        second = self.make().execute(upload_request())
        self.assertEqual(second, first)
        self.assertGreater(self.dest_fake.checks, checks)
        copy_calls = [call for call in self.dest_fake.calls
                      if 'copy' in call]
        self.assertEqual(len(copy_calls), 1)
        status = self.make().execute(status_request())
        self.assertEqual(len(status['copies']), 1)
        self.assertEqual(status['copies'][0]['repositoryId'], 'dest')

    def test_upload_wrong_destination_key(self):
        self.capture()
        self.dest_fake.rc['cat'] = 12
        response = self.make().execute(upload_request())
        self.expect_blocked(response, 'repository-key-unavailable')
        self.assertNotIn('dest', self.read_job()['copies'])

    def test_upload_wrong_cache_key_for_copy(self):
        self.capture()
        self.cache_fake.password_content = b'other-key'
        response = self.make().execute(upload_request())
        self.expect_blocked(response, 'repository-key-unavailable')
        self.assertNotIn('dest', self.read_job()['copies'])

    def test_upload_identity_mismatch(self):
        self.capture()
        self.dest_fake.repo_id = 'e' * 64
        response = self.make().execute(upload_request())
        self.expect_blocked(response, 'repository-identity-mismatch')

    def test_upload_missing_cached_payload(self):
        self.capture()
        self.cache_fake.rc['cat'] = 1
        response = self.make().execute(upload_request())
        self.expect_blocked(response, 'repository-command-failed')
        self.assertNotIn('dest', self.read_job()['copies'])

    def test_upload_rejects_mismatched_destination_receipt(self):
        # A copy whose returned receipt does not bind the exact cached
        # point is never persisted.
        self.capture()
        job = self.read_job()
        foreign = dict(job['cache'])
        foreign['repositoryId'] = 'dest'
        foreign['repositoryIdentity'] = DEST_REPO_ID
        foreign['snapshotId'] = 'f' * 64
        foreign['manifest'] = dict(
            foreign['manifest'],
            capture=dict(foreign['manifest']['capture'],
                         completedAt=1))

        class BadRepo:
            def copy_from(self, source, snapshot_id):
                return foreign

        def repo_factory(config):
            if config['id'] == 'dest':
                return BadRepo()
            return repository.ResticRepository(
                config, runner=self.cache_fake)
        response = self.make(repo_factory=repo_factory)\
            .execute(upload_request())
        self.expect_blocked(response, 'repository-point-invalid')
        self.assertNotIn('dest', self.read_job()['copies'])

    def test_upload_replay_copy_identity_mismatch(self):
        # A forged repositoryIdentity on the recorded copy is refused
        # on the side-effect path even though the journal entry is
        # internally consistent.
        self.capture()
        self.assertEqual(
            self.make().execute(upload_request())['status'],
            'completed')
        job = self.read_job()
        job['copies']['dest']['record']['repositoryIdentity'] = 'f' * 64
        statefiles.write_json(self.job_path(), job)
        response = self.make().execute(upload_request())
        self.expect_blocked(response, 'capture-conflict')

    def test_upload_invalid_clock_no_persist(self):
        self.capture()
        self.now = float('nan')
        response = self.make().execute(upload_request())
        self.expect_blocked(response, 'clock-invalid')
        self.assertNotIn('dest', self.read_job()['copies'])

    def test_upload_error_keeps_prior_receipt(self):
        self.capture()
        self.assertEqual(
            self.make().execute(upload_request())['status'],
            'completed')
        job_before = self.read_job()
        self.dest_fake.rc['cat'] = 1
        response = self.make().execute(upload_request())
        self.expect_blocked(response, 'repository-command-failed')
        self.assertEqual(self.read_job(), job_before)
        # Destination point data was never deleted.
        self.assertTrue(any(FINAL_TAG in s['tags']
                            for s in self.dest_fake.snapshots))


class PrivateDirTests(BackupFixture):

    def test_safe_0755_parent_creates_0700_child(self):
        parent = os.path.join(self.root, 'shared-parent')
        os.mkdir(parent, 0o755)
        child = os.path.join(parent, 'nexus-backup')
        backup._ensure_private_dir(child)
        st = os.lstat(child)
        self.assertTrue(stat.S_ISDIR(st.st_mode))
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o700)
        self.assertEqual(st.st_uid, os.geteuid())

    def test_unsafe_parent_rejected(self):
        parent = os.path.join(self.root, 'open-parent')
        os.mkdir(parent)
        os.chmod(parent, 0o777)
        child = os.path.join(parent, 'nexus-backup')
        with self.assertRaises(backup.BackupError) as ctx:
            backup._ensure_private_dir(child)
        self.assertEqual(ctx.exception.code, 'path-unsafe')
        self.assertFalse(os.path.exists(child))

    def test_fsync_failure_retry_durable(self):
        path = os.path.join(self.root, 'private-retry')
        with mock.patch('os.fsync', side_effect=OSError(5, 'io')):
            with self.assertRaises(backup.BackupError) as ctx:
                backup._ensure_private_dir(path)
        self.assertEqual(ctx.exception.code, 'path-unavailable')
        # The directory was created; the retry must re-establish both
        # directory and parent durability.
        backup._ensure_private_dir(path)
        st = os.lstat(path)
        self.assertTrue(stat.S_ISDIR(st.st_mode))
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o700)

    def test_existing_unsafe_dir_not_repaired(self):
        path = os.path.join(self.root, 'loose')
        os.mkdir(path, 0o755)
        with self.assertRaises(backup.BackupError) as ctx:
            backup._ensure_private_dir(path)
        self.assertEqual(ctx.exception.code, 'path-unsafe')
        self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o755)


class CliTests(BackupFixture):

    def test_config_fd_ownership_and_permissions_rechecked(self):
        original = backup._fstat
        for overrides in ({'st_uid': 1000},
                          {'st_mode': stat.S_IFREG | 0o666}):
            def changed(fd):
                result = original(fd)
                values = dict(st_uid=result.st_uid,
                              st_mode=result.st_mode,
                              st_ino=result.st_ino, st_dev=result.st_dev)
                values.update(overrides)
                return SimpleNamespace(**values)

            with self.subTest(overrides=overrides), \
                    mock.patch.object(backup, '_fstat', changed):
                with self.assertRaises(backup.BackupError) as ctx:
                    backup._read_config_file(self.worker_config_path)
                self.assertEqual(ctx.exception.code, 'path-unsafe')

    def test_config_read_rejects_oversized_file(self):
        with open(self.worker_config_path, 'wb') as handle:
            handle.write(b' ' * (backup._MAX_CONFIG_BYTES + 1))
        with self.assertRaises(backup.BackupError) as ctx:
            backup._read_config_file(self.worker_config_path)
        self.assertEqual(ctx.exception.code, 'invalid-config')

    def test_requires_root(self):
        config_path = os.path.join(self.private, 'backup.json')
        with open(config_path, 'wb') as handle:
            handle.write(
                artifacts.canonical_bytes(self.backup_config()))
        os.chmod(config_path, 0o600)
        with mock.patch('os.geteuid', return_value=1000):
            rc = backup.main(['--config', config_path, 'execute'])
        self.assertEqual(rc, 1)
        # No state files were created by the refused invocation.
        self.assertFalse(os.path.exists(self.job_path()))

    def test_config_file_safety(self):
        config_path = os.path.join(self.private, 'backup.json')
        with open(config_path, 'wb') as handle:
            handle.write(
                artifacts.canonical_bytes(self.backup_config()))
        os.chmod(config_path, 0o600)
        # Non-root-owned files are never accepted (unit runs unrooted).
        with self.assertRaises(backup.BackupError) as ctx:
            backup._check_config_path(config_path)
        self.assertEqual(ctx.exception.code, 'path-unsafe')
        # Symlinks are refused outright.
        link = os.path.join(self.private, 'linked.json')
        os.symlink(config_path, link)
        with self.assertRaises(backup.BackupError) as ctx:
            backup._check_config_path(link)
        self.assertEqual(ctx.exception.code, 'path-unsafe')
        # Group/world-writable candidates are refused.
        writable = os.path.join(self.private, 'writable.json')
        with open(writable, 'wb') as handle:
            handle.write(b'{}')
        os.chmod(writable, 0o666)
        with self.assertRaises(backup.BackupError):
            backup._check_config_path(writable)


if __name__ == '__main__':
    unittest.main()
