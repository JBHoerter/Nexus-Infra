import hashlib
import json
import os
import shlex
import stat
import subprocess
import sys
import time
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import recovery
import repository
from test_catalog import sealed


INSTANCE = 'ab' * 16
CAPTURE_ID = 'c1' * 16
REPO_ID = 'a' * 64
FINAL_TAG = 'nexus-recovery-v2'
DRAFT_TAG = 'nexus-capture-v1:' + CAPTURE_ID


def source(**overrides):
    record = {'hostId': 'host-a', 'instanceId': INSTANCE,
              'generation': 1, 'uidBase': 65536}
    record.update(overrides)
    return record


def capture(**overrides):
    record = {'adapter': 'quiesce-v1', 'consistency': 'quiesced',
              'startedAt': 1000, 'completedAt': 1005}
    record.update(overrides)
    return record


class Completed:
    def __init__(self, returncode, stdout=b'', stderr=b''):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeRestic:
    """In-memory restic CLI behind the runner seam.

    Builds trees and blobs with real SHA256 ids from the staged files,
    so the adapter's hashed-blob verification runs against content the
    same way real restic presents it. Flags simulate corruption,
    missing objects and command failures."""

    def __init__(self, repo_id=REPO_ID):
        self.repo_id = repo_id
        self.format_version = 2
        self.calls = []
        self.cwds = []
        self.snapshots = []
        self.blobs = {}
        self.files = {}
        self.rc = {}
        self.stdout_override = {}
        self.node_uid = 65536
        self.node_gid = 65536
        self.checks = 0
        self.sources = {}
        self.password_content = None
        self.copy_id_suffix = 0
        self.omit_manifest = False
        self.no_final_tag = False
        self.no_draft_tag = False
        self.extra_root = False
        self.corrupt_blob = False
        self.symlink_state = False
        self.skip_mount = None

    def verbs(self):
        return [self._verb(call) for call in self.calls]

    def _verb(self, argv):
        index = 1
        while index < len(argv) and argv[index].startswith('-'):
            index += 2 if argv[index] in (
                '--repo', '--password-file', '-o') else 1
        return argv[index]

    def run(self, argv, *, cwd=None, max_bytes=None, timeout=None):
        self.calls.append(list(argv))
        self.cwds.append(cwd)
        verb = self._verb(argv)
        if verb in self.rc:
            return Completed(self.rc[verb], b'', b'forced failure')
        handler = getattr(self, '_cmd_' + verb, None)
        if handler is None:
            return Completed(1, b'', b'unknown verb')
        return handler(argv, cwd)

    # -- helpers -------------------------------------------------------

    def _tree_blob(self, nodes):
        raw = json.dumps({'nodes': nodes}, sort_keys=True,
                         separators=(',', ':')).encode()
        blob_id = hashlib.sha256(raw).hexdigest()
        self.blobs[blob_id] = raw
        return blob_id

    def _build_tree(self, path):
        nodes = []
        for name in sorted(os.listdir(path)):
            full = os.path.join(path, name)
            st = os.lstat(full)
            if stat.S_ISDIR(st.st_mode):
                nodes.append({'name': name, 'type': 'dir',
                              'uid': self.node_uid, 'gid': self.node_gid,
                              'subtree': self._build_tree(full),
                              'content': None})
            else:
                with open(full, 'rb') as handle:
                    data = handle.read()
                blob_id = hashlib.sha256(data).hexdigest()
                self.blobs[blob_id] = data
                nodes.append({'name': name, 'type': 'file',
                              'uid': self.node_uid, 'gid': self.node_gid,
                              'size': len(data), 'content': [blob_id]})
        return self._tree_blob(nodes)

    def _add_snapshot(self, paths, host, tags, cwd):
        nodes = []
        file_records = []
        for rel in paths:
            full = os.path.join(cwd, rel)
            if os.path.isdir(full) and not os.path.islink(full):
                nodes.append({'name': rel, 'type': 'dir',
                              'uid': self.node_uid, 'gid': self.node_gid,
                              'subtree': self._build_tree(full),
                              'content': None})
            else:
                with open(full, 'rb') as handle:
                    data = handle.read()
                blob_id = hashlib.sha256(data).hexdigest()
                self.blobs[blob_id] = data
                file_records.append(('/' + rel, data))
                nodes.append({'name': rel, 'type': 'file',
                              'uid': self.node_uid, 'gid': self.node_gid,
                              'size': len(data), 'content': [blob_id]})
        if self.extra_root:
            nodes.append({'name': 'stray', 'type': 'file',
                          'uid': self.node_uid, 'gid': self.node_gid,
                          'size': 1, 'content': ['0' * 64]})
        tree_id = self._tree_blob(nodes)
        snapshot_id = hashlib.sha256(
            ('snapshot' + str(len(self.snapshots))).encode()).hexdigest()
        snapshot = {
            'id': snapshot_id, 'short_id': snapshot_id[:8],
            'tree': tree_id,
            'paths': [os.path.join(cwd, rel) for rel in paths],
            'hostname': host, 'username': 'root',
            'tags': sorted(tags),
            'program_version': 'restic 0.18.1',
            'time': '2026-09-25T12:35:20+02:00',
        }
        self.snapshots.append(snapshot)
        for path, data in file_records:
            self.files[(snapshot_id, path)] = data
        if self.corrupt_blob:
            self.blobs[tree_id] = b'corrupted-tree-blob'
        return snapshot

    def _materialize(self, tree_id, destination):
        nodes = json.loads(self.blobs[tree_id])['nodes']
        for node in nodes:
            target = os.path.join(destination, node['name'])
            if node['type'] == 'dir':
                os.mkdir(target, 0o700)
                self._materialize(node['subtree'], target)
            elif node['name'] == 'state' and self.symlink_state:
                os.symlink('/nonexistent-state', target)
            else:
                with open(target, 'wb') as handle:
                    handle.write(self.blobs[node['content'][0]])

    # -- verbs ----------------------------------------------------------

    def _cmd_cat(self, argv, cwd):
        index = argv.index('cat')
        sub = argv[index + 1]
        key = ('cat', sub)
        if key in self.stdout_override:
            return Completed(0, self.stdout_override[key])
        if sub == 'config':
            body = {'version': self.format_version, 'id': self.repo_id,
                    'chunker_polynomial': '20dc537bcfb0ed'}
            return Completed(0, json.dumps(body).encode())
        if sub == 'snapshot':
            snapshot_id = argv[index + 2]
            for snapshot in self.snapshots:
                if snapshot['id'] == snapshot_id:
                    return Completed(0, json.dumps(snapshot).encode())
            return Completed(1, b'', b'snapshot not found')
        if sub == 'blob':
            blob_id = argv[index + 2]
            if blob_id in self.blobs:
                return Completed(0, self.blobs[blob_id])
            return Completed(1, b'', b'blob not found')
        return Completed(1, b'', b'unknown cat object')

    def _cmd_snapshots(self, argv, cwd):
        key = ('snapshots', '')
        if key in self.stdout_override:
            return Completed(0, self.stdout_override[key])
        groups = []
        for index, arg in enumerate(argv):
            if arg == '--tag':
                groups.append(set(argv[index + 1].split(',')))
        matches = []
        for snapshot in self.snapshots:
            tags = set(snapshot['tags'])
            if not groups or any(group <= tags for group in groups):
                row = dict(snapshot)
                row['summary'] = {'snapshot_id': snapshot['id']}
                matches.append(row)
        return Completed(0, json.dumps(matches).encode())

    def _cmd_backup(self, argv, cwd):
        tags = []
        paths = []
        host = 'unknown'
        index = argv.index('backup') + 1
        while index < len(argv):
            arg = argv[index]
            if arg == '--tag':
                tags.extend(argv[index + 1].split(','))
                index += 2
            elif arg == '--host':
                host = argv[index + 1]
                index += 2
            elif arg.startswith('-'):
                index += 2 if arg in ('--host', '--tag') else 1
            else:
                paths.append(arg)
                index += 1
        if 'manifest.json' in paths:
            if self.no_final_tag:
                tags = [tag for tag in tags if tag != FINAL_TAG]
            if self.no_draft_tag:
                tags = [tag for tag in tags
                        if not tag.startswith('nexus-capture-v1')]
            if self.omit_manifest:
                paths = [path for path in paths
                         if path != 'manifest.json']
        snapshot = self._add_snapshot(paths, host, tags, cwd)
        summary = {'message_type': 'summary',
                   'snapshot_id': snapshot['id'],
                   'files_new': 1, 'files_changed': 0,
                   'total_bytes_processed': 21}
        return Completed(0, json.dumps(summary).encode() + b'\n')

    def _cmd_dump(self, argv, cwd):
        index = argv.index('dump')
        key = (argv[index + 1], argv[index + 2])
        if key in self.files:
            return Completed(0, self.files[key])
        return Completed(1, b'', b'path not found')

    def _cmd_restore(self, argv, cwd):
        index = argv.index('restore')
        snapshot_id = argv[index + 1]
        target = argv[argv.index('--target') + 1]
        snapshot = next((s for s in self.snapshots
                         if s['id'] == snapshot_id), None)
        if snapshot is None:
            return Completed(1, b'', b'snapshot not found')
        try:
            self._materialize(snapshot['tree'], target)
        except (KeyError, OSError) as error:
            return Completed(1, b'', str(error).encode())
        return Completed(0, b'restored\n')

    def _cmd_check(self, argv, cwd):
        self.checks += 1
        return Completed(0, b'no errors were found\n')

    def _cmd_copy(self, argv, cwd):
        index = argv.index('copy')
        args = argv[index + 1:]
        source_path = args[args.index('--from-repo') + 1]
        password_path = args[args.index('--from-password-file') + 1]
        snapshot_id = args[-1]
        source = self.sources.get(source_path)
        if source is None:
            return Completed(10, b'', b'unknown source repository')
        if source.password_content is not None:
            try:
                with open(password_path, 'rb') as handle:
                    supplied = handle.read()
            except OSError:
                return Completed(12, b'', b'password file unavailable')
            if supplied != source.password_content:
                return Completed(12, b'', b'wrong password')
        snapshot = next((entry for entry in source.snapshots
                         if entry['id'] == snapshot_id), None)
        if snapshot is None:
            return Completed(1, b'', b'snapshot not found')
        self.copy_id_suffix += 1
        copied = dict(snapshot)
        copied['original'] = snapshot_id
        copied['id'] = hashlib.sha256(
            ('copied:' + snapshot_id + ':' + self.repo_id + ':'
             + str(self.copy_id_suffix)).encode()).hexdigest()
        copied['short_id'] = copied['id'][:8]
        self.snapshots.append(copied)
        for key, data in source.blobs.items():
            self.blobs.setdefault(key, data)
        for (sid, path), data in source.files.items():
            if sid == snapshot_id:
                self.files[(copied['id'], path)] = data
        return Completed(0, b'copied 1 snapshots\n')


def make_private_dir(parent, name, mode=0o700):
    path = os.path.join(parent, name)
    os.mkdir(path, mode)
    return path


def write_private_file(path, content=b'secret', mode=0o600):
    with open(path, 'wb') as handle:
        handle.write(content)
    os.chmod(path, mode)
    return path


class RepositoryFixture(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        self.private = make_private_dir(self.root, 'private')
        self.password = write_private_file(
            os.path.join(self.private, 'password'))
        self.repo_dir = make_private_dir(self.root, 'repo')
        self.fake = FakeRestic()
        self._stage_count = 0
        self.addCleanup(mock.patch.stopall)

    def config(self, **overrides):
        record = {
            'schemaVersion': 1,
            'id': 'repo-a',
            'repositoryIdentity': self.fake.repo_id,
            'passwordFile': self.password,
            'transport': {'kind': 'local', 'path': self.repo_dir},
        }
        record.update(overrides)
        return record

    def sftp_config(self, **overrides):
        identity = write_private_file(
            os.path.join(self.private, 'id_ed25519'))
        known_hosts = write_private_file(
            os.path.join(self.private, 'known_hosts'))
        transport = {
            'kind': 'sftp', 'host': 'repository', 'port': 22,
            'user': 'backup', 'path': '/canary',
            'identityFile': identity, 'knownHostsFile': known_hosts,
        }
        overrides.setdefault('transport', transport)
        return self.config(**overrides)

    def repo(self, config=None, fake=None):
        return repository.ResticRepository(
            config or self.config(),
            runner=fake or self.fake)

    def stage(self, name=None, mounts=('data',), marker=True):
        self._stage_count += 1
        stage = make_private_dir(self.root,
                                 name or 'stage%d' % self._stage_count)
        state = make_private_dir(stage, 'state')
        for mount in mounts:
            leaf = make_private_dir(state, mount)
            if marker:
                write_private_file(
                    os.path.join(leaf, 'value'), b'restic-canary-content')
        self._own(state, mounts)
        return stage

    def _own(self, state, mounts, uid=65536, gid=65536):
        real_lstat = os.lstat
        owned = {os.path.join(state, mount): (uid, gid)
                 for mount in mounts}

        def fake_lstat(path):
            result = real_lstat(path)
            if path in owned:
                uid_value, gid_value = owned[path]
                return SimpleNamespace(st_mode=result.st_mode,
                                       st_uid=uid_value,
                                       st_gid=gid_value)
            return result
        mock.patch.object(repository, '_lstat', fake_lstat).start()

    def store(self, stage=None, **kwargs):
        stage = stage or self.stage()
        kwargs.setdefault('capture_id', CAPTURE_ID)
        return self.repo().store(
            stage, kwargs.pop('definition', sealed()),
            kwargs.pop('source', source()),
            kwargs.pop('capture', capture()), **kwargs)


class ConfigTests(RepositoryFixture):

    def expect_bad(self, config):
        with self.assertRaises(repository.RepositoryError):
            self.repo(config)

    def test_field_strictness(self):
        config = self.config()
        config['extra'] = True
        self.expect_bad(config)
        config = self.config()
        del config['id']
        self.expect_bad(config)
        self.expect_bad(self.config(schemaVersion=2))
        self.expect_bad(self.config(schemaVersion='1'))
        self.expect_bad(self.config(schemaVersion=True))
        self.expect_bad(self.config(id='Bad Id'))
        self.expect_bad(self.config(id=7))
        self.expect_bad(self.config(id='a' * 65))

    def test_identity_and_password_shape(self):
        for bad in ('sha256:' + 'a' * 64, 'a' * 63, 'A' * 64, 5, None):
            self.expect_bad(self.config(repositoryIdentity=bad))
        for bad in ('relative/path', '/x/../y', '/x/', '', '/x\x01y',
                    '/etc/passwd;', 7):
            self.expect_bad(self.config(passwordFile=bad))

    def test_transport_strictness(self):
        self.expect_bad(self.config(transport=None))
        self.expect_bad(self.config(transport={'kind': 's3'}))
        self.expect_bad(self.config(
            transport={'kind': 'local'}))
        self.expect_bad(self.config(
            transport={'kind': 'local', 'path': '/x', 'extra': 1}))
        self.expect_bad(self.config(
            transport={'kind': 'local', 'path': 'relative'}))
        self.expect_bad(self.config(
            transport={'kind': 'local', 'path': '/'}))

    def test_sftp_strictness(self):
        base = {'kind': 'sftp', 'host': 'repository', 'port': 22,
                'user': 'backup', 'path': '/canary',
                'identityFile': '/i', 'knownHostsFile': '/k'}
        for change in ({'host': 'http://repo'}, {'host': 'user@repo'},
                       {'host': 'a/b'}, {'host': '[10.0.0.1]'},
                       {'host': '-oProxyCommand=x'},
                       {'host': 'repo;evil'}, {'host': ''},
                       {'host': '010.0.0.1'}, {'host': '999.1.1.1'},
                       {'host': '1.2.3'},
                       {'host': 9}, {'user': 'bad user'},
                       {'user': 'root;rm'}, {'port': 0},
                       {'port': 65536}, {'port': '22'},
                       {'port': True}, {'port': 22.5},
                       {'path': 'relative'}, {'path': '/'},
                       {'identityFile': 'rel'}, {'kind': 'sftp2'}):
            bad = dict(base, **change)
            with self.subTest(change=change):
                self.expect_bad(self.config(transport=bad))
        for missing in base:
            if missing == 'kind':
                continue
            bad = {k: v for k, v in base.items() if k != missing}
            with self.subTest(missing=missing):
                self.expect_bad(self.config(transport=bad))
        extra = dict(base, option='-oBatchMode=no')
        self.expect_bad(self.config(transport=extra))
        # Canonical IPv4 literal is a permitted host form.
        config = self.sftp_config()
        config['transport']['host'] = '10.0.0.5'
        self.repo(config)

    def test_secret_file_rules(self):
        os.unlink(self.password)
        self.assertRaises_code('repository-key-missing', self.config())
        self.password = write_private_file(self.password)
        os.chmod(self.password, 0o644)
        self.assertRaises_code('path-unsafe', self.config())

    def assertRaises_code(self, code, config):
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.repo(config)
        self.assertEqual(ctx.exception.code, code)

    def test_sftp_secret_files(self):
        config = self.sftp_config()
        os.unlink(config['transport']['identityFile'])
        self.assertRaises_code('repository-transport-unavailable', config)
        config = self.sftp_config()
        os.unlink(config['transport']['knownHostsFile'])
        self.assertRaises_code('repository-transport-unavailable', config)
        config = self.sftp_config()
        os.chmod(config['transport']['identityFile'], 0o640)
        self.assertRaises_code('path-unsafe', config)

    def test_local_repo_dir_private(self):
        os.chmod(self.repo_dir, 0o770)
        self.assertRaises_code('path-unsafe', self.config())

    def test_missing_parents_typed(self):
        # A password path under a missing parent is a missing key, not
        # an untyped FileNotFoundError.
        self.assertRaises_code(
            'repository-key-missing',
            self.config(passwordFile='/missing-parent-x/password'))
        config = self.sftp_config()
        config['transport']['identityFile'] = '/missing-parent-x/id'
        self.assertRaises_code('repository-transport-unavailable',
                               config)
        # A missing local repository directory is a missing repo.
        os.rmdir(self.repo_dir)
        self.assertRaises_code('repository-missing', self.config())

    def test_os_error_path_unavailable(self):
        broken = mock.Mock(side_effect=PermissionError(13, 'denied'))
        with mock.patch.object(repository.statefiles,
                               'check_private_dir', broken):
            with self.assertRaises(repository.RepositoryError) as ctx:
                self.repo(self.config())
        self.assertEqual(ctx.exception.code, 'path-unavailable')

    def test_config_mutation_after_construction(self):
        config = self.sftp_config()
        repo = self.repo(config)
        # Mutate the caller's dict, including nested transport and the
        # approved identity; the adapter must retain its own copy.
        config['id'] = 'mutated'
        config['repositoryIdentity'] = 'b' * 64
        config['passwordFile'] = '/etc/passwd'
        config['transport']['host'] = 'evil.example.org'
        config['transport']['port'] = 1
        config['transport']['path'] = '/mutated'
        config['transport']['identityFile'] = '/etc/passwd'
        self.assertEqual(repo.verify_identity(), REPO_ID)
        argv = self.fake.calls[0]
        self.assertIn('sftp:backup@repository:/canary', argv)
        self.assertIn(self.password, argv)
        self.assertNotIn('evil.example.org', argv)
        self.assertNotIn('/mutated', argv)

    def test_sftp_argv_exact(self):
        repo = self.repo(self.sftp_config())
        repo.verify_identity()
        argv = self.fake.calls[0]
        ssh_argv = [
            'ssh', '-F', '/dev/null',
            '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
            '-o', 'IdentityAgent=none', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=' +
            self.sftp_config()['transport']['knownHostsFile'],
            '-o', 'GlobalKnownHostsFile=/dev/null',
            '-i', self.sftp_config()['transport']['identityFile'],
            '-p', '22', '-s', 'backup@repository', 'sftp']
        expected = [
            'restic', '--no-cache', '--repo',
            'sftp:backup@repository:/canary',
            '--password-file', self.password,
            '-o', 'sftp.command=' + shlex.join(ssh_argv),
            'cat', 'config']
        self.assertEqual(argv, expected)

    def test_local_argv(self):
        repo = self.repo()
        repo.verify_identity()
        self.assertEqual(self.fake.calls[0], [
            'restic', '--no-cache', '--repo', self.repo_dir,
            '--password-file', self.password, 'cat', 'config'])

    def test_environment_scrubbed(self):
        poison = {'RESTIC_PASSWORD_COMMAND': 'evil',
                  'RESTIC_REPOSITORY': 's3:evil', 'SSH_AUTH_SOCK': '/s',
                  'HTTP_PROXY': 'http://evil', 'HTTPS_PROXY': 'http://e',
                  'RESTIC_PASSWORD_FILE': '/dev/null'}
        with mock.patch.dict(os.environ, poison):
            env = repository._subprocess_env()
            runner = repository.BoundedRunner()
        self.assertEqual(set(env), {'PATH', 'LANG', 'LC_ALL'})
        self.assertEqual(set(runner.env), {'PATH', 'LANG', 'LC_ALL'})
        self.assertEqual(env['LANG'], 'C.UTF-8')
        self.assertEqual(env['LC_ALL'], 'C.UTF-8')


class RunnerTests(RepositoryFixture):

    def test_returncode_mapping(self):
        cases = [(3, 'capture-incomplete'), (10, 'repository-missing'),
                 (11, 'repository-locked'),
                 (12, 'repository-key-unavailable'),
                 (1, 'repository-command-failed'),
                 (99, 'repository-command-failed')]
        for rc, code in cases:
            fake = FakeRestic()
            fake.rc['check'] = rc
            repo = self.repo(fake=fake)
            with self.subTest(rc=rc):
                with self.assertRaises(repository.RepositoryError) as ctx:
                    repo.check()
                self.assertEqual(ctx.exception.code, code)

    def test_check_success_returns_none(self):
        self.assertIsNone(self.repo().check())

    def test_timeout_kills_process_group(self):
        pid_path = os.path.join(self.root, 'pid')
        child = (
            'import os,subprocess,time;'
            'open(%r,"w").write(str(os.getpid()));'
            'subprocess.Popen(["sleep","60"]);time.sleep(60)') % pid_path
        runner = repository.BoundedRunner()
        with self.assertRaises(repository.RepositoryError) as ctx:
            runner.run([sys.executable, '-c', child], timeout=1)
        self.assertEqual(ctx.exception.code, 'repository-timeout')
        with open(pid_path) as handle:
            pgid = int(handle.read())
        # The killed grandchild may briefly remain a zombie child of
        # init; poll until the group is fully gone.
        gone = False
        for _ in range(200):
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                gone = True
                break
            time.sleep(0.025)
        self.assertTrue(gone)

    def test_output_limit_kills(self):
        runner = repository.BoundedRunner()
        child = 'import sys;sys.stdout.write("x" * 65536)'
        with self.assertRaises(repository.RepositoryError) as ctx:
            runner.run([sys.executable, '-c', child], max_bytes=1024)
        self.assertEqual(ctx.exception.code,
                         'repository-output-too-large')

    def test_stderr_limit_kills(self):
        runner = repository.BoundedRunner()
        child = 'import sys;sys.stderr.write("x" * 131072)'
        with self.assertRaises(repository.RepositoryError) as ctx:
            runner.run([sys.executable, '-c', child])
        self.assertEqual(ctx.exception.code,
                         'repository-output-too-large')

    def _spawned(self):
        spawned = []
        real_popen = subprocess.Popen

        def tracking(*args, **kwargs):
            proc = real_popen(*args, **kwargs)
            spawned.append(proc)
            return proc
        return spawned, tracking

    def test_selector_failure_reaps_child(self):
        spawned, tracking = self._spawned()
        runner = repository.BoundedRunner()
        with mock.patch.object(repository.subprocess, 'Popen',
                               tracking), \
                mock.patch.object(repository.selectors,
                                  'DefaultSelector',
                                  side_effect=OSError('selector dead')):
            with self.assertRaises(repository.RepositoryError) as ctx:
                runner.run(['sleep', '60'])
        self.assertEqual(ctx.exception.code,
                         'repository-command-failed')
        proc = spawned[0]
        self.assertEqual(proc.returncode, -9)
        self.assertTrue(proc.stdout.closed)
        self.assertTrue(proc.stderr.closed)

    def test_keyboard_interrupt_reaps_child(self):
        spawned, tracking = self._spawned()

        class InterruptingSelector:
            def register(self, *args, **kwargs):
                pass

            def get_map(self):
                return {1: 1}

            def select(self, timeout=None):
                raise KeyboardInterrupt

            def close(self):
                pass

        runner = repository.BoundedRunner()
        with mock.patch.object(repository.subprocess, 'Popen',
                               tracking), \
                mock.patch.object(repository.selectors,
                                  'DefaultSelector',
                                  return_value=InterruptingSelector()):
            with self.assertRaises(KeyboardInterrupt):
                runner.run(['sleep', '60'])
        proc = spawned[0]
        self.assertEqual(proc.returncode, -9)
        self.assertTrue(proc.stdout.closed)
        self.assertTrue(proc.stderr.closed)

    def test_error_text_has_no_output(self):
        fake = FakeRestic()
        fake.rc['check'] = 3
        repo = self.repo(fake=fake)
        with self.assertRaises(repository.RepositoryError) as ctx:
            repo.check()
        self.assertEqual(str(ctx.exception), 'capture-incomplete')


class IdentityTests(RepositoryFixture):

    def test_wrong_identity_blocks_everything(self):
        fake = FakeRestic(repo_id='b' * 64)
        repo = self.repo(fake=fake)
        for action in (repo.check, repo.list_points,
                       lambda: repo.inspect('0' * 64),
                       lambda: repo.store(self.stage(), sealed(),
                                          source(), capture(),
                                          capture_id=CAPTURE_ID),
                       lambda: repo.restore('0' * 64,
                                            os.path.join(self.root,
                                                         'restored'))):
            with self.subTest(action=action):
                with self.assertRaises(repository.RepositoryError) as c:
                    action()
                self.assertEqual(c.exception.code,
                                 'repository-identity-mismatch')
        self.assertNotIn('backup', fake.verbs())
        self.assertNotIn('restore', fake.verbs())

    def test_identity_returned(self):
        self.assertEqual(self.repo().verify_identity(), REPO_ID)

    def test_bad_format_version_rejected(self):
        for version in (99, 0, 3, True, 2.0, '2'):
            fake = FakeRestic()
            fake.format_version = version
            repo = self.repo(fake=fake)
            with self.subTest(version=version):
                with self.assertRaises(
                        repository.RepositoryError) as ctx:
                    repo.check()
                self.assertEqual(ctx.exception.code,
                                 'repository-identity-mismatch')


class JsonRobustnessTests(RepositoryFixture):

    def test_duplicate_keys_rejected(self):
        fake = FakeRestic()
        fake.stdout_override[('cat', 'config')] = (
            b'{"version":2,"id":"' + REPO_ID.encode() +
            b'","id":"' + REPO_ID.encode() + b'"}')
        repo = self.repo(fake=fake)
        with self.assertRaises(repository.RepositoryError) as ctx:
            repo.check()
        self.assertEqual(ctx.exception.code,
                         'repository-output-invalid')

    def test_nonfinite_rejected(self):
        fake = FakeRestic()
        fake.stdout_override[('cat', 'config')] = (
            b'{"version":2,"id":NaN}')
        repo = self.repo(fake=fake)
        with self.assertRaises(repository.RepositoryError) as ctx:
            repo.check()
        self.assertEqual(ctx.exception.code,
                         'repository-output-invalid')

    def test_huge_integer_rejected(self):
        fake = FakeRestic()
        fake.stdout_override[('cat', 'config')] = (
            b'{"version":2,"id":' + b'9' * 5000 + b'}')
        repo = self.repo(fake=fake)
        with self.assertRaises(repository.RepositoryError) as ctx:
            repo.check()
        self.assertEqual(ctx.exception.code,
                         'repository-output-invalid')

    def test_deep_nesting_rejected(self):
        fake = FakeRestic()
        fake.stdout_override[('cat', 'config')] = (
            b'[' * 5000 + b']' * 5000)
        repo = self.repo(fake=fake)
        with self.assertRaises(repository.RepositoryError) as ctx:
            repo.check()
        self.assertEqual(ctx.exception.code,
                         'repository-output-invalid')


class StoreTests(RepositoryFixture):

    def test_happy_path_record_and_digest(self):
        record = self.store()
        self.assertEqual(set(record), {
            'schemaVersion', 'repositoryId', 'repositoryIdentity',
            'snapshotId', 'manifest'})
        self.assertEqual(record['schemaVersion'], 1)
        self.assertEqual(record['repositoryId'], 'repo-a')
        self.assertEqual(record['repositoryIdentity'], REPO_ID)
        self.assertRegex(record['snapshotId'], r'^[0-9a-f]{64}$')
        manifest = recovery.validate_manifest(record['manifest'])
        entry = manifest['state'][0]
        self.assertEqual(entry['id'], 'data')
        self.assertEqual(entry['path'], 'state/data')
        self.assertRegex(entry['treeDigest'],
                         r'^sha256:[0-9a-f]{64}$')
        # The recorded digest is the actual restic tree id read back
        # through the hashed blob channel.
        subtree = entry['treeDigest'][len('sha256:'):]
        self.assertIn(subtree, self.fake.blobs)
        self.assertEqual(
            hashlib.sha256(self.fake.blobs[subtree]).hexdigest(),
            subtree)
        verbs = self.fake.verbs()
        self.assertEqual(verbs.count('backup'), 2)
        self.assertNotIn('check', verbs)
        # Draft backup ran inside the staging dir over 'state' only.
        backups = [call for call in self.fake.calls
                   if self.fake._verb(call) == 'backup']
        draft, final = backups
        tag_index = draft.index('--tag') + 1
        self.assertEqual(draft[tag_index], DRAFT_TAG)
        self.assertEqual(draft[-1], 'state')
        self.assertIn(FINAL_TAG, final)
        self.assertIn(DRAFT_TAG, final)
        self.assertEqual(final[-2:], ['state', 'manifest.json'])

    def test_manifest_has_no_host_paths(self):
        record = self.store()
        raw = recovery.encode_manifest(record['manifest'])
        self.assertNotIn(self.root.encode(), raw)
        self.assertNotIn(b'/srv/workloads', raw)

    def test_replay_same_capture_returns_same_point(self):
        stage = self.stage()
        first = self.store(stage=stage)
        calls_before = len(self.fake.calls)
        second = self.store(stage=stage)
        self.assertEqual(first['snapshotId'], second['snapshotId'])
        self.assertEqual(first['manifest'], second['manifest'])
        new_backups = [call for call in self.fake.calls[calls_before:]
                       if self.fake._verb(call) == 'backup' and
                       FINAL_TAG in call]
        self.assertEqual(new_backups, [])

    def test_changed_data_same_capture_conflicts(self):
        stage = self.stage()
        self.store(stage=stage)
        fresh = self.stage()
        write_private_file(
            os.path.join(fresh, 'state', 'data', 'value'),
            b'changed-content')
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.store(stage=fresh)
        self.assertEqual(ctx.exception.code, 'capture-conflict')

    def test_preexisting_conflicting_manifest_refused(self):
        stage = self.stage()
        other = recovery.build_manifest(
            sealed(), source(), capture(completedAt=1006),
            state_tree_digests={'data': 'sha256:' + '9' * 64})
        write_private_file(
            os.path.join(stage, 'manifest.json'),
            recovery.encode_manifest(other))
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.store(stage=stage)
        self.assertEqual(ctx.exception.code, 'capture-conflict')

    def test_matching_preexisting_manifest_reused(self):
        stage = self.stage()
        first = self.store(stage=stage)
        fresh = self.stage()
        # Re-stage identical content plus the generated manifest.
        write_private_file(
            os.path.join(fresh, 'manifest.json'),
            recovery.encode_manifest(first['manifest']))
        record = self.store(stage=fresh)
        self.assertEqual(record['manifest'], first['manifest'])
        self.assertEqual(record['snapshotId'], first['snapshotId'])

    def test_capture_id_strict(self):
        stage = self.stage()
        for bad in (CAPTURE_ID.upper(), 'x' * 32, 'c1' * 15,
                    CAPTURE_ID + 'ff', 0, None):
            with self.subTest(bad=bad):
                with self.assertRaises(repository.RepositoryError) as c:
                    self.store(stage=stage, capture_id=bad)
                self.assertEqual(c.exception.code,
                                 'invalid-capture-id')

    def test_stage_shape_refused(self):
        stage = make_private_dir(self.root, 'stagex')
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.store(stage=stage)
        self.assertEqual(ctx.exception.code, 'invalid-stage')

    def test_stage_extra_entry_refused(self):
        stage = self.stage()
        write_private_file(os.path.join(stage, 'note.txt'), b'x')
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.store(stage=stage)
        self.assertEqual(ctx.exception.code, 'invalid-stage')

    def test_state_missing_extra_and_symlink_refused(self):
        stage = make_private_dir(self.root, 'stagey')
        state = make_private_dir(stage, 'state')
        self._own(state, ())
        with self.assertRaises(repository.RepositoryError):
            self.store(stage=stage)
        leaf = make_private_dir(state, 'data')
        write_private_file(os.path.join(leaf, 'value'), b'x')
        self._own(state, ('data',))
        extra = make_private_dir(state, 'extra')
        self._own(state, ('data', 'extra'))
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.store(stage=stage)
        self.assertEqual(ctx.exception.code, 'invalid-stage')
        os.rmdir(extra)
        os.unlink(os.path.join(leaf, 'value'))
        os.rmdir(leaf)
        os.symlink('/elsewhere', leaf)
        self._own(state, ('data',))
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.store(stage=stage)
        self.assertEqual(ctx.exception.code, 'invalid-stage')

    def test_state_ownership_refused(self):
        stage = make_private_dir(self.root, 'stagez')
        state = make_private_dir(stage, 'state')
        leaf = make_private_dir(state, 'data')
        write_private_file(os.path.join(leaf, 'value'), b'x')
        # Report ownership that does not match uidBase + ownerUid.
        self._own(state, ('data',), uid=99, gid=99)
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.store(stage=stage)
        self.assertEqual(ctx.exception.code, 'invalid-stage')

    def test_stage_symlink_manifest_refused(self):
        stage = self.stage()
        os.symlink('/etc/hostname',
                   os.path.join(stage, 'manifest.json'))
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.store(stage=stage)
        self.assertEqual(ctx.exception.code, 'invalid-stage')

    def test_invalid_capture_inputs_typed(self):
        stage = self.stage()
        cases = [
            dict(definition=sealed(allowedOperations=['start'])),
            dict(definition={'broken': True}),
            dict(source={'hostId': 7}),
            dict(capture={'adapter': 7}),
            dict(secret_bundle={'bad': True}),
        ]
        for overrides in cases:
            with self.subTest(overrides=overrides):
                with self.assertRaises(
                        repository.RepositoryError) as ctx:
                    self.store(stage=stage, **overrides)
                self.assertEqual(ctx.exception.code, 'invalid-capture')

    def test_incomplete_backup_rejected(self):
        fake = FakeRestic()
        fake.rc['backup'] = 3
        repo = self.repo(fake=fake)
        stage = self.stage()
        with self.assertRaises(repository.RepositoryError) as ctx:
            repo.store(stage, sealed(), source(), capture(),
                       capture_id=CAPTURE_ID)
        self.assertEqual(ctx.exception.code, 'capture-incomplete')
        # No final tag was ever requested.
        for call in fake.calls:
            if fake._verb(call) == 'backup':
                self.assertNotIn(FINAL_TAG, call)

    def test_manifest_write_oserror_typed(self):
        fake = self.fake
        repo = self.repo()
        stage = self.stage()
        marker = os.path.join(stage, 'state', 'data', 'value')
        with mock.patch.object(repository.statefiles, 'write_json',
                               side_effect=OSError(28, 'No space')):
            with self.assertRaises(repository.RepositoryError) as ctx:
                repo.store(stage, sealed(), source(), capture(),
                           capture_id=CAPTURE_ID)
        self.assertEqual(ctx.exception.code, 'path-unavailable')
        # No final-tag backup was ever requested; only the draft ran.
        for call in fake.calls:
            if fake._verb(call) == 'backup':
                self.assertNotIn(FINAL_TAG, call)
        self.assertEqual(len(fake.snapshots), 1)
        # The stage and its captured data are untouched.
        with open(marker, 'rb') as handle:
            self.assertEqual(handle.read(), b'restic-canary-content')

    def test_multi_line_summary_rejected(self):
        fake = FakeRestic()
        original = fake._cmd_backup

        def bad_summary(argv, cwd):
            result = original(argv, cwd)
            return Completed(0, result.stdout + result.stdout)
        fake._cmd_backup = bad_summary
        repo = self.repo(fake=fake)
        stage = self.stage()
        with self.assertRaises(repository.RepositoryError) as ctx:
            repo.store(stage, sealed(), source(), capture(),
                       capture_id=CAPTURE_ID)
        self.assertEqual(ctx.exception.code,
                         'repository-output-invalid')

    def test_tree_blob_hash_mismatch_refused(self):
        fake = FakeRestic()
        fake.corrupt_blob = True
        repo = self.repo(fake=fake)
        stage = self.stage()
        with self.assertRaises(repository.RepositoryError) as ctx:
            repo.store(stage, sealed(), source(), capture(),
                       capture_id=CAPTURE_ID)
        self.assertEqual(ctx.exception.code, 'repository-point-invalid')

    def test_missing_manifest_root_refused(self):
        fake = FakeRestic()
        fake.omit_manifest = True
        repo = self.repo(fake=fake)
        stage = self.stage()
        with self.assertRaises(repository.RepositoryError) as ctx:
            repo.store(stage, sealed(), source(), capture(),
                       capture_id=CAPTURE_ID)
        self.assertEqual(ctx.exception.code, 'repository-point-invalid')

    def test_extra_root_refused(self):
        fake = FakeRestic()
        fake.extra_root = True
        repo = self.repo(fake=fake)
        stage = self.stage()
        with self.assertRaises(repository.RepositoryError) as ctx:
            repo.store(stage, sealed(), source(), capture(),
                       capture_id=CAPTURE_ID)
        self.assertEqual(ctx.exception.code, 'repository-point-invalid')

    def test_missing_final_tag_refused(self):
        fake = FakeRestic()
        fake.no_final_tag = True
        repo = self.repo(fake=fake)
        stage = self.stage()
        with self.assertRaises(repository.RepositoryError) as ctx:
            repo.store(stage, sealed(), source(), capture(),
                       capture_id=CAPTURE_ID)
        self.assertEqual(ctx.exception.code, 'repository-point-invalid')

    def test_missing_draft_tag_on_final_refused(self):
        # The capture tag is revalidated on the snapshot document
        # itself; the --tag filter is never trusted.
        fake = FakeRestic()
        fake.no_draft_tag = True
        repo = self.repo(fake=fake)
        stage = self.stage()
        with self.assertRaises(repository.RepositoryError) as ctx:
            repo.store(stage, sealed(), source(), capture(),
                       capture_id=CAPTURE_ID)
        self.assertEqual(ctx.exception.code, 'repository-point-invalid')

    def test_manifest_node_size_strict(self):
        record = self.store()
        snapshot = next(s for s in self.fake.snapshots
                        if s['id'] == record['snapshotId'])
        nodes = json.loads(self.fake.blobs[snapshot['tree']])['nodes']
        for bad in ('missing', '12345', -1, True,
                    2 * 1024 * 1024 + 1):
            for node in nodes:
                if node['name'] == 'manifest.json':
                    if bad == 'missing':
                        node.pop('size', None)
                    else:
                        node['size'] = bad
            raw = json.dumps({'nodes': nodes}, sort_keys=True,
                             separators=(',', ':')).encode()
            blob_id = hashlib.sha256(raw).hexdigest()
            self.fake.blobs[blob_id] = raw
            snapshot['tree'] = blob_id
            with self.subTest(size=bad):
                with self.assertRaises(
                        repository.RepositoryError) as ctx:
                    self.repo().inspect(record['snapshotId'])
                self.assertEqual(ctx.exception.code,
                                 'repository-point-invalid')

    def test_state_ownership_node_refused(self):
        fake = FakeRestic()
        fake.node_uid = 99
        repo = self.repo(fake=fake)
        stage = self.stage()
        with self.assertRaises(repository.RepositoryError) as ctx:
            repo.store(stage, sealed(), source(), capture(),
                       capture_id=CAPTURE_ID)
        self.assertEqual(ctx.exception.code, 'repository-point-invalid')

    def test_manifest_tree_digest_mismatch_refused(self):
        fake = FakeRestic()
        original_add = fake._add_snapshot

        def add_and_swap(paths, host, tags, cwd):
            snapshot = original_add(paths, host, tags, cwd)
            if 'manifest.json' in paths:
                # Rewrite the state subtree's children to point at a
                # subtree that does not exist; reading it back through
                # the hashed blob channel fails closed.
                nodes = json.loads(
                    fake.blobs[snapshot['tree']])['nodes']
                state_id = next(
                    n['subtree'] for n in nodes if n['name'] == 'state')
                children = json.loads(
                    fake.blobs[state_id])['nodes']
                for node in children:
                    node['subtree'] = hashlib.sha256(b'wrong').hexdigest()
                fake.blobs[state_id] = json.dumps(
                    {'nodes': children}, sort_keys=True,
                    separators=(',', ':')).encode()
            return snapshot
        fake._add_snapshot = add_and_swap
        repo = self.repo(fake=fake)
        stage = self.stage()
        with self.assertRaises(repository.RepositoryError) as ctx:
            repo.store(stage, sealed(), source(), capture(),
                       capture_id=CAPTURE_ID)
        # The altered subtree id no longer hashes to its own id when
        # read back through _tree, so the point fails closed.
        self.assertEqual(ctx.exception.code, 'repository-point-invalid')


class ListTests(RepositoryFixture):

    def test_list_returns_points_sorted_and_skips_drafts(self):
        first = self.store()
        second = self.store(
            stage=self.stage(name='stage2'), capture_id='d2' * 16)
        records = self.repo().list_points()
        self.assertEqual(len(records), 2)
        order = [(r['manifest']['recoveryPointId'], r['snapshotId'])
                 for r in records]
        self.assertEqual(order, sorted(order))
        ids = {first['snapshotId'], second['snapshotId']}
        self.assertEqual({r['snapshotId'] for r in records}, ids)
        # The two draft snapshots exist but are never selected.
        self.assertEqual(len(self.fake.snapshots), 4)

    def test_list_reconstructs_without_catalog(self):
        self.store()
        records = self.repo().list_points()
        manifest = records[0]['manifest']
        recovery.validate_manifest(manifest)
        self.assertEqual(manifest['definition']['workloadId'], 'demo')
        self.assertEqual(manifest['source']['instanceId'], INSTANCE)

    def test_corrupt_point_fails_closed(self):
        self.store()
        second = self.store(
            stage=self.stage(name='stage2'), capture_id='d2' * 16)
        # Corrupt the final snapshot's tree blob bytes.
        snapshot = next(s for s in self.fake.snapshots
                        if s['id'] == second['snapshotId'])
        self.fake.blobs[snapshot['tree']] = b'garbage'
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.repo().list_points()
        self.assertEqual(ctx.exception.code, 'repository-point-invalid')

    def test_snapshot_bound_enforced(self):
        fake = FakeRestic()
        fake.stdout_override[('snapshots', '')] = json.dumps(
            [{'id': '0' * 64}] * 10001).encode()
        repo = self.repo(fake=fake)
        with self.assertRaises(repository.RepositoryError) as ctx:
            repo.list_points()
        self.assertEqual(ctx.exception.code,
                         'repository-output-invalid')


class RestoreTests(RepositoryFixture):

    def test_restore_extracts_verified_point(self):
        record = self.store()
        destination = os.path.join(self.root, 'restored')
        # Model restic's numeric-ownership extraction: restored mount
        # roots carry uidBase + owner ids.
        self._own(os.path.join(destination, 'state'), ('data',))
        result = self.repo().restore(record['snapshotId'], destination)
        self.assertEqual(result, record)
        with open(os.path.join(
                destination, 'state', 'data', 'value'), 'rb') as h:
            self.assertEqual(h.read(), b'restic-canary-content')
        raw = self.repo()._read_bounded(
            os.path.join(destination, 'manifest.json'),
            2 * 1024 * 1024)
        self.assertEqual(recovery.decode_manifest(raw),
                         record['manifest'])
        # Original numeric ownership is asserted by state binding;
        # layout is exactly state + manifest.json.
        self.assertEqual(set(os.listdir(destination)),
                         {'state', 'manifest.json'})
        self.assertTrue(stat.S_ISDIR(os.lstat(os.path.join(
            destination, 'state', 'data')).st_mode))

    def test_existing_destination_refused_before_restore(self):
        record = self.store()
        calls_before = len(self.fake.calls)
        for form in ('dir', 'file', 'symlink'):
            dest = os.path.join(self.root, 'existing-' + form)
            if form == 'dir':
                os.mkdir(dest, 0o700)
            elif form == 'file':
                write_private_file(dest)
            else:
                os.symlink('/gone-target', dest)
            with self.subTest(form=form):
                with self.assertRaises(repository.RepositoryError) as c:
                    self.repo().restore(record['snapshotId'], dest)
                self.assertEqual(c.exception.code, 'destination-exists')
        for call in self.fake.calls[calls_before:]:
            self.assertNotEqual(self.fake._verb(call), 'restore')

    def test_unsafe_parent_refused(self):
        record = self.store()
        parent = make_private_dir(self.root, 'shared', mode=0o777)
        dest = os.path.join(parent, 'restored')
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.repo().restore(record['snapshotId'], dest)
        self.assertEqual(ctx.exception.code, 'path-unsafe')

    def test_failed_restore_retained_not_ready(self):
        record = self.store()
        fake = self.fake
        original = fake._cmd_restore

        def partial(argv, cwd):
            target = argv[argv.index('--target') + 1]
            os.mkdir(os.path.join(target, 'partial'), 0o700)
            return Completed(1, b'', b'partial failure')
        fake._cmd_restore = partial
        dest = os.path.join(self.root, 'restored')
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.repo().restore(record['snapshotId'], dest)
        self.assertEqual(ctx.exception.code, 'repository-command-failed')
        self.assertTrue(os.path.isdir(os.path.join(dest, 'partial')))
        fake._cmd_restore = original

    def test_restored_manifest_mismatch_refused(self):
        record = self.store()
        fake = self.fake
        other = recovery.build_manifest(
            sealed(), source(generation=2), capture(),
            state_tree_digests={
                entry['id']: entry['treeDigest']
                for entry in record['manifest']['state']})
        manifest_blob = hashlib.sha256(
            recovery.encode_manifest(record['manifest'])).hexdigest()
        fake.blobs[manifest_blob] = recovery.encode_manifest(other)
        dest = os.path.join(self.root, 'restored')
        self._own(os.path.join(dest, 'state'), ('data',))
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.repo().restore(record['snapshotId'], dest)
        self.assertEqual(ctx.exception.code, 'repository-point-invalid')

    def test_restored_ownership_refused(self):
        record = self.store()
        dest = os.path.join(self.root, 'restored')
        # A mount root restored with foreign numeric ownership must
        # never produce a successful receipt.
        self._own(os.path.join(dest, 'state'), ('data',),
                  uid=99, gid=98)
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.repo().restore(record['snapshotId'], dest)
        self.assertEqual(ctx.exception.code, 'repository-point-invalid')

    def test_restored_symlink_state_refused(self):
        record = self.store()
        fake = self.fake
        original = fake._materialize

        def linked(tree_id, destination):
            os.mkdir(os.path.join(destination, 'state'), 0o700)
            os.symlink('/elsewhere',
                       os.path.join(destination, 'state', 'data'))
            with open(os.path.join(destination, 'manifest.json'),
                      'wb') as handle:
                handle.write(fake.files[
                    (record['snapshotId'], '/manifest.json')])
        fake._materialize = linked
        dest = os.path.join(self.root, 'restored')
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.repo().restore(record['snapshotId'], dest)
        self.assertEqual(ctx.exception.code, 'repository-point-invalid')
        fake._materialize = original

    def test_missing_state_root_refused(self):
        record = self.store()
        fake = self.fake

        def short(tree_id, destination):
            with open(os.path.join(destination, 'manifest.json'),
                      'wb') as handle:
                handle.write(fake.files[
                    (record['snapshotId'], '/manifest.json')])
        fake._materialize = short
        dest = os.path.join(self.root, 'restored')
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.repo().restore(record['snapshotId'], dest)
        self.assertEqual(ctx.exception.code, 'repository-point-invalid')


class InspectTests(RepositoryFixture):

    def test_inspect_final(self):
        record = self.store()
        looked = self.repo().inspect(record['snapshotId'])
        self.assertEqual(looked, record)

    def test_inspect_draft_refused(self):
        self.store()
        draft = next(s for s in self.fake.snapshots
                     if FINAL_TAG not in s['tags'])
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.repo().inspect(draft['id'])
        self.assertEqual(ctx.exception.code, 'repository-point-invalid')

    def test_inspect_malformed_id_refused(self):
        for bad in ('latest', 'abc', '0' * 64 + 'f', 'A' * 64, 7):
            with self.subTest(bad=bad):
                with self.assertRaises(repository.RepositoryError):
                    self.repo().inspect(bad)


class CaptureFinishedTests(RepositoryFixture):

    def test_callback_result_binds_manifest(self):
        stage = self.stage()
        finished = []
        supplied = capture(completedAt=7777)

        def callback():
            finished.append('called')
            return supplied

        record = self.repo().store(
            stage, sealed(), source(), capture(), capture_id=CAPTURE_ID,
            capture_finished=callback)
        self.assertEqual(finished, ['called'])
        self.assertEqual(record['manifest']['capture'], supplied)
        self.assertNotEqual(
            record['manifest']['capture']['completedAt'],
            capture()['completedAt'])

    def test_callback_failure_blocks_final_tag(self):
        stage = self.stage()

        def callback():
            raise BackupBoom()

        class BackupBoom(Exception):
            pass

        with self.assertRaises(repository.RepositoryError) as ctx:
            self.repo().store(stage, sealed(), source(), capture(),
                              capture_id=CAPTURE_ID,
                              capture_finished=callback)
        self.assertEqual(ctx.exception.code,
                         'capture-checkpoint-failed')
        for snapshot in self.fake.snapshots:
            self.assertNotIn(FINAL_TAG, snapshot['tags'])
        self.assertFalse(os.path.exists(
            os.path.join(stage, 'manifest.json')))


class CopyFromTests(RepositoryFixture):

    def setUp(self):
        super().setUp()
        self.dest_dir = make_private_dir(self.root, 'dest-repo')
        self.dest_password = write_private_file(
            os.path.join(self.private, 'dest-password'),
            b'destination-key')
        self.dest_fake = FakeRestic(repo_id='d' * 64)
        self.dest_fake.sources = {self.repo_dir: self.fake}
        self.dest_fake.password_content = None

    def dest(self):
        config = self.config(
            id='repo-b', repositoryIdentity=self.dest_fake.repo_id,
            passwordFile=self.dest_password,
            transport={'kind': 'local', 'path': self.dest_dir})
        return repository.ResticRepository(
            config, runner=self.dest_fake)

    def source_repo(self):
        return self.repo()

    def test_copy_to_empty_destination(self):
        record = self.store()
        copied = self.dest().copy_from(
            self.source_repo(), record['snapshotId'])
        self.assertNotEqual(
            copied['snapshotId'], record['snapshotId'])
        self.assertEqual(copied['repositoryId'], 'repo-b')
        self.assertEqual(copied['manifest'], record['manifest'])
        copies = [call for call in self.dest_fake.calls
                  if 'copy' in call]
        self.assertEqual(len(copies), 1)
        argv = copies[0]
        verb_index = argv.index('copy')
        self.assertIn('--from-repo', argv)
        self.assertIn('--from-password-file', argv)
        self.assertIn(record['snapshotId'], argv[verb_index:])
        self.assertGreaterEqual(self.dest_fake.checks, 1)

    def test_copy_replay_returns_existing(self):
        record = self.store()
        first = self.dest().copy_from(
            self.source_repo(), record['snapshotId'])
        second = self.dest().copy_from(
            self.source_repo(), record['snapshotId'])
        self.assertEqual(second, first)
        copy_calls = [call for call in self.dest_fake.calls
                      if 'copy' in call]
        self.assertEqual(len(copy_calls), 1)
        self.assertGreaterEqual(self.dest_fake.checks, 2)

    def test_copy_conflict_refused(self):
        record = self.store()
        # A final snapshot under the same capture tag whose manifest
        # is valid but different must be a conflict, not an upload.
        self.dest().store(self.stage(), sealed(), source(),
                          capture(completedAt=9999),
                          capture_id=CAPTURE_ID)
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.dest().copy_from(
                self.source_repo(), record['snapshotId'])
        self.assertEqual(ctx.exception.code, 'capture-conflict')

    def test_copy_wrong_source_key_refused(self):
        record = self.store()
        self.fake.password_content = b'source-key'
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.dest().copy_from(
                self.source_repo(), record['snapshotId'])
        self.assertEqual(ctx.exception.code,
                         'repository-key-unavailable')

    def test_copy_source_identity_checked(self):
        record = self.store()
        source_repo = self.source_repo()
        self.fake.repo_id = 'e' * 64
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.dest().copy_from(
                source_repo, record['snapshotId'])
        self.assertEqual(ctx.exception.code,
                         'repository-identity-mismatch')
        self.assertFalse(
            any('copy' in call for call in self.dest_fake.calls))

    def test_copy_missing_snapshot_refused(self):
        self.store()
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.dest().copy_from(
                self.source_repo(), 'f' * 64)
        self.assertEqual(ctx.exception.code,
                         'repository-command-failed')

    def test_copy_draft_snapshot_refused(self):
        self.store()
        draft = next(s for s in self.fake.snapshots
                     if FINAL_TAG not in s['tags'])
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.dest().copy_from(self.source_repo(), draft['id'])
        self.assertEqual(ctx.exception.code,
                         'repository-point-invalid')

    def test_copy_sftp_source_refused(self):
        sftp = self.repo(self.sftp_config())
        with self.assertRaises(repository.RepositoryError) as ctx:
            self.dest().copy_from(sftp, 'a' * 64)
        self.assertEqual(ctx.exception.code, 'invalid-transport')

    def test_copy_corruption_detected(self):
        record = self.store()
        dest = self.dest()
        copied = dest.copy_from(
            self.source_repo(), record['snapshotId'])
        # Corrupting the copied manifest makes the next replay fail
        # inspection rather than return stale success.
        for key in list(self.dest_fake.files):
            self.dest_fake.files[key] = b'not-json-manifest'
        with self.assertRaises(repository.RepositoryError):
            dest.copy_from(self.source_repo(), record['snapshotId'])


if __name__ == '__main__':
    unittest.main()
