import base64
import copy
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

CONSOLE = Path(__file__).resolve().parent
sys.path.insert(0, str(CONSOLE))
import artifacts
import catalog
import worker


def store_path(name, marker):
    alphabet = '0123456789abcdfghijklmnpqrsvwxyz'
    return '/nix/store/' + alphabet[marker % 32] * 32 + '-' + name


ROOT = store_path('nixos-system-canary', 3)
DEP = store_path('dep', 2)
NAR = 'ab' * 32


def manifest_fixture(**overrides):
    manifest = {
        'schemaVersion': 1,
        'kind': 'nixos-closure',
        'runtimeVersion': 'nspawn-v1',
        'architecture': 'x86_64-linux',
        'root': ROOT,
        'closure': [
            {'path': DEP, 'narHash': 'sha256:' + NAR, 'narSize': 10, 'references': []},
            {'path': ROOT, 'narHash': 'sha256:' + NAR, 'narSize': 20, 'references': [DEP]},
        ],
    }
    manifest.update(overrides)
    return manifest


def draft_fixture(**overrides):
    definition = {
        'schemaVersion': 2,
        'workloadId': 'canary',
        'displayName': 'Canary',
        'category': 'project',
        'runtimeVersion': 'nspawn-v1',
        'architecture': 'x86_64-linux',
        'runtimeArtifactId': 'runtime',
        'artifacts': [],
        'stateSchemaVersion': 1,
        'stateMounts': [{'id': 'data', 'mountPoint': '/state', 'ownerUid': 0,
                         'ownerGid': 0, 'consistencyAdapter': 'quiesce-v1'}],
        'secretSetRef': None,
        'dependencies': [],
        'services': [{'id': 'web', 'protocol': 'http', 'port': 8080, 'exposure': 'private'}],
        'requirements': {'memoryMiB': 256, 'cpuMillis': 100, 'stateBytes': 1048576,
                         'capabilities': ['userns', 'nspawn-v1']},
        'allowedOperations': ['start', 'stop', 'restart', 'backup', 'restore', 'move'],
        'policyProfiles': ['normal'],
    }
    definition.update(overrides)
    return definition


def sealed_fixture(**overrides):
    draft = draft_fixture(**overrides)
    manifest = manifest_fixture()
    return artifacts.seal_workload(draft, manifest), manifest


class Result:
    def __init__(self, argv, returncode=0, stdout='', stderr=''):
        self.argv = argv
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeRunner:
    def __init__(self, manifest=None):
        self.calls = []
        self.units = {}
        self.owner = None
        self.fail_start = False
        self.show_mode = 'ok'
        self.mount_rows = []
        self.mount_rc = 0
        self.nix_rc = 0
        self.nix_records = None
        self.manifest = manifest or manifest_fixture()
        self.crash_after = None
        self.listed_units = None
        self.list_units_mode = 'ok'

    def unit_state(self, unit):
        return self.units.get(unit, {'LoadState': 'not-found',
                                     'ActiveState': 'inactive',
                                     'SubState': 'dead', 'MainPID': '0',
                                     'ControlGroup': ''})

    def _nix(self, argv):
        if self.nix_rc != 0:
            return Result(argv, self.nix_rc, '', 'nix failed')
        if argv[0] == 'nix':
            if self.nix_records is not None:
                records = self.nix_records
            else:
                records = [{'path': e['path'], 'narHash': e['narHash'],
                            'narSize': e['narSize'],
                            'references': e['references']}
                           for e in self.manifest['closure']]
            return Result(argv, 0, json.dumps(records))
        if argv[0] == 'nix-store':
            return Result(argv, 0, '')
        return Result(argv, 1, '', 'unexpected store call')

    def run(self, argv):
        self.calls.append(list(argv))
        if argv[0] == 'findmnt':
            if self.mount_rc != 0:
                return Result(argv, self.mount_rc, '', 'findmnt failed')
            return Result(argv, 0,
                          json.dumps({'filesystems': self.mount_rows}))
        if argv[0] in ('nix', 'nix-store'):
            return self._nix(argv)
        verb = argv[2] if argv[0] == 'systemctl' else argv[0]
        result = self._systemd(verb, argv)
        if self.crash_after == verb:
            self.crash_after = None
            raise KeyboardInterrupt('simulated crash after ' + verb)
        return result

    def _systemd(self, verb, argv):
        if verb == 'daemon-reload':
            return Result(argv, 0)
        if verb == 'list-units':
            if self.list_units_mode == 'rc':
                return Result(argv, 1, '', 'list-units failed')
            names = self.listed_units if self.listed_units is not None \
                else sorted(self.units)
            lines = []
            for unit in names:
                state = self.unit_state(unit)
                lines.append('{} {} {} {} test'.format(
                    unit, state['LoadState'], state['ActiveState'],
                    state['SubState']))
            return Result(argv, 0,
                          '\n'.join(lines) + ('\n' if lines else ''))
        if verb == 'start':
            unit = argv[3]
            machine = unit[len('nexus-workload@'):-len('.service')]
            if self.fail_start or self.owner is None \
                    or self.owner.guard(machine) != 0:
                self.units[unit] = {'LoadState': 'loaded', 'ActiveState': 'failed',
                                    'SubState': 'failed', 'MainPID': '0',
                                    'ControlGroup': ''}
                return Result(argv, 1, '', 'condition failed')
            self.units[unit] = {'LoadState': 'loaded', 'ActiveState': 'active',
                                'SubState': 'running', 'MainPID': '4242',
                                'ControlGroup': '/machine.slice/' + unit}
            return Result(argv, 0)
        if verb == 'stop':
            unit = argv[3]
            self.units[unit] = {'LoadState': 'loaded', 'ActiveState': 'inactive',
                                'SubState': 'dead', 'MainPID': '0',
                                'ControlGroup': '/machine.slice/' + unit}
            return Result(argv, 0)
        if verb == 'show':
            if self.show_mode == 'rc':
                return Result(argv, 1, '', 'show failed')
            if self.show_mode == 'raise':
                raise subprocess.TimeoutExpired('systemctl', 5)
            state = self.unit_state(argv[3])
            if self.show_mode == 'missing':
                state = {k: v for k, v in state.items() if k != 'MainPID'}
            body = '\n'.join('{}={}'.format(k, v) for k, v in state.items())
            return Result(argv, 0, body + '\n')
        return Result(argv, 1, '', 'unexpected argv')


class FakeClock:
    def __init__(self):
        self.now = 1000.0
        self.mono = 500.0

    def time(self):
        return self.now

    def monotonic(self):
        return self.mono


FAKE_BUNDLE = '/nix/store/' + 'a' * 32 + '-nexus-workload-canary'


class FakeFilesystem(worker.HostFilesystem):
    def __init__(self, mem_kb=2097152, free_bytes=1 << 30,
                 cgroup_populated='0', cgroup_error=None, bundle_dir=None):
        self.mem_kb = mem_kb
        self.free_bytes = free_bytes
        self.cgroup_populated = cgroup_populated
        self.cgroup_error = cgroup_error
        self.bundle_dir = bundle_dir
        self.chowns = []
        self.owners = {}
        self.synced_dirs = []

    def _map(self, path):
        if self.bundle_dir is not None and path.startswith(FAKE_BUNDLE):
            return self.bundle_dir + path[len(FAKE_BUNDLE):]
        return path

    def lstat(self, path):
        real = os.lstat(self._map(path))
        uid, gid = self.owners.get(path, (0, 0))
        return SimpleNamespace(st_mode=real.st_mode, st_uid=uid, st_gid=gid)

    def mkdir(self, path, mode):
        os.mkdir(self._map(path), mode)
        os.chmod(self._map(path), mode)

    def sync_dir(self, path):
        self.synced_dirs.append(path)
        mapped = self._map(path)
        if mapped != path or not path.startswith('/nix/'):
            super().sync_dir(mapped)

    def listdir(self, path):
        return os.listdir(self._map(path))

    def create_file(self, path, mode):
        fd = os.open(self._map(path),
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        os.close(fd)

    def write_file(self, path, data, mode):
        super().write_file(self._map(path), data, mode)

    def exists(self, path):
        return os.path.exists(self._map(path))

    def is_symlink(self, path):
        return os.path.islink(self._map(path))

    def read_bytes(self, path):
        return Path(self._map(path)).read_bytes()

    def read_bounded(self, path, limit):
        with open(self._map(path), 'rb') as handle:
            return handle.read(limit + 1)

    def read_text(self, path):
        if path == '/proc/meminfo':
            return 'MemTotal: 4194304 kB\nMemAvailable: {} kB\n'.format(self.mem_kb)
        if path.endswith('/cgroup.events'):
            if self.cgroup_error is not None:
                raise self.cgroup_error
            return 'populated {}\nfrozen 0\n'.format(self.cgroup_populated)
        return Path(self._map(path)).read_text()

    def chown(self, path, uid, gid):
        self.chowns.append((path, uid, gid))
        self.owners[path] = (uid, gid)

    def statvfs(self, path):
        os.statvfs(self._map(path))
        value = SimpleNamespace()
        value.f_bavail = self.free_bytes // 4096
        value.f_frsize = 4096
        return value


def make_config(tmp, uuid='1111-2222', storage_subdir=False):
    state = os.path.join(tmp, 'worker-state')
    storage = os.path.join(tmp, 'storage')
    os.makedirs(storage)
    if storage_subdir:
        storage = os.path.join(storage, 'sub')
    bundle = os.path.join(tmp, 'bundle')
    os.makedirs(bundle)
    return {
        'schemaVersion': 1,
        'hostId': 'host-a',
        'architecture': 'x86_64-linux',
        'stateDir': state,
        'storage': {'root': storage,
                    'mountPoint': os.path.join(tmp, 'storage'), 'uuid': uuid},
        'capacity': {'memoryMiB': 768, 'cpuMillis': 1000, 'stateBytes': 33554432},
        'capabilities': ['userns', 'nspawn-v1'],
        'approvedBundles': [FAKE_BUNDLE],
        'slots': [
            {'id': 'first', 'uidBase': 65536, 'hostAddress': '192.168.130.1',
             'localAddress': '192.168.130.2'},
            {'id': 'second', 'uidBase': 131072, 'hostAddress': '192.168.131.1',
             'localAddress': '192.168.131.2'},
        ],
    }, bundle


def write_bundle(bundle_dir, manifest=None, definition=None, canonical=True):
    manifest = manifest or manifest_fixture()
    if definition is None:
        definition, _ = sealed_fixture()
    manifest_bytes = artifacts.canonical_bytes(manifest)
    if not canonical:
        manifest_bytes = json.dumps(manifest, indent=2).encode()
    Path(bundle_dir, 'artifact.json').write_bytes(manifest_bytes)
    Path(bundle_dir, 'artifact.sha256').write_text(
        artifacts.manifest_digest(manifest) + '\n')
    Path(bundle_dir, 'definition.json').write_bytes(
        artifacts.canonical_bytes(definition))


_LIVE_WORKERS = []


def new_worker(*args, **kwargs):
    instance = worker.Worker(*args, **kwargs)
    _LIVE_WORKERS.append(instance)
    return instance


def tearDownModule():
    for instance in _LIVE_WORKERS:
        instance.close()
    _LIVE_WORKERS.clear()


def make_worker(tmp, definition_overrides=None, runner=None, fs=None, clock=None,
                bundle_manifest=None, config=None):
    config = config or make_config(tmp)[0]
    bundle = os.path.join(tmp, 'bundle')
    manifest = bundle_manifest or manifest_fixture()
    if definition_overrides is None:
        definition, _ = sealed_fixture()
    else:
        definition = artifacts.seal_workload(
            draft_fixture(**definition_overrides), manifest)
    write_bundle(bundle, manifest, definition)
    runner = runner or FakeRunner(manifest)
    runner.manifest = manifest
    fs = fs or FakeFilesystem()
    fs.bundle_dir = bundle
    clock = clock or FakeClock()
    runner.mount_rows = [{'target': config['storage']['mountPoint'],
                          'source': '/dev/vdb',
                          'uuid': config['storage']['uuid']}]
    os.makedirs(os.path.join(tmp, 'units'), exist_ok=True)
    instance = new_worker(config, runner=runner, fs=fs, clock=clock,
                             boot_id='test-boot-id',
                             unit_dir=os.path.join(tmp, 'units'))
    runner.owner = instance
    return instance, runner, fs, clock, definition, manifest


def request(action, instance='0a' * 16, op='aa' * 16, generation=1, **overrides):
    req = {'schemaVersion': 1, 'operationId': op, 'action': action,
           'workloadId': 'canary', 'revisionDigest': '', 'instanceId': instance,
           'generation': generation}
    req.update(overrides)
    return req


def observe(instance_id='0a' * 16):
    return {'schemaVersion': 1, 'action': 'observe', 'instanceId': instance_id}


def set_pending_start(instance, clock, instance_id='0a' * 16,
                      boot_id='test-boot-id', deadline=None):
    instance.db.execute(
        "UPDATE instances SET phase='starting', permit=1, boot_id=?,"
        ' permit_deadline=? WHERE instance_id=?',
        (boot_id, deadline if deadline is not None else clock.monotonic() + 60,
         instance_id))
    instance.db.commit()


def insert_instance(instance, digest, instance_id='0a' * 16, phase='preparing',
                    slot_id='first', generation=1, binding=True):
    if binding is True:
        slot = next(s for s in instance.config['slots'] if s['id'] == slot_id)
        binding = {'hostId': instance.config['hostId'],
                   'architecture': instance.config['architecture'],
                   'storage': copy.deepcopy(instance.config['storage']),
                   'slot': copy.deepcopy(slot)}
    instance.db.execute(
        "INSERT INTO instances(instance_id, workload_id, revision_digest,"
        " generation, slot_id, machine_name, phase, requirements, binding_json)"
        " VALUES(?,?,?,?,?,?,?,?,?)",
        (instance_id, 'canary', digest, generation, slot_id,
         worker._machine_name(instance_id), phase,
         artifacts.canonical_bytes({'memoryMiB': 256, 'cpuMillis': 100,
                                    'stateBytes': 1048576}).decode(),
         artifacts.canonical_bytes(binding).decode() if binding else None))
    instance.db.commit()


class RequestValidationTests(unittest.TestCase):
    def test_strict_request_shapes(self):
        good = request('prepare')
        good['revisionDigest'] = 'sha256:' + '0' * 64
        action, parsed = worker.validate_request(good)
        self.assertEqual(action, 'prepare')
        for mutate in (
            lambda r: r.update(extra='x'),
            lambda r: r.pop('operationId'),
            lambda r: r.update(action='restore'),
            lambda r: r.update(operationId='zz' * 16),
            lambda r: r.update(instanceId='AB' * 16),
            lambda r: r.update(revisionDigest='sha256:' + '0' * 63),
            lambda r: r.update(generation=True),
            lambda r: r.update(generation=0),
            lambda r: r.update(generation=2**63),
            lambda r: r.update(schemaVersion=2),
            lambda r: r.update(unitName='evil.service'),
            lambda r: r.update(command='rm -rf /'),
        ):
            req = request('stop')
            req['revisionDigest'] = 'sha256:' + '0' * 64
            mutate(req)
            with self.assertRaises(worker.WorkerError, msg=mutate):
                worker.validate_request(req)

    def test_observe_shape(self):
        action, parsed = worker.validate_request(observe())
        self.assertEqual(action, 'observe')
        with self.assertRaises(worker.WorkerError):
            worker.validate_request(
                {'schemaVersion': 1, 'action': 'observe',
                 'instanceId': 'ab' * 16, 'extra': 1})
        with self.assertRaises(worker.WorkerError):
            worker.validate_request(
                {'schemaVersion': 1, 'action': 'observe', 'instanceId': 'not-hex'})

    def test_load_json_bytes(self):
        with self.assertRaises(worker.WorkerError):
            worker.load_json_bytes(b'{"a": 1, "a": 2}')
        with self.assertRaises(worker.WorkerError):
            worker.load_json_bytes(b'{"a": NaN}')
        with self.assertRaises(worker.WorkerError):
            worker.load_json_bytes(b'not json')
        with self.assertRaises(worker.WorkerError):
            worker.load_json_bytes(b'\xff\xfe{"a":1}')
        self.assertEqual(worker.load_json_bytes(b'{"a": 1}'), {'a': 1})


class ConfigValidationTests(unittest.TestCase):
    def test_slot_collisions_and_bad_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            base, _ = make_config(tmp)
            dup_uid = copy.deepcopy(base)
            dup_uid['slots'][1]['uidBase'] = 65536
            with self.assertRaises(worker.WorkerError):
                worker.validate_config(dup_uid)
            for bad_uid in (0, -1, 65537, 2**32 - 65535, True, '65536'):
                cfg = copy.deepcopy(base)
                cfg['slots'][0]['uidBase'] = bad_uid
                with self.assertRaises(worker.WorkerError, msg=bad_uid):
                    worker.validate_config(cfg)
            dup_addr = copy.deepcopy(base)
            dup_addr['slots'][1]['localAddress'] = '192.168.130.2'
            with self.assertRaises(worker.WorkerError):
                worker.validate_config(dup_addr)
            for bad_ip in ('8.8.8.8', '127.0.0.1', '224.0.0.1', '192.168.130.1/24',
                           'same-as-host'):
                cfg = copy.deepcopy(base)
                cfg['slots'][0]['localAddress'] = bad_ip
                with self.assertRaises(worker.WorkerError, msg=bad_ip):
                    worker.validate_config(cfg)
            same = copy.deepcopy(base)
            same['slots'][0]['localAddress'] = same['slots'][0]['hostAddress']
            with self.assertRaises(worker.WorkerError):
                worker.validate_config(same)

    def test_config_fields_and_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            base, _ = make_config(tmp)
            for mutate in (
                lambda c: c.update(extra='x'),
                lambda c: c.pop('slots'),
                lambda c: c.update(stateDir='relative/path'),
                lambda c: c.update(stateDir='/bad path/x'),
                lambda c: c['storage'].update(uuid=''),
                lambda c: c['storage'].update(uuid='../../etc'),
                lambda c: c.update(approvedBundles=['/tmp/not-a-store-path']),
                lambda c: c.update(approvedBundles=[]),
                lambda c: c.update(schemaVersion=2),
            ):
                cfg = copy.deepcopy(base)
                mutate(cfg)
                with self.assertRaises(worker.WorkerError, msg=mutate):
                    worker.validate_config(cfg)
            self.assertIsNotNone(worker.validate_config(copy.deepcopy(base)))

    def test_storage_root_must_be_mount_descendant(self):
        with tempfile.TemporaryDirectory() as tmp:
            base, _ = make_config(tmp)
            cfg = copy.deepcopy(base)
            cfg['storage'] = {'root': os.path.join(tmp, 'storage'),
                              'mountPoint': os.path.join(tmp, 'storage'),
                              'uuid': 'aaaa-bbbb'}
            worker.validate_config(cfg)
            cfg = copy.deepcopy(base)
            cfg['storage']['root'] = cfg['storage']['mountPoint'] + '/sub'
            worker.validate_config(cfg)
            for root, mount in (('/srv', '/srv/workloads'),
                                ('/srv/work', '/srv/workloads'),
                                ('/srv/workloads2', '/srv/workloads'),
                                ('/other', '/srv/workloads')):
                cfg = copy.deepcopy(base)
                cfg['storage'] = {'root': root, 'mountPoint': mount,
                                  'uuid': 'aaaa-bbbb'}
                with self.assertRaises(worker.WorkerError, msg=(root, mount)):
                    worker.validate_config(cfg)

    def test_metadata_outside_guest_storage(self):
        with tempfile.TemporaryDirectory() as tmp:
            base, _ = make_config(tmp)
            cfg = copy.deepcopy(base)
            cfg['stateDir'] = cfg['storage']['root'] + '/meta'
            with self.assertRaises(worker.WorkerError):
                worker.validate_config(cfg)
            cfg = copy.deepcopy(base)
            cfg['stateDir'] = cfg['storage']['mountPoint']
            with self.assertRaises(worker.WorkerError):
                worker.validate_config(cfg)


class MetadataSafetyTests(unittest.TestCase):
    def test_state_dir_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, bundle = make_config(tmp)
            write_bundle(bundle)
            os.symlink('/tmp', config['stateDir'])
            with self.assertRaises(worker.WorkerError) as ctx:
                new_worker(config, runner=FakeRunner(),
                              fs=FakeFilesystem(bundle_dir=bundle),
                              clock=FakeClock(), boot_id='b',
                              unit_dir=os.path.join(tmp, 'units'))
            self.assertEqual(ctx.exception.code, 'path-unsafe')

    def test_state_dir_wrong_owner_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, bundle = make_config(tmp)
            write_bundle(bundle)
            fs = FakeFilesystem(bundle_dir=bundle)
            fs.owners[config['stateDir']] = (1000, 0)
            with self.assertRaises(worker.WorkerError):
                new_worker(config, runner=FakeRunner(), fs=fs,
                              clock=FakeClock(), boot_id='b',
                              unit_dir=os.path.join(tmp, 'units'))

    def test_existing_db_wrong_mode_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, bundle = make_config(tmp)
            write_bundle(bundle)
            os.makedirs(config['stateDir'])
            db = os.path.join(config['stateDir'], 'worker.db')
            Path(db).write_text('')
            os.chmod(db, 0o644)
            with self.assertRaises(worker.WorkerError):
                new_worker(config, runner=FakeRunner(),
                              fs=FakeFilesystem(bundle_dir=bundle),
                              clock=FakeClock(), boot_id='b',
                              unit_dir=os.path.join(tmp, 'units'))


class PrepareTests(unittest.TestCase):
    def test_prepare_start_stop_happy_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, manifest = make_worker(tmp)
            digest = definition['revisionDigest']
            result = instance.execute(request('prepare', revisionDigest=digest))
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(result['appliedPhase'], 'prepared')
            machine = worker._machine_name('0a' * 16)
            env = Path(tmp, 'worker-state', 'instances', machine,
                       'nspawn.env').read_text()
            self.assertIn('SYSTEM_PATH=' + ROOT, env)
            self.assertIn('PRIVATE_USERS=65536', env)
            self.assertIn('LOCAL_ADDRESS=192.168.130.2', env)
            self.assertIn('--bind=', env)
            dropin = Path(tmp, 'units',
                          'nexus-workload@{}.service.d'.format(machine),
                          'nexus.conf').read_text()
            self.assertIn('CPUQuota=10.0%', dropin)
            self.assertIn('MemoryMax=256M', dropin)
            leaf = os.path.join(tmp, 'storage', '0a' * 16, 'data')
            self.assertIn((leaf, 65536, 65536), fs.chowns)
            result = instance.execute(request('start', op='bb' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['appliedPhase'], 'running')
            self.assertIn(['systemctl', '--no-ask-password', 'start',
                           'nexus-workload@' + machine + '.service'], runner.calls)
            result = instance.execute(request('stop', op='cc' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['appliedPhase'], 'stopped')

    def test_no_shell_or_overlay_invocations(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            instance.execute(request('start', op='bb' * 16,
                                     revisionDigest=digest))
            for argv in runner.calls:
                self.assertNotIn('unshare', argv)
                self.assertNotIn('mount', argv)
                self.assertNotIn('sh', argv)
                self.assertNotIn('-c', argv)
                if argv[0] in ('nix', 'nix-store'):
                    pair = list(zip(argv, argv[1:]))
                    self.assertIn(('--store', 'daemon'), pair)

    def test_operation_replay_and_conflict(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, *_ , definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            first = instance.execute(request('prepare', revisionDigest=digest))
            replay = instance.execute(request('prepare', revisionDigest=digest))
            self.assertEqual(first, replay)
            with self.assertRaises(worker.WorkerError) as ctx:
                instance.execute(request('prepare', generation=2,
                                         revisionDigest=digest))
            self.assertEqual(ctx.exception.code, 'operation-conflict')

    def test_failed_receipt_replays_identically(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            runner.mount_rows = [{'target': '/',
                                  'source': 'rootfs', 'uuid': 'rootfs'}]
            first = instance.execute(request('prepare', revisionDigest=digest))
            self.assertEqual(first['status'], 'failed')
            self.assertEqual(first['error'], 'storage-mount-mismatch')
            replay = instance.execute(request('prepare', revisionDigest=digest))
            self.assertEqual(first, replay)

    def test_unknown_workload_and_revision(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, *_ , definition, _ = make_worker(tmp)
            result = instance.execute(request('prepare', workloadId='other',
                                              revisionDigest='sha256:' + '0' * 64))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'unknown-workload')
            result = instance.execute(request('prepare', op='ab' * 16,
                                              revisionDigest='sha256:' + '0' * 64))
            self.assertEqual(result['error'], 'unknown-workload')

    def test_blocked_definitions(self):
        cases = [
            ({'secretSetRef': 'ops-secrets'}, 'secret-provisioning-unavailable'),
            ({'dependencies': ['db']}, 'dependency-readiness-unavailable'),
            ({'allowedOperations': ['backup']}, 'operation-not-allowed'),
            ({'category': 'infrastructure',
              'allowedOperations': ['backup']}, 'workload-not-mutable'),
        ]
        for overrides, code in cases:
            with tempfile.TemporaryDirectory() as tmp:
                instance, *_ , definition, _ = make_worker(
                    tmp, definition_overrides=overrides)
                result = instance.execute(request(
                    'prepare', revisionDigest=definition['revisionDigest']))
                self.assertEqual(result['status'], 'failed', overrides)
                self.assertEqual(result['error'], code, overrides)

    def test_archive_bundle_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, bundle = make_config(tmp)
            draft = draft_fixture(
                category='archive', runtimeVersion=None,
                runtimeArtifactId=None, allowedOperations=[],
                artifacts=[{'id': 'blob', 'kind': 'archive',
                            'digest': 'sha256:' + '1' * 64}],
                requirements={'memoryMiB': 0, 'cpuMillis': 0, 'stateBytes': 0,
                              'capabilities': []})
            definition = catalog.seal_definition(draft)
            write_bundle(bundle, manifest_fixture(), definition)
            instance = new_worker(
                config, runner=FakeRunner(),
                fs=FakeFilesystem(bundle_dir=bundle), clock=FakeClock(),
                boot_id='b', unit_dir=os.path.join(tmp, 'units'))
            result = instance.execute(request(
                'prepare', revisionDigest=definition['revisionDigest']))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'invalid-bundle')

    def test_tampered_bundle_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, bundle = make_config(tmp)
            definition, manifest = sealed_fixture()
            write_bundle(bundle, manifest, definition)
            tampered = manifest_fixture()
            tampered['closure'][0]['narSize'] = 11
            Path(bundle, 'artifact.json').write_bytes(
                artifacts.canonical_bytes(tampered))
            with self.assertRaises(worker.WorkerError) as ctx:
                new_worker(config, runner=FakeRunner(),
                              fs=FakeFilesystem(bundle_dir=bundle),
                              clock=FakeClock(), boot_id='b',
                              unit_dir=os.path.join(tmp, 'units')
                              )._resolve('x', 'y')
            self.assertEqual(ctx.exception.code, 'invalid-bundle')

    def test_bundle_strictness(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, bundle = make_config(tmp)
            definition, manifest = sealed_fixture()
            write_bundle(bundle, manifest, definition, canonical=False)
            with self.assertRaises(worker.WorkerError) as ctx:
                new_worker(config, runner=FakeRunner(),
                              fs=FakeFilesystem(bundle_dir=bundle),
                              clock=FakeClock(), boot_id='b',
                              unit_dir=os.path.join(tmp, 'units')
                              )._resolve('x', 'y')
            self.assertEqual(ctx.exception.code, 'invalid-bundle')
        with tempfile.TemporaryDirectory() as tmp:
            config, bundle = make_config(tmp)
            definition, manifest = sealed_fixture()
            write_bundle(bundle, manifest, definition)
            Path(bundle, 'artifact.sha256').write_text('sha256:' + '0' * 64 + '\n')
            with self.assertRaises(worker.WorkerError):
                new_worker(config, runner=FakeRunner(),
                              fs=FakeFilesystem(bundle_dir=bundle),
                              clock=FakeClock(), boot_id='b',
                              unit_dir=os.path.join(tmp, 'units')
                              )._resolve('x', 'y')
        with tempfile.TemporaryDirectory() as tmp:
            config, bundle = make_config(tmp)
            definition, manifest = sealed_fixture()
            write_bundle(bundle, manifest, definition)
            raw = artifacts.canonical_bytes(manifest).decode()
            dup = raw.replace('"architecture"', '"architecture2":0,"architecture"', 1)
            Path(bundle, 'artifact.json').write_text(dup)
            with self.assertRaises(worker.WorkerError):
                new_worker(config, runner=FakeRunner(),
                              fs=FakeFilesystem(bundle_dir=bundle),
                              clock=FakeClock(), boot_id='b',
                              unit_dir=os.path.join(tmp, 'units')
                              )._resolve('x', 'y')

    def test_mount_must_match_uuid(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            runner.mount_rc = 1
            result = instance.execute(request('prepare',
                                              revisionDigest=definition['revisionDigest']))
            self.assertEqual(result['error'], 'storage-not-mounted')
            self.assertFalse(os.listdir(os.path.join(tmp, 'storage')))
            runner.mount_rc = 0
            runner.mount_rows = [{'target': instance.config['storage']['mountPoint'],
                                  'source': '/', 'uuid': 'rootfs'}]
            result = instance.execute(request('prepare', op='ab' * 16,
                                              revisionDigest=definition['revisionDigest']))
            self.assertEqual(result['error'], 'storage-mount-mismatch')
            self.assertFalse(os.listdir(os.path.join(tmp, 'storage')))

    def test_nested_wrong_filesystem_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            runner.mount_rows = [
                {'target': instance.config['storage']['root'],
                 'source': '/dev/evil', 'uuid': 'dead-beef'}]
            result = instance.execute(request(
                'prepare', revisionDigest=definition['revisionDigest']))
            self.assertEqual(result['error'], 'storage-mount-mismatch')
            self.assertFalse(os.listdir(os.path.join(tmp, 'storage')))

    def test_storage_subroot_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, bundle = make_config(tmp, storage_subdir=True)
            write_bundle(bundle)
            runner = FakeRunner()
            fs = FakeFilesystem(bundle_dir=bundle)
            runner.mount_rows = [{'target': config['storage']['mountPoint'],
                                  'source': '/dev/vdb',
                                  'uuid': config['storage']['uuid']}]
            instance = new_worker(config, runner=runner, fs=fs,
                                     clock=FakeClock(), boot_id='b',
                                     unit_dir=os.path.join(tmp, 'units'))
            runner.owner = instance
            definition, _ = sealed_fixture()
            result = instance.execute(request(
                'prepare', revisionDigest=definition['revisionDigest']))
            self.assertEqual(result['status'], 'completed')
            self.assertTrue(os.path.isdir(os.path.join(
                config['storage']['root'], '0a' * 16, 'data')))

    def test_insufficient_capacity_and_reservation(self):
        with tempfile.TemporaryDirectory() as tmp:
            fs = FakeFilesystem(mem_kb=100 * 1024)
            instance, *_ , definition, _ = make_worker(tmp, fs=fs)
            result = instance.execute(request(
                'prepare', revisionDigest=definition['revisionDigest']))
            self.assertEqual(result['error'], 'admission-insufficient-memory')

    def test_own_state_reservation_excluded_on_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, bundle = make_config(tmp)
            config['capacity']['stateBytes'] = 1048576
            fs = FakeFilesystem(free_bytes=1 << 30)
            instance, runner, fs, clock, definition, _ = make_worker(
                tmp, config=config, fs=fs)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            instance.execute(request('start', op='b0' * 16, revisionDigest=digest))
            instance.execute(request('stop', op='b1' * 16, revisionDigest=digest))
            result = instance.execute(request('start', op='b2' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'completed', result)

    def test_stale_generation_and_second_slot(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, *_ , definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            instance.execute(request('stop', op='b0' * 16, revisionDigest=digest))
            result = instance.execute(request('prepare', instance='2c' * 16,
                                              op='b1' * 16, generation=2,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'completed')
            result = instance.execute(request('start', op='b2' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'generation-stale')

    def test_symlinked_instance_dir_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            os.symlink('/tmp', os.path.join(tmp, 'storage', '0a' * 16))
            result = instance.execute(request('prepare', revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'storage-state-conflict')

    def test_preexisting_instance_dir_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            os.makedirs(os.path.join(tmp, 'storage', '0a' * 16, 'data'))
            result = instance.execute(request(
                'prepare', revisionDigest=definition['revisionDigest']))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'storage-state-conflict')

    def test_foreign_dir_rejected_before_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            foreign = os.path.join(tmp, 'storage', '0a' * 16)
            os.makedirs(foreign)
            result = instance.execute(
                request('prepare', revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'storage-state-conflict')
            self.assertIsNone(instance._get_instance('0a' * 16))
            retry = instance.execute(
                request('prepare', op='bb' * 16, revisionDigest=digest))
            self.assertEqual(retry['status'], 'failed')
            self.assertEqual(retry['error'], 'storage-state-conflict')
            self.assertIsNone(instance._get_instance('0a' * 16))
            self.assertEqual(os.listdir(foreign), [])
            rows = instance.db.execute(
                'SELECT COUNT(*) FROM generations').fetchone()[0]
            self.assertEqual(rows, 0)

    def test_prepare_resume_completes_own_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.db.execute(
                "INSERT INTO operations(operation_id, request, status)"
                " VALUES(?,?,'pending')",
                ('aa' * 16,
                 artifacts.canonical_bytes(
                     request('prepare', revisionDigest=digest)).decode()))
            insert_instance(instance, digest)
            os.mkdir(os.path.join(tmp, 'storage', '0a' * 16), 0o700)
            result = instance.execute(request('prepare', revisionDigest=digest))
            self.assertEqual(result['status'], 'completed', result)
            self.assertTrue(os.path.isdir(
                os.path.join(tmp, 'storage', '0a' * 16, 'data')))

    def test_prepare_resume_rejects_nonempty_foreign_leaf(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.db.execute(
                "INSERT INTO operations(operation_id, request, status)"
                " VALUES(?,?,'pending')",
                ('aa' * 16,
                 artifacts.canonical_bytes(
                     request('prepare', revisionDigest=digest)).decode()))
            insert_instance(instance, digest)
            leaf = os.path.join(tmp, 'storage', '0a' * 16, 'data')
            os.makedirs(leaf)
            os.chmod(os.path.dirname(leaf), 0o700)
            Path(leaf, 'foreign-file').write_text('data')
            result = instance.execute(request('prepare', revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'storage-state-conflict')

    def test_prepare_resume_requires_mount(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.db.execute(
                "INSERT INTO operations(operation_id, request, status)"
                " VALUES(?,?,'pending')",
                ('aa' * 16,
                 artifacts.canonical_bytes(
                     request('prepare', revisionDigest=digest)).decode()))
            insert_instance(instance, digest)
            runner.mount_rows = [{'target': '/', 'source': 'rootfs',
                                  'uuid': 'rootfs'}]
            result = instance.execute(request('prepare', revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'storage-mount-mismatch')


class StartStopTests(unittest.TestCase):
    def test_start_failed_unit_marks_stopped(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            runner.fail_start = True
            result = instance.execute(request('start', op='bb' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['appliedPhase'], 'stopped')
            rec = instance._get_instance('0a' * 16)
            self.assertEqual(rec['phase'], 'stopped')
            result = instance.execute(request('start', op='bc' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')

    def test_start_blocked_when_storage_unmounted(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            runner.mount_rows = [{'target': '/', 'source': 'rootfs',
                                  'uuid': 'rootfs'}]
            result = instance.execute(request('start', op='bb' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'storage-mount-mismatch')
            rec = instance._get_instance('0a' * 16)
            self.assertEqual(rec['phase'], 'prepared')
            self.assertEqual(rec['permit'], 0)

    def test_start_refused_while_restore_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            sentinel = os.path.join(tmp, 'storage', '0a' * 16,
                                    worker._RESTORE_SENTINEL)
            Path(sentinel).write_text('x')
            result = instance.execute(request('start', op='bb' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'restore-incomplete')
            self.assertFalse(
                any(c[2:3] == ['start'] for c in runner.calls))
            self.assertEqual(instance._get_instance('0a' * 16)['phase'],
                             'prepared')
            os.unlink(sentinel)
            result = instance.execute(request('start', op='cc' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(result['appliedPhase'], 'running')

    def test_observe_reports_restore_pending(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, *_ , definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            self.assertFalse(instance.execute(observe())['restorePending'])
            sentinel = os.path.join(tmp, 'storage', '0a' * 16,
                                    worker._RESTORE_SENTINEL)
            Path(sentinel).write_text('x')
            self.assertTrue(instance.execute(observe())['restorePending'])
            os.unlink(sentinel)
            self.assertFalse(instance.execute(observe())['restorePending'])

    def test_start_rechecks_closure(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            runner.nix_rc = 1
            result = instance.execute(request('start', op='bb' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'store-verify-failed')
            self.assertEqual(instance._get_instance('0a' * 16)['phase'],
                             'prepared')

    def test_running_shortcut_verifies_actual_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            instance.execute(request('start', op='bb' * 16,
                                     revisionDigest=digest))
            unit = 'nexus-workload@' + worker._machine_name('0a' * 16) + '.service'
            runner.units[unit] = {'LoadState': 'loaded', 'ActiveState': 'inactive',
                                  'SubState': 'dead', 'MainPID': '0',
                                  'ControlGroup': ''}
            starts = [c for c in runner.calls if c[2:3] == ['start']]
            result = instance.execute(request('start', op='cc' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(
                len([c for c in runner.calls if c[2:3] == ['start']]),
                len(starts) + 1)

    def test_running_shortcut_uncertain_on_show_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            instance.execute(request('start', op='bb' * 16,
                                     revisionDigest=digest))
            runner.show_mode = 'rc'
            result = instance.execute(request('start', op='cc' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'uncertain')

    def test_stopped_shortcut_issues_stop_when_unit_active(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            instance.execute(request('start', op='bb' * 16,
                                     revisionDigest=digest))
            instance.execute(request('stop', op='cc' * 16,
                                     revisionDigest=digest))
            unit = 'nexus-workload@' + worker._machine_name('0a' * 16) + '.service'
            runner.units[unit] = {'LoadState': 'loaded', 'ActiveState': 'active',
                                  'SubState': 'running', 'MainPID': '4242',
                                  'ControlGroup': '/machine.slice/' + unit}
            result = instance.execute(request('stop', op='dd' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(runner.unit_state(unit)['ActiveState'], 'inactive')

    def test_stop_uncertain_when_cgroup_populated(self):
        with tempfile.TemporaryDirectory() as tmp:
            fs = FakeFilesystem(cgroup_populated='1')
            instance, runner, fs, clock, definition, _ = make_worker(tmp, fs=fs)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            instance.execute(request('start', op='bb' * 16,
                                     revisionDigest=digest))
            result = instance.execute(request('stop', op='cc' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'uncertain')
            self.assertEqual(instance._get_instance('0a' * 16)['phase'],
                             'unknown')
            starts_before = [c for c in runner.calls if c[2:3] == ['start']]
            result = instance.execute(request('start', op='dd' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'uncertain')
            self.assertEqual(result['error'], 'operation-in-progress')
            starts_after = [c for c in runner.calls if c[2:3] == ['start']]
            self.assertEqual(len(starts_before), len(starts_after))

    def test_stop_uncertain_on_cgroup_read_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            fs = FakeFilesystem(cgroup_error=PermissionError('denied'))
            instance, runner, fs, clock, definition, _ = make_worker(tmp, fs=fs)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            instance.execute(request('start', op='bb' * 16,
                                     revisionDigest=digest))
            result = instance.execute(request('stop', op='cc' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'uncertain')

    def test_stop_uncertain_when_show_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            instance.execute(request('start', op='bb' * 16,
                                     revisionDigest=digest))
            runner.show_mode = 'raise'
            result = instance.execute(request('stop', op='cc' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'uncertain')
            self.assertEqual(instance._get_instance('0a' * 16)['phase'],
                             'unknown')

    def test_stop_unknown_instance_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            instance.execute(request('start', op='bb' * 16,
                                     revisionDigest=digest))
            instance.db.execute(
                "UPDATE instances SET phase='unknown' WHERE instance_id=?",
                ('0a' * 16,))
            instance.db.commit()
            result = instance.execute(request('stop', op='cc' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(result['appliedPhase'], 'stopped')


class GuardTests(unittest.TestCase):
    def test_guard_consumes_single_use_permit(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            machine = worker._machine_name('0a' * 16)
            instance.execute(request('start', op='bb' * 16, revisionDigest=digest))
            rec = instance._get_instance('0a' * 16)
            self.assertEqual(rec['permit'], 0)
            self.assertEqual(rec['phase'], 'running')
            self.assertNotEqual(instance.guard(machine), 0)

    def test_guard_rejects_wrong_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            machine = worker._machine_name('0a' * 16)
            self.assertNotEqual(instance.guard(machine), 0)
            set_pending_start(instance, clock, boot_id='other-boot')
            self.assertNotEqual(instance.guard(machine), 0)
            instance.db.execute(
                'UPDATE instances SET boot_id=? WHERE instance_id=?',
                ('test-boot-id', '0a' * 16))
            instance.db.commit()
            clock.mono += 3600
            self.assertNotEqual(instance.guard(machine), 0)
            instance.db.execute(
                'UPDATE instances SET permit_deadline=? WHERE instance_id=?',
                (clock.monotonic() + 60, '0a' * 16))
            instance.db.commit()
            self.assertEqual(instance.guard(machine), 0)
            self.assertNotEqual(instance.guard(machine), 0)

    def test_guard_rejects_stale_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            machine = worker._machine_name('0a' * 16)
            set_pending_start(instance, clock)
            instance.db.execute(
                "UPDATE generations SET generation=2 WHERE workload_id='canary'")
            instance.db.commit()
            self.assertNotEqual(instance.guard(machine), 0)

    def test_guard_rejects_tampered_runtime_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            machine = worker._machine_name('0a' * 16)
            env_path = instance._env_path(machine)
            dropin_path = instance._dropin_path(machine)
            tampers = [
                lambda: Path(env_path).write_text(''),
                lambda: Path(env_path).write_text(
                    Path(env_path).read_text().replace('PRIVATE_NETWORK=1',
                                                       'PRIVATE_NETWORK=0')),
                lambda: os.unlink(dropin_path),
                lambda: Path(dropin_path).write_text('[Service]\n'),
            ]
            rec = instance._get_instance('0a' * 16)
            slot = instance._slot('first')
            for tamper in tampers:
                set_pending_start(instance, clock)
                tamper()
                self.assertNotEqual(instance.guard(machine), 0)
                instance.db.execute(
                    "UPDATE instances SET phase='prepared', permit=0"
                    ' WHERE instance_id=?', ('0a' * 16,))
                instance.db.commit()
                instance._render_runtime_files(
                    instance._get_instance('0a' * 16), definition,
                    manifest_fixture(), slot)

    def test_guard_rejects_symlink_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            machine = worker._machine_name('0a' * 16)
            env_path = instance._env_path(machine)
            os.unlink(env_path)
            os.symlink('/etc/passwd', env_path)
            set_pending_start(instance, clock)
            self.assertNotEqual(instance.guard(machine), 0)

    def test_start_rebuilds_runtime_files_after_loss(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            instance.execute(request('start', op='bb' * 16, revisionDigest=digest))
            instance.execute(request('stop', op='cc' * 16, revisionDigest=digest))
            machine = worker._machine_name('0a' * 16)
            os.unlink(instance._env_path(machine))
            os.unlink(instance._dropin_path(machine))
            instance2 = new_worker(
                instance.config, runner=runner, fs=fs, clock=clock,
                boot_id='new-boot-id', unit_dir=instance.unit_dir)
            runner.owner = instance2
            result = instance2.execute(request('start', op='dd' * 16,
                                               revisionDigest=digest))
            self.assertEqual(result['status'], 'completed', result)
            self.assertTrue(os.path.exists(instance._env_path(machine)))
            self.assertTrue(os.path.exists(instance._dropin_path(machine)))


class CrashReconciliationTests(unittest.TestCase):
    def test_starting_unit_reconciled_to_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            machine = worker._machine_name('0a' * 16)
            unit = 'nexus-workload@' + machine + '.service'
            set_pending_start(instance, clock)
            runner.units[unit] = {'LoadState': 'loaded', 'ActiveState': 'active',
                                  'SubState': 'running', 'MainPID': '4242',
                                  'ControlGroup': '/machine.slice/' + unit}
            starts_before = [c for c in runner.calls if c[2:3] == ['start']]
            result = instance.execute(observe())
            self.assertEqual(result['phase'], 'running')
            self.assertEqual(result['unitActiveState'], 'active')
            self.assertIn('endpointAddress', result)
            self.assertNotIn('ready', result)
            starts_after = [c for c in runner.calls if c[2:3] == ['start']]
            self.assertEqual(len(starts_before), len(starts_after))

    def test_failed_pending_start_marks_stopped(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            machine = worker._machine_name('0a' * 16)
            unit = 'nexus-workload@' + machine + '.service'
            set_pending_start(instance, clock, deadline=clock.monotonic() - 1)
            runner.units[unit] = {'LoadState': 'loaded', 'ActiveState': 'inactive',
                                  'SubState': 'dead', 'MainPID': '0',
                                  'ControlGroup': ''}
            result = instance.execute(observe())
            self.assertEqual(result['phase'], 'stopped')

    def test_expired_deadline_does_not_resolve_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            set_pending_start(instance, clock, deadline=clock.monotonic() - 1)
            runner.show_mode = 'rc'
            result = instance.execute(observe())
            self.assertEqual(result['phase'], 'starting')
            self.assertEqual(result['unitActiveState'], 'unknown')

    def test_unknown_phase_reconciles_to_facts(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            machine = worker._machine_name('0a' * 16)
            unit = 'nexus-workload@' + machine + '.service'
            instance.db.execute(
                "UPDATE instances SET phase='unknown' WHERE instance_id=?",
                ('0a' * 16,))
            instance.db.commit()
            runner.units[unit] = {'LoadState': 'loaded', 'ActiveState': 'active',
                                  'SubState': 'running', 'MainPID': '77',
                                  'ControlGroup': '/machine.slice/' + unit}
            result = instance.execute(observe())
            self.assertEqual(result['phase'], 'running')
            instance.db.execute(
                "UPDATE instances SET phase='unknown' WHERE instance_id=?",
                ('0a' * 16,))
            instance.db.commit()
            runner.units[unit] = {'LoadState': 'loaded', 'ActiveState': 'inactive',
                                  'SubState': 'dead', 'MainPID': '0',
                                  'ControlGroup': ''}
            result = instance.execute(observe())
            self.assertEqual(result['phase'], 'stopped')
            self.assertEqual(result['unitActiveState'], 'inactive')
            instance.db.execute(
                "UPDATE instances SET phase='unknown' WHERE instance_id=?",
                ('0a' * 16,))
            instance.db.commit()
            runner.show_mode = 'rc'
            result = instance.execute(observe())
            self.assertEqual(result['phase'], 'unknown')
            self.assertEqual(result['unitActiveState'], 'unknown')

    def test_observe_unknown_instance(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, *_ = make_worker(tmp)
            with self.assertRaises(worker.WorkerError) as ctx:
                instance.execute(observe())
            self.assertEqual(ctx.exception.code, 'unknown-instance')

    def test_crash_after_start_reconciles_without_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            start = request('start', op='bb' * 16, revisionDigest=digest)
            runner.crash_after = 'start'
            with self.assertRaises(KeyboardInterrupt):
                instance.execute(start)
            row = instance.db.execute(
                'SELECT status FROM operations WHERE operation_id=?',
                ('bb' * 16,)).fetchone()
            self.assertEqual(row[0], 'pending')
            instance2 = new_worker(
                instance.config, runner=runner, fs=fs, clock=clock,
                boot_id='test-boot-id', unit_dir=instance.unit_dir)
            runner.owner = instance2
            starts = [c for c in runner.calls if c[2:3] == ['start']]
            result = instance2.execute(start)
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(result['appliedPhase'], 'running')
            self.assertEqual(
                len([c for c in runner.calls if c[2:3] == ['start']]),
                len(starts))
            changed = dict(start)
            changed['generation'] = 2
            changed['operationId'] = 'bb' * 16
            with self.assertRaises(worker.WorkerError) as ctx:
                instance2.execute(changed)
            self.assertEqual(ctx.exception.code, 'operation-conflict')

    def test_crash_after_stop_reconciles_without_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            instance.execute(request('start', op='bb' * 16, revisionDigest=digest))
            stop = request('stop', op='cc' * 16, revisionDigest=digest)
            runner.crash_after = 'stop'
            with self.assertRaises(KeyboardInterrupt):
                instance.execute(stop)
            row = instance.db.execute(
                'SELECT status FROM operations WHERE operation_id=?',
                ('cc' * 16,)).fetchone()
            self.assertEqual(row[0], 'pending')
            instance2 = new_worker(
                instance.config, runner=runner, fs=fs, clock=clock,
                boot_id='test-boot-id', unit_dir=instance.unit_dir)
            runner.owner = instance2
            stops = [c for c in runner.calls if c[2:3] == ['stop']]
            result = instance2.execute(stop)
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(result['appliedPhase'], 'stopped')
            self.assertEqual(
                len([c for c in runner.calls if c[2:3] == ['stop']]),
                len(stops))

    def test_concurrent_same_id_performs_one_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            config = instance.config
            instance2 = new_worker(
                config, runner=runner, fs=fs, clock=clock,
                boot_id='test-boot-id', unit_dir=instance.unit_dir)
            entered = threading.Event()
            release = threading.Event()
            real_verify = instance._verify_closure

            def blocking_verify(manifest):
                entered.set()
                release.wait(10)
                return real_verify(manifest)

            instance._verify_closure = blocking_verify
            errors = []

            def first():
                instance.execute(request('prepare', revisionDigest=digest))

            def second():
                try:
                    instance2.execute(request('prepare', revisionDigest=digest,
                                              generation=2))
                except worker.WorkerError as error:
                    errors.append(error.code)

            t1 = threading.Thread(target=first)
            t1.start()
            self.assertTrue(entered.wait(10))
            t2 = threading.Thread(target=second)
            t2.start()
            release.set()
            t1.join(10)
            t2.join(10)
            self.assertEqual(errors, ['operation-conflict'])
            count = instance.db.execute(
                'SELECT COUNT(*) FROM instances').fetchone()[0]
            self.assertEqual(count, 1)


class CliTests(unittest.TestCase):
    def _run_cli(self, argv, stdin=b''):
        out = io.StringIO()
        fake_stdin = SimpleNamespace(
            buffer=SimpleNamespace(read=lambda n: stdin))
        with mock.patch.object(worker.os, 'geteuid', return_value=0), \
                mock.patch.object(sys, 'stdin', fake_stdin), \
                mock.patch.object(sys, 'stdout', out):
            code = worker.main(argv)
        return code, out.getvalue()

    def test_unprivileged_cli_fails_before_file_access(self):
        out = io.StringIO()
        with mock.patch.object(worker.os, 'geteuid', return_value=1000), \
                mock.patch.object(worker.Path, 'read_bytes',
                                  side_effect=AssertionError('config read')), \
                mock.patch.object(sys, 'stdout', out):
            code = worker.main(['--config', '/nonexistent/config.json',
                                'execute'])
        self.assertEqual(code, 1)
        response = json.loads(out.getvalue())
        self.assertEqual(response['error'], 'requires-root')
        self.assertNotIn('/nonexistent', out.getvalue())

    def test_cli_exit_codes(self):
        class FakeWorker:
            response = {'status': 'completed'}

            def __init__(self, config):
                pass

            def execute(self, request):
                return self.response

        with tempfile.TemporaryDirectory() as tmp:
            config_path = os.path.join(tmp, 'config.json')
            Path(config_path).write_text('{}')
            with mock.patch.object(worker, 'Worker', FakeWorker):
                for response, expected in (({'status': 'completed'}, 0),
                                           ({'status': 'failed',
                                             'error': 'x'}, 1),
                                           ({'status': 'uncertain',
                                             'error': 'x'}, 1)):
                    FakeWorker.response = response
                    code, out = self._run_cli(
                        ['--config', config_path, 'execute'],
                        json.dumps(request('prepare')).encode())
                    self.assertEqual(code, expected, response)

    def test_cli_invalid_and_oversized_input(self):
        class FakeWorker:
            def __init__(self, config):
                pass

            def execute(self, request):
                return {'status': 'completed'}

        with tempfile.TemporaryDirectory() as tmp:
            config_path = os.path.join(tmp, 'config.json')
            Path(config_path).write_text('{}')
            with mock.patch.object(worker, 'Worker', FakeWorker):
                code, out = self._run_cli(['--config', config_path, 'execute'],
                                          b'\xff\xfe{}')
                self.assertEqual(code, 1)
                self.assertEqual(json.loads(out)['error'], 'invalid-json')
                code, out = self._run_cli(['--config', config_path, 'execute'],
                                          b' ' * 20000)
                self.assertEqual(code, 1)
                self.assertEqual(json.loads(out)['error'], 'request-too-large')

    def test_error_codes_do_not_echo_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, *_ = make_worker(tmp)
            secret = 'secret-token-9f8e7d'
            req = request('prepare')
            req['revisionDigest'] = 'sha256:' + secret + '0' * 64
            try:
                instance.execute(req)
            except worker.WorkerError as error:
                self.assertNotIn(secret, error.code)
            else:
                self.fail('expected rejection')


class NarHashTests(unittest.TestCase):
    def test_forms_normalize_equal(self):
        raw = bytes.fromhex('ab' * 32)
        self.assertEqual(worker.nar_hash_bytes('sha256:' + 'ab' * 32), raw)
        self.assertEqual(
            worker.nar_hash_bytes('sha256-' + base64.b64encode(raw).decode()),
            raw)
        with self.assertRaises(worker.WorkerError):
            worker.nar_hash_bytes('sha256:' + '2' + '0' * 51)
        with self.assertRaises(worker.WorkerError):
            worker.nar_hash_bytes('md5:' + 'ab' * 16)

    def test_sri_rejects_noncanonical_and_wrong_length(self):
        raw = bytes.fromhex('ab' * 32)
        with self.assertRaises(worker.WorkerError):
            worker.nar_hash_bytes(
                'sha256-' + base64.b64encode(raw + b'x').decode())
        noncanonical = base64.b64encode(raw).decode().replace('=', '')
        with self.assertRaises(worker.WorkerError):
            worker.nar_hash_bytes('sha256-' + noncanonical)
        with self.assertRaises(worker.WorkerError):
            worker.nar_hash_bytes('sha256-' + '!' * 44)

    def test_closure_verification_matches_across_encodings(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, manifest = make_worker(tmp)
            b64 = 'sha256-' + base64.b64encode(bytes.fromhex('ab' * 32)).decode()
            runner.nix_records = [{'path': e['path'], 'narHash': b64,
                                   'narSize': e['narSize'],
                                   'references': e['references']}
                                  for e in manifest['closure']]
            for entry in manifest['closure']:
                entry['narHash'] = b64
            Path(tmp, 'bundle', 'artifact.json').write_bytes(
                artifacts.canonical_bytes(manifest))
            Path(tmp, 'bundle', 'artifact.sha256').write_text(
                artifacts.manifest_digest(manifest) + '\n')
            instance._bundles = None
            instance._verify_closure(manifest)

    def test_closure_verification_dict_shape_and_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, manifest = make_worker(tmp)
            shape = [True]

            def path_info(argv):
                if shape[0]:
                    records = {
                        entry['path']: {'narHash': entry['narHash'],
                                        'narSize': entry['narSize'],
                                        'references': list(entry['references'])}
                        for entry in manifest['closure']}
                else:
                    records = [
                        {'path': e['path'], 'narHash': e['narHash'],
                         'narSize': e['narSize'], 'references': e['references']}
                        for e in manifest['closure']]
                return Result(argv, 0, json.dumps(records))

            runner.nix_records = None
            real_nix = runner._nix

            def dispatch(argv):
                if argv[0] == 'nix':
                    return path_info(argv)
                return real_nix(argv)

            runner._nix = dispatch
            instance._verify_closure(manifest)
            shape[0] = False
            instance._verify_closure(manifest)
            bad = copy.deepcopy(manifest)
            bad['closure'][0]['narSize'] += 1
            with self.assertRaises(worker.WorkerError):
                instance._verify_closure(bad)
            bad = copy.deepcopy(manifest)
            bad['closure'][1]['references'] = [ROOT]
            with self.assertRaises(worker.WorkerError):
                instance._verify_closure(bad)
            missing = copy.deepcopy(manifest)
            missing['closure'] = missing['closure'][:1]
            with self.assertRaises(worker.WorkerError):
                instance._verify_closure(missing)

    def test_closure_duplicate_and_missing_records_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, manifest = make_worker(tmp)
            records = [{'path': e['path'], 'narHash': e['narHash'],
                        'narSize': e['narSize'], 'references': e['references']}
                       for e in manifest['closure']]
            runner.nix_records = records + [dict(records[0])]
            with self.assertRaises(worker.WorkerError):
                instance._verify_closure(manifest)
            runner.nix_records = [dict(records[0], path=ROOT),
                                  dict(records[1])]
            with self.assertRaises(worker.WorkerError):
                instance._verify_closure(manifest)




class PendingBarrierTests(unittest.TestCase):
    def _crash_after(self, tmp, verb):
        instance, runner, fs, clock, definition, _ = make_worker(tmp)
        digest = definition['revisionDigest']
        instance.execute(request('prepare', revisionDigest=digest))
        instance.execute(request('start', op='bb' * 16,
                                 revisionDigest=digest))
        return instance, runner, fs, clock, definition, digest

    def _reopen(self, instance, runner, fs, clock):
        instance2 = new_worker(
            instance.config, runner=runner, fs=fs, clock=clock,
            boot_id='test-boot-id', unit_dir=instance.unit_dir)
        runner.owner = instance2
        return instance2

    def test_pending_stop_finalizes_before_new_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, digest = \
                self._crash_after(tmp, 'stop')
            stop = request('stop', op='cc' * 16, revisionDigest=digest)
            runner.crash_after = 'stop'
            with self.assertRaises(KeyboardInterrupt):
                instance.execute(stop)
            instance2 = self._reopen(instance, runner, fs, clock)
            machine = worker._machine_name('0a' * 16)
            unit = 'nexus-workload@' + machine + '.service'
            start = request('start', op='dd' * 16, revisionDigest=digest)
            result = instance2.execute(start)
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(result['appliedPhase'], 'running')
            stops = [c for c in runner.calls if c[2:3] == ['stop']]
            replay = instance2.execute(stop)
            self.assertEqual(replay['status'], 'completed')
            self.assertEqual(replay['appliedPhase'], 'stopped')
            self.assertEqual(
                len([c for c in runner.calls if c[2:3] == ['stop']]),
                len(stops))
            self.assertEqual(runner.unit_state(unit)['ActiveState'], 'active')

    def test_pending_start_finalizes_before_new_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            start = request('start', op='bb' * 16, revisionDigest=digest)
            runner.crash_after = 'start'
            with self.assertRaises(KeyboardInterrupt):
                instance.execute(start)
            instance2 = self._reopen(instance, runner, fs, clock)
            machine = worker._machine_name('0a' * 16)
            unit = 'nexus-workload@' + machine + '.service'
            stop = request('stop', op='cc' * 16, revisionDigest=digest)
            result = instance2.execute(stop)
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(result['appliedPhase'], 'stopped')
            starts = [c for c in runner.calls if c[2:3] == ['start']]
            replay = instance2.execute(start)
            self.assertEqual(replay['status'], 'completed')
            self.assertEqual(replay['appliedPhase'], 'running')
            self.assertEqual(
                len([c for c in runner.calls if c[2:3] == ['start']]),
                len(starts))
            self.assertEqual(runner.unit_state(unit)['ActiveState'],
                             'inactive')

    def test_uncertain_pending_op_blocks_new_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            start = request('start', op='bb' * 16, revisionDigest=digest)
            runner.crash_after = 'start'
            with self.assertRaises(KeyboardInterrupt):
                instance.execute(start)
            instance2 = self._reopen(instance, runner, fs, clock)
            runner.show_mode = 'rc'
            observed = instance2.execute(observe())
            self.assertEqual(observed['unitActiveState'], 'unknown')
            stop = request('stop', op='cc' * 16, revisionDigest=digest)
            result = instance2.execute(stop)
            self.assertEqual(result['status'], 'uncertain')
            self.assertEqual(result['error'], 'operation-in-progress')
            self.assertFalse(
                any(c[2:3] == ['stop'] for c in runner.calls))
            rows = instance2.db.execute(
                'SELECT COUNT(*) FROM operations').fetchone()[0]
            self.assertEqual(rows, 2)
            pending = instance2.db.execute(
                "SELECT COUNT(*) FROM operations WHERE status='pending'"
            ).fetchone()[0]
            self.assertEqual(pending, 1)
            replay = instance2.execute(start)
            self.assertEqual(replay['status'], 'uncertain')


class DrainProofTests(unittest.TestCase):
    def test_expired_start_populated_cgroup_never_stopped(self):
        with tempfile.TemporaryDirectory() as tmp:
            fs = FakeFilesystem(cgroup_populated='1')
            instance, runner, fs, clock, definition, _ = make_worker(
                tmp, fs=fs)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            machine = worker._machine_name('0a' * 16)
            unit = 'nexus-workload@' + machine + '.service'
            set_pending_start(instance, clock,
                              deadline=clock.monotonic() - 1)
            runner.units[unit] = {'LoadState': 'loaded',
                                  'ActiveState': 'inactive',
                                  'SubState': 'dead', 'MainPID': '0',
                                  'ControlGroup': '/machine.slice/' + unit}
            result = instance.execute(observe())
            self.assertNotEqual(result['phase'], 'stopped')
            self.assertEqual(result['phase'], 'unknown')
            other = request('prepare', instance='3d' * 16, op='ee' * 16,
                            generation=2, revisionDigest=digest)
            result = instance.execute(other)
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'workload-not-stopped')

    def test_expired_start_nonzero_mainpid_never_stopped(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            machine = worker._machine_name('0a' * 16)
            unit = 'nexus-workload@' + machine + '.service'
            set_pending_start(instance, clock,
                              deadline=clock.monotonic() - 1)
            runner.units[unit] = {'LoadState': 'loaded',
                                  'ActiveState': 'failed',
                                  'SubState': 'failed', 'MainPID': '77',
                                  'ControlGroup': ''}
            result = instance.execute(observe())
            self.assertEqual(result['phase'], 'unknown')

    def test_failed_unit_cgroup_read_error_never_stopped(self):
        with tempfile.TemporaryDirectory() as tmp:
            fs = FakeFilesystem(cgroup_error=PermissionError('denied'))
            instance, runner, fs, clock, definition, _ = make_worker(
                tmp, fs=fs)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            machine = worker._machine_name('0a' * 16)
            unit = 'nexus-workload@' + machine + '.service'
            set_pending_start(instance, clock,
                              deadline=clock.monotonic() - 1)
            runner.units[unit] = {'LoadState': 'loaded',
                                  'ActiveState': 'failed',
                                  'SubState': 'failed', 'MainPID': '0',
                                  'ControlGroup': '/machine.slice/' + unit}
            result = instance.execute(observe())
            self.assertEqual(result['phase'], 'unknown')

    def test_not_found_with_contradictory_facts_uncertain(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            machine = worker._machine_name('0a' * 16)
            unit = 'nexus-workload@' + machine + '.service'
            set_pending_start(instance, clock,
                              deadline=clock.monotonic() - 1)
            runner.units[unit] = {'LoadState': 'not-found',
                                  'ActiveState': 'inactive',
                                  'SubState': 'dead', 'MainPID': '4242',
                                  'ControlGroup': ''}
            result = instance.execute(observe())
            self.assertEqual(result['phase'], 'unknown')

    def test_deactivating_settle_is_uncertain(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            real = runner._systemd

            def patched(verb, argv):
                if verb == 'start':
                    unit = argv[3]
                    runner.units[unit] = {
                        'LoadState': 'loaded', 'ActiveState': 'deactivating',
                        'SubState': 'stop-sigterm', 'MainPID': '4242',
                        'ControlGroup': '/machine.slice/' + unit}
                    return Result(argv, 0)
                return real(verb, argv)

            runner._systemd = patched
            result = instance.execute(request('start', op='bb' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'uncertain')
            self.assertEqual(
                instance._get_instance('0a' * 16)['phase'], 'unknown')


class HostFilesystemTests(unittest.TestCase):
    def test_primitives_propagate_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            fs = worker.HostFilesystem()
            with self.assertRaises(FileNotFoundError):
                fs.sync_dir(os.path.join(tmp, 'missing'))
            with self.assertRaises(FileExistsError):
                fs.mkdir(tmp, 0o700)
            fs.sync_dir(tmp)


class CrashPrepareWindowTests(unittest.TestCase):
    def _reopen(self, instance, runner, fs, clock):
        instance2 = new_worker(
            instance.config, runner=runner, fs=fs, clock=clock,
            boot_id='test-boot-id', unit_dir=instance.unit_dir)
        runner.owner = instance2
        return instance2

    def test_crash_after_insert_before_mkdir_resumes(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            real_mkdir = fs.mkdir

            def crash_mkdir(path, mode):
                if path.endswith('0a' * 16):
                    raise KeyboardInterrupt()
                return real_mkdir(path, mode)

            fs.mkdir = crash_mkdir
            prepare = request('prepare', revisionDigest=digest)
            with self.assertRaises(KeyboardInterrupt):
                instance.execute(prepare)
            fs.mkdir = real_mkdir
            row = instance.db.execute(
                "SELECT status FROM operations WHERE operation_id=?",
                ('aa' * 16,)).fetchone()
            self.assertEqual(row[0], 'pending')
            self.assertFalse(os.path.exists(
                os.path.join(tmp, 'storage', '0a' * 16)))
            instance2 = self._reopen(instance, runner, fs, clock)
            result = instance2.execute(prepare)
            self.assertEqual(result['status'], 'completed', result)
            self.assertTrue(os.path.isdir(
                os.path.join(tmp, 'storage', '0a' * 16, 'data')))

    def test_crash_after_leaf_mkdir_before_chown_resumes(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            real_chown = fs.chown
            fired = []

            def crash_chown(path, uid, gid):
                if not fired:
                    fired.append(True)
                    raise KeyboardInterrupt()
                return real_chown(path, uid, gid)

            fs.chown = crash_chown
            prepare = request('prepare', revisionDigest=digest)
            with self.assertRaises(KeyboardInterrupt):
                instance.execute(prepare)
            fs.chown = real_chown
            instance2 = self._reopen(instance, runner, fs, clock)
            result = instance2.execute(prepare)
            self.assertEqual(result['status'], 'completed', result)
            self.assertTrue(os.path.isdir(
                os.path.join(tmp, 'storage', '0a' * 16, 'data')))

    def test_crash_resume_unmounted_creates_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            real_mkdir = fs.mkdir

            def crash_mkdir(path, mode):
                if path.endswith('0a' * 16):
                    raise KeyboardInterrupt()
                return real_mkdir(path, mode)

            fs.mkdir = crash_mkdir
            prepare = request('prepare', revisionDigest=digest)
            with self.assertRaises(KeyboardInterrupt):
                instance.execute(prepare)
            fs.mkdir = real_mkdir
            runner.mount_rows = [{'target': '/', 'source': 'rootfs',
                                  'uuid': 'rootfs'}]
            instance2 = self._reopen(instance, runner, fs, clock)
            result = instance2.execute(prepare)
            self.assertEqual(result['status'], 'failed')
            self.assertTrue(result['error'].startswith('storage-'))
            self.assertFalse(os.path.exists(
                os.path.join(tmp, 'storage', '0a' * 16)))

    def test_exact_capacity_still_resumes(self):
        with tempfile.TemporaryDirectory() as tmp:
            fs = FakeFilesystem(mem_kb=256 * 1024)
            instance, runner, fs, clock, definition, _ = make_worker(
                tmp, fs=fs)
            digest = definition['revisionDigest']
            real_mkdir = fs.mkdir

            def crash_mkdir(path, mode):
                if path.endswith('0a' * 16):
                    raise KeyboardInterrupt()
                return real_mkdir(path, mode)

            fs.mkdir = crash_mkdir
            prepare = request('prepare', revisionDigest=digest)
            with self.assertRaises(KeyboardInterrupt):
                instance.execute(prepare)
            fs.mkdir = real_mkdir
            instance2 = self._reopen(instance, runner, fs, clock)
            result = instance2.execute(prepare)
            self.assertEqual(result['status'], 'completed', result)

    def test_generation_recorded_before_state_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            real_mkdir = fs.mkdir

            def crash_mkdir(path, mode):
                if path.endswith('0a' * 16):
                    raise KeyboardInterrupt()
                return real_mkdir(path, mode)

            fs.mkdir = crash_mkdir
            prepare = request('prepare', revisionDigest=digest)
            with self.assertRaises(KeyboardInterrupt):
                instance.execute(prepare)
            fs.mkdir = real_mkdir
            row = instance.db.execute(
                'SELECT generation FROM generations WHERE workload_id=?',
                ('canary',)).fetchone()
            self.assertEqual(row[0], 1)
            instance2 = self._reopen(instance, runner, fs, clock)
            newer = request('prepare', instance='3d' * 16, op='ee' * 16,
                            generation=2, revisionDigest=digest)
            result = instance2.execute(newer)
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'instance-conflict')
            stop = request('stop', op='dd' * 16, revisionDigest=digest)
            result = instance2.execute(stop)
            self.assertEqual(result['status'], 'completed', result)
            newer2 = request('prepare', instance='3d' * 16, op='e2' * 16,
                             generation=2, revisionDigest=digest)
            result = instance2.execute(newer2)
            self.assertEqual(result['status'], 'completed', result)
            start = request('start', op='ff' * 16, revisionDigest=digest)
            result = instance2.execute(start)
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'generation-stale')

    def test_sync_dir_failure_leaves_prepare_pending_and_replays(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance_dir = os.path.join(tmp, 'storage', '0a' * 16)
            real_sync = fs.sync_dir

            def fail_sync(path):
                if path == instance_dir:
                    raise OSError('injected sync failure')
                return real_sync(path)

            fs.sync_dir = fail_sync
            prepare = request('prepare', revisionDigest=digest)
            result = instance.execute(prepare)
            self.assertEqual(result['status'], 'uncertain', result)
            row = instance.db.execute(
                "SELECT status FROM operations WHERE operation_id=?",
                ('aa' * 16,)).fetchone()
            self.assertEqual(row[0], 'pending')
            row = instance.db.execute(
                "SELECT phase FROM instances WHERE instance_id=?",
                ('0a' * 16,)).fetchone()
            self.assertEqual(row[0], 'preparing')
            self.assertFalse(any(
                call[0] == 'systemctl' and 'start' in call
                for call in runner.calls))
            fs.sync_dir = real_sync
            instance2 = self._reopen(instance, runner, fs, clock)
            result = instance2.execute(prepare)
            self.assertEqual(result['status'], 'completed', result)
            leaf = os.path.join(instance_dir, 'data')
            st = os.lstat(leaf)
            self.assertTrue(stat.S_ISDIR(st.st_mode))
            self.assertEqual(stat.S_IMODE(st.st_mode), 0o700)
            self.assertEqual(fs.owners[leaf], (65536, 65536))

    def test_missing_prepared_state_dir_start_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            result = instance.execute(
                request('prepare', revisionDigest=digest))
            self.assertEqual(result['status'], 'completed', result)
            instance_dir = os.path.join(tmp, 'storage', '0a' * 16)
            shutil.rmtree(instance_dir)
            result = instance.execute(
                request('start', op='ab' * 16, revisionDigest=digest))
            self.assertEqual(result['status'], 'failed', result)
            self.assertEqual(result['error'], 'path-unsafe')
            self.assertFalse(os.path.exists(instance_dir))
            self.assertFalse(any(
                call[0] == 'systemctl' and 'start' in call
                for call in runner.calls))


class MetadataHardeningTests(unittest.TestCase):
    def test_statedir_permissive_mode_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, _ = make_config(tmp)
            os.makedirs(config['stateDir'], mode=0o777)
            os.chmod(config['stateDir'], 0o777)
            with self.assertRaises(worker.WorkerError) as ctx:
                new_worker(config, runner=FakeRunner(),
                              fs=FakeFilesystem(), clock=FakeClock(),
                              boot_id='b', unit_dir=os.path.join(tmp, 'u'))
            self.assertEqual(ctx.exception.code, 'path-unsafe')

    def test_writable_ancestor_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, _ = make_config(tmp)
            parent = os.path.dirname(config['stateDir'])
            loose = os.path.join(tmp, 'loose')
            os.makedirs(loose)
            os.chmod(loose, 0o777)
            config['stateDir'] = os.path.join(loose, 'state')
            with self.assertRaises(worker.WorkerError) as ctx:
                new_worker(config, runner=FakeRunner(),
                              fs=FakeFilesystem(), clock=FakeClock(),
                              boot_id='b', unit_dir=os.path.join(tmp, 'u'))
            self.assertEqual(ctx.exception.code, 'path-unsafe')

    def test_symlinked_metadata_file_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, _ = make_config(tmp)
            os.makedirs(config['stateDir'], mode=0o700)
            target = os.path.join(tmp, 'elsewhere')
            Path(target).write_text('x')
            os.symlink(target, os.path.join(config['stateDir'], 'worker.db'))
            with self.assertRaises(worker.WorkerError) as ctx:
                new_worker(config, runner=FakeRunner(),
                              fs=FakeFilesystem(), clock=FakeClock(),
                              boot_id='b', unit_dir=os.path.join(tmp, 'u'))
            self.assertEqual(ctx.exception.code, 'path-unsafe')

    def test_symlinked_wal_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, _ = make_config(tmp)
            os.makedirs(config['stateDir'], mode=0o700)
            target = os.path.join(tmp, 'elsewhere')
            Path(target).write_text('x')
            os.symlink(target,
                       os.path.join(config['stateDir'], 'worker.db-wal'))
            with self.assertRaises(worker.WorkerError) as ctx:
                new_worker(config, runner=FakeRunner(),
                              fs=FakeFilesystem(), clock=FakeClock(),
                              boot_id='b', unit_dir=os.path.join(tmp, 'u'))
            self.assertEqual(ctx.exception.code, 'path-unsafe')

    def test_sidecar_bad_mode_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, _ = make_config(tmp)
            os.makedirs(config['stateDir'], mode=0o700)
            db = os.path.join(config['stateDir'], 'worker.db')
            fd = os.open(db, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
            wal = db + '-wal'
            fd = os.open(wal, os.O_CREAT | os.O_WRONLY, 0o644)
            os.close(fd)
            os.chmod(wal, 0o644)
            with self.assertRaises(worker.WorkerError) as ctx:
                new_worker(config, runner=FakeRunner(),
                              fs=FakeFilesystem(), clock=FakeClock(),
                              boot_id='b', unit_dir=os.path.join(tmp, 'u'))
            self.assertEqual(ctx.exception.code, 'path-unsafe')

    def test_no_external_effects_on_metadata_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, _ = make_config(tmp)
            parent = os.path.join(tmp, 'bad')
            os.makedirs(parent)
            os.chmod(parent, 0o777)
            config['stateDir'] = os.path.join(parent, 'state')
            runner = FakeRunner()
            with self.assertRaises(worker.WorkerError):
                new_worker(config, runner=runner, fs=FakeFilesystem(),
                              clock=FakeClock(), boot_id='b',
                              unit_dir=os.path.join(tmp, 'u'))
            self.assertEqual(runner.calls, [])


class LeafPermissionTests(unittest.TestCase):
    def test_leaf_mode_preserved_across_start_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            leaf = os.path.join(tmp, 'storage', '0a' * 16, 'data')
            os.chmod(leaf, 0o710)
            Path(leaf, 'value').write_text('kept')
            result = instance.execute(request('start', op='bb' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(stat.S_IMODE(os.lstat(leaf).st_mode), 0o710)
            self.assertEqual(Path(leaf, 'value').read_text(), 'kept')
            result = instance.execute(request('stop', op='cc' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'completed', result)
            result = instance.execute(request('start', op='dd' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(stat.S_IMODE(os.lstat(leaf).st_mode), 0o710)
            fs.owners[leaf] = (999, 999)
            result = instance.execute(request('stop', op='ee' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'completed')
            result = instance.execute(request('start', op='ff' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'storage-state-conflict')


class EdgeValidationTests(unittest.TestCase):
    def test_deep_json_rejected(self):
        deep = b'[' * 2000 + b']' * 2000
        self.assertLess(len(deep), worker._MAX_REQUEST_BYTES)
        with self.assertRaises(worker.WorkerError):
            worker.validate_request(worker.load_json_bytes(deep))
        old_limit = sys.getrecursionlimit()
        try:
            sys.setrecursionlimit(300)
            with self.assertRaises(worker.WorkerError) as ctx:
                worker.load_json_bytes(b'[' * 200000 + b']' * 200000)
            self.assertEqual(ctx.exception.code, 'invalid-json')
        finally:
            sys.setrecursionlimit(old_limit)

    def test_uid_base_reserved_range_rejected(self):
        for uid_base, valid in ((2**32 - 131072, True),
                                (2**32 - 65536, False)):
            config = {
                'schemaVersion': 1, 'hostId': 'h',
                'architecture': 'x86_64-linux', 'stateDir': '/var/lib/w',
                'storage': {'root': '/srv/w', 'mountPoint': '/srv/w',
                            'uuid': 'aaaa-bbbb'},
                'capacity': {'memoryMiB': 1, 'cpuMillis': 1,
                             'stateBytes': 1},
                'capabilities': [], 'approvedBundles': ['/nix/store/'
                                                        + 'a' * 32 + '-x'],
                'slots': [{'id': 's', 'uidBase': uid_base,
                           'hostAddress': '10.0.0.1',
                           'localAddress': '10.0.0.2'}]}
            if valid:
                worker.validate_config(config)
            else:
                with self.assertRaises(worker.WorkerError):
                    worker.validate_config(config)

    def test_competing_prepare_structured_conflict(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            second = request('prepare', instance='3d' * 16, op='ee' * 16,
                             generation=2, revisionDigest=digest)
            result = instance.execute(second)
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'instance-conflict')
            replay = instance.execute(second)
            self.assertEqual(replay, result)
            self.assertEqual(
                instance._get_instance('0a' * 16)['phase'], 'prepared')


class BindingTests(unittest.TestCase):
    def _prepare(self, tmp):
        instance, runner, fs, clock, definition, _ = make_worker(tmp)
        digest = definition['revisionDigest']
        result = instance.execute(request('prepare', revisionDigest=digest))
        self.assertEqual(result['status'], 'completed', result)
        return instance, runner, fs, clock, digest

    def _reopen(self, instance, runner, fs, clock, config):
        instance2 = new_worker(
            config, runner=runner, fs=fs, clock=clock,
            boot_id='test-boot-id', unit_dir=instance.unit_dir)
        runner.owner = instance2
        return instance2

    def test_binding_change_blocks_mutations(self):
        mutations = (
            lambda c: c['slots'][0].update(localAddress='192.168.130.9'),
            lambda c: c['slots'][0].update(uidBase=196608),
            lambda c: c['storage'].update(uuid='9999-8888'),
            lambda c: c['storage'].update(root=c['storage']['root'] + '/new'),
            lambda c: c.update(hostId='host-b'),
            lambda c: c.update(architecture='aarch64-linux'),
        )
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as tmp:
                instance, runner, fs, clock, digest = self._prepare(tmp)
                config = copy.deepcopy(instance.config)
                mutate(config)
                instance2 = self._reopen(instance, runner, fs, clock, config)
                starts = [c for c in runner.calls if c[2:3] == ['start']]
                result = instance2.execute(
                    request('start', op='bb' * 16, revisionDigest=digest))
                self.assertEqual(result['status'], 'failed')
                self.assertEqual(result['error'], 'binding-changed')
                self.assertEqual(
                    [c for c in runner.calls if c[2:3] == ['start']], starts)
                result = instance2.execute(
                    request('prepare', op='cc' * 16, revisionDigest=digest))
                self.assertEqual(result['status'], 'failed')
                self.assertEqual(result['error'], 'binding-changed')
                set_pending_start(instance2, clock)
                self.assertEqual(
                    instance2.guard(worker._machine_name('0a' * 16)), 1)
                observed = instance2.execute(observe())
                self.assertFalse(observed['bindingCurrent'])
                self.assertEqual(observed['endpointAddress'], '192.168.130.2')
                self.assertEqual(observed['hostId'], 'host-a')
                leaf = os.path.join(instance.config['storage']['root'],
                                    '0a' * 16, 'data')
                self.assertTrue(os.path.isdir(leaf))
                self.assertFalse(os.path.exists(
                    os.path.join(instance.config['storage']['root'], 'new')))
                result = instance2.execute(
                    request('stop', op='dd' * 16, revisionDigest=digest))
                self.assertEqual(result['status'], 'completed', result)

    def test_missing_binding_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.db.execute(
                "INSERT INTO operations(operation_id, request, status)"
                " VALUES(?,?,'pending')",
                ('aa' * 16,
                 artifacts.canonical_bytes(
                     request('prepare', revisionDigest=digest)).decode()))
            insert_instance(instance, digest, binding=None)
            result = instance.execute(request('prepare', revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'binding-missing')
            result = instance.execute(
                request('start', op='bb' * 16, revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'binding-missing')
            set_pending_start(instance, clock)
            self.assertEqual(
                instance.guard(worker._machine_name('0a' * 16)), 1)
            instance.db.execute(
                "UPDATE instances SET phase='running' WHERE instance_id=?",
                ('0a' * 16,))
            instance.db.commit()
            result = instance.execute(
                request('stop', op='cc' * 16, revisionDigest=digest))
            self.assertEqual(result['status'], 'completed', result)

    def test_new_instance_on_changed_binding_after_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, digest = self._prepare(tmp)
            result = instance.execute(
                request('stop', op='cc' * 16, revisionDigest=digest))
            self.assertEqual(result['status'], 'completed', result)
            config = copy.deepcopy(instance.config)
            config['slots'][0]['localAddress'] = '192.168.130.9'
            instance2 = self._reopen(instance, runner, fs, clock, config)
            result = instance2.execute(
                request('start', op='dd' * 16, revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'binding-changed')
            result = instance2.execute(request(
                'prepare', instance='3d' * 16, op='ee' * 16, generation=2,
                revisionDigest=digest))
            self.assertEqual(result['status'], 'completed', result)
            rec = instance2._get_instance('3d' * 16)
            self.assertEqual(rec['slot_id'], 'second')
            self.assertEqual(rec['binding']['slot']['id'], 'second')
            observed = instance2.execute(observe('3d' * 16))
            self.assertTrue(observed['bindingCurrent'])


class RetireTests(unittest.TestCase):
    def _running(self, tmp, fs=None):
        instance, runner, fs, clock, definition, _ = make_worker(tmp, fs=fs)
        digest = definition['revisionDigest']
        instance.execute(request('prepare', revisionDigest=digest))
        instance.execute(request('start', op='bb' * 16, revisionDigest=digest))
        return instance, runner, fs, clock, digest

    def test_retire_marks_and_drains(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, digest = self._running(tmp)
            start_receipt = instance.execute(
                request('start', op='bb' * 16, revisionDigest=digest))
            action, _ = worker.validate_request(
                request('retire', op='cc' * 16, revisionDigest=digest))
            self.assertEqual(action, 'retire')
            result = instance.execute(
                request('retire', op='cc' * 16, revisionDigest=digest))
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(result['appliedPhase'], 'stopped')
            self.assertEqual(result['action'], 'retire')
            observed = instance.execute(observe())
            self.assertTrue(observed['retired'])
            self.assertTrue(observed['unitDrained'])
            self.assertEqual(observed['phase'], 'stopped')
            starts = [c for c in runner.calls if c[2:3] == ['start']]
            replay = instance.execute(
                request('start', op='bb' * 16, revisionDigest=digest))
            self.assertEqual(replay, start_receipt)
            self.assertEqual(
                len([c for c in runner.calls if c[2:3] == ['start']]),
                len(starts))

    def test_retired_rejects_start_prepare_and_guard(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, digest = self._running(tmp)
            instance.execute(
                request('retire', op='cc' * 16, revisionDigest=digest))
            instance2 = new_worker(
                instance.config, runner=runner, fs=fs, clock=clock,
                boot_id='new-boot-id', unit_dir=instance.unit_dir)
            runner.owner = instance2
            starts = [c for c in runner.calls if c[2:3] == ['start']]
            result = instance2.execute(
                request('start', op='dd' * 16, revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'instance-retired')
            result = instance2.execute(
                request('prepare', op='ee' * 16, revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'instance-retired')
            self.assertEqual(
                len([c for c in runner.calls if c[2:3] == ['start']]),
                len(starts))
            set_pending_start(instance2, clock)
            self.assertEqual(
                instance2.guard(worker._machine_name('0a' * 16)), 1)
            rec = instance2._get_instance('0a' * 16)
            self.assertEqual(rec['retired'], 1)

    def test_new_generation_needs_retired_instance_drained(self):
        with tempfile.TemporaryDirectory() as tmp:
            fs = FakeFilesystem()
            instance, runner, fs, clock, digest = self._running(tmp, fs=fs)
            fs.cgroup_populated = '1'
            retire = request('retire', op='cc' * 16, revisionDigest=digest)
            result = instance.execute(retire)
            self.assertEqual(result['status'], 'uncertain', result)
            newer = request('prepare', instance='3d' * 16, op='ee' * 16,
                            generation=2, revisionDigest=digest)
            result = instance.execute(newer)
            self.assertEqual(result['status'], 'uncertain')
            self.assertEqual(result['error'], 'operation-in-progress')
            self.assertIsNone(instance._get_instance('3d' * 16))
            fs.cgroup_populated = '0'
            result = instance.execute(newer)
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(result['appliedPhase'], 'prepared')
            old = instance._get_instance('0a' * 16)
            self.assertEqual(old['retired'], 1)
            self.assertEqual(old['phase'], 'stopped')

    def test_retire_after_binding_drift_still_stops(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, digest = self._running(tmp)
            instance.config['storage']['uuid'] = 'drifted-uuid'
            observed = instance.execute(observe())
            self.assertFalse(observed['bindingCurrent'])
            result = instance.execute(
                request('retire', op='cc' * 16, revisionDigest=digest))
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(result['appliedPhase'], 'stopped')
            result = instance.execute(
                request('start', op='dd' * 16, revisionDigest=digest))
            self.assertEqual(result['error'], 'instance-retired')

    def test_retire_crash_after_marker_replays_and_drains(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, digest = self._running(tmp)
            retire = request('retire', op='cc' * 16, revisionDigest=digest)
            runner.crash_after = 'stop'
            with self.assertRaises(KeyboardInterrupt):
                instance.execute(retire)
            instance2 = new_worker(
                instance.config, runner=runner, fs=fs, clock=clock,
                boot_id='new-boot-id', unit_dir=instance.unit_dir)
            runner.owner = instance2
            rec = instance2._get_instance('0a' * 16)
            self.assertEqual(rec['retired'], 1)
            self.assertEqual(rec['phase'], 'stopping')
            stops = [c for c in runner.calls if c[2:3] == ['stop']]
            result = instance2.execute(retire)
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(result['appliedPhase'], 'stopped')
            rec = instance2._get_instance('0a' * 16)
            self.assertEqual(rec['retired'], 1)
            self.assertEqual(
                len([c for c in runner.calls if c[2:3] == ['stop']]),
                len(stops))

    def test_retire_systemd_unknown_stays_uncertain(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, digest = self._running(tmp)
            runner.show_mode = 'rc'
            result = instance.execute(
                request('retire', op='cc' * 16, revisionDigest=digest))
            self.assertEqual(result['status'], 'uncertain')
            rec = instance._get_instance('0a' * 16)
            self.assertEqual(rec['retired'], 1)
            self.assertEqual(rec['phase'], 'unknown')
            observed = instance.execute(observe())
            self.assertIsNone(observed['unitDrained'])

    def test_retire_replay_exact_receipt_no_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, digest = self._running(tmp)
            retire = request('retire', op='cc' * 16, revisionDigest=digest)
            result = instance.execute(retire)
            self.assertEqual(result['status'], 'completed', result)
            stops = [c for c in runner.calls if c[2:3] == ['stop']]
            replay = instance.execute(retire)
            self.assertEqual(replay, result)
            self.assertEqual(
                len([c for c in runner.calls if c[2:3] == ['stop']]),
                len(stops))
            self.assertEqual(instance._get_instance('0a' * 16)['retired'], 1)


class OrphanRuntimeTests(unittest.TestCase):
    def test_untracked_active_unit_blocks_prepare(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            orphan = 'nexus-workload@n' + 'a' * 10 + '.service'
            runner.units[orphan] = {'LoadState': 'loaded',
                                    'ActiveState': 'active',
                                    'SubState': 'running', 'MainPID': '99',
                                    'ControlGroup': '/machine.slice/' + orphan}
            result = instance.execute(
                request('prepare', revisionDigest=definition['revisionDigest']))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'unknown-runtime')
            self.assertIsNone(instance._get_instance('0a' * 16))
            self.assertFalse(os.path.exists(
                os.path.join(tmp, 'storage', '0a' * 16)))

    def test_untracked_active_unit_blocks_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            orphan = 'nexus-workload@n' + 'a' * 10 + '.service'
            runner.units[orphan] = {'LoadState': 'loaded',
                                    'ActiveState': 'active',
                                    'SubState': 'running', 'MainPID': '99',
                                    'ControlGroup': '/machine.slice/' + orphan}
            result = instance.execute(
                request('start', op='bb' * 16, revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'unknown-runtime')
            machine = worker._machine_name('0a' * 16)
            self.assertNotIn('nexus-workload@' + machine + '.service',
                             runner.units)

    def test_drained_or_not_found_orphan_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            runner.listed_units = [
                'nexus-workload@n' + 'b' * 10 + '.service']
            result = instance.execute(
                request('prepare', revisionDigest=definition['revisionDigest']))
            self.assertEqual(result['status'], 'completed', result)

    def test_unexpected_name_format_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            runner.listed_units = ['nexus-workload@bogus.service']
            result = instance.execute(
                request('prepare', revisionDigest=definition['revisionDigest']))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'unknown-runtime')

    def test_list_units_failure_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            runner.list_units_mode = 'rc'
            result = instance.execute(
                request('prepare', revisionDigest=definition['revisionDigest']))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'],
                             'runtime-observation-unavailable')

    def test_unrelated_units_never_queried(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            runner.listed_units = [
                'microvm@test-vm.service',
                'nexus-workload@n' + 'c' * 10 + '.service']
            result = instance.execute(
                request('prepare', revisionDigest=definition['revisionDigest']))
            self.assertEqual(result['status'], 'completed', result)
            for call in runner.calls:
                if call[0] == 'systemctl':
                    self.assertNotIn('microvm@test-vm.service', call)

    def test_stopped_record_with_active_unit_blocks_new_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            instance.execute(
                request('stop', op='cc' * 16, revisionDigest=digest))
            machine = worker._machine_name('0a' * 16)
            unit = 'nexus-workload@' + machine + '.service'
            runner.units[unit] = {'LoadState': 'loaded',
                                  'ActiveState': 'active',
                                  'SubState': 'running', 'MainPID': '88',
                                  'ControlGroup': '/machine.slice/' + unit}
            newer = request('prepare', instance='3d' * 16, op='ee' * 16,
                            generation=2, revisionDigest=digest)
            result = instance.execute(newer)
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'workload-not-stopped')
            self.assertIsNone(instance._get_instance('3d' * 16))
            self.assertFalse(os.path.exists(
                os.path.join(tmp, 'storage', '3d' * 16)))
            runner.units[unit] = {'LoadState': 'loaded',
                                  'ActiveState': 'inactive',
                                  'SubState': 'dead', 'MainPID': '0',
                                  'ControlGroup': ''}
            result = instance.execute(dict(newer, operationId='e2' * 16))
            self.assertEqual(result['status'], 'completed', result)

    def test_unit_query_failure_blocks_new_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            instance.execute(
                request('stop', op='cc' * 16, revisionDigest=digest))
            runner.show_mode = 'rc'
            result = instance.execute(request(
                'prepare', instance='3d' * 16, op='ee' * 16, generation=2,
                revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'unknown-runtime')
            self.assertIsNone(instance._get_instance('3d' * 16))

    def test_populated_cgroup_blocks_new_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            fs = FakeFilesystem(cgroup_populated='1')
            instance, runner, fs, clock, definition, _ = make_worker(
                tmp, fs=fs)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            instance.db.execute(
                "UPDATE instances SET phase='stopped' WHERE instance_id=?",
                ('0a' * 16,))
            instance.db.commit()
            unit = 'nexus-workload@' + worker._machine_name('0a' * 16) \
                + '.service'
            runner.units[unit] = {'LoadState': 'loaded',
                                  'ActiveState': 'inactive',
                                  'SubState': 'dead', 'MainPID': '0',
                                  'ControlGroup': '/machine.slice/' + unit}
            result = instance.execute(request(
                'prepare', instance='3d' * 16, op='ee' * 16, generation=2,
                revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'workload-not-stopped')
            self.assertIsNone(instance._get_instance('3d' * 16))


class CaptureBarrierTests(unittest.TestCase):
    def _running(self, tmp, fs=None, definition_overrides=None):
        instance, runner, fs, clock, definition, _ = make_worker(
            tmp, fs=fs, definition_overrides=definition_overrides)
        digest = definition['revisionDigest']
        instance.execute(request('prepare', revisionDigest=digest))
        instance.execute(request('start', op='bb' * 16,
                                 revisionDigest=digest))
        return instance, runner, fs, clock, digest

    def _reopen(self, instance, runner, fs, clock, boot_id='test-boot-id'):
        instance2 = new_worker(
            instance.config, runner=runner, fs=fs, clock=clock,
            boot_id=boot_id, unit_dir=instance.unit_dir)
        runner.owner = instance2
        return instance2

    def _freeze(self, digest, token='5e' * 16, op='dd' * 16,
                instance='0a' * 16, generation=1):
        req = request('freeze', instance=instance, op=op,
                      generation=generation, revisionDigest=digest,
                      captureId=token)
        return req

    def _thaw(self, digest, token='5e' * 16, op='ee' * 16,
              instance='0a' * 16, generation=1):
        req = request('thaw', instance=instance, op=op,
                      generation=generation, revisionDigest=digest,
                      captureId=token)
        return req

    def test_freeze_thaw_request_shape(self):
        req = self._freeze('sha256:' + '0' * 64)
        action, parsed = worker.validate_request(req)
        self.assertEqual(action, 'freeze')
        req = self._thaw('sha256:' + '0' * 64)
        action, _ = worker.validate_request(req)
        self.assertEqual(action, 'thaw')
        for mutate in (
            lambda r: r.pop('captureId'),
            lambda r: r.update(captureId='5E' * 16),
            lambda r: r.update(captureId='5e' * 15),
            lambda r: r.update(captureId='not-hex'),
            lambda r: r.update(extra='x'),
        ):
            bad = self._freeze('sha256:' + '0' * 64)
            mutate(bad)
            with self.assertRaises(worker.WorkerError, msg=mutate):
                worker.validate_request(bad)
        bad = request('start', revisionDigest='sha256:' + '0' * 64,
                      captureId='5e' * 16)
        with self.assertRaises(worker.WorkerError):
            worker.validate_request(bad)
        bad = request('freeze', revisionDigest='sha256:' + '0' * 64)
        with self.assertRaises(worker.WorkerError):
            worker.validate_request(bad)

    def test_freeze_running_drains_and_holds(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, digest = self._running(tmp)
            machine = worker._machine_name('0a' * 16)
            unit = 'nexus-workload@' + machine + '.service'
            result = instance.execute(self._freeze(digest))
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(result['appliedPhase'], 'stopped')
            self.assertEqual(result['captureId'], '5e' * 16)
            observed = instance.execute(observe())
            self.assertEqual(observed['captureId'], '5e' * 16)
            self.assertTrue(observed['unitDrained'])
            self.assertEqual(observed['phase'], 'stopped')
            self.assertEqual(runner.unit_state(unit)['ActiveState'],
                             'inactive')

    def test_freeze_stopped_instance(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, digest = self._running(tmp)
            instance.execute(request('stop', op='cc' * 16,
                                     revisionDigest=digest))
            result = instance.execute(self._freeze(digest))
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(result['appliedPhase'], 'stopped')
            self.assertEqual(instance.execute(observe())['captureId'],
                             '5e' * 16)

    def test_plain_stop_is_not_a_barrier(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, digest = self._running(tmp)
            result = instance.execute(request(
                'stop', op='cc' * 16, revisionDigest=digest))
            self.assertEqual(result['status'], 'completed')
            self.assertIsNone(instance.execute(observe())['captureId'])
            result = instance.execute(request(
                'start', op='dd' * 16, revisionDigest=digest))
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(result['appliedPhase'], 'running')

    def test_held_blocks_start_guard_and_new_prepare(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, digest = self._running(tmp)
            instance.execute(self._freeze(digest))
            result = instance.execute(request(
                'start', op='e1' * 16, revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'capture-held')
            set_pending_start(instance, clock)
            machine = worker._machine_name('0a' * 16)
            self.assertEqual(instance.guard(machine), 1)
            self.assertEqual(instance._get_instance('0a' * 16)['permit'], 1)
            newer = request('prepare', instance='3d' * 16, op='e2' * 16,
                            generation=2, revisionDigest=digest)
            result = instance.execute(newer)
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'capture-held')
            self.assertIsNone(instance._get_instance('3d' * 16))
            self.assertFalse(os.path.exists(
                os.path.join(tmp, 'storage', '3d' * 16)))

    def test_conflicting_and_released_capture_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, digest = self._running(tmp)
            instance.execute(self._freeze(digest))
            result = instance.execute(self._freeze(
                digest, token='6f' * 16, op='e1' * 16))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'capture-conflict')
            result = instance.execute(self._thaw(
                digest, token='6f' * 16, op='e2' * 16))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'capture-missing')
            result = instance.execute(self._thaw(digest))
            self.assertEqual(result['status'], 'completed', result)
            result = instance.execute(self._freeze(
                digest, op='e3' * 16))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'capture-released')
            result = instance.execute(self._freeze(
                digest, token='6f' * 16, op='e4' * 16))
            self.assertEqual(result['status'], 'completed', result)
            result = instance.execute(self._thaw(
                digest, op='e5' * 16))
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(instance.execute(observe())['captureId'],
                             '6f' * 16)
            result = instance.execute(request(
                'start', op='e6' * 16, revisionDigest=digest))
            self.assertEqual(result['error'], 'capture-held')

    def test_thaw_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, digest = self._running(tmp)
            instance.execute(self._freeze(digest))
            result = instance.execute(self._thaw(
                digest, generation=2))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'instance-conflict')
            result = instance.execute(self._thaw(
                'sha256:' + '0' * 64, op='e7' * 16))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'instance-conflict')

    def test_thaw_leaves_stopped_until_explicit_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, digest = self._running(tmp)
            instance.execute(self._freeze(digest))
            result = instance.execute(self._thaw(digest))
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(result['appliedPhase'], 'stopped')
            self.assertEqual(result['captureId'], '5e' * 16)
            observed = instance.execute(observe())
            self.assertIsNone(observed['captureId'])
            self.assertEqual(observed['phase'], 'stopped')
            machine = worker._machine_name('0a' * 16)
            unit = 'nexus-workload@' + machine + '.service'
            self.assertEqual(runner.unit_state(unit)['ActiveState'],
                             'inactive')
            result = instance.execute(request(
                'start', op='e8' * 16, revisionDigest=digest))
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(result['appliedPhase'], 'running')

    def test_retired_survives_freeze_thaw(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, digest = self._running(tmp)
            instance.execute(request('retire', op='cc' * 16,
                                     revisionDigest=digest))
            result = instance.execute(self._freeze(digest))
            self.assertEqual(result['status'], 'completed', result)
            self.assertTrue(instance.execute(observe())['retired'])
            result = instance.execute(self._thaw(digest))
            self.assertEqual(result['status'], 'completed', result)
            observed = instance.execute(observe())
            self.assertTrue(observed['retired'])
            self.assertIsNone(observed['captureId'])
            result = instance.execute(request(
                'start', op='e9' * 16, revisionDigest=digest))
            self.assertEqual(result['error'], 'instance-retired')

    def test_freeze_requires_backup_and_stop(self):
        for overrides, code in (
            ({'allowedOperations': ['start', 'stop']},
             'operation-not-allowed'),
            ({'allowedOperations': ['start', 'backup']},
             'operation-not-allowed'),
            ({'secretSetRef': 'sec'}, 'secret-provisioning-unavailable'),
            ({'dependencies': ['other']},
             'dependency-readiness-unavailable'),
        ):
            with tempfile.TemporaryDirectory() as tmp:
                instance, runner, fs, clock, definition, _ = make_worker(
                    tmp, definition_overrides=overrides)
                digest = definition['revisionDigest']
                insert_instance(instance, digest, phase='stopped')
                result = instance.execute(self._freeze(digest))
                self.assertEqual(result['status'], 'failed')
                self.assertEqual(result['error'], code, overrides)

    def test_freeze_requires_prepared_phase_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', revisionDigest=digest))
            result = instance.execute(self._freeze(digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'phase-conflict')
            self.assertIsNone(instance.execute(observe())['captureId'])

    def test_freeze_refuses_unsafe_surfaces(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, digest = self._running(tmp)
            runner.mount_rc = 1
            result = instance.execute(self._freeze(digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'storage-not-mounted')
            self.assertIsNone(instance.execute(observe())['captureId'])
            runner.mount_rc = 0
            instance.config['storage']['uuid'] = 'drifted-uuid'
            result = instance.execute(self._freeze(digest, op='e1' * 16))
            self.assertEqual(result['error'], 'binding-changed')
            instance.config['storage']['uuid'] = '1111-2222'
            storage = instance.config['storage']['root']
            instance_dir = os.path.join(storage, '0a' * 16)
            shutil.rmtree(instance_dir)
            result = instance.execute(self._freeze(digest, op='e2' * 16))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'path-unsafe')
            os.mkdir(instance_dir, 0o700)
            os.mkdir(os.path.join(instance_dir, 'foreign'))
            result = instance.execute(self._freeze(digest, op='e3' * 16))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'storage-state-conflict')

    def test_stop_query_unknown_keeps_barrier_uncertain(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, digest = self._running(tmp)
            runner.show_mode = 'rc'
            result = instance.execute(self._freeze(digest))
            self.assertEqual(result['status'], 'uncertain', result)
            rec = instance._get_instance('0a' * 16)
            self.assertEqual(rec['phase'], 'unknown')
            self.assertIsNotNone(instance._held_capture('canary'))
            result = instance.execute(request(
                'start', op='ea' * 16, revisionDigest=digest))
            self.assertEqual(result['status'], 'uncertain')
            self.assertEqual(result['error'], 'operation-in-progress')
            runner.show_mode = 'ok'
            result = instance.execute(request(
                'start', op='eb' * 16, revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'capture-held')

    def test_crash_after_barrier_commit_resumes_held(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, digest = self._running(tmp)
            freeze = self._freeze(digest)
            runner.crash_after = 'stop'
            with self.assertRaises(KeyboardInterrupt):
                instance.execute(freeze)
            row = instance.db.execute(
                'SELECT status FROM operations WHERE operation_id=?',
                ('dd' * 16,)).fetchone()
            self.assertEqual(row[0], 'pending')
            instance2 = self._reopen(instance, runner, fs, clock,
                                     boot_id='new-boot-id')
            self.assertIsNotNone(instance2._held_capture('canary'))
            result = instance2.execute(freeze)
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(result['appliedPhase'], 'stopped')
            observed = instance2.execute(observe())
            self.assertEqual(observed['captureId'], '5e' * 16)
            self.assertTrue(observed['unitDrained'])
            result = instance2.execute(request(
                'start', op='ec' * 16, revisionDigest=digest))
            self.assertEqual(result['error'], 'capture-held')

    def test_crash_after_release_replays_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, digest = self._running(tmp)
            instance.execute(self._freeze(digest))
            thaw = self._thaw(digest)
            instance.db.execute(
                "INSERT INTO operations(operation_id, request, status)"
                " VALUES(?,?,'pending')",
                (thaw['operationId'],
                 artifacts.canonical_bytes(thaw).decode()))
            instance.db.execute(
                "UPDATE captures SET status='released'"
                " WHERE capture_id=?", ('5e' * 16,))
            instance.db.commit()
            result = instance.execute(thaw)
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(result['appliedPhase'], 'stopped')
            self.assertIsNone(instance.execute(observe())['captureId'])

    def test_held_survives_reopen_and_boot_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, digest = self._running(tmp)
            instance.execute(self._freeze(digest))
            instance2 = self._reopen(instance, runner, fs, clock,
                                     boot_id='new-boot-id')
            observed = instance2.execute(observe())
            self.assertEqual(observed['captureId'], '5e' * 16)
            result = instance2.execute(request(
                'start', op='ed' * 16, revisionDigest=digest))
            self.assertEqual(result['error'], 'capture-held')
            set_pending_start(instance2, clock)
            self.assertEqual(
                instance2.guard(worker._machine_name('0a' * 16)), 1)

    def test_held_capture_retains_capacity(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, digest = self._running(tmp)
            instance.execute(request('stop', op='cc' * 16,
                                     revisionDigest=digest))
            reserved = instance._reservation_map()
            self.assertEqual(reserved['memoryMiB'], 0)
            self.assertEqual(reserved['cpuMillis'], 0)
            self.assertEqual(reserved['stateBytes'], 1048576)
            instance.execute(self._freeze(digest))
            reserved = instance._reservation_map()
            self.assertEqual(reserved['memoryMiB'], 256)
            self.assertEqual(reserved['cpuMillis'], 100)
            self.assertEqual(reserved['stateBytes'], 1048576)
            instance.execute(self._thaw(digest))
            reserved = instance._reservation_map()
            self.assertEqual(reserved['memoryMiB'], 0)
            self.assertEqual(reserved['cpuMillis'], 0)

    def test_old_database_gains_captures_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, bundle = make_config(tmp)
            state = config['stateDir']
            os.makedirs(state, 0o700)
            os.chmod(state, 0o700)
            db_path = os.path.join(state, 'worker.db')
            os.makedirs(os.path.join(state, 'instances'), 0o700)
            db = __import__('sqlite3').connect(db_path)
            db.executescript(
                'CREATE TABLE instances(instance_id TEXT PRIMARY KEY,'
                ' workload_id TEXT NOT NULL, revision_digest TEXT NOT NULL,'
                ' generation INTEGER NOT NULL, slot_id TEXT NOT NULL UNIQUE,'
                ' machine_name TEXT NOT NULL UNIQUE, phase TEXT NOT NULL,'
                " requirements TEXT NOT NULL DEFAULT '{}',"
                ' binding_json TEXT, boot_id TEXT, permit_deadline REAL,'
                ' permit INTEGER NOT NULL DEFAULT 0,'
                ' retired INTEGER NOT NULL DEFAULT 0);'
                'CREATE TABLE generations(workload_id TEXT PRIMARY KEY,'
                ' generation INTEGER NOT NULL);'
                'CREATE TABLE operations(operation_id TEXT PRIMARY KEY,'
                ' request TEXT NOT NULL, status TEXT NOT NULL, result TEXT);')
            db.commit()
            db.close()
            os.chmod(db_path, 0o600)
            write_bundle(bundle)
            instance = new_worker(
                config, runner=FakeRunner(),
                fs=FakeFilesystem(bundle_dir=bundle), clock=FakeClock(),
                boot_id='b', unit_dir=os.path.join(tmp, 'units'))
            self.assertEqual(instance.db.execute(
                'SELECT COUNT(*) FROM captures').fetchone()[0], 0)

    def test_released_thaw_new_op_reports_current_phase(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, digest = self._running(tmp)
            instance.execute(self._freeze(digest))
            result = instance.execute(self._thaw(digest))
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(result['appliedPhase'], 'stopped')
            start = request('start', op='e8' * 16, revisionDigest=digest)
            result = instance.execute(start)
            self.assertEqual(result['appliedPhase'], 'running', result)
            machine = worker._machine_name('0a' * 16)
            unit = 'nexus-workload@' + machine + '.service'
            pid = runner.unit_state(unit)['MainPID']
            # A new-operationId thaw replaying the spent token is a
            # no-op: it reports the recorded phase, stops nothing and
            # leaves the running unit and released barrier untouched.
            stops = [c for c in runner.calls if c[2:3] == ['stop']]
            result = instance.execute(self._thaw(digest, op='e9' * 16))
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(result['appliedPhase'], 'running')
            self.assertEqual(runner.unit_state(unit)['MainPID'], pid)
            self.assertEqual(runner.unit_state(unit)['ActiveState'],
                             'active')
            self.assertIsNone(instance.execute(observe())['captureId'])
            self.assertEqual(
                len([c for c in runner.calls if c[2:3] == ['stop']]),
                len(stops))


class AdoptTests(unittest.TestCase):
    """M8 worker state-dir adoption: a strictly validated exception to
    ``prepare``'s no-pre-existing-dir invariant, for DRBD failover pairs
    whose slots share a symmetric uidBase."""

    def _replica(self, storage_root, fs, instance='0a' * 16,
                 uid_base=65536, mounts=('data',), leaf=None):
        """Lay down a uidBase-owned replica dir exactly as failover
        provisioning delivers it."""
        idir = os.path.join(storage_root, instance)
        os.mkdir(idir, 0o700)
        fs.owners[idir] = (uid_base, uid_base)
        for name in mounts:
            leaf_dir = os.path.join(idir, name)
            os.mkdir(leaf_dir, 0o700)
            fs.owners[leaf_dir] = (uid_base, uid_base)
            if leaf is not None:
                fs.owners[leaf_dir] = leaf
        return idir

    def test_adopt_start_retire_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            storage = instance.config['storage']['root']
            idir = self._replica(storage, fs)
            result = instance.execute(request(
                'adopt', revisionDigest=digest))
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(result['appliedPhase'], 'prepared')
            self.assertEqual(result['action'], 'adopt')
            # The replica dir is claimed into normal root ownership.
            self.assertIn((idir, 0, 0), fs.chowns)
            # Adopted provenance is journaled and observable.
            row = instance._get_instance('0a' * 16)
            self.assertEqual(row['adopted'], 1)
            observed = instance.execute(observe())
            self.assertTrue(observed['adopted'])
            self.assertEqual(observed['phase'], 'prepared')
            result = instance.execute(request('start', op='bb' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['appliedPhase'], 'running')
            result = instance.execute(request('retire', op='cc' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['appliedPhase'], 'stopped')
            observed = instance.execute(observe())
            self.assertTrue(observed['retired'])
            self.assertTrue(observed['adopted'])

    def test_adopt_replay_and_rejects(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            storage = instance.config['storage']['root']
            self._replica(storage, fs)
            first = instance.execute(request('adopt',
                                             revisionDigest=digest))
            self.assertEqual(first['status'], 'completed')
            replay = instance.execute(request('adopt',
                                              revisionDigest=digest))
            self.assertEqual(replay, first)
            # A fresh prepare cannot hijack the adopted instance, and a
            # second adopt under a new operation id resumes cleanly.
            result = instance.execute(request(
                'prepare', op='ab' * 16, revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'instance-conflict')
            result = instance.execute(request(
                'adopt', op='ac' * 16, revisionDigest=digest))
            self.assertEqual(result['status'], 'completed')
            # A stale generation is refused.
            result = instance.execute(request(
                'adopt', instance='3d' * 16, op='ad' * 16,
                revisionDigest=digest))
            self.assertEqual(result['error'], 'generation-stale')

    def test_adopt_rejections(self):
        cases = (
            # absent dir: plain prepare territory
            ('absent', 'adopt-state-absent'),
            # replica for a different uidBase (or a local root dir)
            ('root-owned', 'adopt-ownership-conflict'),
            ('other-uid', 'adopt-ownership-conflict'),
            # manifest violations
            ('missing-leaf', 'adopt-state-conflict'),
            ('extra-file', 'adopt-state-conflict'),
            ('extra-dir', 'adopt-state-conflict'),
            ('leaf-not-dir', 'adopt-state-conflict'),
            ('leaf-wrong-owner', 'adopt-ownership-conflict'),
            ('top-not-dir', 'adopt-state-conflict'),
            ('top-wrong-mode', 'adopt-state-conflict'),
        )
        for scenario, code in cases:
            with tempfile.TemporaryDirectory() as tmp:
                instance, runner, fs, clock, definition, _ =                     make_worker(tmp)
                digest = definition['revisionDigest']
                storage = instance.config['storage']['root']
                idir = os.path.join(storage, '0a' * 16)
                if scenario == 'absent':
                    pass
                elif scenario == 'root-owned':
                    os.mkdir(idir, 0o700)
                    leaf = os.path.join(idir, 'data')
                    os.mkdir(leaf, 0o700)
                    fs.owners[leaf] = (65536, 65536)
                elif scenario == 'other-uid':
                    self._replica(storage, fs, uid_base=131072)
                elif scenario == 'missing-leaf':
                    self._replica(storage, fs, mounts=())
                elif scenario == 'extra-file':
                    self._replica(storage, fs)
                    Path(idir, 'stray').write_text('x')
                elif scenario == 'extra-dir':
                    self._replica(storage, fs)
                    os.mkdir(os.path.join(idir, 'stray'), 0o700)
                elif scenario == 'leaf-not-dir':
                    self._replica(storage, fs, mounts=())
                    Path(idir, 'data').write_text('x')
                elif scenario == 'leaf-wrong-owner':
                    self._replica(storage, fs, leaf=(0, 0))
                elif scenario == 'top-not-dir':
                    Path(idir).write_text('x')
                    fs.owners[idir] = (65536, 65536)
                elif scenario == 'top-wrong-mode':
                    self._replica(storage, fs)
                    os.chmod(idir, 0o755)
                result = instance.execute(request(
                    'adopt', revisionDigest=digest))
                self.assertEqual(result['status'], 'failed', scenario)
                self.assertEqual(result['error'], code, scenario)
                # A rejected adopt journals no instance record.
                self.assertIsNone(instance._get_instance('0a' * 16))

    def test_adopt_prepare_still_refuses_existing_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            storage = instance.config['storage']['root']
            self._replica(storage, fs)
            result = instance.execute(request(
                'prepare', revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'storage-state-conflict')

    def test_adopt_tolerates_worker_own_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            storage = instance.config['storage']['root']
            idir = self._replica(storage, fs)
            # A replicated in-flight restore claim and staging area are
            # the worker's own files — tolerated, and the sentinel still
            # blocks start until a restore commit.
            Path(idir, '.nexus-restore-pending').write_text(
                '{"schemaVersion":1,"restoreId":"' + 'ef' * 16 + '"}')
            os.mkdir(os.path.join(idir, '.nexus-restore-staging'), 0o700)
            result = instance.execute(request(
                'adopt', revisionDigest=digest))
            self.assertEqual(result['status'], 'completed', result)
            observed = instance.execute(observe())
            self.assertTrue(observed['restorePending'])
            result = instance.execute(request('start', op='bb' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'restore-incomplete')

    def test_adopt_resume_after_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            storage = instance.config['storage']['root']
            # Journal says adopted but the dir is already root-owned —
            # the crash landed between claim and the phase commit.
            insert_instance(instance, digest, phase='preparing')
            instance.db.execute(
                'UPDATE instances SET adopted=1 WHERE instance_id=?',
                ('0a' * 16,))
            instance.db.commit()
            idir = os.path.join(storage, '0a' * 16)
            os.mkdir(idir, 0o700)
            leaf = os.path.join(idir, 'data')
            os.mkdir(leaf, 0o700)
            fs.owners[leaf] = (65536, 65536)
            result = instance.execute(request(
                'adopt', revisionDigest=digest))
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(result['appliedPhase'], 'prepared')
            self.assertNotIn((idir, 0, 0), fs.chowns)

    def test_adopt_on_normal_instance_conflicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            instance.execute(request('prepare', op='aa' * 16,
                                     revisionDigest=digest))
            result = instance.execute(request(
                'adopt', op='ab' * 16, revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'], 'instance-conflict')

    def test_adopt_uses_bound_slot_uidbase(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            storage = instance.config['storage']['root']
            # Slot 'first' is held by an unrelated workload, so adoption
            # binds slot 'second' (uidBase 131072) — a replica carrying
            # the first slot's ownership is asymmetric and must fail
            # rather than be translated.
            instance.db.execute(
                "INSERT INTO instances(instance_id, workload_id,"
                " revision_digest, generation, slot_id, machine_name,"
                " phase, requirements) VALUES(?,?,?,?,?,?,?,?)",
                ('7e' * 16, 'other', digest, 1, 'first',
                 worker._machine_name('7e' * 16), 'prepared',
                 artifacts.canonical_bytes(
                     {'memoryMiB': 1, 'cpuMillis': 1,
                      'stateBytes': 1}).decode()))
            instance.db.commit()
            idir = self._replica(storage, fs, uid_base=65536)
            result = instance.execute(request(
                'adopt', revisionDigest=digest))
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['error'],
                             'adopt-ownership-conflict')
            fs.owners[idir] = (131072, 131072)
            fs.owners[os.path.join(idir, 'data')] = (131072, 131072)
            result = instance.execute(request(
                'adopt', op='ab' * 16, revisionDigest=digest))
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(
                instance._get_instance('0a' * 16)['slot_id'], 'second')

    def test_adopt_populated_leaves_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            instance, runner, fs, clock, definition, _ = make_worker(tmp)
            digest = definition['revisionDigest']
            storage = instance.config['storage']['root']
            idir = self._replica(storage, fs)
            # Replicated application payload survives adoption —
            # unlike resume-prepare, leaf contents are the whole point.
            Path(idir, 'data', 'payload.db').write_text('replicated')
            result = instance.execute(request(
                'adopt', revisionDigest=digest))
            self.assertEqual(result['status'], 'completed', result)
            self.assertEqual(
                Path(idir, 'data', 'payload.db').read_text(),
                'replicated')
            result = instance.execute(request('start', op='bb' * 16,
                                              revisionDigest=digest))
            self.assertEqual(result['appliedPhase'], 'running')


if __name__ == '__main__':
    unittest.main()
