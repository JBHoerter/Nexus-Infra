"""Unit tests for console/controller.py (M5 durable controller).

The registry client, subprocess runner and worker handle are all
injected doubles — no TLS, systemd or filesystem beyond the private
state directory is touched. Registry-state fixtures model only the
documented /v2/state projection.
"""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

CONSOLE = Path(__file__).resolve().parent
sys.path.insert(0, str(CONSOLE))

import controller
import statefiles
import test_registry
import worker


I1, I2 = '0a' * 16, '3d' * 16
OP1, OP2 = '1a' * 16, '2b' * 16
DIGEST = test_registry.DIGEST
SNAPSHOT = 'f0' * 32
_PHASE_BY_ACTION = {'freeze': 'stopped', 'thaw': 'stopped',
                    'retire': 'stopped', 'stop': 'stopped',
                    'prepare': 'prepared', 'start': 'running'}


def write_private_file(path, data, mode=0o600):
    with open(path, 'wb') as handle:
        handle.write(data)
    os.chmod(path, mode)
    return path


def worker_config(root):
    return {
        'schemaVersion': 1, 'hostId': 'host-a',
        'architecture': 'x86_64-linux',
        'stateDir': os.path.join(root, 'worker-state'),
        'storage': {'root': os.path.join(root, 'storage'),
                    'mountPoint': os.path.join(root, 'storage'),
                    'uuid': '1111-2222-3333'},
        'capacity': {'memoryMiB': 256, 'cpuMillis': 100,
                     'stateBytes': 1048576},
        'capabilities': [],
        'approvedBundles': ['/nix/store/' + 'a' * 32 + '-bundle'],
        'slots': [{'id': 's0', 'uidBase': 65536,
                   'hostAddress': '192.168.130.1',
                   'localAddress': '192.168.140.2'},
                  {'id': 's1', 'uidBase': 131072,
                   'hostAddress': '192.168.130.2',
                   'localAddress': '192.168.140.3'}],
    }


def observation(instance=I1, host='host-a', phase='running',
                unit='active', drained=False, retired=False,
                ready=('web',), observed_at=1000, generation=1):
    return {'schemaVersion': 2, 'hostId': host,
            'sessionId': 'aa' * 16, 'sequence': 7,
            'instanceId': instance, 'workloadId': 'canary',
            'revisionDigest': DIGEST, 'generation': generation,
            'observedAt': observed_at, 'phase': phase,
            'unitActiveState': unit, 'unitDrained': drained,
            'retired': retired,
            'endpointAddress': '192.168.140.2',
            'readyServices': list(ready),
            'receivedAt': observed_at}


def workload_row(instance=I1, host='host-a', generation=1,
                 published=True, observed_state='running', obs=None,
                 workload_id='canary'):
    if obs is None and observed_state not in ('unknown',):
        obs = observation(instance, host, generation=generation)
    return {'workloadId': workload_id, 'generation': generation,
            'instanceId': instance, 'hostId': host,
            'revisionDigest': DIGEST, 'published': published,
            'observedState': observed_state, 'observation': obs}


def state_body(*rows):
    return {'schemaVersion': 2, 'registryEpoch': 'e0' * 16,
            'version': 1, 'workloads': list(rows)}


def plan_request(operation_id=OP1, **overrides):
    request = {'schemaVersion': 1, 'action': 'plan',
               'operationId': operation_id, 'workloadId': 'canary',
               'revisionDigest': DIGEST, 'fromInstanceId': I1,
               'toHostId': 'host-b', 'toSlotId': None,
               'repositoryId': 'repo-a'}
    request.update(overrides)
    return request


def action_request(action, operation_id=OP1):
    return {'schemaVersion': 1, 'action': action,
            'operationId': operation_id}


class FakeRegistryTransport:
    """Scriptable /v2/state + placement endpoint double."""

    def __init__(self, state_fn):
        self.state_fn = state_fn
        self.requests = []
        self.assigned = False
        self.post_failures = {}

    def request(self, method, path, payload=None):
        self.requests.append((method, path,
                              copy.deepcopy(payload)))
        if method == 'GET' and path == '/v2/state':
            return 200, self.state_fn()
        if method == 'POST' and path == '/v2/placements/assign':
            failure = self.post_failures.get('assign')
            if failure is not None:
                return failure
            self.assigned = True
            return 200, {'schemaVersion': 2, 'status': 'completed',
                         'requestId': payload['requestId'],
                         'action': 'assign',
                         'workloadId': payload['workloadId'],
                         'generation':
                             payload['expectedGeneration'] + 1}
        if method == 'POST' and path == '/v2/placements/publish':
            failure = self.post_failures.get('publish')
            if failure is not None:
                return failure
            return 200, {'schemaVersion': 2, 'status': 'completed',
                         'requestId': payload['requestId'],
                         'action': 'publish',
                         'workloadId': payload['workloadId'],
                         'generation': payload['expectedGeneration']}
        raise AssertionError('unexpected request {} {}'.format(
            method, path))


class FakeWorker:
    """Scriptable worker.execute double honouring operation receipts."""

    def __init__(self, observes=None, failures=None):
        self.requests = []
        self.observes = observes or {}
        self.failures = failures or {}
        self.retired = False
        self.closed = False

    def execute(self, request):
        self.requests.append(copy.deepcopy(request))
        action = request['action']
        if action == 'observe':
            record = self.observes.get(request['instanceId'])
            if record is None:
                raise worker.WorkerError('unknown-instance')
            return copy.deepcopy(record)
        if action in self.failures:
            raise worker.WorkerError(self.failures[action])
        if action == 'retire':
            self.retired = True
        receipt = {'schemaVersion': 1,
                   'operationId': request['operationId'],
                   'action': action, 'workloadId': request['workloadId'],
                   'instanceId': request['instanceId'],
                   'generation': request['generation'],
                   'hostId': 'host-a', 'status': 'completed',
                   'appliedPhase': _PHASE_BY_ACTION[action]}
        if 'captureId' in request:
            receipt['captureId'] = request['captureId']
        return receipt

    def close(self):
        self.closed = True


class FakeRunner:
    """Scriptable CliRunner double keyed on (program, action)."""

    def __init__(self, responses=None):
        self.calls = []
        self.responses = responses or {}

    def run(self, argv, input_bytes, *, timeout, max_bytes):
        request = json.loads(input_bytes.decode('utf-8'))
        self.calls.append((list(argv), copy.deepcopy(request)))
        response = self.responses.get((argv[0], request['action']))
        if callable(response):
            response = response(request)
        if response is None:
            raise AssertionError('no scripted response for ' + argv[0])
        if isinstance(response, Exception):
            raise response
        return subprocess.CompletedProcess(
            argv, 0, json.dumps(response).encode('utf-8'), b'')


def backup_capture_response(request):
    return {'schemaVersion': 1, 'status': 'completed',
            'action': 'capture', 'captureId': request['captureId'],
            'record': {'schemaVersion': 1, 'repositoryId': 'repo-a',
                       'repositoryIdentity': 'a' * 64,
                       'snapshotId': SNAPSHOT, 'manifest': {}}}


def backup_upload_response(request):
    return {'schemaVersion': 1, 'status': 'completed',
            'action': 'upload', 'captureId': request['captureId'],
            'repositoryId': request['repositoryId'],
            'record': {'schemaVersion': 1,
                       'repositoryId': request['repositoryId'],
                       'repositoryIdentity': 'a' * 64,
                       'snapshotId': SNAPSHOT, 'manifest': {}},
            'verifiedAt': 1005}


def restore_response(action):
    def respond(request):
        return {'schemaVersion': 1, 'status': 'completed',
                'action': action, 'restoreId': request['restoreId'],
                'record': {'schemaVersion': 1, 'restoreId':
                           request['restoreId']}}
    return respond


class ControllerFixture(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        self.state_dir = os.path.join(self.root, 'controller-state')
        self.worker_config_path = write_private_file(
            os.path.join(self.root, 'worker.json'),
            json.dumps(worker_config(self.root)).encode())
        self.new_instance = controller._derive(OP1, 'instance')
        self.capture_id = controller._derive(OP1, 'capture')
        self.stage = [workload_row()]
        self.transport = FakeRegistryTransport(
            lambda: state_body(*self.stage))
        self.fake_worker = FakeWorker(observes={
            self.new_instance: self._target_observe()})
        self.runner = FakeRunner({
            ('/nix/nexus-backup', 'capture'): backup_capture_response,
            ('/nix/nexus-backup', 'upload'): backup_upload_response,
            ('/nix/nexus-restore', 'stage'): restore_response('stage'),
            ('/nix/nexus-restore', 'commit'): restore_response('commit')})
        self.controllers = []
        self.addCleanup(self._close_all)
        self.addCleanup(mock.patch.stopall)
        real_lstat = os.lstat
        real_fstat = os.fstat
        config_path = self.worker_config_path

        def fake_lstat(path):
            result = real_lstat(path)
            if path == config_path:
                return SimpleNamespace(st_mode=result.st_mode,
                                       st_uid=0, st_gid=result.st_gid,
                                       st_ino=result.st_ino,
                                       st_dev=result.st_dev)
            return result

        def fake_fstat(fd):
            result = real_fstat(fd)
            config_stat = real_lstat(config_path)
            if (result.st_dev, result.st_ino) == (
                    config_stat.st_dev, config_stat.st_ino):
                return SimpleNamespace(st_mode=result.st_mode,
                                       st_uid=0, st_gid=result.st_gid,
                                       st_ino=result.st_ino,
                                       st_dev=result.st_dev)
            return result

        mock.patch.object(controller, '_lstat', fake_lstat).start()
        mock.patch.object(controller, '_fstat', fake_fstat).start()

    def _target_observe(self, slot='s1'):
        return {'schemaVersion': 1, 'action': 'observe',
                'instanceId': self.new_instance, 'hostId': 'host-a',
                'workloadId': 'canary', 'revisionDigest': DIGEST,
                'generation': 2, 'bindingCurrent': True,
                'slotId': slot, 'phase': 'running',
                'unitActiveState': 'active', 'unitDrained': False,
                'retired': False,
                'endpointAddress': '192.168.140.3'}

    def _close_all(self):
        for instance in self.controllers:
            instance.close()

    def config(self, **overrides):
        config = {'schemaVersion': 1, 'hostId': 'host-a',
                  'stateDir': self.state_dir,
                  'workerConfigFile': self.worker_config_path,
                  'registryUrl': 'https://127.0.0.1:9444',
                  'registry': test_registry.make_config(),
                  'backupProgram': '/nix/nexus-backup',
                  'backupConfigFile': '/etc/nexus/backup.json',
                  'restoreProgram': '/nix/nexus-restore',
                  'restoreConfigFile': '/etc/nexus/restore.json',
                  'requestTimeoutSeconds': 10}
        config.update(overrides)
        return config

    def make_controller(self, **kwargs):
        instance = controller.Controller(
            self.config(),
            transport=kwargs.pop('transport', self.transport),
            runner=kwargs.pop('runner', self.runner),
            worker_factory=lambda config: kwargs.pop(
                'fake_worker', self.fake_worker),
            clock=lambda: 1000.0)
        self.controllers.append(instance)
        return instance

    def job_path(self, operation_id=OP1):
        return os.path.join(self.state_dir, 'operations',
                            operation_id + '.json')

    def read_job(self, operation_id=OP1):
        return statefiles.read_json(self.job_path(operation_id),
                                    256 * 1024)

    def expect_blocked(self, response, code, operation_id=OP1):
        self.assertEqual(response['status'], 'blocked',
                         msg=response)
        self.assertEqual(response['error'], code, msg=response)
        self.assertEqual(response['operationId'], operation_id)


class ConfigTests(ControllerFixture):
    def test_config_rejections(self):
        good = self.config()
        for mutate in (
                lambda c: c.update(schemaVersion=2),
                lambda c: c.update(hostId='Bad_Host'),
                lambda c: c.update(registryUrl='http://insecure.test'),
                lambda c: c.update(requestTimeoutSeconds=0),
                lambda c: c.pop('backupProgram'),
                lambda c: c.update(extra=1)):
            mutated = dict(good)
            mutate(mutated)
            with self.assertRaises(controller.ControllerError,
                                   msg=mutated):
                controller.validate_config(mutated)
        mutated = dict(good)
        mutated['hostId'] = 'host-z'
        with self.assertRaises(controller.ControllerError) as ctx:
            controller.validate_config(mutated)
        self.assertEqual(ctx.exception.code, 'invalid-config-hostId')

    def test_worker_config_host_mismatch(self):
        bad = dict(worker_config(self.root), hostId='host-z')
        path = write_private_file(
            os.path.join(self.root, 'bad-worker.json'),
            json.dumps(bad).encode())
        controller._lstat  # patched in setUp only for original path
        with self.assertRaises(controller.ControllerError):
            controller._load_worker_config(path)


class PlanTests(ControllerFixture):
    def test_plan_persists_and_replays(self):
        instance = self.make_controller()
        first = instance.execute(plan_request())
        self.assertEqual(first['status'], 'completed')
        operation = first['operation']
        self.assertEqual(operation['phase'], 'planned')
        self.assertEqual(operation['fromHostId'], 'host-a')
        self.assertEqual(operation['toHostId'], 'host-b')
        self.assertEqual(operation['generation'], 1)
        self.assertEqual(operation['newGeneration'], 2)
        self.assertEqual(operation['newInstanceId'], self.new_instance)
        self.assertEqual(operation['captureId'], self.capture_id)
        self.assertEqual(operation['snapshotId'], None)
        steps = {entry['step']: entry['disposition']
                 for entry in operation['plan']['steps']}
        self.assertEqual(list(steps), list(controller._STEP_ORDER))
        self.assertEqual(steps['install-target'], 'remote')
        self.assertEqual(steps['freeze'], 'local')
        self.assertTrue(os.path.isfile(self.job_path()))
        replay = instance.execute(plan_request())
        self.assertEqual(replay, first)

    def test_plan_rejections(self):
        instance = self.make_controller()
        self.expect_blocked(
            instance.execute(plan_request(workloadId='ghost')),
            'unknown-workload')
        self.stage[0] = {'workloadId': 'canary', 'generation': 0,
                         'instanceId': None, 'hostId': None,
                         'revisionDigest': None, 'published': False,
                         'observedState': 'unknown',
                         'observation': None}
        self.expect_blocked(instance.execute(plan_request(OP2)),
                            'workload-not-placed', OP2)
        self.stage[0] = workload_row()
        self.expect_blocked(
            instance.execute(plan_request(OP2, fromInstanceId=I2)),
            'instance-mismatch', OP2)
        self.stage[0] = workload_row(observed_state='stale')
        self.expect_blocked(instance.execute(plan_request(OP2)),
                            'evidence-stale', OP2)
        self.stage[0] = workload_row()
        self.expect_blocked(
            instance.execute(plan_request(OP2, toHostId='ghost')),
            'unknown-host', OP2)
        self.expect_blocked(
            instance.execute(plan_request(OP2, toHostId='host-a',
                                          toSlotId='zz')),
            'unknown-slot', OP2)

    def test_plan_operation_conflict(self):
        instance = self.make_controller()
        instance.execute(plan_request())
        self.expect_blocked(
            instance.execute(plan_request(toHostId='host-a')),
            'operation-conflict')

    def test_request_validation(self):
        instance = self.make_controller()
        for request in ({}, {'schemaVersion': 1, 'action': 'plan'},
                        plan_request(operationId='zz'),
                        plan_request(extra=1),
                        {'schemaVersion': 1, 'action': 'erase',
                         'operationId': OP1},
                        'not-a-dict', ['list']):
            response = instance.execute(request)
            self.assertEqual(response['status'], 'blocked',
                             msg=request)


class ExecuteLocalTests(ControllerFixture):
    """Same-host move: every step local, end-to-end happy path."""

    def make_controller(self, **kwargs):
        return super().make_controller(**kwargs)

    def _drive(self):
        """State machine: running -> retired+drained -> successor."""
        def state_fn():
            if self.transport.assigned:
                return state_body(workload_row(
                    self.new_instance, 'host-a', 2, published=False,
                    observed_state='running',
                    obs=observation(self.new_instance, 'host-a',
                                    generation=2)))
            if self.fake_worker.retired:
                return state_body(workload_row(
                    I1, 'host-a', 1, published=True,
                    observed_state='retired',
                    obs=observation(I1, 'host-a', phase='stopped',
                                    unit='inactive', drained=True,
                                    retired=True, ready=())))
            return state_body(workload_row())
        self.transport.state_fn = state_fn

    def test_full_local_move(self):
        instance = self.make_controller()
        self.assertEqual(instance.execute(plan_request(
            toHostId='host-a'))['status'], 'completed')
        self._drive()
        response = instance.execute(action_request('execute'))
        self.assertEqual(response['status'], 'completed', msg=response)
        operation = response['operation']
        self.assertEqual(operation['phase'], 'completed')
        self.assertIsNotNone(operation['completedAt'])
        self.assertEqual(operation['snapshotId'], SNAPSHOT)
        self.assertEqual(operation['toSlotId'], 's1')
        checkpoints = operation['checkpoints']
        self.assertEqual([entry['step'] for entry in checkpoints],
                         list(controller._STEP_ORDER))
        self.assertTrue(all(entry['state'] == 'completed'
                            for entry in checkpoints))
        # CaptureId bound across worker freeze/thaw and both CLIs.
        freeze = next(r for r in self.fake_worker.requests
                      if r['action'] == 'freeze')
        self.assertEqual(freeze['captureId'], self.capture_id)
        capture_call = next(r for _a, r in self.runner.calls
                            if r['action'] == 'capture')
        self.assertEqual(capture_call['captureId'], self.capture_id)
        upload_call = next(r for _a, r in self.runner.calls
                           if r['action'] == 'upload')
        self.assertEqual(upload_call['repositoryId'], 'repo-a')
        # Worker order: freeze, thaw, retire, prepare, observe, start.
        actions = [r['action'] for r in self.fake_worker.requests]
        self.assertEqual(actions,
                         ['freeze', 'thaw', 'retire', 'prepare',
                          'observe', 'start'])
        # Registry order: assign(gen2) then publish(gen2).
        posts = [(p, r) for _m, p, r in self.transport.requests
                 if p.startswith('/v2/placements')]
        self.assertEqual([p for p, _r in posts],
                         ['/v2/placements/assign',
                          '/v2/placements/publish'])
        self.assertEqual(posts[0][1]['expectedGeneration'], 1)
        self.assertEqual(posts[0][1]['instanceId'], self.new_instance)
        self.assertEqual(posts[1][1]['expectedGeneration'], 2)
        # Retention marker, never a delete.
        marker = os.path.join(self.state_dir, 'retained',
                              OP1 + '.json')
        self.assertTrue(os.path.isfile(marker))
        saved = statefiles.read_json(marker, 4096)
        self.assertEqual(saved['marker'], 'retain-source-state')
        # Replay-identical execute and status.
        replay = instance.execute(action_request('execute'))
        self.assertEqual(replay, response)
        status = instance.execute(action_request('status'))
        self.assertEqual(status['operation'], operation)
        self.assertFalse(os.path.exists(
            os.path.join(self.state_dir, 'retained',
                         OP1 + '.json.tmp')))

    def test_deferred_retire_evidence(self):
        instance = self.make_controller()
        instance.execute(plan_request(toHostId='host-a'))
        # Never provide retired evidence: retire-source defers.
        self.transport.state_fn = lambda: state_body(workload_row())
        response = instance.execute(action_request('execute'))
        self.assertEqual(response['status'], 'deferred')
        entry = next(e for e in response['operation']['checkpoints']
                     if e['step'] == 'retire-source')
        self.assertEqual(entry['state'], 'deferred')
        self.assertEqual(entry['detail'],
                         {'awaiting': 'retired-drained-evidence'})
        # Retry still defers; the worker retire is not re-issued.
        again = instance.execute(action_request('execute'))
        self.assertEqual(again['status'], 'deferred')
        self.assertEqual(len([r for r in self.fake_worker.requests
                              if r['action'] == 'retire']), 1)
        # Once fresh retired+drained evidence appears, resume.
        self._drive()
        final = instance.execute(action_request('execute'))
        self.assertEqual(final['status'], 'completed', msg=final)

    def test_execute_evidence_stale_at_validate(self):
        instance = self.make_controller()
        instance.execute(plan_request(toHostId='host-a'))
        self.stage[0] = workload_row(observed_state='stale')
        self.expect_blocked(instance.execute(action_request('execute')),
                            'evidence-stale')
        job = self.read_job()
        self.assertEqual(job['phase'], 'validate')

    def test_source_not_local(self):
        self.stage[0] = workload_row(I1, 'host-b', 1)
        instance = self.make_controller()
        plan = instance.execute(plan_request(toHostId='host-a'))
        self.assertEqual(plan['status'], 'completed')
        self.expect_blocked(instance.execute(action_request('execute')),
                            'source-not-local')

    def test_worker_failure_is_typed(self):
        self.fake_worker.failures['freeze'] = 'phase-conflict'
        instance = self.make_controller()
        instance.execute(plan_request(toHostId='host-a'))
        self.expect_blocked(instance.execute(action_request('execute')),
                            'worker-phase-conflict')

    def test_backup_cli_failure_is_typed(self):
        self.runner.responses[('/nix/nexus-backup', 'capture')] = {
            'schemaVersion': 1, 'status': 'blocked',
            'error': 'capture-missing'}
        instance = self.make_controller()
        instance.execute(plan_request(toHostId='host-a'))
        self.expect_blocked(instance.execute(action_request('execute')),
                            'backup-capture-missing')

    def test_assign_generation_conflict(self):
        instance = self.make_controller()
        instance.execute(plan_request(toHostId='host-a'))
        self._drive()
        self.transport.post_failures['assign'] = (
            409, {'schemaVersion': 2, 'status': 'error',
                  'error': 'generation-conflict'})
        self.expect_blocked(instance.execute(action_request('execute')),
                            'registry-generation-conflict')
        # Journal stopped at assign; checkpoints up to retire completed.
        job = self.read_job()
        self.assertEqual(job['phase'], 'assign')
        done = [e['step'] for e in job['checkpoints']]
        self.assertEqual(done, ['validate', 'freeze', 'capture',
                                'thaw', 'retire-source'])


class RemoteTargetTests(ControllerFixture):
    """Cross-host move: install-target is remote-deferred evidence."""

    def _state(self):
        def state_fn():
            stage = self.remote_stage
            if stage == 'assigned-prepared':
                rows = [workload_row(
                    self.new_instance, 'host-b', 2,
                    published=False, observed_state='prepared',
                    obs=observation(self.new_instance, 'host-b',
                                    phase='prepared', unit='inactive',
                                    drained=True, ready=(),
                                    generation=2))]
            elif stage == 'running':
                rows = [workload_row(
                    self.new_instance, 'host-b', 2,
                    published=False, observed_state='running',
                    obs=observation(self.new_instance, 'host-b',
                                    generation=2))]
            else:
                rows = []
            if not self.transport.assigned:
                rows.append(workload_row(
                    I1, 'host-a', 1, observed_state='retired'
                    if self.fake_worker.retired else 'running',
                    obs=observation(
                        I1, 'host-a', phase='stopped' if
                        self.fake_worker.retired else 'running',
                        unit='inactive' if self.fake_worker.retired
                        else 'active',
                        drained=self.fake_worker.retired,
                        retired=self.fake_worker.retired,
                        ready=() if self.fake_worker.retired
                        else ('web',))))
            # host-b liveness proof for validate.
            rows.append(workload_row(
                I2, 'host-b', 3, workload_id='other',
                obs={'schemaVersion': 2, 'hostId': 'host-b',
                     'sessionId': 'bb' * 16, 'sequence': 3,
                     'instanceId': I2, 'workloadId': 'other',
                     'revisionDigest': DIGEST, 'generation': 3,
                     'observedAt': 1000, 'phase': 'running',
                     'unitActiveState': 'active', 'unitDrained': False,
                     'retired': False,
                     'endpointAddress': '192.168.141.2',
                     'readyServices': [], 'receivedAt': 1000}))
            return state_body(*rows)
        return state_fn

    def setUp(self):
        super().setUp()
        self.remote_stage = 'initial'
        self.transport.state_fn = self._state()

    def test_remote_install_deferred_then_verified(self):
        instance = self.make_controller()
        self.assertEqual(instance.execute(plan_request())['status'],
                         'completed')
        response = instance.execute(action_request('execute'))
        self.assertEqual(response['status'], 'deferred', msg=response)
        entry = next(e for e in response['operation']['checkpoints']
                     if e['step'] == 'install-target')
        self.assertEqual(entry['state'], 'deferred')
        instruction = entry['detail']['instruction']
        self.assertEqual(entry['detail']['disposition'],
                         'remote-deferred')
        self.assertEqual(instruction['prepare']['action'], 'prepare')
        self.assertEqual(instruction['prepare']['instanceId'],
                         self.new_instance)
        self.assertEqual(instruction['restoreStage']['snapshotId'],
                         SNAPSHOT)
        self.assertEqual(instruction['restoreCommit']['restoreId'],
                         controller._derive(OP1, 'restore'))
        self.assertEqual(instruction['start']['generation'], 2)
        # Remote operator completes; fresh registry evidence resumes.
        self.remote_stage = 'assigned-prepared'
        response = instance.execute(action_request('execute'))
        self.assertEqual(response['status'], 'deferred')
        self.assertEqual(response['operation']['phase'], 'await-ready')
        self.remote_stage = 'running'
        final = instance.execute(action_request('execute'))
        self.assertEqual(final['status'], 'completed', msg=final)
        steps = [e['step'] for e in
                 final['operation']['checkpoints']]
        self.assertEqual(steps, list(controller._STEP_ORDER))

    def test_validate_requires_target_session_evidence(self):
        # Remove host-b liveness: no fresh observation on target host.
        self.stage[0] = workload_row()
        self.transport.state_fn = lambda: state_body(workload_row())
        instance = self.make_controller()
        instance.execute(plan_request())
        self.expect_blocked(instance.execute(action_request('execute')),
                            'target-session-unproven')


class AbortTests(ControllerFixture):
    def test_abort_before_publish(self):
        instance = self.make_controller()
        instance.execute(plan_request())
        response = instance.execute(action_request('abort'))
        self.assertEqual(response['status'], 'completed')
        self.assertEqual(response['operation']['phase'], 'aborted')
        self.assertEqual(instance.execute(action_request('abort')),
                         response)  # replay-identical
        self.expect_blocked(instance.execute(action_request('execute')),
                            'operation-aborted')

    def test_abort_during_deferred_execute(self):
        self.remote_stage = 'initial'
        self.transport.state_fn = RemoteTargetTests._state(self)
        instance = self.make_controller()
        instance.execute(plan_request())
        response = instance.execute(action_request('execute'))
        self.assertEqual(response['status'], 'deferred')
        abort = instance.execute(action_request('abort'))
        self.assertEqual(abort['status'], 'completed')
        self.assertEqual(abort['operation']['phase'], 'aborted')

    def test_abort_after_publish_forbidden(self):
        instance = self.make_controller()
        instance.execute(plan_request(toHostId='host-a'))
        # Drive the whole local pipeline to completion.
        ExecuteLocalTests._drive(self)
        final = instance.execute(action_request('execute'))
        self.assertEqual(final['status'], 'completed')
        self.expect_blocked(instance.execute(action_request('abort')),
                            'abort-forbidden')
        # Also forbidden mid-tail: publish done, retain pending.
        job = self.read_job()
        job['phase'] = 'retain'
        job['checkpoints'] = [
            {'step': 'publish', 'state': 'completed', 'at': 1,
             'detail': {'generation': 2}}]
        statefiles.write_json(self.job_path(), job)
        self.expect_blocked(instance.execute(action_request('abort')),
                            'abort-forbidden')


class JournalTests(ControllerFixture):
    def test_journal_rejects_corruption(self):
        instance = self.make_controller()
        instance.execute(plan_request())
        job = self.read_job()
        job['phase'] = 'teleport'
        statefiles.write_json(self.job_path(), job)
        self.expect_blocked(instance.execute(action_request('status')),
                            'journal-invalid')

    def test_config_change_blocks_replay(self):
        instance = self.make_controller()
        instance.execute(plan_request())
        other = controller.Controller(
            self.config(requestTimeoutSeconds=11),
            transport=self.transport, runner=self.runner,
            worker_factory=lambda c: self.fake_worker,
            clock=lambda: 1000.0)
        self.controllers.append(other)
        self.expect_blocked(other.execute(action_request('status')),
                            'controller-config-changed')

    def test_operation_missing(self):
        instance = self.make_controller()
        self.expect_blocked(instance.execute(action_request('status')),
                            'operation-missing')

    def test_controller_busy(self):
        first = self.make_controller()
        second = self.make_controller()
        first._acquire_lock()
        try:
            self.expect_blocked(second.execute(plan_request()),
                                'controller-busy')
        finally:
            first._release_lock()

    def test_no_fencing_claim(self):
        """A dead source can never complete: stale evidence blocks
        both plan-time validation and the execute retire path — the
        controller never proceeds without current-session proof."""
        instance = self.make_controller()
        self.stage[0] = workload_row(observed_state='lost')
        self.expect_blocked(instance.execute(plan_request()),
                            'evidence-stale')


if __name__ == '__main__':
    unittest.main()
