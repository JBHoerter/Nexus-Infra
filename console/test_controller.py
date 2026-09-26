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
from test_worker import sealed_fixture
import worker


I1, I2, I3 = '0a' * 16, '3d' * 16, '7e' * 16
OP1, OP2 = '1a' * 16, '2b' * 16
DIGEST = test_registry.DIGEST
SNAPSHOT = 'f0' * 32
_PHASE_BY_ACTION = {'freeze': 'stopped', 'thaw': 'stopped',
                    'retire': 'stopped', 'stop': 'stopped',
                    'prepare': 'prepared', 'adopt': 'prepared',
                    'start': 'running'}


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
                ready=('web',), observed_at=1000, generation=1,
                workload_id='canary', digest=DIGEST):
    return {'schemaVersion': 2, 'hostId': host,
            'sessionId': 'aa' * 16, 'sequence': 7,
            'instanceId': instance, 'workloadId': workload_id,
            'revisionDigest': digest, 'generation': generation,
            'observedAt': observed_at, 'phase': phase,
            'unitActiveState': unit, 'unitDrained': drained,
            'retired': retired,
            'endpointAddress': '192.168.140.2',
            'readyServices': list(ready),
            'receivedAt': observed_at}


def workload_row(instance=I1, host='host-a', generation=1,
                 published=True, observed_state='running', obs=None,
                 workload_id='canary', digest=DIGEST):
    if obs is None and observed_state not in ('unknown',):
        obs = observation(instance, host, generation=generation,
                          workload_id=workload_id, digest=digest)
    return {'workloadId': workload_id, 'generation': generation,
            'instanceId': instance, 'hostId': host,
            'revisionDigest': digest, 'published': published,
            'observedState': observed_state, 'observation': obs}


def state_body(*rows, fences=()):
    return {'schemaVersion': 2, 'registryEpoch': 'e0' * 16,
            'version': 1, 'workloads': list(rows),
            'fences': list(fences)}


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


def failover_request(operation_id=OP1, **overrides):
    request = {'schemaVersion': 1, 'action': 'failover',
               'operationId': operation_id, 'workloadId': 'canary',
               'fenceRequestId': 'f5' * 16, 'toHostId': 'host-b',
               'toSlotId': None, 'evidence': 'quorum-attested'}
    request.update(overrides)
    return request


class FakeRegistryTransport:
    """Scriptable /v2/state + placement + operation-queue double.

    ``operations`` models the registry's durable queue: POST accepts
    (idempotent on requestId), GET returns the view. ``receipt_fn``,
    when set, is invoked at POST time to simulate the remote reporter's
    receipt; ``complete_on_read`` additionally completes rows lazily on
    GET so a test can let an op complete between execute calls.
    """

    def __init__(self, state_fn):
        self.state_fn = state_fn
        self.requests = []
        self.assigned = False
        self.post_failures = {}
        self.operations = {}
        self.fences = {}
        self.fence_receipts = {}
        self.receipt_fn = None
        self.complete_on_read = False

    def fence_rows(self):
        return [copy.deepcopy(row) for row in self.fences.values()]

    def completed_steps(self):
        return {row['step'] for row in self.operations.values()
                if row['status'] == 'completed'}

    def operation_rows(self, step):
        return [row for row in self.operations.values()
                if row['step'] == step]

    def fail_step(self, step, error_code):
        for row in self.operation_rows(step):
            if row['status'] in ('pending', 'claimed'):
                row['status'] = 'failed'
                row['errorCode'] = error_code

    def request(self, method, path, payload=None):
        self.requests.append((method, path,
                              copy.deepcopy(payload)))
        if method == 'GET' and path == '/v2/state':
            return 200, self.state_fn()
        if method == 'POST' and path == '/v2/operations':
            failure = self.post_failures.get('operations')
            if failure is not None:
                return failure
            operation_id = payload['operationId']
            row = self.operations.get(operation_id)
            if row is None:
                row = {'operationId': operation_id,
                       'requestId': payload['requestId'],
                       'workloadId': payload['workloadId'],
                       'hostId': payload['hostId'],
                       'generation': payload['generation'],
                       'step': payload['step'],
                       'payload': copy.deepcopy(payload['payload']),
                       'status': 'pending',
                       'result': None, 'errorCode': None}
                self.operations[operation_id] = row
                if self.receipt_fn is not None:
                    self.receipt_fn(row)
            return 200, {'schemaVersion': 2, 'status': 'accepted',
                         'operationId': operation_id,
                         'requestId': payload['requestId']}
        if method == 'GET' and path.startswith('/v2/operations/'):
            suffix = path[len('/v2/operations/'):]
            operation_id, _, query = suffix.partition('?')
            request_id = query.partition('requestId=')[2]
            row = self.operations.get(operation_id)
            if row is None or row['requestId'] != request_id:
                return 404, {'schemaVersion': 2, 'status': 'error',
                             'error': 'operation-missing'}
            if self.complete_on_read and row['status'] == 'pending' \
                    and self.receipt_fn is not None:
                self.receipt_fn(row)
            body = {'schemaVersion': 2,
                    'operationId': row['operationId'],
                    'requestId': row['requestId'],
                    'workloadId': row['workloadId'],
                    'hostId': row['hostId'],
                    'generation': row['generation'],
                    'step': row['step'], 'status': row['status']}
            if row['status'] == 'completed':
                body['result'] = copy.deepcopy(row['result'])
            if row['status'] == 'failed':
                body['errorCode'] = row['errorCode']
            return 200, body
        if method == 'POST' and path == '/v2/placements/fence':
            failure = self.post_failures.get('fence')
            if failure is not None:
                return failure
            replay = self.fence_receipts.get(payload['requestId'])
            if replay is not None:
                return 200, copy.deepcopy(replay)
            key = (payload['workloadId'], payload['generation'])
            row = self.fences.get(key)
            if row is not None \
                    and (row['hostId'], row['evidence']) \
                    != (payload['hostId'], payload['evidence']):
                return 409, {'schemaVersion': 2, 'status': 'error',
                             'error': 'fence-conflict'}
            if row is None:
                self.fences[key] = {
                    'workloadId': payload['workloadId'],
                    'generation': payload['generation'],
                    'hostId': payload['hostId'],
                    'evidence': payload['evidence'],
                    'attestedBy': 'urn:controller',
                    'requestId': payload['requestId'],
                    'recordedAt': 1000}
            receipt = {'schemaVersion': 2, 'status': 'accepted',
                       'requestId': payload['requestId'],
                       'workloadId': payload['workloadId'],
                       'generation': payload['generation'],
                       'hostId': payload['hostId'],
                       'evidence': payload['evidence']}
            self.fence_receipts[payload['requestId']] = \
                copy.deepcopy(receipt)
            return 200, receipt
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


def dispatch_receipt(slot='s9'):
    """A ``receipt_fn`` completing every queued op the way the remote
    reporter's receipts look after real local execution."""
    def complete(row):
        step = row['step']
        payload = row['payload']
        if step in ('freeze', 'thaw'):
            result = {'appliedPhase': 'stopped',
                      'captureId': payload['captureId']}
        elif step in ('stop', 'retire'):
            result = {'appliedPhase': 'stopped'}
        elif step in ('prepare', 'adopt'):
            result = {'appliedPhase': 'prepared'}
        elif step == 'start':
            result = {'appliedPhase': 'running'}
        elif step == 'observe':
            result = {'bindingCurrent': True, 'slotId': slot,
                      'phase': 'prepared', 'unitActiveState': 'inactive',
                      'retired': False}
        elif step == 'capture':
            result = {'snapshotId': SNAPSHOT,
                      'repositoryId':
                          payload['upload']['repositoryId'],
                      'verifiedAt': 1005}
        else:  # restore-stage / restore-commit
            result = {'status': 'completed',
                      'restoreId': payload['restoreId'],
                      'action': payload['action']}
        row['status'] = 'completed'
        row['result'] = result
    return complete


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
            clock=lambda: 1000.0,
            sleeper=kwargs.pop('sleeper', lambda seconds: None))
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

    def test_source_remote_no_longer_rejected(self):
        # The old 'source-not-local' gate is gone: a remote source is
        # dispatched through the operation queue instead.
        self.stage[0] = workload_row(I1, 'host-b', 1)
        instance = self.make_controller()
        plan = instance.execute(plan_request(toHostId='host-a'))
        self.assertEqual(plan['status'], 'completed')
        steps = {entry['step']: entry['disposition']
                 for entry in plan['operation']['plan']['steps']}
        self.assertEqual(steps['freeze'], 'remote')
        self.assertEqual(steps['capture'], 'remote')
        self.assertEqual(steps['thaw'], 'remote')
        self.assertEqual(steps['retire-source'], 'remote')
        self.assertEqual(steps['install-target'], 'local')

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

    def test_remote_install_deferred_then_completed(self):
        """Remote install defers while ops are pending; once the host
        reporter posts receipts, execute resumes and finishes."""
        instance = self.make_controller()
        self.assertEqual(instance.execute(plan_request())['status'],
                         'completed')
        response = instance.execute(action_request('execute'))
        self.assertEqual(response['status'], 'deferred', msg=response)
        entry = next(e for e in response['operation']['checkpoints']
                     if e['step'] == 'install-target')
        self.assertEqual(entry['state'], 'deferred')
        detail = entry['detail']
        self.assertEqual(detail['disposition'], 'remote-dispatched')
        self.assertEqual(detail['step'], 'prepare')
        self.assertEqual(detail['hostId'], 'host-b')
        self.assertEqual(detail['operationStatus'], 'pending')
        self.assertEqual(detail['operationId'],
                         controller._derive(OP1, 'prepare'))
        self.assertEqual(detail['requestId'],
                         controller._derive(OP1, 'post:prepare'))
        self.assertEqual(detail['instruction']['action'], 'prepare')
        self.assertEqual(detail['instruction']['instanceId'],
                         self.new_instance)
        # Re-execute replays the identical POST (same requestId and
        # operationId — the queue stays at one prepare row).
        again = instance.execute(action_request('execute'))
        self.assertEqual(again['status'], 'deferred')
        self.assertEqual(len(self.transport.operation_rows('prepare')),
                         1)
        # Host reporter completes queued ops; the move proceeds.
        self.transport.receipt_fn = dispatch_receipt(slot='s9')
        self.transport.complete_on_read = True
        self.remote_stage = 'running'
        final = instance.execute(action_request('execute'))
        self.assertEqual(final['status'], 'completed', msg=final)
        operation = final['operation']
        self.assertEqual(operation['toSlotId'], 's9')
        install = next(e for e in operation['checkpoints']
                       if e['step'] == 'install-target')
        self.assertEqual(install['state'], 'completed')
        self.assertEqual(install['detail'],
                         {'disposition': 'remote', 'slotId': 's9'})
        steps = [e['step'] for e in operation['checkpoints']]
        self.assertEqual(steps, list(controller._STEP_ORDER))
        # All five install ops were posted to host-b at generation 2.
        posted = {(row['step'], row['hostId'], row['generation'])
                  for row in self.transport.operations.values()}
        for step in ('prepare', 'observe', 'restore-stage',
                     'restore-commit', 'start'):
            self.assertIn((step, 'host-b', 2), posted)
        # The dispatched restore stage carried the allocated slot.
        stage = self.transport.operation_rows('restore-stage')[0]
        self.assertEqual(stage['payload']['target']['slotId'], 's9')
        self.assertEqual(stage['payload']['snapshotId'], SNAPSHOT)
        commit = self.transport.operation_rows('restore-commit')[0]
        self.assertEqual(commit['payload']['restoreId'],
                         controller._derive(OP1, 'restore'))

    def test_remote_install_poll_is_bounded(self):
        """A pending op is polled exactly _DISPATCH_POLLS times before
        the step journals 'deferred'; the sleeper bounds the wait."""
        slept = []
        instance = self.make_controller(
            sleeper=lambda seconds: slept.append(seconds))
        instance.execute(plan_request())
        response = instance.execute(action_request('execute'))
        self.assertEqual(response['status'], 'deferred')
        gets = [path for _m, path, _p in self.transport.requests
                if path.startswith('/v2/operations/')
                and 'requestId=' in path]
        self.assertEqual(len(gets), controller._DISPATCH_POLLS)
        self.assertEqual(len(slept), controller._DISPATCH_POLLS - 1)

    def test_remote_receipt_failed_is_typed(self):
        instance = self.make_controller()
        instance.execute(plan_request())

        def fail_prepare(row):
            if row['step'] == 'prepare':
                row['status'] = 'failed'
                row['errorCode'] = 'worker-unknown-instance'
        self.transport.receipt_fn = fail_prepare
        self.transport.complete_on_read = True
        self.expect_blocked(instance.execute(action_request('execute')),
                            'remote-worker-unknown-instance')
        job = self.read_job()
        self.assertEqual(job['phase'], 'install-target')

    def test_remote_receipt_invalid_result(self):
        instance = self.make_controller()
        instance.execute(plan_request())

        def bad_observe(row):
            if row['step'] == 'observe':
                row['status'] = 'completed'
                row['result'] = {'bindingCurrent': False,
                                 'slotId': 's9'}
            elif row['step'] == 'prepare':
                row['status'] = 'completed'
                row['result'] = {'appliedPhase': 'prepared'}
        self.transport.receipt_fn = bad_observe
        self.transport.complete_on_read = True
        self.expect_blocked(instance.execute(action_request('execute')),
                            'remote-receipt-invalid')

    def test_remote_observe_slot_mismatch(self):
        instance = self.make_controller()
        instance.execute(plan_request(toSlotId='s0'))
        self.transport.receipt_fn = dispatch_receipt(slot='s9')
        self.transport.complete_on_read = True
        self.expect_blocked(instance.execute(action_request('execute')),
                            'slot-mismatch')

    def test_remote_operation_post_failure(self):
        instance = self.make_controller()
        instance.execute(plan_request())
        self.transport.post_failures['operations'] = (
            503, {'schemaVersion': 2, 'status': 'error',
                  'error': 'unavailable'})
        self.expect_blocked(instance.execute(action_request('execute')),
                            'registry-unavailable')

    def test_validate_requires_target_session_evidence(self):
        # Remove host-b liveness: no fresh observation on target host.
        self.stage[0] = workload_row()
        self.transport.state_fn = lambda: state_body(workload_row())
        instance = self.make_controller()
        instance.execute(plan_request())
        self.expect_blocked(instance.execute(action_request('execute')),
                            'target-session-unproven')


class RemoteSourceTests(ControllerFixture):
    """Cross-host move with the SOURCE remote: freeze/capture/thaw/
    retire are dispatched to host-b through the operation queue."""

    def _state(self):
        def state_fn():
            retired = 'retire' in self.transport.completed_steps()
            if self.transport.assigned:
                rows = [workload_row(
                    self.new_instance, 'host-a', 2, published=False,
                    observed_state='running',
                    obs=observation(self.new_instance, 'host-a',
                                    generation=2))]
            else:
                rows = [workload_row(
                    I1, 'host-b', 1,
                    observed_state='retired' if retired else 'running',
                    obs=observation(
                        I1, 'host-b',
                        phase='stopped' if retired else 'running',
                        unit='inactive' if retired else 'active',
                        drained=retired, retired=retired,
                        ready=() if retired else ('web',)))]
            # Local-host liveness proof for validate.
            rows.append(workload_row(
                I2, 'host-a', 4, workload_id='other',
                obs={'schemaVersion': 2, 'hostId': 'host-a',
                     'sessionId': 'cc' * 16, 'sequence': 2,
                     'instanceId': I2, 'workloadId': 'other',
                     'revisionDigest': DIGEST, 'generation': 4,
                     'observedAt': 1000, 'phase': 'running',
                     'unitActiveState': 'active', 'unitDrained': False,
                     'retired': False,
                     'endpointAddress': '192.168.140.9',
                     'readyServices': [], 'receivedAt': 1000}))
            return state_body(*rows)
        return state_fn

    def setUp(self):
        super().setUp()
        self.stage = [workload_row(I1, 'host-b', 1)]
        self.transport.state_fn = self._state()

    def test_remote_source_full_move(self):
        """End-to-end: remote source ops execute via receipts, the
        local install then completes the move."""
        self.transport.receipt_fn = dispatch_receipt()
        self.transport.complete_on_read = True
        instance = self.make_controller()
        plan = instance.execute(plan_request(toHostId='host-a'))
        self.assertEqual(plan['status'], 'completed')
        response = instance.execute(action_request('execute'))
        self.assertEqual(response['status'], 'completed', msg=response)
        operation = response['operation']
        self.assertEqual(operation['phase'], 'completed')
        self.assertEqual(operation['snapshotId'], SNAPSHOT)
        # Source-side ops went to host-b at generation 1 with the
        # derived worker operationIds as both payload and queue id.
        posted = {row['step']: row
                  for row in self.transport.operations.values()}
        for step in ('freeze', 'capture', 'thaw', 'retire'):
            row = posted[step]
            self.assertEqual(row['hostId'], 'host-b')
            self.assertEqual(row['generation'], 1)
            self.assertEqual(row['status'], 'completed')
        self.assertEqual(posted['freeze']['payload']['operationId'],
                         posted['freeze']['operationId'])
        self.assertEqual(posted['freeze']['payload']['captureId'],
                         self.capture_id)
        capture = posted['capture']['payload']
        self.assertEqual(capture['capture']['captureId'],
                         self.capture_id)
        self.assertEqual(capture['capture']['instanceId'], I1)
        self.assertEqual(capture['upload']['repositoryId'], 'repo-a')
        # The retire checkpoint carries the remote disposition.
        retire = next(e for e in operation['checkpoints']
                      if e['step'] == 'retire-source')
        self.assertEqual(retire['state'], 'completed')
        self.assertEqual(retire['detail']['appliedPhase'], 'stopped')
        # Local install ran the local worker for the new instance.
        actions = [r['action'] for r in self.fake_worker.requests]
        self.assertEqual(actions, ['prepare', 'observe', 'start'])
        self.assertEqual(self.fake_worker.requests[0]['instanceId'],
                         self.new_instance)

    def test_remote_source_deferred_until_receipt(self):
        """Pending remote source ops keep execute deferred; receipts
        unblock the next call without re-posting."""
        instance = self.make_controller()
        instance.execute(plan_request(toHostId='host-a'))
        response = instance.execute(action_request('execute'))
        self.assertEqual(response['status'], 'deferred')
        freeze = next(e for e in response['operation']['checkpoints']
                      if e['step'] == 'freeze')
        self.assertEqual(freeze['state'], 'deferred')
        self.assertEqual(freeze['detail']['disposition'],
                         'remote-dispatched')
        self.assertEqual(freeze['detail']['hostId'], 'host-b')
        posts = [p for m, p, _pl in self.transport.requests
                 if m == 'POST' and p == '/v2/operations']
        self.assertEqual(len(posts), 1)
        # Replay while still pending: same op row, no duplicate.
        again = instance.execute(action_request('execute'))
        self.assertEqual(again['status'], 'deferred')
        self.assertEqual(len(posts) + 1,
                         len([p for m, p, _pl in
                              self.transport.requests
                              if m == 'POST'
                              and p == '/v2/operations']))
        self.assertEqual(len(self.transport.operations), 1)
        # Complete everything; the whole move finishes in one call.
        self.transport.receipt_fn = dispatch_receipt()
        self.transport.complete_on_read = True
        final = instance.execute(action_request('execute'))
        self.assertEqual(final['status'], 'completed', msg=final)

    def test_remote_source_receipt_failure(self):
        instance = self.make_controller()
        instance.execute(plan_request(toHostId='host-a'))

        def fail_freeze(row):
            if row['step'] == 'freeze':
                row['status'] = 'failed'
                row['errorCode'] = 'worker-phase-conflict'
        self.transport.receipt_fn = fail_freeze
        self.transport.complete_on_read = True
        self.expect_blocked(instance.execute(action_request('execute')),
                            'remote-worker-phase-conflict')
        job = self.read_job()
        self.assertEqual(job['phase'], 'freeze')

    def test_remote_capture_missing_snapshot(self):
        instance = self.make_controller()
        instance.execute(plan_request(toHostId='host-a'))

        def bad_capture(row):
            if row['step'] == 'freeze':
                row['status'] = 'completed'
                row['result'] = {'appliedPhase': 'stopped',
                                 'captureId':
                                     row['payload']['captureId']}
            elif row['step'] == 'capture':
                row['status'] = 'completed'
                # Missing snapshotId.
                row['result'] = {'repositoryId': 'repo-a'}
        self.transport.receipt_fn = bad_capture
        self.transport.complete_on_read = True
        self.expect_blocked(instance.execute(action_request('execute')),
                            'remote-receipt-invalid')


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


class FailoverTests(ControllerFixture):
    """M8 operator-explicit failover to a remote target:
    refresh -> fence -> assign -> adopt -> ready -> publish.

    The incumbent 'canary' sits stale on dead host-a; a sibling
    workload keeps host-b proven live; the successor appears on host-b
    once the assign commits and the remote adopt/observe/start ops
    complete."""

    def _other_row(self, host='host-b'):
        """Fresh live observation bound to ``host`` — target-session
        evidence, exactly like the move fixture uses."""
        return workload_row(
            I2, host, 3, workload_id='other',
            obs={'schemaVersion': 2, 'hostId': host,
                 'sessionId': 'bb' * 16, 'sequence': 3,
                 'instanceId': I2, 'workloadId': 'other',
                 'revisionDigest': DIGEST, 'generation': 3,
                 'observedAt': 1000, 'phase': 'running',
                 'unitActiveState': 'active', 'unitDrained': False,
                 'retired': False, 'endpointAddress': '192.168.141.2',
                 'readyServices': [], 'receivedAt': 1000})

    def _stale_incumbent(self):
        return workload_row(I1, 'host-a', 1, observed_state='stale')

    def _successor_row(self):
        if self.successor_running:
            return workload_row(
                self.new_instance, 'host-b', 2, published=False,
                observed_state='running',
                obs=observation(self.new_instance, 'host-b',
                                generation=2))
        return workload_row(
            self.new_instance, 'host-b', 2, published=False,
            observed_state='prepared',
            obs=observation(self.new_instance, 'host-b',
                            phase='prepared', unit='inactive',
                            drained=True, ready=(), generation=2))

    def _state(self):
        def state_fn():
            canary = self._successor_row() if self.transport.assigned \
                else self._stale_incumbent()
            return state_body(canary, self._other_row(),
                              fences=self.transport.fence_rows())
        return state_fn

    def setUp(self):
        super().setUp()
        self.successor_running = False
        self.transport.state_fn = self._state()

    def test_failover_remote_happy_path(self):
        self.transport.receipt_fn = dispatch_receipt(slot='s9')
        self.transport.complete_on_read = True
        self.successor_running = True
        instance = self.make_controller()
        response = instance.execute(failover_request())
        self.assertEqual(response['status'], 'completed', msg=response)
        operation = response['operation']
        self.assertEqual(operation['phase'], 'completed')
        self.assertIsNotNone(operation['completedAt'])
        self.assertEqual(operation['generation'], 1)
        self.assertEqual(operation['newGeneration'], 2)
        self.assertEqual(operation['fromHostId'], 'host-a')
        self.assertEqual(operation['fromInstanceId'], I1)
        self.assertEqual(operation['newInstanceId'], self.new_instance)
        self.assertEqual(operation['toSlotId'], 's9')
        self.assertIsNone(operation['captureId'])
        self.assertIsNone(operation['repositoryId'])
        self.assertIsNone(operation['snapshotId'])
        checkpoints = operation['checkpoints']
        self.assertEqual([e['step'] for e in checkpoints],
                         list(controller._FAILOVER_STEP_ORDER))
        self.assertTrue(all(e['state'] == 'completed'
                            for e in checkpoints))
        # Ordering proof: the fence post strictly precedes assign, and
        # the assign strictly precedes the adopt dispatch.
        posts = [(m, p, r) for m, p, r in self.transport.requests
                 if m == 'POST']
        fence_at = [p for _m, p, _r in posts].index(
            '/v2/placements/fence')
        assign_at = [p for _m, p, _r in posts].index(
            '/v2/placements/assign')
        adopt_at = [p for _m, p, _r in posts].index('/v2/operations')
        publish_at = [p for _m, p, _r in posts].index(
            '/v2/placements/publish')
        self.assertLess(fence_at, assign_at)
        self.assertLess(assign_at, adopt_at)
        self.assertLess(adopt_at, publish_at)
        # The fence carries the operator-supplied evidence descriptor
        # verbatim, scoped to the incumbent placement.
        fence_post = posts[fence_at][2]
        self.assertEqual(fence_post, {
            'schemaVersion': 2, 'requestId': 'f5' * 16,
            'workloadId': 'canary', 'generation': 1,
            'hostId': 'host-a', 'evidence': 'quorum-attested'})
        assign_post = posts[assign_at][2]
        self.assertEqual(assign_post['expectedGeneration'], 1)
        self.assertEqual(assign_post['instanceId'], self.new_instance)
        # Adopt/observe/start went to host-b at the successor
        # generation with replay-safe derived ids.
        adopt = self.transport.operation_rows('adopt')[0]
        self.assertEqual((adopt['hostId'], adopt['generation']),
                         ('host-b', 2))
        self.assertEqual(adopt['operationId'],
                         controller._derive(OP1, 'adopt'))
        self.assertEqual(adopt['requestId'],
                         controller._derive(OP1, 'post:adopt'))
        self.assertEqual(adopt['payload']['action'], 'adopt')
        self.assertEqual(adopt['payload']['instanceId'],
                         self.new_instance)
        self.assertEqual(adopt['payload']['generation'], 2)
        for step in ('adopt', 'observe', 'start'):
            self.assertIn(
                (step, 'host-b', 2),
                {(row['step'], row['hostId'], row['generation'])
                 for row in self.transport.operations.values()})
        # The fence checkpoint records the committed record's identity.
        fence_cp = next(e for e in checkpoints if e['step'] == 'fence')
        self.assertEqual(fence_cp['detail']['requestId'], 'f5' * 16)
        self.assertEqual(fence_cp['detail']['hostId'], 'host-a')
        adopt_cp = next(e for e in checkpoints if e['step'] == 'adopt')
        self.assertEqual(adopt_cp['detail'],
                         {'disposition': 'remote', 'slotId': 's9'})
        # Replay-identical on re-run; a plain execute resumes the same
        # journal to the identical completed view.
        replay = instance.execute(failover_request())
        self.assertEqual(replay, response)
        resumed = instance.execute(action_request('execute'))
        self.assertEqual(resumed['operation'], operation)
        self.assertEqual(resumed['action'], 'execute')

    def test_failover_validation(self):
        instance = self.make_controller()
        for request in (
                {}, {'schemaVersion': 1, 'action': 'failover'},
                failover_request(operationId='zz'),
                failover_request(fenceRequestId='zz'),
                failover_request(toHostId='Bad_Host'),
                failover_request(toSlotId='Bad_Slot'),
                failover_request(extra=1),
                failover_request(evidence=None)):
            response = instance.execute(request)
            self.assertEqual(response['status'], 'blocked',
                             msg=request)
        self.expect_blocked(
            instance.execute(failover_request(evidence='invented')),
            'invalid-evidence')
        self.assertFalse(os.path.exists(self.job_path()))

    def test_failover_requires_active_placement(self):
        self.transport.state_fn = lambda: state_body(
            {'workloadId': 'canary', 'generation': 0,
             'instanceId': None, 'hostId': None,
             'revisionDigest': None, 'published': False,
             'observedState': 'unknown', 'observation': None},
            self._other_row())
        instance = self.make_controller()
        self.expect_blocked(instance.execute(failover_request()),
                            'workload-not-placed')
        self.assertFalse(os.path.exists(self.job_path()))

    def test_failover_incumbent_is_target(self):
        instance = self.make_controller()
        self.expect_blocked(
            instance.execute(failover_request(toHostId='host-a')),
            'incumbent-is-target')
        self.assertFalse(os.path.exists(self.job_path()))

    def test_failover_unknown_target(self):
        instance = self.make_controller()
        self.expect_blocked(
            instance.execute(failover_request(toHostId='ghost')),
            'unknown-host')

    def test_failover_refuses_live_incumbent(self):
        # A freshly-reporting incumbent is not host-loss: refuse, no
        # journal, no fence.
        self.transport.state_fn = lambda: state_body(
            workload_row(), self._other_row())
        instance = self.make_controller()
        self.expect_blocked(instance.execute(failover_request()),
                            'incumbent-live')
        self.assertFalse(os.path.exists(self.job_path()))
        self.assertFalse(any(
            p == '/v2/placements/fence'
            for _m, p, _r in self.transport.requests))

    def test_failover_operator_evidence_overrides_live_incumbent(self):
        # 'operator' evidence is the explicit human override for a
        # reporting-but-untrusted incumbent — journaled and posted as
        # the fence basis.
        def state_fn():
            canary = self._successor_row() if self.transport.assigned \
                else workload_row()
            return state_body(canary, self._other_row(),
                              fences=self.transport.fence_rows())
        self.transport.state_fn = state_fn
        self.transport.receipt_fn = dispatch_receipt()
        self.transport.complete_on_read = True
        self.successor_running = True
        instance = self.make_controller()
        response = instance.execute(
            failover_request(evidence='operator'))
        self.assertEqual(response['status'], 'completed', msg=response)
        fence_post = next(r for m, p, r in self.transport.requests
                          if p == '/v2/placements/fence')
        self.assertEqual(fence_post['evidence'], 'operator')

    def test_failover_requires_target_session(self):
        # No fresh observation from host-b: fail closed before fencing.
        self.transport.state_fn = lambda: state_body(
            self._stale_incumbent())
        instance = self.make_controller()
        self.expect_blocked(instance.execute(failover_request()),
                            'target-session-unproven')
        self.assertFalse(any(
            p == '/v2/placements/fence'
            for _m, p, _r in self.transport.requests))

    def test_failover_conflicting_fence_evidence(self):
        # A fence already committed for this scope with a different
        # evidence basis conflicts at POST time.
        self.transport.fences[('canary', 1)] = {
            'workloadId': 'canary', 'generation': 1,
            'hostId': 'host-a', 'evidence': 'operator',
            'attestedBy': 'urn:controller', 'requestId': 'e1' * 16,
            'recordedAt': 999}
        instance = self.make_controller()
        self.expect_blocked(instance.execute(failover_request()),
                            'registry-fence-conflict')
        job = self.read_job()
        self.assertEqual(job['phase'], 'fence')

    def test_failover_fence_replay_same_record(self):
        # An identical fence committed earlier under a different
        # requestId is a second attestation, accepted and verified.
        self.transport.fences[('canary', 1)] = {
            'workloadId': 'canary', 'generation': 1,
            'hostId': 'host-a', 'evidence': 'quorum-attested',
            'attestedBy': 'urn:controller', 'requestId': 'e1' * 16,
            'recordedAt': 999}
        self.transport.receipt_fn = dispatch_receipt()
        self.transport.complete_on_read = True
        self.successor_running = True
        instance = self.make_controller()
        response = instance.execute(failover_request())
        self.assertEqual(response['status'], 'completed', msg=response)

    def test_failover_resume_through_every_boundary(self):
        """Crash/resume replay at each phase boundary: refresh, fence,
        assign, adopt, ready, publish — completed phases are never
        redone and derived ids stay stable."""
        instance = self.make_controller()
        # Blocked at 'fence': the refresh checkpoint is durable, the
        # failed step leaves only its phase marker.
        self.transport.post_failures['fence'] = (
            503, {'schemaVersion': 2, 'status': 'error',
                  'error': 'unavailable'})
        self.expect_blocked(instance.execute(failover_request()),
                            'registry-unavailable')
        job = self.read_job()
        self.assertEqual(job['phase'], 'fence')
        self.assertEqual([e['step'] for e in job['checkpoints']],
                         ['refresh'])
        # Blocked at 'assign': fence committed exactly once — a
        # completed checkpoint is never re-posted on resume.
        del self.transport.post_failures['fence']
        self.transport.post_failures['assign'] = (
            409, {'schemaVersion': 2, 'status': 'error',
                  'error': 'generation-conflict'})
        self.expect_blocked(instance.execute(failover_request()),
                            'registry-generation-conflict')
        job = self.read_job()
        self.assertEqual(job['phase'], 'assign')
        self.assertEqual([e['step'] for e in job['checkpoints']],
                         ['refresh', 'fence'])
        # The failed first fence attempt was retried with the identical
        # caller-supplied requestId and body — replay-safe, never a
        # re-scoped second fence.
        fence_posts = [r for m, p, r in self.transport.requests
                       if (m, p) == ('POST', '/v2/placements/fence')]
        self.assertEqual(len(fence_posts), 2)
        self.assertEqual(fence_posts[0], fence_posts[1])
        self.assertEqual(fence_posts[0]['requestId'], 'f5' * 16)
        # Deferred at 'adopt': the remote op sits pending.
        del self.transport.post_failures['assign']
        response = instance.execute(failover_request())
        self.assertEqual(response['status'], 'deferred', msg=response)
        adopt = next(e for e in response['operation']['checkpoints']
                     if e['step'] == 'adopt')
        self.assertEqual(adopt['state'], 'deferred')
        self.assertEqual(adopt['detail']['disposition'],
                         'remote-dispatched')
        self.assertEqual(adopt['detail']['step'], 'adopt')
        self.assertEqual(adopt['detail']['hostId'], 'host-b')
        self.assertEqual(len(self.transport.operation_rows('adopt')), 1)
        # Replay while pending: identical POST, still one row.
        again = instance.execute(failover_request())
        self.assertEqual(again['status'], 'deferred')
        self.assertEqual(len(self.transport.operation_rows('adopt')), 1)
        # Deferred at 'ready': ops all complete but the successor has
        # not yet produced a running observation.
        self.transport.receipt_fn = dispatch_receipt(slot='s9')
        self.transport.complete_on_read = True
        response = instance.execute(action_request('execute'))
        self.assertEqual(response['status'], 'deferred', msg=response)
        ready = next(e for e in response['operation']['checkpoints']
                     if e['step'] == 'ready')
        self.assertEqual(ready['state'], 'deferred')
        self.assertEqual(ready['detail'],
                         {'awaiting': 'readiness-evidence'})
        # Blocked at 'publish', then the final resume completes.
        self.successor_running = True
        self.transport.post_failures['publish'] = (
            409, {'schemaVersion': 2, 'status': 'error',
                  'error': 'generation-conflict'})
        self.expect_blocked(instance.execute(failover_request()),
                            'registry-generation-conflict')
        self.assertEqual(self.read_job()['phase'], 'publish')
        del self.transport.post_failures['publish']
        final = instance.execute(failover_request())
        self.assertEqual(final['status'], 'completed', msg=final)
        self.assertEqual(
            [e['step'] for e in final['operation']['checkpoints']],
            list(controller._FAILOVER_STEP_ORDER))

    def test_failover_revived_incumbent_blocks_fence_retry(self):
        # Refresh passed while the incumbent was stale; if the host
        # revives before the fence lands, the re-run refuses — the
        # controller never fences a live incumbent on replay.
        self.transport.post_failures['fence'] = (
            503, {'schemaVersion': 2, 'status': 'error',
                  'error': 'unavailable'})
        instance = self.make_controller()
        self.expect_blocked(instance.execute(failover_request()),
                            'registry-unavailable')
        del self.transport.post_failures['fence']
        self.transport.state_fn = lambda: state_body(
            workload_row(), self._other_row(),
            fences=self.transport.fence_rows())
        self.expect_blocked(instance.execute(failover_request()),
                            'incumbent-live')
        self.assertFalse(self.transport.fences)

    def test_failover_adopt_receipt_handling(self):
        # A failed adopt receipt surfaces its typed worker error.
        def fail_adopt(row):
            if row['step'] == 'adopt':
                row['status'] = 'failed'
                row['errorCode'] = 'worker-adopt-state-absent'
        self.transport.receipt_fn = fail_adopt
        self.transport.complete_on_read = True
        instance = self.make_controller()
        self.expect_blocked(instance.execute(failover_request()),
                            'remote-worker-adopt-state-absent')
        self.assertEqual(self.read_job()['phase'], 'adopt')

    def test_failover_adopt_receipt_invalid(self):
        def bad_adopt(row):
            if row['step'] == 'adopt':
                row['status'] = 'completed'
                row['result'] = {'appliedPhase': 'stopped'}
        self.transport.receipt_fn = bad_adopt
        self.transport.complete_on_read = True
        instance = self.make_controller()
        self.expect_blocked(instance.execute(failover_request()),
                            'remote-receipt-invalid')
        self.assertEqual(self.read_job()['phase'], 'adopt')

    def test_failover_slot_mismatch(self):
        self.transport.receipt_fn = dispatch_receipt(slot='s9')
        self.transport.complete_on_read = True
        instance = self.make_controller()
        self.expect_blocked(
            instance.execute(failover_request(toSlotId='s0')),
            'slot-mismatch')

    def test_failover_request_conflict(self):
        self.transport.receipt_fn = dispatch_receipt()
        self.transport.complete_on_read = True
        instance = self.make_controller()
        instance.execute(failover_request())
        self.expect_blocked(
            instance.execute(failover_request(
                fenceRequestId='a0' * 16)),
            'operation-conflict')
        self.expect_blocked(instance.execute(plan_request()),
                            'operation-conflict')

    def test_failover_abort_before_publish(self):
        instance = self.make_controller()
        response = instance.execute(failover_request())
        self.assertEqual(response['status'], 'deferred')
        abort = instance.execute(action_request('abort'))
        self.assertEqual(abort['status'], 'completed')
        self.assertEqual(abort['operation']['phase'], 'aborted')
        self.assertEqual(instance.execute(action_request('abort')),
                         abort)
        self.expect_blocked(instance.execute(failover_request()),
                            'operation-aborted')

    def test_failover_abort_after_publish_forbidden(self):
        self.transport.receipt_fn = dispatch_receipt()
        self.transport.complete_on_read = True
        self.successor_running = True
        instance = self.make_controller()
        response = instance.execute(failover_request())
        self.assertEqual(response['status'], 'completed')
        self.expect_blocked(instance.execute(action_request('abort')),
                            'abort-forbidden')
        # Mid-tail: publish committed, operation still running.
        job = self.read_job()
        job['phase'] = 'ready'
        job['completedAt'] = None
        statefiles.write_json(self.job_path(), job)
        self.expect_blocked(instance.execute(action_request('abort')),
                            'abort-forbidden')

    def test_failover_local_target(self):
        """Failover onto the controller's own host: adopt/observe/start
        run through the local worker, not the queue."""
        self.successor_running = True

        def state_fn():
            if self.transport.assigned:
                canary = workload_row(
                    self.new_instance, 'host-a', 2, published=False,
                    observed_state='running',
                    obs=observation(self.new_instance, 'host-a',
                                    generation=2))
            else:
                canary = workload_row(I1, 'host-b', 1,
                                      observed_state='stale')
            return state_body(canary, self._other_row('host-a'),
                              fences=self.transport.fence_rows())

        self.transport.state_fn = state_fn
        instance = self.make_controller()
        response = instance.execute(failover_request(toHostId='host-a'))
        self.assertEqual(response['status'], 'completed', msg=response)
        adopt = next(e for e in response['operation']['checkpoints']
                     if e['step'] == 'adopt')
        self.assertEqual(adopt['detail'],
                         {'disposition': 'local', 'slotId': 's1'})
        self.assertEqual(
            [r['action'] for r in self.fake_worker.requests],
            ['adopt', 'observe', 'start'])
        self.assertEqual(self.transport.operations, {})


class DependencyTests(ControllerFixture):
    """Controller-owned dependency readiness (real readiness model).

    'canary' declares dependencies; 'broker' is a dep-less workload and
    'bridge' itself depends on 'broker' for multi-level topological
    order. The controller verifies the whole closure against fresh
    /v2/state evidence at plan and again before every journaled step,
    and marks dep-having worker requests ``dependenciesResolved``."""

    def _defs(self, deps=('broker',)):
        self.broker, _ = sealed_fixture(
            workloadId='broker',
            services=[{'id': 'api', 'protocol': 'http', 'port': 9000,
                       'exposure': 'private'}])
        self.bridge, _ = sealed_fixture(
            workloadId='bridge', dependencies=['broker'])
        self.canary_dep, _ = sealed_fixture(dependencies=list(deps))
        self.digests = {
            'broker': self.broker['revisionDigest'],
            'bridge': self.bridge['revisionDigest'],
            'canary': self.canary_dep['revisionDigest']}

    def _dep_config(self, extra_routes=()):
        config = test_registry.make_config()
        config['definitions'] = [self.canary_dep, self.broker,
                                 self.bridge]
        config['routes'] += [dict(route) for route in extra_routes]
        return config

    def make_dep(self, extra_routes=()):
        instance = controller.Controller(
            self.config(registry=self._dep_config(extra_routes)),
            transport=self.transport, runner=self.runner,
            worker_factory=lambda c: self.fake_worker,
            clock=lambda: 1000.0, sleeper=lambda s: None)
        self.controllers.append(instance)
        return instance

    def _dep_row(self, workload='broker', host='host-b', instance=I2,
                 observed_state='running', ready=('api',), generation=1):
        digest = self.digests[workload]
        return workload_row(
            instance, host, generation, workload_id=workload,
            digest=digest, observed_state=observed_state,
            obs=observation(instance, host, workload_id=workload,
                            digest=digest, generation=generation,
                            ready=ready))

    def _canary_row(self, **kwargs):
        kwargs.setdefault('digest', self.digests['canary'])
        kwargs.setdefault('workload_id', 'canary')
        obs = kwargs.pop('obs', None)
        if obs is None and kwargs.get('observed_state', 'running') \
                not in ('unknown',):
            obs = observation(
                kwargs.get('instance', I1), kwargs.get('host', 'host-a'),
                workload_id='canary', digest=self.digests['canary'],
                generation=kwargs.get('generation', 1))
        return workload_row(obs=obs, **kwargs)

    def _dep_drive(self):
        """The ExecuteLocalTests._drive state machine extended with a
        permanently-serving broker row."""
        def state_fn():
            if self.transport.assigned:
                canary = workload_row(
                    self.new_instance, 'host-a', 2, published=False,
                    observed_state='running',
                    obs=observation(self.new_instance, 'host-a',
                                    generation=2,
                                    digest=self.digests['canary']))
            elif self.fake_worker.retired:
                canary = workload_row(
                    I1, 'host-a', 1, published=True,
                    observed_state='retired',
                    obs=observation(
                        I1, 'host-a', phase='stopped', unit='inactive',
                        drained=True, retired=True, ready=(),
                        digest=self.digests['canary']))
            else:
                canary = self._canary_row()
            return state_body(canary, self._dep_row())
        self.transport.state_fn = state_fn

    def _dep_plan(self, operation_id=OP1, **overrides):
        overrides.setdefault('revisionDigest', self.digests['canary'])
        return plan_request(operation_id=operation_id, **overrides)

    def test_plan_dependencies_verified_and_journaled(self):
        self._defs()
        self.stage = [self._canary_row(), self._dep_row()]
        instance = self.make_dep()
        response = instance.execute(self._dep_plan())
        self.assertEqual(response['status'], 'completed')
        plan = response['operation']['plan']
        self.assertEqual(plan['dependencies'], ['broker'])
        self.assertEqual(plan['dependents'], [])
        # Replay-identical on re-run.
        self.assertEqual(instance.execute(self._dep_plan()), response)

    def test_plan_dependency_not_placed(self):
        self._defs()
        self.stage = [self._canary_row()]
        instance = self.make_dep()
        self.expect_blocked(
            instance.execute(self._dep_plan()),
            'dependency-not-placed')
        self.assertFalse(os.path.exists(self.job_path()))

    def test_plan_dependency_stale(self):
        self._defs()
        self.stage = [self._canary_row(),
                      self._dep_row(observed_state='stale')]
        instance = self.make_dep()
        self.expect_blocked(
            instance.execute(self._dep_plan()), 'dependency-stale')

    def test_plan_dependency_not_ready(self):
        # The dep is placed and fresh but not running with its routed
        # services — distinct from 'not placed' and 'stale'.
        self._defs()
        route = {'id': 'route-broker', 'workloadId': 'broker',
                 'serviceId': 'api', 'hostname': 'broker.internal'}
        self.stage = [self._canary_row(),
                      workload_row(
                          I2, 'host-b', 1, workload_id='broker',
                          digest=self.digests['broker'],
                          observed_state='prepared',
                          obs=observation(
                              I2, 'host-b', phase='prepared',
                              unit='inactive', drained=True, ready=(),
                              workload_id='broker',
                              digest=self.digests['broker']))]
        instance = self.make_dep(extra_routes=[route])
        self.expect_blocked(
            instance.execute(self._dep_plan()),
            'dependency-not-ready')
        # Running but the routed service missing from readyServices.
        self.stage[1] = self._dep_row(ready=())
        self.expect_blocked(
            instance.execute(self._dep_plan(operation_id=OP2)),
            'dependency-not-ready', OP2)
        # Routed service listed: the gate opens.
        self.stage[1] = self._dep_row(ready=('api',))
        response = instance.execute(self._dep_plan(operation_id=OP2))
        self.assertEqual(response['status'], 'completed')

    def test_plan_dependencies_topological_order(self):
        # canary depends on bridge and broker; bridge itself depends on
        # broker — broker must be verified (and journaled) first.
        self._defs(deps=('bridge', 'broker'))
        self.stage = [self._canary_row(),
                      self._dep_row('broker', instance=I2),
                      self._dep_row('bridge', instance=I3)]
        instance = self.make_dep()
        response = instance.execute(self._dep_plan())
        self.assertEqual(response['status'], 'completed')
        self.assertEqual(response['operation']['plan']['dependencies'],
                         ['broker', 'bridge'])
        # The deepest unmet need fails first even though the direct
        # dep 'bridge' is also listed.
        self.stage[1] = self._dep_row('broker', instance=I2,
                                    observed_state='stale')
        self.expect_blocked(
            instance.execute(self._dep_plan(operation_id=OP2)),
            'dependency-stale', OP2)

    def test_execute_reverifies_dependencies(self):
        # A dep that dies between plan and execute resume blocks the
        # resume: the current step defers with the failing dep and
        # reason journaled, and recovers when the dep comes back.
        self._defs()
        self._dep_drive()
        instance = self.make_dep()
        self.assertEqual(instance.execute(
            self._dep_plan(toHostId='host-a'))['status'], 'completed')
        broker_row = self._dep_row()
        stale_broker = self._dep_row(observed_state='stale')
        rows = [stale_broker]

        def flaky_state():
            canary = self._canary_row()
            return state_body(canary, *rows)
        self.transport.state_fn = flaky_state
        response = instance.execute(action_request('execute'))
        self.assertEqual(response['status'], 'deferred')
        entry = next(e for e in response['operation']['checkpoints']
                     if e['step'] == 'validate')
        self.assertEqual(entry['state'], 'deferred')
        self.assertEqual(entry['detail'],
                         {'awaiting': 'dependency-evidence',
                          'dependency': 'broker',
                          'reason': 'dependency-stale'})
        # Dep recovers: the same execute resumes and completes.
        self._dep_drive()
        final = instance.execute(action_request('execute'))
        self.assertEqual(final['status'], 'completed', msg=final)
        validate = next(e for e in final['operation']['checkpoints']
                        if e['step'] == 'validate')
        self.assertEqual(validate['detail']['dependenciesVerified'], 1)

    def test_full_local_move_marks_worker_requests(self):
        # Every gated worker request for a dep-having workload carries
        # the controller's dependenciesResolved marker; observe (a
        # different strict field set) never does.
        self._defs()
        self._dep_drive()
        instance = self.make_dep()
        self.assertEqual(instance.execute(
            self._dep_plan(toHostId='host-a'))['status'], 'completed')
        response = instance.execute(action_request('execute'))
        self.assertEqual(response['status'], 'completed', msg=response)
        gated = [r for r in self.fake_worker.requests
                 if r['action'] != 'observe']
        self.assertTrue(gated)
        for request in gated:
            self.assertIs(request['dependenciesResolved'], True,
                          msg=request)
        for request in self.fake_worker.requests:
            if request['action'] == 'observe':
                self.assertNotIn('dependenciesResolved', request)

    def test_dependents_journaled_for_dep_hub_move(self):
        # Moving 'broker' while its dependents 'bridge' and 'canary'
        # run journals the exposure — advisory, never a silent drop.
        self._defs()
        self.stage = [
            self._dep_row('broker', host='host-b', instance=I2),
            self._dep_row('bridge', host='host-a', instance=I3),
            self._canary_row()]
        instance = self.make_dep()
        response = instance.execute(plan_request(
            workloadId='broker', revisionDigest=self.digests['broker'],
            fromInstanceId=I2, toHostId='host-a'))
        self.assertEqual(response['status'], 'completed')
        plan = response['operation']['plan']
        self.assertEqual(plan['dependencies'], [])
        self.assertEqual(plan['dependents'], ['bridge', 'canary'])

    def test_failover_dependency_not_placed(self):
        # The failover journal refuses to form while a declared dep
        # has no current placement — recovery ordering is explicit.
        self._defs()
        self.transport.state_fn = lambda: state_body(
            self._canary_row(observed_state='stale'),
            FailoverTests._other_row(self))
        instance = self.make_dep()
        self.expect_blocked(instance.execute(failover_request()),
                            'dependency-not-placed')
        self.assertFalse(os.path.exists(self.job_path()))
        self.assertFalse(any(
            p == '/v2/placements/fence'
            for _m, p, _r in self.transport.requests))

    def test_failover_dependency_having_completes(self):
        # A dep-having workload fails over once its dep is serving —
        # and the remote adopt payload carries the resolved marker.
        self._defs()

        def state_fn():
            if self.transport.assigned:
                canary = workload_row(
                    self.new_instance, 'host-b', 2, published=False,
                    observed_state='running',
                    obs=observation(self.new_instance, 'host-b',
                                    generation=2,
                                    digest=self.digests['canary']))
            else:
                canary = self._canary_row(observed_state='stale')
            return state_body(canary, self._dep_row(),
                              fences=self.transport.fence_rows())
        self.transport.state_fn = state_fn
        self.transport.receipt_fn = dispatch_receipt(slot='s9')
        self.transport.complete_on_read = True
        instance = self.make_dep()
        response = instance.execute(failover_request())
        self.assertEqual(response['status'], 'completed', msg=response)
        plan = response['operation']['plan']
        self.assertEqual(plan['dependencies'], ['broker'])
        adopt = self.transport.operation_rows('adopt')[0]
        self.assertIs(adopt['payload']['dependenciesResolved'], True)
        start = self.transport.operation_rows('start')[0]
        self.assertIs(start['payload']['dependenciesResolved'], True)

    def test_failover_resume_reverifies_dependencies(self):
        # Journal formed with the dep ready; the dep dies before the
        # fence step — resume defers on dep evidence and the fence is
        # never posted.
        self._defs()
        live = [self._dep_row()]

        def state_fn():
            return state_body(self._canary_row(observed_state='stale'),
                              *live,
                              fences=self.transport.fence_rows())
        self.transport.state_fn = state_fn
        self.transport.post_failures['fence'] = (
            503, {'schemaVersion': 2, 'status': 'error',
                  'error': 'unavailable'})
        instance = self.make_dep()
        self.expect_blocked(instance.execute(failover_request()),
                            'registry-unavailable')
        self.assertEqual(self.read_job()['phase'], 'fence')
        del self.transport.post_failures['fence']
        live[0] = self._dep_row(observed_state='stale')
        response = instance.execute(failover_request())
        self.assertEqual(response['status'], 'deferred', msg=response)
        fence = next(e for e in response['operation']['checkpoints']
                     if e['step'] == 'fence')
        self.assertEqual(fence['state'], 'deferred')
        self.assertEqual(fence['detail'],
                         {'awaiting': 'dependency-evidence',
                          'dependency': 'broker',
                          'reason': 'dependency-stale'})
        self.assertFalse(self.transport.fences)


if __name__ == '__main__':
    unittest.main()
