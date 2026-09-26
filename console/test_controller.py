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
        self.receipt_fn = None
        self.complete_on_read = False

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
        elif step == 'prepare':
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


if __name__ == '__main__':
    unittest.main()
