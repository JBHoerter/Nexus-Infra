"""Unit tests for console/reporter.py (M5 host reporter).

Transport is injected; a real mutual-TLS loopback class reuses the
test_registry_api PKI helpers to prove the session/observation flow
against a live registry. No private key material is ever printed.
"""
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

CONSOLE = Path(__file__).resolve().parent
sys.path.insert(0, str(CONSOLE))

import registry
import registry_api
import reporter
import statefiles
import test_registry
import test_registry_api
import worker


I1, I2 = '0a' * 16, '3d' * 16
DIGEST = test_registry.DIGEST


def write_private_file(path, data, mode=0o600):
    with open(path, 'wb') as handle:
        handle.write(data)
    os.chmod(path, mode)
    return path


def worker_config(tmp):
    return {
        'schemaVersion': 1, 'hostId': 'host-a',
        'architecture': 'x86_64-linux',
        'stateDir': os.path.join(tmp, 'worker-state'),
        'storage': {'root': os.path.join(tmp, 'storage'),
                    'mountPoint': os.path.join(tmp, 'storage'),
                    'uuid': '1111-2222-3333'},
        'capacity': {'memoryMiB': 256, 'cpuMillis': 100,
                     'stateBytes': 1048576},
        'capabilities': [],
        'approvedBundles': ['/nix/store/' + 'a' * 32 + '-bundle'],
        'slots': [{'id': 's0', 'uidBase': 65536,
                   'hostAddress': '192.168.130.1',
                   'localAddress': '192.168.140.2'}],
    }


def observe_record(instance_id=I1, **overrides):
    record = {'schemaVersion': 1, 'action': 'observe',
              'instanceId': instance_id, 'hostId': 'host-a',
              'workloadId': 'canary', 'revisionDigest': DIGEST,
              'generation': 1, 'phase': 'running',
              'bindingCurrent': True, 'unitActiveState': 'active',
              'unitDrained': False, 'retired': False,
              'endpointAddress': '192.168.140.2'}
    record.update(overrides)
    return record


def assignment(instance_id=I1, host='host-a', generation=1):
    return {'instanceId': instance_id, 'workloadId': 'canary',
            'revisionDigest': DIGEST, 'hostId': host,
            'generation': generation}


def pending_operation(seq=1, operation_id='11' * 16, step='observe',
                      generation=1, payload=None):
    if payload is None:
        payload = {'schemaVersion': 1, 'action': 'observe',
                   'instanceId': I1}
    return {'seq': seq, 'operationId': operation_id,
            'workloadId': 'canary', 'generation': generation,
            'step': step, 'payload': payload}


class FakeTransport:
    """Scriptable registry transport double."""

    def __init__(self):
        self.calls = []
        self.posted = []
        self.receipts = []
        self.session_count = 0
        self.session = None
        self.epoch = 'ab' * 16
        self.assignments = [assignment(I1)]
        self.operations = []
        self.observation_responses = []
        self.session_responses = []
        self.assignments_responses = []
        self.operations_responses = []
        self.receipt_responses = []
        self.fail = None

    def request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        if self.fail is not None:
            raise self.fail
        if path == '/v2/hosts/session':
            if self.session_responses:
                return self.session_responses.pop(0)
            self.session_count += 1
            self.session = '{:032x}'.format(self.session_count)
            return 200, {'schemaVersion': 2, 'hostId': 'host-a',
                         'sessionId': self.session,
                         'registryEpoch': self.epoch}
        if path == '/v2/assignments':
            if self.assignments_responses:
                return self.assignments_responses.pop(0)
            return 200, {'schemaVersion': 2, 'hostId': 'host-a',
                         'instances': list(self.assignments)}
        if path == '/v2/observations':
            if self.observation_responses:
                return self.observation_responses.pop(0)
            self.posted.append(dict(payload))
            return 200, {'schemaVersion': 2, 'status': 'accepted',
                         'instanceId': payload['instanceId'],
                         'sequence': payload['sequence']}
        if path.startswith('/v2/operations?'):
            if self.operations_responses:
                return self.operations_responses.pop(0)
            return 200, {'schemaVersion': 2, 'hostId': 'host-a',
                         'operations': [dict(op)
                                        for op in self.operations]}
        if path.startswith('/v2/operations/') \
                and path.endswith('/receipt'):
            operation_id = path[len('/v2/operations/'):-len('/receipt')]
            self.receipts.append((operation_id, dict(payload)))
            if self.receipt_responses:
                return self.receipt_responses.pop(0)
            return 200, {'schemaVersion': 2, 'status': 'accepted',
                         'operationId': operation_id,
                         'receipt': payload['status']}
        raise AssertionError('unexpected path ' + path)


class FakeCliRunner:
    """Scriptable bounded-subprocess double keyed on (program, action)."""

    def __init__(self, responses=None):
        self.calls = []
        self.responses = responses or {}

    def run(self, argv, input_bytes, *, timeout):
        request = json.loads(input_bytes.decode('utf-8'))
        self.calls.append((list(argv), request))
        response = self.responses.get((argv[0], request['action']))
        if callable(response):
            response = response(request)
        if response is None:
            raise AssertionError('no scripted response for ' + argv[0])
        if isinstance(response, Exception):
            raise response
        return subprocess.CompletedProcess(
            argv, 0, json.dumps(response).encode('utf-8'), b'')


def worker_receipt(action='prepare', phase='prepared', **extra):
    receipt = {'schemaVersion': 1, 'operationId': '11' * 16,
               'action': action, 'workloadId': 'canary',
               'instanceId': I1, 'generation': 1, 'hostId': 'host-a',
               'status': 'completed', 'appliedPhase': phase}
    receipt.update(extra)
    return receipt


class ReporterFixture(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        self.state_dir = os.path.join(self.root, 'reporter-state')
        os.mkdir(self.state_dir, 0o700)
        self.worker_config_path = write_private_file(
            os.path.join(self.root, 'worker.json'),
            json.dumps(worker_config(self.root)).encode())
        self.transport = FakeTransport()
        self.observed = {I1: observe_record(I1),
                         I2: observe_record(I2)}
        self.executed = []
        self.runner = FakeCliRunner()
        self.logs = []
        self._reporters = []
        self.addCleanup(self._close_all)

    def _close_all(self):
        for instance in self._reporters:
            instance.close()

    def config(self, **overrides):
        config = {'schemaVersion': 2, 'hostId': 'host-a',
                  'registryUrl': 'https://127.0.0.1:9444',
                  'registry': test_registry.make_config(),
                  'stateDir': self.state_dir,
                  'workerConfigFile': self.worker_config_path,
                  'observeIntervalSeconds': 5,
                  'requestTimeoutSeconds': 10,
                  'maxBackoffSeconds': 60}
        config.update(overrides)
        return config

    def executor(self, request):
        """Default dispatch executor: worker.execute double."""
        self.executed.append(dict(request))
        action = request.get('action')
        if action == 'observe':
            return dict(self.observed.get(
                request['instanceId'], {'instanceId':
                                        request['instanceId']}))
        receipt = worker_receipt(
            action=action,
            phase={'freeze': 'stopped', 'thaw': 'stopped',
                   'stop': 'stopped', 'retire': 'stopped',
                   'start': 'running', 'prepare': 'prepared'}[action],
            operationId=request['operationId'])
        if request.get('captureId') is not None:
            receipt['captureId'] = request['captureId']
        return receipt

    def make_reporter(self, observer=None, prober=None,
                      transport=None, executor=None, runner=None,
                      **config_overrides):
        observe = observer or (lambda instance_id:
                               dict(self.observed[instance_id]))
        instance = reporter.Reporter(
            self.config(**config_overrides),
            transport=transport or self.transport,
            observer=observe,
            prober=prober or (lambda address, port: True),
            executor=executor if executor is not None
            else self.executor,
            runner=runner or self.runner,
            clock=lambda: 1000.0, log=self.logs.append,
            rand=lambda: 0.5)
        self._reporters.append(instance)
        return instance


class ConfigTests(ReporterFixture):
    def test_valid_config(self):
        parsed = reporter.validate_config(self.config())
        self.assertEqual(parsed['hostId'], 'host-a')
        self.assertEqual(parsed['observeIntervalSeconds'], 5)

    def test_config_rejections(self):
        good = self.config()
        for mutate in (
                lambda c: c.update(schemaVersion=1),
                lambda c: c.update(hostId='Bad_Host'),
                lambda c: c.update(registryUrl='http://insecure.test'),
                lambda c: c.update(registryUrl='https://h.test/x'),
                lambda c: c.update(stateDir='relative'),
                lambda c: c.update(observeIntervalSeconds=0),
                lambda c: c.update(requestTimeoutSeconds=999),
                lambda c: c.update(maxBackoffSeconds=0),
                lambda c: c.pop('registry'),
                lambda c: c.update(extra=1)):
            mutated = dict(good)
            mutate(mutated)
            with self.assertRaises(reporter.ReporterError, msg=mutated):
                reporter.validate_config(mutated)
        mutated = dict(good)
        mutated['hostId'] = 'host-z'
        with self.assertRaises(reporter.ReporterError) as ctx:
            reporter.validate_config(mutated)
        self.assertEqual(ctx.exception.code, 'invalid-config-hostId')


class CycleTests(ReporterFixture):
    def test_session_open_and_post(self):
        self.transport.assignments = [assignment(I1), assignment(
            I2, generation=2)]
        instance = self.make_reporter()
        posted, skipped = instance.run_once()
        self.assertEqual((posted, skipped), (2, 0))
        calls = self.transport.calls
        self.assertEqual(calls[0][1], '/v2/hosts/session')
        self.assertEqual([c[1] for c in calls[1:]],
                         ['/v2/assignments', '/v2/observations',
                          '/v2/observations',
                          '/v2/operations?host=host-a&after=0'])
        sequences = [c[2]['sequence'] for c in calls[2:4]]
        self.assertEqual(sequences, [1, 2])
        self.assertTrue(all(c[2]['sessionId'] == self.transport.session
                            for c in calls[2:4]))
        self.assertTrue(all(c[2]['readyServices'] == ['web']
                            for c in calls[2:4]))

    def test_sequence_resume_across_restart(self):
        first = self.make_reporter()
        first.run_once()
        first.close()
        self._reporters.remove(first)
        second = self.make_reporter()
        self.assertEqual(second._session_id, self.transport.session)
        second.run_once()
        # Session resumed, not re-opened; sequence continued.
        self.assertEqual(self.transport.session_count, 1)
        self.assertEqual(
            [c[2]['sequence'] for c in self.transport.calls
             if c[1] == '/v2/observations'], [1, 1 + 1])
        state = statefiles.read_json(
            os.path.join(self.state_dir, 'reporter-state.json'), 4096)
        self.assertEqual(state['nextSequence'], 3)
        self.assertEqual(state['sessionId'], self.transport.session)

    def test_session_mismatch_reopens_session(self):
        self.transport.observation_responses = [
            (403, {'schemaVersion': 2, 'status': 'error',
                   'error': 'session-mismatch'})]
        instance = self.make_reporter()
        posted, _ = instance.run_once()
        self.assertEqual(posted, 1)
        self.assertEqual(self.transport.session_count, 2)
        self.assertEqual(self.transport.posted[-1]['sequence'], 1)
        self.assertEqual(self.transport.posted[-1]['sessionId'],
                         self.transport.session)

    def test_sequence_conflict_reopens_session(self):
        self.transport.observation_responses = [
            (409, {'schemaVersion': 2, 'status': 'error',
                   'error': 'sequence-conflict'})]
        instance = self.make_reporter()
        posted, _ = instance.run_once()
        self.assertEqual(posted, 1)
        self.assertEqual(self.transport.session_count, 2)
        self.assertEqual(self.transport.posted[-1]['sequence'], 1)

    def test_state_persisted_before_post(self):
        # After a cycle the durable file already holds the next
        # sequence — a crash can never reuse a consumed value.
        instance = self.make_reporter()
        instance.run_once()
        state = statefiles.read_json(
            os.path.join(self.state_dir, 'reporter-state.json'), 4096)
        self.assertEqual(state['nextSequence'], 2)
        self.assertEqual(state['sessionId'], self.transport.session)
        self.assertEqual(state['registryEpoch'], 'ab' * 16)

    def test_instance_mismatch_is_dropped_not_fatal(self):
        self.transport.observation_responses = [
            (403, {'schemaVersion': 2, 'status': 'error',
                   'error': 'instance-mismatch'})]
        instance = self.make_reporter()
        posted, skipped = instance.run_once()
        self.assertEqual((posted, skipped), (0, 1))

    def test_observer_failure_skips_instance(self):
        self.transport.assignments = [assignment(I1), assignment(
            I2, generation=2)]

        def observer(instance_id):
            if instance_id == I1:
                raise worker.WorkerError('unknown-instance')
            return dict(self.observed[instance_id])

        instance = self.make_reporter(observer=observer)
        posted, skipped = instance.run_once()
        self.assertEqual((posted, skipped), (1, 1))
        events = [entry['event'] for entry in self.logs]
        self.assertIn('observe-skipped', events)
        self.assertIn('cycle', events)

    def test_unapproved_endpoint_skipped(self):
        self.observed[I1] = observe_record(
            I1, endpointAddress='10.9.9.9')
        instance = self.make_reporter()
        posted, skipped = instance.run_once()
        self.assertEqual((posted, skipped), (0, 1))

    def test_probe_gates_ready_services(self):
        instance = self.make_reporter(
            prober=lambda address, port: False)
        instance.run_once()
        self.assertEqual(self.transport.posted[0]['readyServices'],
                         [])

    def test_ready_not_claimed_when_not_running(self):
        self.observed[I1] = observe_record(
            I1, phase='stopped', unitActiveState='inactive',
            unitDrained=True)
        instance = self.make_reporter()
        instance.run_once()
        self.assertEqual(self.transport.posted[0]['readyServices'],
                         [])
        self.assertEqual(self.transport.posted[0]['phase'],
                         'stopped')

    def test_single_instance_lock(self):
        self.make_reporter()
        with self.assertRaises(reporter.ReporterError) as ctx:
            self.make_reporter()
        self.assertEqual(ctx.exception.code, 'reporter-in-use')

    def test_state_file_corruption(self):
        path = os.path.join(self.state_dir, 'reporter-state.json')
        statefiles.ensure_private_file(path)
        statefiles.write_json(path, {'schemaVersion': 1,
                                     'hostId': 'host-b',
                                     'sessionId': None,
                                     'registryEpoch': None,
                                     'nextSequence': 1})
        with self.assertRaises(reporter.ReporterError) as ctx:
            self.make_reporter()
        self.assertEqual(ctx.exception.code,
                         'reporter-state-mismatch')
        statefiles.write_json(path, {'schemaVersion': 1,
                                     'hostId': 'host-a',
                                     'sessionId': None,
                                     'registryEpoch': None,
                                     'nextSequence': 0})
        with self.assertRaises(reporter.ReporterError):
            self.make_reporter()

    def test_assignments_rejected_malformed(self):
        self.transport.assignments_responses = [
            (200, {'schemaVersion': 2, 'hostId': 'host-a',
                   'instances': [{'instanceId': 'zz'}]})]
        instance = self.make_reporter()
        with self.assertRaises(reporter.ReporterError) as ctx:
            instance.run_once()
        self.assertEqual(ctx.exception.code,
                         'registry-response-invalid')

    def test_backoff_bounded_with_jitter(self):
        instance = self.make_reporter()
        for failures in range(1, 40):
            delay = instance._backoff(failures)
            self.assertGreaterEqual(delay, 0.0)
            self.assertLessEqual(delay, 60)
        instance._rand = lambda: 1.0
        for failures in range(1, 40):
            self.assertLessEqual(instance._backoff(failures), 60)


class DispatchTests(ReporterFixture):
    """Pull-model operation dispatch: claim, execute, receipt."""

    def worker_op(self, action='prepare', operation_id='11' * 16,
                  instance_id=I1, **extra):
        payload = {'schemaVersion': 1, 'operationId': operation_id,
                   'action': action, 'workloadId': 'canary',
                   'revisionDigest': DIGEST, 'instanceId': instance_id,
                   'generation': 1}
        payload.update(extra)
        return pending_operation(step=action, operation_id=operation_id,
                                 payload=payload)

    def receipts(self, operation_id='11' * 16):
        return [body for op_id, body in self.transport.receipts
                if op_id == operation_id]

    def journal_path(self, operation_id='11' * 16):
        return os.path.join(self.state_dir, 'dispatch',
                            operation_id + '.json')

    def test_dispatch_observe_completes(self):
        self.transport.operations = [pending_operation()]
        instance = self.make_reporter()
        instance.run_once()
        receipts = self.receipts()
        self.assertEqual([r['status'] for r in receipts],
                         ['claimed', 'completed'])
        self.assertEqual(receipts[1]['result']['phase'], 'running')
        # Deterministic receipt ids per operation.
        self.assertEqual(receipts[0]['requestId'],
                         instance._receipt_id('11' * 16, 'claim'))
        self.assertEqual(receipts[1]['requestId'],
                         instance._receipt_id('11' * 16, 'receipt'))
        self.assertFalse(os.path.exists(self.journal_path()))
        self.assertEqual(len(self.executed), 1)

    def test_dispatch_worker_step(self):
        self.transport.operations = [self.worker_op(
            'freeze', captureId='cc' * 16)]
        instance = self.make_reporter()
        instance.run_once()
        self.assertEqual(self.executed[0]['action'], 'freeze')
        self.assertEqual(self.executed[0]['operationId'], '11' * 16)
        receipts = self.receipts()
        self.assertEqual(receipts[1]['status'], 'completed')
        self.assertEqual(receipts[1]['result']['captureId'],
                         'cc' * 16)
        self.assertEqual(receipts[1]['result']['appliedPhase'],
                         'stopped')

    def test_dispatch_refuses_foreign_instance(self):
        self.transport.operations = [self.worker_op(
            'stop', instance_id=I2)]
        instance = self.make_reporter()
        instance.run_once()
        receipts = self.receipts()
        self.assertEqual([r['status'] for r in receipts],
                         ['claimed', 'failed'])
        self.assertEqual(receipts[1]['errorCode'],
                         'operation-not-held')
        self.assertEqual(self.executed, [])

    def test_dispatch_refuses_stale_generation(self):
        self.transport.operations = [self.worker_op(
            'stop', generation=5)]
        self.transport.operations[0]['generation'] = 5
        self.transport.operations[0]['payload']['generation'] = 5
        instance = self.make_reporter()
        instance.run_once()
        receipts = self.receipts()
        self.assertEqual(receipts[1]['status'], 'failed')
        self.assertEqual(receipts[1]['errorCode'],
                         'operation-not-held')

    def test_dispatch_refuses_invalid_payload(self):
        bad = pending_operation(step='prepare',
                                payload={'schemaVersion': 1})
        self.transport.operations = [bad]
        instance = self.make_reporter()
        instance.run_once()
        self.assertEqual(self.receipts()[1]['errorCode'],
                         'operation-invalid')
        instance.close()
        self._reporters.remove(instance)
        # Payload operationId must equal the registry operationId.
        mismatch = self.worker_op('prepare', operation_id='99' * 16)
        mismatch['payload']['operationId'] = '77' * 16
        self.transport.operations = [mismatch]
        second = self.make_reporter()
        second.run_once()
        self.assertEqual(self.receipts('99' * 16)[1]['errorCode'],
                         'operation-not-held')
        self.assertEqual(self.executed, [])

    def test_dispatch_claim_conflict_drops(self):
        self.transport.operations = [pending_operation()]
        self.transport.receipt_responses = [
            (409, {'schemaVersion': 2, 'status': 'error',
                   'error': 'receipt-conflict'})]
        instance = self.make_reporter()
        instance.run_once()
        self.assertEqual(len(self.transport.receipts), 1)
        self.assertEqual(self.executed, [])
        self.assertFalse(os.path.exists(self.journal_path()))
        events = [e['event'] for e in self.logs]
        self.assertIn('dispatch-conflict', events)

    def test_dispatch_crash_resumes_journal(self):
        # Simulate crash after claim: durable entry in 'claimed'.
        os.mkdir(os.path.join(self.state_dir, 'dispatch'), 0o700)
        entry = {'schemaVersion': 1, 'operationId': '11' * 16,
                 'seq': 1, 'workloadId': 'canary', 'generation': 1,
                 'step': 'observe',
                 'payload': {'schemaVersion': 1, 'action': 'observe',
                             'instanceId': I1},
                 'claimRequestId': 'aa' * 16,
                 'receiptRequestId': 'bb' * 16, 'phase': 'claimed',
                 'result': None, 'errorCode': None}
        statefiles.ensure_private_file(self.journal_path())
        statefiles.write_json(self.journal_path(), entry)
        instance = self.make_reporter()
        instance.run_once()
        # No re-claim: the journal skips straight to execute+receipt.
        self.assertEqual([r['status'] for r in self.receipts()],
                         ['completed'])
        self.assertFalse(os.path.exists(self.journal_path()))
        instance.close()
        self._reporters.remove(instance)
        # A 'claiming' entry re-posts the identical claim request.
        entry['operationId'] = '22' * 16
        entry['phase'] = 'claiming'
        self.transport.operations = []
        statefiles.ensure_private_file(self.journal_path('22' * 16))
        statefiles.write_json(self.journal_path('22' * 16), entry)
        third = self.make_reporter()
        third.run_once()
        self.assertEqual(
            [r['status'] for r in self.receipts('22' * 16)],
            ['claimed', 'completed'])

    def test_dispatch_worker_failed_maps_error(self):
        def executor(request):
            receipt = worker_receipt(action='retire')
            receipt.update(status='failed', error='instance-retired')
            return receipt
        self.transport.operations = [self.worker_op('retire')]
        instance = self.make_reporter(executor=executor)
        instance.run_once()
        self.assertEqual(self.receipts()[1]['errorCode'],
                         'worker-instance-retired')

    def test_dispatch_worker_uncertain_retries(self):
        def executor(request):
            receipt = worker_receipt(action='stop')
            receipt.update(status='uncertain')
            return receipt
        self.transport.operations = [self.worker_op('stop')]
        instance = self.make_reporter(executor=executor)
        with self.assertRaises(reporter.ReporterError) as ctx:
            instance.run_once()
        self.assertEqual(ctx.exception.code, 'worker-uncertain')
        # Claim survives: journal stays at 'claimed', no final receipt.
        journal = statefiles.read_json(self.journal_path(), 16384)
        self.assertEqual(journal['phase'], 'claimed')
        self.assertEqual(len(self.receipts()), 1)

    def test_dispatch_restore_cli(self):
        stage = {'schemaVersion': 1, 'action': 'stage',
                 'restoreId': 'ee' * 16, 'repositoryId': 'repo-a',
                 'snapshotId': 'f0' * 32,
                 'target': {'workloadId': 'canary',
                            'revisionDigest': DIGEST,
                            'instanceId': I1, 'generation': 1,
                            'slotId': 's0'}}
        self.transport.operations = [pending_operation(
            step='restore-stage', payload=stage)]
        self.runner.responses[('/nix/nexus-restore', 'stage')] = {
            'schemaVersion': 1, 'status': 'completed',
            'action': 'stage', 'restoreId': 'ee' * 16}
        instance = self.make_reporter(
            restoreProgram='/nix/nexus-restore',
            restoreConfigFile='/etc/nexus/restore.json')
        instance.run_once()
        argv, request = self.runner.calls[0]
        self.assertEqual(argv, ['/nix/nexus-restore', '--config',
                                '/etc/nexus/restore.json', 'execute'])
        self.assertEqual(request['target']['slotId'], 's0')
        self.assertEqual(self.receipts()[1]['status'], 'completed')

    def test_dispatch_cli_unavailable_refuses(self):
        commit = {'schemaVersion': 1, 'action': 'commit',
                  'restoreId': 'ee' * 16}
        self.transport.operations = [pending_operation(
            step='restore-commit', payload=commit)]
        instance = self.make_reporter()
        instance.run_once()
        self.assertEqual(self.receipts()[1]['errorCode'],
                         'dispatch-unavailable')

    def test_dispatch_capture_runs_both_clis(self):
        capture = {'schemaVersion': 1, 'action': 'capture',
                   'captureId': 'cc' * 16, 'workloadId': 'canary',
                   'revisionDigest': DIGEST, 'instanceId': I1,
                   'generation': 1}
        upload = {'schemaVersion': 1, 'action': 'upload',
                  'captureId': 'cc' * 16, 'repositoryId': 'repo-a'}
        self.transport.operations = [pending_operation(
            step='capture',
            payload={'capture': capture, 'upload': upload})]
        self.runner.responses[('/nix/nexus-backup', 'capture')] = {
            'schemaVersion': 1, 'status': 'completed',
            'action': 'capture', 'captureId': 'cc' * 16}
        self.runner.responses[('/nix/nexus-backup', 'upload')] = {
            'schemaVersion': 1, 'status': 'completed',
            'action': 'upload', 'captureId': 'cc' * 16,
            'record': {'snapshotId': 'f0' * 32,
                       'repositoryId': 'repo-a'},
            'verifiedAt': 1005}
        instance = self.make_reporter(
            backupProgram='/nix/nexus-backup',
            backupConfigFile='/etc/nexus/backup.json')
        instance.run_once()
        self.assertEqual([c[1]['action'] for c in self.runner.calls],
                         ['capture', 'upload'])
        result = self.receipts()[1]['result']
        self.assertEqual(result['snapshotId'], 'f0' * 32)
        self.assertEqual(result['verifiedAt'], 1005)

    def test_dispatch_operations_response_invalid(self):
        self.transport.operations_responses = [
            (200, {'schemaVersion': 2, 'hostId': 'host-a',
                   'operations': [{'operationId': 'zz'}]})]
        instance = self.make_reporter()
        with self.assertRaises(reporter.ReporterError) as ctx:
            instance.run_once()
        self.assertEqual(ctx.exception.code,
                         'registry-response-invalid')

    def test_dispatch_corrupt_journal_blocks(self):
        os.mkdir(os.path.join(self.state_dir, 'dispatch'), 0o700)
        statefiles.ensure_private_file(self.journal_path())
        statefiles.write_json(self.journal_path(),
                              {'schemaVersion': 1})
        instance = self.make_reporter()
        with self.assertRaises(reporter.ReporterError) as ctx:
            instance.run_once()
        self.assertEqual(ctx.exception.code,
                         'dispatch-journal-invalid')


class LoggingTests(ReporterFixture):
    def test_no_secrets_or_bodies_in_logs(self):
        self.transport.fail = ConnectionError(
            'dial failed: password=hunter2 key=/run/secrets/hostkey')
        stop = threading.Event()
        delays = []

        def sleeper(delay):
            delays.append(delay)
            stop.set()

        instance = reporter.Reporter(
            self.config(), transport=self.transport,
            observer=lambda instance_id: dict(self.observed[I1]),
            prober=lambda a, p: True, clock=lambda: 1000.0,
            log=self.logs.append, sleeper=sleeper,
            rand=lambda: 0.5)
        self._reporters.append(instance)
        instance.run(stop=stop)
        rendered = json.dumps(self.logs)
        self.assertNotIn('hunter2', rendered)
        self.assertNotIn('secrets/hostkey', rendered)
        self.assertNotIn('dial failed', rendered)
        for record in self.logs:
            self.assertLessEqual(set(record),
                                 reporter._LOG_KEYS)
        # backoff(1) = interval * 2^0 * (0.5 + rand) = 5 * 1 * 1.0
        self.assertEqual(delays, [5.0])

    def test_cycle_error_recovers(self):
        stop = threading.Event()
        calls = []

        def sleeper(delay):
            calls.append(delay)
            if len(calls) == 2:
                stop.set()

        scripted = [ConnectionError('boom')]
        original = self.transport.request

        def flaky(method, path, payload=None):
            if scripted:
                raise scripted.pop(0)
            return original(method, path, payload)

        self.transport.request = flaky
        instance = reporter.Reporter(
            self.config(), transport=self.transport,
            observer=lambda instance_id: dict(self.observed[I1]),
            prober=lambda a, p: True, clock=lambda: 1000.0,
            log=self.logs.append, sleeper=sleeper,
            rand=lambda: 0.5)
        self._reporters.append(instance)
        instance.run(stop=stop)
        events = [entry['event'] for entry in self.logs]
        self.assertIn('cycle-error', events)
        self.assertIn('session-opened', events)
        self.assertEqual(self.transport.session_count, 1)


class TlsReporterTests(unittest.TestCase):
    """Reporter against a real registry_api TLS listener."""

    @classmethod
    def setUpClass(cls):
        cls.pki = tempfile.mkdtemp(prefix='nexus-reporter-pki-')
        os.chmod(cls.pki, 0o700)
        cls.ca_key, cls.ca_crt = test_registry_api._ca(
            cls.pki, 'ca', 'Nexus Test CA')
        cls.server_key, cls.server_crt = test_registry_api._leaf(
            cls.pki, 'server', 100, 'nexus-registry', cls.ca_crt,
            cls.ca_key,
            'IP:127.0.0.1,DNS:localhost', 'serverAuth')
        cls.host_key, cls.host_crt = test_registry_api._leaf(
            cls.pki, 'host-a', 200, 'host-a', cls.ca_crt, cls.ca_key,
            'URI:urn:nexus:host:host-a,DNS:host-a.test', 'clientAuth')

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.pki)

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nexus-reporter-tls-')
        os.chmod(self.tmp, 0o700)
        self.db_path = os.path.join(self.tmp, 'registry.db')
        self.config = registry_api.validate_config(
            test_registry_api.api_config(self.db_path))
        self._serve(epoch='e0' * 16)
        self.state_dir = os.path.join(self.tmp, 'reporter-state')
        os.mkdir(self.state_dir, 0o700)
        self.worker_config_path = write_private_file(
            os.path.join(self.tmp, 'worker.json'),
            json.dumps(worker_config(self.tmp)).encode())
        self.reporter_instance = None

    def _serve(self, epoch):
        self.reg = registry.Registry(self.config['registry'],
                                     self.db_path, epoch=epoch)
        context = ssl.create_default_context(
            ssl.Purpose.CLIENT_AUTH, cafile=self.ca_crt)
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.server_crt, self.server_key)
        self.server = registry_api.make_server(
            self.reg, self.config['clients'], ('127.0.0.1', 0),
            context)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def _stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=10)
        self.reg.close()

    def _restart_registry(self, epoch):
        self._stop_server()
        self._serve(epoch)
        if self.reporter_instance is not None:
            self.reporter_instance._transport = reporter.TlsTransport(
                'https://127.0.0.1:{}'.format(self.port),
                self.client_context(), timeout=10)

    def tearDown(self):
        if self.reporter_instance is not None:
            self.reporter_instance.close()
        self._stop_server()
        shutil.rmtree(self.tmp)

    def client_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=self.ca_crt)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.host_crt, self.host_key)
        return context

    def make_reporter(self, observed=None, executor=None):
        config = {'schemaVersion': 2, 'hostId': 'host-a',
                  'registryUrl': 'https://127.0.0.1:{}'.format(
                      self.port),
                  'registry': test_registry.make_config(),
                  'stateDir': self.state_dir,
                  'workerConfigFile': self.worker_config_path,
                  'observeIntervalSeconds': 5,
                  'requestTimeoutSeconds': 10,
                  'maxBackoffSeconds': 60}
        transport = reporter.TlsTransport(
            config['registryUrl'], self.client_context(), timeout=10)
        self.reporter_instance = reporter.Reporter(
            config, transport=transport,
            observer=observed or (lambda instance_id: dict(
                observe_record(instance_id))),
            executor=executor,
            prober=lambda a, p: True)
        return self.reporter_instance

    def test_live_dispatch_executes_and_receipts(self):
        """Real mTLS: controller posts an op, the host reporter claims,
        executes and posts a receipt the controller can read back."""
        controller_p = registry.Principal('test', 'controller')
        self.reg.assign(controller_p, test_registry.assign_request(
            I1, 'host-a', 0, 'a1' * 16))
        self.reg.post_operation(controller_p,
                                test_registry.operation_request())
        executed = []
        instance = self.make_reporter(
            executor=lambda request: executed.append(request)
            or {'bindingCurrent': True, 'slotId': 's0',
                'phase': 'prepared'})
        instance.run_once()
        self.assertEqual(len(executed), 1)
        view = self.reg.operation_status(controller_p, '11' * 16,
                                         '22' * 16)
        self.assertEqual(view['status'], 'completed')
        self.assertEqual(view['result']['slotId'], 's0')
        # Queue drained; nothing re-executes next cycle.
        instance.run_once()
        self.assertEqual(len(executed), 1)

    def test_live_dispatch_foreign_receipt_rejected(self):
        """The registry refuses receipts for operations addressed to
        another host — enforced by the certificate role binding."""
        controller_p = registry.Principal('test', 'controller')
        self.reg.assign(controller_p, test_registry.assign_request(
            I1, 'host-b', 0, 'a1' * 16))
        self.reg.post_operation(
            controller_p,
            test_registry.operation_request(host='host-b'))
        instance = self.make_reporter()
        # host-a's queue is empty — nothing is claimed or run.
        instance.run_once()
        view = self.reg.operation_status(controller_p, '11' * 16,
                                         '22' * 16)
        self.assertEqual(view['status'], 'pending')

    def test_live_session_observe_and_routes(self):
        self.reg.assign(
            registry.Principal('test', 'controller'),
            test_registry.assign_request(I1, 'host-a', 0, 'a1' * 16))
        instance = self.make_reporter()
        posted, skipped = instance.run_once()
        self.assertEqual((posted, skipped), (1, 0))
        entry = self.reg.state(
            registry.Principal('r', 'reader'))['workloads'][0]
        self.assertEqual(entry['observedState'], 'running')
        self.assertEqual(entry['observation']['readyServices'],
                         ['web'])
        backend = self.reg.routes(
            registry.Principal('i', 'ingress'), test_registry.NONCE
        )['routes'][0]['backend']
        self.assertIsNone(backend)  # unpublished: evidence only
        # Reporter evidence enables generation-1 publish.
        self.reg.publish(
            registry.Principal('test', 'controller'),
            test_registry.placement_request(1, 'c1' * 16))
        backend = self.reg.routes(
            registry.Principal('i', 'ingress'), test_registry.NONCE
        )['routes'][0]['backend']
        self.assertEqual(backend['instanceId'], I1)

    def test_stale_session_recovers_after_registry_restart(self):
        self.reg.assign(
            registry.Principal('test', 'controller'),
            test_registry.assign_request(I1, 'host-a', 0, 'a1' * 16))
        instance = self.make_reporter()
        instance.run_once()
        # Registry restart: new epoch invalidates the old session; the
        # reporter must reopen a session and restart at sequence 1.
        self._restart_registry('e1' * 16)
        posted, skipped = instance.run_once()
        self.assertEqual((posted, skipped), (1, 0))
        entry = self.reg.state(
            registry.Principal('r', 'reader'))['workloads'][0]
        self.assertEqual(entry['observation']['sequence'], 1)

    def test_host_identity_enforced_by_registry(self):
        # A reporter can only report for its certificate's host; the
        # mTLS role binding is the registry's enforcement.
        self.reg.assign(
            registry.Principal('test', 'controller'),
            test_registry.assign_request(I1, 'host-b', 0, 'a1' * 16))
        instance = self.make_reporter()
        # host-a cert -> assignments for host-a only (empty list).
        posted, skipped = instance.run_once()
        self.assertEqual((posted, skipped), (0, 0))


if __name__ == '__main__':
    unittest.main()
