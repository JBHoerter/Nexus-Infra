"""Unit tests for console/reporter.py (M5 host reporter).

Transport is injected; a real mutual-TLS loopback class reuses the
test_registry_api PKI helpers to prove the session/observation flow
against a live registry. No private key material is ever printed.
"""
import json
import os
import shutil
import ssl
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


class FakeTransport:
    """Scriptable registry transport double."""

    def __init__(self):
        self.calls = []
        self.posted = []
        self.session_count = 0
        self.session = None
        self.epoch = 'ab' * 16
        self.assignments = [assignment(I1)]
        self.observation_responses = []
        self.session_responses = []
        self.assignments_responses = []
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
        raise AssertionError('unexpected path ' + path)


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

    def make_reporter(self, observer=None, prober=None,
                      transport=None, **config_overrides):
        observe = observer or (lambda instance_id:
                               dict(self.observed[instance_id]))
        instance = reporter.Reporter(
            self.config(**config_overrides),
            transport=transport or self.transport,
            observer=observe,
            prober=prober or (lambda address, port: True),
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
                          '/v2/observations'])
        sequences = [c[2]['sequence'] for c in calls[2:]]
        self.assertEqual(sequences, [1, 2])
        self.assertTrue(all(c[2]['sessionId'] == self.transport.session
                            for c in calls[2:]))
        self.assertTrue(all(c[2]['readyServices'] == ['web']
                            for c in calls[2:]))

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

    def make_reporter(self, observed=None):
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
            prober=lambda a, p: True)
        return self.reporter_instance

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
