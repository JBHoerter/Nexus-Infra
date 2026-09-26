import copy
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

CONSOLE = Path(__file__).resolve().parent
sys.path.insert(0, str(CONSOLE))
import catalog
import registry
import test_worker
from test_worker import draft_fixture, sealed_fixture


DEFINITION, _MANIFEST = sealed_fixture()
DIGEST = DEFINITION['revisionDigest']
I1, I2, I3 = '0a' * 16, '3d' * 16, '7e' * 16
NONCE = 'ab' * 16

HOST_A = {'hostId': 'host-a', 'architecture': 'x86_64-linux',
          'addresses': ['192.168.140.2', '192.168.140.3']}
HOST_B = {'hostId': 'host-b', 'architecture': 'x86_64-linux',
          'addresses': ['192.168.141.2', '192.168.141.3']}
ROUTE = {'id': 'route-web', 'workloadId': 'canary', 'serviceId': 'web',
         'hostname': 'canary.internal'}

CONTROLLER = registry.Principal('urn:controller', 'controller')
CONTROLLER_2 = registry.Principal('urn:controller-2', 'controller')
READER = registry.Principal('urn:reader', 'reader')
INGRESS = registry.Principal('urn:ingress', 'ingress')
P_HOST_A = registry.Principal('urn:host-a', 'host', 'host-a')
P_HOST_B = registry.Principal('urn:host-b', 'host', 'host-b')


class FakeTime:
    def __init__(self, now=1000.0, mono=500.0):
        self.now = now
        self.mono = mono


_LIVE = []


def tearDownModule():
    for instance in _LIVE:
        instance.close()
    _LIVE.clear()


def make_config(definition=None, routes=None):
    return {'schemaVersion': 2,
            'definitions': [definition or DEFINITION],
            'hosts': [copy.deepcopy(HOST_A), copy.deepcopy(HOST_B)],
            'routes': [dict(ROUTE)] if routes is None else routes}


def make_registry(tmp, config=None, fake=None, epoch='test-epoch',
                  name='registry.db'):
    fake = fake or FakeTime()
    config = config or make_config()
    instance = registry.Registry(
        config, os.path.join(tmp, name), clock=lambda: fake.now,
        monotonic=lambda: fake.mono, epoch=epoch)
    _LIVE.append(instance)
    return instance, fake


def session_request(host):
    return {'schemaVersion': 2, 'hostId': host}


def assign_request(instance=I1, host='host-a', expected=0, request_id='a1' * 16,
                   digest=DIGEST):
    return {'schemaVersion': 2, 'requestId': request_id,
            'workloadId': 'canary', 'revisionDigest': digest,
            'hostId': host, 'instanceId': instance,
            'expectedGeneration': expected}


def placement_request(action_gen=1, request_id='c1' * 16):
    return {'schemaVersion': 2, 'requestId': request_id,
            'workloadId': 'canary', 'expectedGeneration': action_gen}


def fence_request(generation=1, host='host-a', request_id='f1' * 16,
                  evidence='quorum-attested', workload='canary'):
    return {'schemaVersion': 2, 'requestId': request_id,
            'workloadId': workload, 'generation': generation,
            'hostId': host, 'evidence': evidence}


def observation(instance=I1, host='host-a', session='s', sequence=1, at=None,
                phase='running', unit='active', drained=False, retired=False,
                endpoint='192.168.140.2', ready=(), digest=DIGEST,
                generation=1, workload='canary'):
    return {'schemaVersion': 2, 'hostId': host, 'sessionId': session,
            'sequence': sequence, 'instanceId': instance,
            'workloadId': workload, 'revisionDigest': digest,
            'generation': generation, 'observedAt': at, 'phase': phase,
            'unitActiveState': unit, 'unitDrained': drained,
            'retired': retired, 'endpointAddress': endpoint,
            'readyServices': list(ready)}


def gen2(reg, fake):
    """Drives gen1 on host-a to retirement evidence, assigns gen2 to
    host-b, and returns host-b's session id."""
    reg.assign(CONTROLLER, assign_request(I1, 'host-a', 0, 'a1' * 16))
    session_a = reg.open_session(
        P_HOST_A, session_request('host-a'))['sessionId']
    reg.observe(P_HOST_A, observation(
        I1, 'host-a', session_a, 1, fake.now, 'stopped', 'inactive',
        True, True))
    reg.assign(CONTROLLER, assign_request(I2, 'host-b', 1, 'a2' * 16))
    return reg.open_session(P_HOST_B, session_request('host-b'))['sessionId']


def published(reg, fake):
    session_b = gen2(reg, fake)
    reg.observe(P_HOST_B, observation(
        I2, 'host-b', session_b, 1, fake.now, 'running', 'active', False,
        False, '192.168.141.2', ('web',), generation=2))
    reg.publish(CONTROLLER, placement_request(2, 'c1' * 16))
    return session_b


class ConfigValidationTests(unittest.TestCase):
    def test_valid_config(self):
        parsed = registry.validate_config(make_config())
        self.assertEqual(parsed['schemaVersion'], 2)
        self.assertEqual(len(parsed['definitions']), 1)

    def test_config_rejections(self):
        cases = []
        cfg = make_config()
        cfg['schemaVersion'] = 1
        cases.append(cfg)
        cfg = make_config()
        cfg['definitions'] = []
        cases.append(cfg)
        cfg = make_config()
        cfg['definitions'].append(copy.deepcopy(DEFINITION))
        cases.append(cfg)
        cfg = make_config()
        cfg['hosts'] = []
        cases.append(cfg)
        cfg = make_config()
        cfg['hosts'][1]['addresses'] = ['192.168.140.2']
        cases.append(cfg)
        cfg = make_config()
        cfg['routes'] = [dict(ROUTE, workloadId='ghost')]
        cases.append(cfg)
        cfg = make_config()
        cfg['routes'] = [dict(ROUTE, serviceId='ghost')]
        cases.append(cfg)
        cfg = make_config()
        cfg['routes'] = [ROUTE, dict(ROUTE, id='route-two')]
        cases.append(cfg)
        for hostname in ('*.internal', 'UPPER.example', 'name:8080',
                         'name/path', 'a..b', '`tick`', '-bad-.x', 'x' * 254):
            cfg = make_config()
            cfg['routes'] = [dict(ROUTE, hostname=hostname)]
            cases.append(cfg)
        for cfg in cases:
            with self.assertRaises(registry.RegistryError, msg=cfg):
                registry.validate_config(cfg)

    def test_route_requires_http_service_in_every_revision(self):
        https_def, _ = sealed_fixture(services=[
            {'id': 'web', 'protocol': 'https', 'port': 8443,
             'exposure': 'private'}])
        cfg = {'schemaVersion': 2, 'definitions': [DEFINITION, https_def],
               'hosts': [copy.deepcopy(HOST_A)], 'routes': [ROUTE]}
        with self.assertRaises(registry.RegistryError):
            registry.validate_config(cfg)

    def test_mutable_categories_only(self):
        archive_def = catalog.seal_definition(draft_fixture(
            category='archive', runtimeVersion=None, runtimeArtifactId=None,
            artifacts=[{'id': 'data', 'kind': 'archive',
                        'digest': 'sha256:' + '0' * 64}],
            stateMounts=[], services=[], allowedOperations=[],
            requirements={'memoryMiB': 0, 'cpuMillis': 0, 'stateBytes': 0,
                          'capabilities': []}))
        cfg = {'schemaVersion': 2, 'definitions': [archive_def],
               'hosts': [copy.deepcopy(HOST_A)], 'routes': [dict(ROUTE)]}
        with self.assertRaises(registry.RegistryError):
            registry.validate_config(cfg)
        infra_def, _ = sealed_fixture(category='infrastructure',
                                      allowedOperations=['backup'])
        with tempfile.TemporaryDirectory() as tmp:
            reg, _ = make_registry(tmp, config={
                'schemaVersion': 2, 'definitions': [infra_def],
                'hosts': [copy.deepcopy(HOST_A)], 'routes': []})
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.assign(CONTROLLER, assign_request(
                    digest=infra_def['revisionDigest']))
            self.assertEqual(ctx.exception.code, 'workload-not-mutable')


class LifecycleTests(unittest.TestCase):
    def test_initial_assign_generation1(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            state = reg.state(READER)
            self.assertEqual(state['workloads'][0]['generation'], 0)
            self.assertIsNone(state['workloads'][0]['instanceId'])
            self.assertEqual(state['workloads'][0]['observedState'], 'unknown')
            result = reg.assign(CONTROLLER, assign_request())
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(result['generation'], 1)
            self.assertEqual(result['action'], 'assign')
            state = reg.state(READER)
            entry = state['workloads'][0]
            self.assertEqual(entry['generation'], 1)
            self.assertEqual(entry['instanceId'], I1)
            self.assertEqual(entry['hostId'], 'host-a')
            self.assertFalse(entry['published'])
            self.assertEqual(entry['observedState'], 'unknown')
            self.assertIsNone(entry['observation'])

    def test_request_replay_idempotent_and_conflicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            result = reg.assign(CONTROLLER, assign_request())
            replay = reg.assign(CONTROLLER, assign_request())
            self.assertEqual(replay, result)
            for mutated in (
                    dict(assign_request(), instanceId=I2),
                    dict(assign_request(), hostId='host-b'),
                    dict(assign_request(), expectedGeneration=1)):
                with self.assertRaises(registry.RegistryError) as ctx:
                    reg.assign(CONTROLLER, mutated)
                self.assertEqual(ctx.exception.code, 'request-conflict')
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.assign(CONTROLLER_2, assign_request())
            self.assertEqual(ctx.exception.code, 'request-conflict')
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.publish(CONTROLLER, placement_request(1, 'a1' * 16))
            self.assertEqual(ctx.exception.code, 'request-conflict')

    def test_concurrent_assign_single_winner(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            barrier = threading.Barrier(2)
            outcomes = []

            def attempt(instance, request_id):
                barrier.wait()
                try:
                    outcomes.append(('ok', reg.assign(
                        CONTROLLER, assign_request(
                            instance, 'host-a', 0, request_id))))
                except registry.RegistryError as error:
                    outcomes.append(('err', error.code))

            threads = [threading.Thread(target=attempt, args=args)
                       for args in ((I1, 'a1' * 16), (I2, 'a3' * 16))]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            wins = [o for o in outcomes if o[0] == 'ok']
            losses = [o for o in outcomes if o[0] == 'err']
            self.assertEqual(len(wins), 1, outcomes)
            self.assertEqual(len(losses), 1, outcomes)
            self.assertEqual(losses[0][1], 'generation-conflict')
            state = reg.state(READER)
            self.assertEqual(state['workloads'][0]['generation'], 1)

    def test_ready_services_malformed_members(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            reg.assign(CONTROLLER, assign_request())
            session = reg.open_session(
                P_HOST_A, session_request('host-a'))['sessionId']
            for bad in ([['web']], [{'id': 'web'}], [None], [b'web'],
                        ['web', 'web']):
                request = observation(I1, 'host-a', session, 1, fake.now,
                                      ready=bad)
                with self.assertRaises(registry.RegistryError,
                                       msg=bad) as ctx:
                    reg.observe(P_HOST_A, request)
                self.assertEqual(ctx.exception.code,
                                 'invalid-readyServices')

    def test_timestamp_bounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            reg.assign(CONTROLLER, assign_request())
            session = reg.open_session(
                P_HOST_A, session_request('host-a'))['sessionId']
            for bad in (10**400, -5, float('inf'), float('-inf'),
                        float('nan'), 'now', None, True):
                request = observation(I1, 'host-a', session, 1, bad)
                with self.assertRaises(registry.RegistryError,
                                       msg=bad) as ctx:
                    reg.observe(P_HOST_A, request)
                self.assertEqual(ctx.exception.code, 'invalid-observedAt')

    def test_symlinked_ancestor_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = os.path.join(tmp, 'real')
            os.mkdir(real, 0o700)
            os.symlink(real, os.path.join(tmp, 'link'))
            with self.assertRaises(registry.RegistryError) as ctx:
                registry.Registry(
                    make_config(), os.path.join(tmp, 'link', 'r.db'))
            self.assertEqual(ctx.exception.code, 'registry-path-unsafe')

    def test_root_directory_parent_rejected(self):
        with self.assertRaises(registry.RegistryError) as ctx:
            registry.Registry(make_config(), '/registry.db')
        self.assertEqual(ctx.exception.code, 'registry-path-unsafe')

    def test_config_incompatible_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            reg.assign(CONTROLLER, assign_request())
            reg.close()
            _LIVE.remove(reg)
            other, _ = sealed_fixture(workloadId='other')
            for mutated in (
                    {'schemaVersion': 2, 'definitions': [other],
                     'hosts': [copy.deepcopy(HOST_A),
                               copy.deepcopy(HOST_B)], 'routes': []},
                    {'schemaVersion': 2, 'definitions': [DEFINITION],
                     'hosts': [copy.deepcopy(HOST_B)], 'routes': []}):
                with self.assertRaises(registry.RegistryError,
                                       msg=mutated) as ctx:
                    registry.Registry(
                        mutated, os.path.join(tmp, 'registry.db'))
                self.assertEqual(ctx.exception.code,
                                 'registry-config-incompatible')

    def test_running_with_unknown_drain_is_not_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            session_b = gen2(reg, fake)
            reg.observe(P_HOST_B, observation(
                I2, 'host-b', session_b, 1, fake.now, 'running', 'active',
                False, False, '192.168.141.2', ('web',), generation=2))
            reg.publish(CONTROLLER, placement_request(2, 'c1' * 16))
            reg.observe(P_HOST_B, observation(
                I2, 'host-b', session_b, 2, fake.now, 'running', 'active',
                None, False, '192.168.141.2', (), generation=2))
            entry = reg.state(READER)['workloads'][0]
            self.assertEqual(entry['observedState'], 'unknown')
            self.assertIsNone(
                reg.routes(INGRESS, NONCE)['routes'][0]['backend'])

    def test_reassignment_requires_retired_drained_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            reg.assign(CONTROLLER, assign_request(I1, 'host-a', 0, 'a1' * 16))
            next_assign = assign_request(I2, 'host-b', 1, 'a2' * 16)
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.assign(CONTROLLER, next_assign)
            self.assertEqual(ctx.exception.code, 'retirement-required')
            session = reg.open_session(
                P_HOST_A, session_request('host-a'))['sessionId']
            reg.observe(P_HOST_A, observation(
                I1, 'host-a', session, 1, fake.now, 'running', 'active'))
            with self.assertRaises(registry.RegistryError):
                reg.assign(CONTROLLER, next_assign)
            reg.observe(P_HOST_A, observation(
                I1, 'host-a', session, 2, fake.now, 'stopped', 'inactive',
                True, False))
            with self.assertRaises(registry.RegistryError):
                reg.assign(CONTROLLER, next_assign)
            reg.observe(P_HOST_A, observation(
                I1, 'host-a', session, 3, fake.now, 'stopped', 'inactive',
                True, True))
            fake.now += 31
            fake.mono += 31
            with self.assertRaises(registry.RegistryError):
                reg.assign(CONTROLLER, next_assign)
            reg.observe(P_HOST_A, observation(
                I1, 'host-a', session, 4, fake.now, 'stopped', 'inactive',
                False, True))
            with self.assertRaises(registry.RegistryError):
                reg.assign(CONTROLLER, next_assign)
            reg.observe(P_HOST_A, observation(
                I1, 'host-a', session, 5, fake.now, 'stopped', 'inactive',
                True, True))
            result = reg.assign(CONTROLLER, next_assign)
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(result['generation'], 2)
            entry = reg.state(READER)['workloads'][0]
            self.assertEqual(entry['generation'], 2)
            self.assertEqual(entry['hostId'], 'host-b')

    def test_generation_conflict_and_used_instance(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            reg.assign(CONTROLLER, assign_request())
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.assign(CONTROLLER, assign_request(I2, 'host-b', 0,
                                                      'a3' * 16))
            self.assertEqual(ctx.exception.code, 'generation-conflict')
            session = reg.open_session(
                P_HOST_A, session_request('host-a'))['sessionId']
            reg.observe(P_HOST_A, observation(
                I1, 'host-a', session, 1, fake.now, 'stopped', 'inactive',
                True, True))
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.assign(CONTROLLER, assign_request(I1, 'host-b', 1,
                                                      'a3' * 16))
            self.assertEqual(ctx.exception.code, 'instance-conflict')
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.assign(CONTROLLER, assign_request(
                    I2, 'host-b', 1, 'a3' * 16, digest='sha256:' + '9' * 64))
            self.assertEqual(ctx.exception.code, 'unknown-workload')
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.assign(CONTROLLER, assign_request(I2, 'ghost', 1,
                                                      'a3' * 16))
            self.assertEqual(ctx.exception.code, 'unknown-host')

    def test_publish_requires_fresh_ready_and_derives_backend(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            session_b = gen2(reg, fake)
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.publish(CONTROLLER, placement_request(2))
            self.assertEqual(ctx.exception.code, 'readiness-required')
            routes = reg.routes(INGRESS, NONCE)
            self.assertIsNone(routes['routes'][0]['backend'])
            reg.observe(P_HOST_B, observation(
                I2, 'host-b', session_b, 1, fake.now, 'running', 'active',
                False, False, '192.168.141.2', (), generation=2))
            with self.assertRaises(registry.RegistryError):
                reg.publish(CONTROLLER, placement_request(2))
            reg.observe(P_HOST_B, observation(
                I2, 'host-b', session_b, 2, fake.now, 'running', 'active',
                False, False, '192.168.141.2', ('web',), generation=2))
            result = reg.publish(CONTROLLER, placement_request(2))
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(result['generation'], 2)
            routes = reg.routes(INGRESS, NONCE)
            backend = routes['routes'][0]['backend']
            self.assertEqual(backend, {
                'instanceId': I2, 'generation': 2, 'hostId': 'host-b',
                'revisionDigest': DIGEST, 'address': '192.168.141.2',
                'port': 8080, 'protocol': 'http'})
            self.assertLessEqual(routes['validUntil'], fake.now + 10)
            self.assertLessEqual(routes['validUntil'], fake.now + 30)
            self.assertEqual(routes['nonce'], NONCE)

    def test_delayed_old_generation_publication_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            gen2(reg, fake)
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.publish(CONTROLLER, placement_request(1, 'c9' * 16))
            self.assertEqual(ctx.exception.code, 'generation-conflict')
            replay = reg.assign(
                CONTROLLER, assign_request(I1, 'host-a', 0, 'a1' * 16))
            self.assertEqual(replay['generation'], 1)

    def test_old_host_cannot_drive_new_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            session_b = gen2(reg, fake)
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.observe(P_HOST_A, observation(
                    I2, 'host-a', 'ef' * 16, 9, fake.now, 'running', 'active',
                    False, False, '192.168.140.2', ('web',)))
            self.assertEqual(ctx.exception.code, 'instance-mismatch')
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.publish(CONTROLLER, placement_request(2))
            self.assertEqual(ctx.exception.code, 'readiness-required')
            result = reg.assignments(P_HOST_A)
            self.assertEqual([i['instanceId'] for i in result['instances']],
                             [I1])
            result = reg.assignments(P_HOST_B)
            self.assertEqual([i['instanceId'] for i in result['instances']],
                             [I2])
            self.assertEqual(result['instances'][0]['generation'], 2)

    def test_roles_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            for bad in (READER, INGRESS, P_HOST_A):
                with self.assertRaises(registry.RegistryError) as ctx:
                    reg.assign(bad, assign_request())
                self.assertEqual(ctx.exception.status, 403)
            with self.assertRaises(registry.RegistryError):
                reg.open_session(CONTROLLER, session_request('host-a'))
            with self.assertRaises(registry.RegistryError):
                reg.open_session(P_HOST_B, session_request('host-a'))
            with self.assertRaises(registry.RegistryError):
                reg.state(P_HOST_A)
            with self.assertRaises(registry.RegistryError):
                reg.routes(READER, NONCE)
            with self.assertRaises(registry.RegistryError):
                reg.assignments(CONTROLLER)
            with self.assertRaises(registry.RegistryError):
                reg.assign(registry.Principal('urn:x', 'superuser'),
                           assign_request())
            with self.assertRaises(registry.RegistryError):
                reg.observe(registry.Principal('urn:x', 'host', 'ghost'),
                            observation())
            self.assertEqual(reg.state(READER)['schemaVersion'], 2)
            self.assertEqual(reg.state(CONTROLLER)['schemaVersion'], 2)
            routes = reg.routes(INGRESS, NONCE)['routes']
            self.assertEqual(len(routes), 1)
            self.assertIsNone(routes[0]['backend'])
            self.assertEqual(
                len(reg.routes(CONTROLLER, NONCE)['routes']), 1)

    def test_observe_rejections_do_not_bump_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            reg.assign(CONTROLLER, assign_request())
            session = reg.open_session(
                P_HOST_A, session_request('host-a'))['sessionId']
            base = reg.state(READER)['version']
            reg.observe(P_HOST_A, observation(
                I1, 'host-a', session, 1, fake.now))
            versioned = reg.state(READER)['version']
            self.assertGreater(versioned, base)
            rejects = [
                (dict(observation(I1, 'host-a', 'ff' * 16, 2, fake.now)),
                 'session-mismatch'),
                (dict(observation(I1, 'host-a', session, 1, fake.now)),
                 'sequence-conflict'),
                (dict(observation(I1, 'host-a', session, 2, fake.now + 5)),
                 'observation-future'),
                (dict(observation(I1, 'host-a', session, 2,
                                  float('nan'))), 'invalid-observedAt'),
                (dict(observation(I1, 'host-a', session, 2, fake.now - 31)),
                 'observation-stale'),
                (dict(observation(I1, 'host-a', session, 2, fake.now,
                                  endpoint='10.9.9.9')),
                 'invalid-endpointAddress'),
                (dict(observation(I1, 'host-a', session, 2, fake.now,
                                  ready=('nope',))), 'invalid-readyServices'),
                (dict(observation(I1, 'host-a', session, 2, fake.now,
                                  phase='stopped', ready=('web',))),
                 'invalid-observation'),
                (dict(observation(I1, 'host-a', session, 2, fake.now,
                                  retired='yes')), 'invalid-retired'),
                (dict(observation(I1, 'host-a', session, 2, fake.now,
                                  drained='yes')), 'invalid-unitDrained'),
                (dict(observation(I1, 'host-a', session, 0, fake.now)),
                 'invalid-sequence'),
                (dict(observation(I2, 'host-a', session, 2, fake.now)),
                 'instance-mismatch'),
            ]
            extra = dict(observation(I1, 'host-a', session, 2, fake.now),
                         evil='x')
            rejects.append((extra, 'invalid-request-fields'))
            for request, code in rejects:
                with self.assertRaises(registry.RegistryError,
                                       msg=(request, code)) as ctx:
                    reg.observe(P_HOST_A, request)
                self.assertEqual(ctx.exception.code, code)
            self.assertEqual(reg.state(READER)['version'], versioned)

    def test_backend_expiry_stale_then_lost(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            published(reg, fake)
            self.assertIsNotNone(
                reg.routes(INGRESS, NONCE)['routes'][0]['backend'])
            fake.now += 31
            fake.mono += 31
            self.assertIsNone(
                reg.routes(INGRESS, NONCE)['routes'][0]['backend'])
            entry = reg.state(READER)['workloads'][0]
            self.assertEqual(entry['observedState'], 'stale')
            self.assertEqual(entry['observation']['phase'], 'running')
            fake.now += 300
            entry = reg.state(READER)['workloads'][0]
            self.assertEqual(entry['observedState'], 'lost')
            self.assertNotEqual(entry['observedState'], 'stopped')

    def test_withdraw_clears_route_keeps_ownership(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            published(reg, fake)
            result = reg.withdraw(CONTROLLER, placement_request(2, 'd1' * 16))
            self.assertEqual(result['status'], 'completed')
            self.assertIsNone(
                reg.routes(INGRESS, NONCE)['routes'][0]['backend'])
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.assign(CONTROLLER, assign_request(I3, 'host-a', 2,
                                                      'a3' * 16))
            self.assertEqual(ctx.exception.code, 'retirement-required')

    def test_restart_preserves_state_invalidates_sessions(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            published(reg, fake)
            reg.close()
            _LIVE.remove(reg)
            reg2, fake2 = make_registry(tmp, epoch='epoch-2',
                                        fake=FakeTime(1100.0, 900.0))
            state = reg2.state(READER)['workloads'][0]
            self.assertEqual(state['generation'], 2)
            self.assertTrue(state['published'])
            replay = reg2.assign(
                CONTROLLER, assign_request(I2, 'host-b', 1, 'a2' * 16))
            self.assertEqual(replay['generation'], 2)
            self.assertIsNone(
                reg2.routes(INGRESS, NONCE)['routes'][0]['backend'])
            self.assertEqual(state['observedState'], 'stale')
            with self.assertRaises(registry.RegistryError) as ctx:
                reg2.observe(P_HOST_B, observation(
                    I2, 'host-b', 'ef' * 16, 9, fake2.now, 'running',
                    'active', False, False, '192.168.141.2', ('web',),
                    generation=2))
            self.assertEqual(ctx.exception.code, 'session-mismatch')
            session = reg2.open_session(
                P_HOST_B, session_request('host-b'))['sessionId']
            reg2.observe(P_HOST_B, observation(
                I2, 'host-b', session, 1, fake2.now, 'running', 'active',
                False, False, '192.168.141.2', ('web',), generation=2))
            backend = reg2.routes(INGRESS, NONCE)['routes'][0]['backend']
            self.assertEqual(backend['instanceId'], I2)

    def test_second_writer_and_hostile_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            with self.assertRaises(registry.RegistryError) as ctx:
                registry.Registry(
                    make_config(), os.path.join(tmp, 'registry.db'),
                    clock=lambda: 1.0, monotonic=lambda: 1.0)
            self.assertEqual(ctx.exception.code, 'registry-in-use')
        with tempfile.TemporaryDirectory() as tmp:
            public = os.path.join(tmp, 'public')
            os.mkdir(public, 0o755)
            with self.assertRaises(registry.RegistryError) as ctx:
                registry.Registry(
                    make_config(), os.path.join(public, 'r.db'))
            self.assertEqual(ctx.exception.code, 'registry-path-unsafe')
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, 'r.db')
            Path(db).write_bytes(b'')
            os.chmod(db, 0o644)
            with self.assertRaises(registry.RegistryError):
                registry.Registry(make_config(), db)
        with tempfile.TemporaryDirectory() as tmp:
            real = os.path.join(tmp, 'real.db')
            Path(real).write_bytes(b'')
            os.chmod(real, 0o600)
            link = os.path.join(tmp, 'link.db')
            os.symlink(real, link)
            with self.assertRaises(registry.RegistryError):
                registry.Registry(make_config(), link)
        with self.assertRaises(registry.RegistryError):
            registry.Registry(make_config(), '/nonexistent-dir-x/r.db')

    def test_transaction_recovery_after_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            with self.assertRaises(registry.RegistryError):
                reg.assign(CONTROLLER, assign_request(expected=5))
            result = reg.assign(CONTROLLER, assign_request())
            self.assertEqual(result['status'], 'completed')
            with self.assertRaises(registry.RegistryError):
                reg.assign(CONTROLLER, assign_request(instance=I2))
            result = reg.assign(CONTROLLER, assign_request())
            self.assertEqual(result['status'], 'completed')
            state = reg.state(READER)
            self.assertEqual(state['workloads'][0]['generation'], 1)


def operation_request(step='observe', operation_id='11' * 16,
                      request_id='22' * 16, host='host-a', generation=1,
                      workload='canary', payload=None):
    if payload is None:
        payload = {'schemaVersion': 1, 'action': 'observe',
                   'instanceId': I1}
    return {'schemaVersion': 2, 'requestId': request_id,
            'operationId': operation_id, 'workloadId': workload,
            'hostId': host, 'generation': generation, 'step': step,
            'payload': payload}


def _deep_tree(depth):
    value = {}
    current = value
    for _ in range(depth):
        current['k'] = {}
        current = current['k']
    return value


def receipt(status, request_id='33' * 16, **extra):
    body = {'schemaVersion': 2, 'requestId': request_id,
            'status': status}
    body.update(extra)
    return body


class OperationQueueTests(unittest.TestCase):
    """The M5 pull-model dispatch queue: post, poll, claim, receipt."""

    def placed(self, tmp, host='host-a'):
        reg, fake = make_registry(tmp)
        reg.assign(CONTROLLER, assign_request(
            I1, host, 0, 'a1' * 16))
        return reg, fake

    def test_post_poll_claim_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = self.placed(tmp)
            accepted = reg.post_operation(
                CONTROLLER, operation_request())
            self.assertEqual(accepted['status'], 'accepted')
            self.assertEqual(accepted['operationId'], '11' * 16)
            self.assertEqual(accepted['seq'], 1)
            listed = reg.poll_operations(P_HOST_A, 'host-a', 0)
            self.assertEqual(listed['hostId'], 'host-a')
            self.assertEqual(len(listed['operations']), 1)
            op = listed['operations'][0]
            self.assertEqual(op['operationId'], '11' * 16)
            self.assertEqual(op['step'], 'observe')
            self.assertEqual(op['payload']['instanceId'], I1)
            # after-cursor paging: seq 1 is not re-delivered.
            self.assertEqual(
                reg.poll_operations(P_HOST_A, 'host-a', 1)
                ['operations'], [])
            claim = reg.operation_receipt(
                P_HOST_A, '11' * 16, receipt('claimed'))
            self.assertEqual(claim['status'], 'accepted')
            self.assertEqual(claim['receipt'], 'claimed')
            # Claimed ops are no longer pending.
            self.assertEqual(
                reg.poll_operations(P_HOST_A, 'host-a', 0)
                ['operations'], [])
            done = reg.operation_receipt(
                P_HOST_A, '11' * 16,
                receipt('completed', '44' * 16,
                        result={'appliedPhase': 'stopped'}))
            self.assertEqual(done['receipt'], 'completed')
            view = reg.operation_status(CONTROLLER, '11' * 16,
                                        '22' * 16)
            self.assertEqual(view['status'], 'completed')
            self.assertEqual(view['result'],
                             {'appliedPhase': 'stopped'})
            self.assertEqual(view['step'], 'observe')
            self.assertEqual(view['hostId'], 'host-a')

    def test_post_replay_idempotent_and_conflict(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = self.placed(tmp)
            first = reg.post_operation(
                CONTROLLER, operation_request())
            replay = reg.post_operation(
                CONTROLLER, operation_request())
            self.assertEqual(replay, first)
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.post_operation(CONTROLLER, operation_request(
                    step='start', payload={
                        'schemaVersion': 1, 'operationId': '11' * 16,
                        'action': 'start', 'workloadId': 'canary',
                        'revisionDigest': DIGEST, 'instanceId': I1,
                        'generation': 1}))
            self.assertEqual(ctx.exception.code, 'request-conflict')
            # Same operationId under a different requestId conflicts.
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.post_operation(CONTROLLER, operation_request(
                    request_id='55' * 16))
            self.assertEqual(ctx.exception.code, 'operation-conflict')
            # A different principal cannot replay the requestId.
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.post_operation(CONTROLLER_2, operation_request())
            self.assertEqual(ctx.exception.code, 'request-conflict')

    def test_stale_or_foreign_generation_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.post_operation(CONTROLLER, operation_request())
            self.assertEqual(ctx.exception.code, 'generation-conflict')
            reg.assign(CONTROLLER, assign_request(I1, 'host-a', 0,
                                                  'a1' * 16))
            # Generation exists but is bound to another host.
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.post_operation(CONTROLLER, operation_request(
                    host='host-b'))
            self.assertEqual(ctx.exception.code, 'generation-conflict')
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.post_operation(CONTROLLER, operation_request(
                    generation=2))
            self.assertEqual(ctx.exception.code, 'generation-conflict')
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.post_operation(CONTROLLER, operation_request(
                    workload='ghost'))
            self.assertEqual(ctx.exception.code, 'unknown-workload')
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.post_operation(CONTROLLER, operation_request(
                    host='ghost'))
            self.assertEqual(ctx.exception.code, 'unknown-host')
            # A superseded generation is stale once assign advances.
            session_a = reg.open_session(
                P_HOST_A, session_request('host-a'))['sessionId']
            reg.observe(P_HOST_A, observation(
                I1, 'host-a', session_a, 1, fake.now, 'stopped',
                'inactive', True, True))
            reg.assign(CONTROLLER, assign_request(I2, 'host-b', 1,
                                                  'a2' * 16))
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.post_operation(CONTROLLER, operation_request(
                    operation_id='66' * 16, request_id='77' * 16,
                    host='host-a', generation=1))
            self.assertEqual(ctx.exception.code, 'generation-conflict')

    def test_role_and_host_enforcement(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = self.placed(tmp)
            for bad in (READER, INGRESS, P_HOST_A):
                with self.assertRaises(registry.RegistryError) as ctx:
                    reg.post_operation(bad, operation_request())
                self.assertEqual(ctx.exception.status, 403)
            reg.post_operation(CONTROLLER, operation_request())
            # Only the owning host polls and receipts.
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.poll_operations(CONTROLLER, 'host-a', 0)
            self.assertEqual(ctx.exception.status, 403)
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.poll_operations(P_HOST_B, 'host-a', 0)
            self.assertEqual(ctx.exception.code, 'host-mismatch')
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.operation_receipt(P_HOST_B, '11' * 16,
                                      receipt('claimed'))
            self.assertEqual(ctx.exception.code, 'host-mismatch')
            # Operation status is controller-only, bound to poster.
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.operation_status(P_HOST_A, '11' * 16, '22' * 16)
            self.assertEqual(ctx.exception.status, 403)
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.operation_status(CONTROLLER_2, '11' * 16,
                                     '22' * 16)
            self.assertEqual(ctx.exception.code, 'forbidden')
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.operation_status(CONTROLLER, '11' * 16,
                                     '88' * 16)
            self.assertEqual(ctx.exception.code, 'forbidden')
            view = reg.operation_status(CONTROLLER, '11' * 16,
                                        '22' * 16)
            self.assertEqual(view['status'], 'pending')

    def test_receipt_exactly_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = self.placed(tmp)
            reg.post_operation(CONTROLLER, operation_request())
            # Terminal receipts require a prior claim.
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.operation_receipt(
                    P_HOST_A, '11' * 16,
                    receipt('completed', '44' * 16, result={}))
            self.assertEqual(ctx.exception.code,
                             'operation-not-claimed')
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.operation_receipt(P_HOST_A, '99' * 16,
                                      receipt('claimed'))
            self.assertEqual(ctx.exception.code, 'unknown-operation')
            reg.operation_receipt(P_HOST_A, '11' * 16,
                                  receipt('claimed'))
            # Identical claim replay accepted; conflicting 409.
            self.assertEqual(reg.operation_receipt(
                P_HOST_A, '11' * 16, receipt('claimed'))['status'],
                'accepted')
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.operation_receipt(P_HOST_A, '11' * 16,
                                      receipt('claimed', '55' * 16))
            self.assertEqual(ctx.exception.code, 'receipt-conflict')
            done = receipt('completed', '44' * 16,
                           result={'appliedPhase': 'stopped'})
            reg.operation_receipt(P_HOST_A, '11' * 16, done)
            self.assertEqual(reg.operation_receipt(
                P_HOST_A, '11' * 16, done)['status'], 'accepted')
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.operation_receipt(P_HOST_A, '11' * 16,
                                      receipt('completed', '44' * 16,
                                              result={'other': 1}))
            self.assertEqual(ctx.exception.code, 'receipt-conflict')
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.operation_receipt(P_HOST_A, '11' * 16,
                                      receipt('failed', '66' * 16,
                                              errorCode='x'))
            self.assertEqual(ctx.exception.code, 'receipt-conflict')

    def test_failed_receipt_visible_to_controller(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = self.placed(tmp)
            reg.post_operation(CONTROLLER, operation_request())
            reg.operation_receipt(P_HOST_A, '11' * 16,
                                  receipt('claimed'))
            reg.operation_receipt(P_HOST_A, '11' * 16,
                                  receipt('failed', '44' * 16,
                                          errorCode='worker-retired'))
            view = reg.operation_status(CONTROLLER, '11' * 16,
                                        '22' * 16)
            self.assertEqual(view['status'], 'failed')
            self.assertEqual(view['errorCode'], 'worker-retired')
            self.assertNotIn('result', view)

    def test_operation_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = self.placed(tmp)
            base = operation_request()
            for mutate, code in (
                    (lambda r: r.update(schemaVersion=1),
                     'invalid-schemaVersion'),
                    (lambda r: r.update(step='wipe'),
                     'invalid-step'),
                    (lambda r: r.update(generation=0),
                     'invalid-generation'),
                    (lambda r: r.update(payload='string'),
                     'invalid-payload'),
                    (lambda r: r.update(payload={'x' * 65: 1}),
                     'invalid-payload'),
                    (lambda r: r.update(payload=_deep_tree(10)),
                     'invalid-payload')):
                request = operation_request()
                mutate(request)
                with self.assertRaises(registry.RegistryError,
                                       msg=code) as ctx:
                    reg.post_operation(CONTROLLER, request)
                self.assertEqual(ctx.exception.code, code)
            with self.assertRaises(registry.RegistryError):
                reg.post_operation(CONTROLLER, dict(base, extra=1))

    def test_operations_survive_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = self.placed(tmp)
            reg.post_operation(CONTROLLER, operation_request())
            reg.operation_receipt(P_HOST_A, '11' * 16,
                                  receipt('claimed'))
            reg.close()
            _LIVE.remove(reg)
            reg2, _ = make_registry(tmp, epoch='epoch-2',
                                    fake=FakeTime(1100.0, 900.0))
            # Claimed ops are not pending; the receipt state survives.
            self.assertEqual(
                reg2.poll_operations(P_HOST_A, 'host-a', 0)
                ['operations'], [])
            view = reg2.operation_status(CONTROLLER, '11' * 16,
                                         '22' * 16)
            self.assertEqual(view['status'], 'claimed')
            reg2.operation_receipt(P_HOST_A, '11' * 16,
                                   receipt('completed', '44' * 16,
                                           result={}))
            view = reg2.operation_status(CONTROLLER, '11' * 16,
                                         '22' * 16)
            self.assertEqual(view['status'], 'completed')

    def test_queue_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = self.placed(tmp)
            for index in range(registry._OPERATION_PENDING_MAX):
                reg.post_operation(CONTROLLER, operation_request(
                    operation_id='{:032x}'.format(index + 1),
                    request_id='{:032x}'.format(index + 0x1000)))
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.post_operation(CONTROLLER, operation_request(
                    operation_id='ee' * 16, request_id='ff' * 16))
            self.assertEqual(ctx.exception.code,
                             'operation-queue-full')
            listed = reg.poll_operations(P_HOST_A, 'host-a', 0)
            self.assertEqual(len(listed['operations']),
                             registry._OPERATION_POLL_MAX)
            seqs = [op['seq'] for op in listed['operations']]
            self.assertEqual(seqs, sorted(seqs))


class FenceTests(unittest.TestCase):
    """M8 placement-fence records: controller-posted, durable, scoped to
    (workloadId, generation) and bound to the incumbent host. A fence
    only substitutes for retired+drained evidence at assign time; it
    never affects routes or observed state of a live instance."""

    def test_fence_post_and_state_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            reg.assign(CONTROLLER, assign_request())
            self.assertEqual(reg.state(READER)['fences'], [])
            result = reg.fence(CONTROLLER, fence_request())
            self.assertEqual(result, {
                'schemaVersion': 2, 'status': 'accepted',
                'requestId': 'f1' * 16, 'workloadId': 'canary',
                'generation': 1, 'hostId': 'host-a',
                'evidence': 'quorum-attested'})
            fences = reg.state(READER)['fences']
            self.assertEqual(len(fences), 1)
            fence = fences[0]
            self.assertEqual(fence['workloadId'], 'canary')
            self.assertEqual(fence['generation'], 1)
            self.assertEqual(fence['hostId'], 'host-a')
            self.assertEqual(fence['evidence'], 'quorum-attested')
            self.assertEqual(fence['attestedBy'], 'urn:controller')
            self.assertEqual(fence['requestId'], 'f1' * 16)
            self.assertEqual(fence['recordedAt'], fake.now)

    def test_assign_via_fence_without_retired_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            reg.assign(CONTROLLER, assign_request(I1, 'host-a', 0,
                                                  'a1' * 16))
            # The host is dead: it can never report retired+drained.
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.assign(CONTROLLER, assign_request(I2, 'host-b', 1,
                                                      'a2' * 16))
            self.assertEqual(ctx.exception.code, 'retirement-required')
            reg.fence(CONTROLLER, fence_request())
            result = reg.assign(CONTROLLER, assign_request(
                I2, 'host-b', 1, 'a2' * 16))
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(result['generation'], 2)
            entry = reg.state(READER)['workloads'][0]
            self.assertEqual((entry['generation'], entry['hostId']),
                             (2, 'host-b'))
            # The consumed fence stays as a durable tombstone; it does
            # not unblock a third generation.
            self.assertEqual(len(reg.state(READER)['fences']), 1)
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.assign(CONTROLLER, assign_request(I3, 'host-a', 2,
                                                      'a3' * 16))
            self.assertEqual(ctx.exception.code, 'retirement-required')
            reg.fence(CONTROLLER, fence_request(
                generation=2, host='host-b', request_id='f2' * 16))
            result = reg.assign(CONTROLLER, assign_request(
                I3, 'host-a', 2, 'a3' * 16))
            self.assertEqual(result['generation'], 3)

    def test_fence_scoped_to_current_incumbent(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            # No placement yet: nothing to fence.
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.fence(CONTROLLER, fence_request())
            self.assertEqual(ctx.exception.code, 'generation-conflict')
            reg.assign(CONTROLLER, assign_request())
            for mutated, code in (
                    (fence_request(generation=0), 'invalid-generation'),
                    (fence_request(generation=2),
                     'generation-conflict'),
                    (fence_request(host='host-b'),
                     'generation-conflict'),
                    (fence_request(host='ghost'), 'unknown-host'),
                    (fence_request(workload='ghost'),
                     'unknown-workload')):
                with self.assertRaises(registry.RegistryError,
                                       msg=mutated) as ctx:
                    reg.fence(CONTROLLER, mutated)
                self.assertEqual(ctx.exception.code, code)
            # A fence for another generation is never posted: fencing is
            # always the CURRENT incumbent, so a stale scope 409s.
            gen2(reg, fake)
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.fence(CONTROLLER, fence_request(
                    generation=1, host='host-a', request_id='f2' * 16))
            self.assertEqual(ctx.exception.code, 'generation-conflict')

    def test_fence_replay_and_conflicts(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            reg.assign(CONTROLLER, assign_request())
            first = reg.fence(CONTROLLER, fence_request())
            # Identical replay returns the recorded receipt.
            self.assertEqual(
                reg.fence(CONTROLLER, fence_request()), first)
            # Same requestId, different body or principal: conflict.
            for mutated in (
                    dict(fence_request(), evidence='operator'),
                    dict(fence_request(), hostId='host-b')):
                with self.assertRaises(registry.RegistryError,
                                       msg=mutated) as ctx:
                    reg.fence(CONTROLLER, mutated)
                self.assertEqual(ctx.exception.code,
                                 'request-conflict')
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.fence(CONTROLLER_2, fence_request())
            self.assertEqual(ctx.exception.code, 'request-conflict')
            # A distinct requestId re-attesting the identical scope and
            # evidence is a harmless duplicate — recorded and accepted.
            again = reg.fence(CONTROLLER, fence_request(
                request_id='f2' * 16))
            self.assertEqual(again['status'], 'accepted')
            self.assertEqual(len(reg.state(READER)['fences']), 1)
            # A differing attestation for the same scope conflicts.
            # (hostId is pinned to the incumbent, so only evidence can
            # differ at this point — a foreign hostId 409s earlier as
            # generation-conflict.)
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.fence(CONTROLLER, fence_request(
                    request_id='f3' * 16, evidence='operator'))
            self.assertEqual(ctx.exception.code, 'fence-conflict')
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.fence(CONTROLLER, fence_request(
                    request_id='f4' * 16, host='host-b'))
            self.assertEqual(ctx.exception.code, 'generation-conflict')

    def test_fence_does_not_affect_live_routes(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            published(reg, fake)
            backend = reg.routes(INGRESS, NONCE)['routes'][0]['backend']
            self.assertEqual(backend['instanceId'], I2)
            # Fencing the LIVE incumbent changes nothing observable.
            reg.fence(CONTROLLER, fence_request(
                generation=2, host='host-b', request_id='f1' * 16))
            entry = reg.state(READER)['workloads'][0]
            self.assertEqual(entry['observedState'], 'running')
            self.assertEqual(
                reg.routes(INGRESS, NONCE)['routes'][0]['backend'],
                backend)
            # It does, however, permit the successor assign even though
            # host-b still reports running (the partitioned-survivor
            # case).
            result = reg.assign(CONTROLLER, assign_request(
                I3, 'host-a', 2, 'a3' * 16))
            self.assertEqual(result['generation'], 3)
            # Placement moved: stale old-host reports no longer route.
            self.assertIsNone(
                reg.routes(INGRESS, NONCE)['routes'][0]['backend'])

    def test_fence_survives_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            reg.assign(CONTROLLER, assign_request())
            reg.fence(CONTROLLER, fence_request())
            reg.close()
            _LIVE.remove(reg)
            reg2, fake2 = make_registry(tmp, epoch='epoch-2',
                                        fake=FakeTime(1100.0, 900.0))
            fences = reg2.state(READER)['fences']
            self.assertEqual(len(fences), 1)
            self.assertEqual(fences[0]['hostId'], 'host-a')
            self.assertEqual(fences[0]['attestedBy'], 'urn:controller')
            # Replay still returns the durable receipt post-restart.
            replay = reg2.fence(CONTROLLER, fence_request())
            self.assertEqual(replay['status'], 'accepted')
            result = reg2.assign(CONTROLLER, assign_request(
                I2, 'host-b', 1, 'a2' * 16))
            self.assertEqual(result['generation'], 2)

    def test_fence_validation_and_roles(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg, fake = make_registry(tmp)
            reg.assign(CONTROLLER, assign_request())
            for mutated, code in (
                    (dict(fence_request(), schemaVersion=1),
                     'invalid-schemaVersion'),
                    (dict(fence_request(), requestId='zz' * 16),
                     'invalid-requestId'),
                    (dict(fence_request(), workloadId='CAN'),
                     'invalid-workloadId'),
                    (dict(fence_request(), generation=True),
                     'invalid-generation'),
                    (dict(fence_request(), hostId='BAD'),
                     'invalid-hostId'),
                    (dict(fence_request(), evidence='stonith'),
                     'invalid-evidence'),
                    (dict(fence_request(), evidence=None),
                     'invalid-evidence'),
                    (dict(fence_request(), extra=1),
                     'invalid-request-fields')):
                with self.assertRaises(registry.RegistryError,
                                       msg=mutated) as ctx:
                    reg.fence(CONTROLLER, mutated)
                self.assertEqual(ctx.exception.code, code)
            for bad in (READER, INGRESS, P_HOST_A):
                with self.assertRaises(registry.RegistryError) as ctx:
                    reg.fence(bad, fence_request())
                self.assertEqual(ctx.exception.status, 403)
            self.assertEqual(reg.state(READER)['fences'], [])


class DependencyAssignTests(unittest.TestCase):
    """Declared-dependency readiness enforced atomically at the
    assign/publish commit points: a dependent cannot be placed while a
    dep lacks a current placement with fresh ready evidence — the same
    /v2/state view the controller verifies at plan time."""

    def _dep_config(self, broker_route=False):
        broker, _ = sealed_fixture(
            workloadId='broker',
            services=[{'id': 'api', 'protocol': 'http', 'port': 9000,
                       'exposure': 'private'}])
        dependent, _ = sealed_fixture(dependencies=['broker'])
        routes = [dict(ROUTE)]
        if broker_route:
            routes.append({'id': 'route-broker', 'workloadId': 'broker',
                           'serviceId': 'api',
                           'hostname': 'broker.internal'})
        return {'schemaVersion': 2,
                'definitions': [dependent, broker],
                'hosts': [copy.deepcopy(HOST_A), copy.deepcopy(HOST_B)],
                'routes': routes}, dependent, broker

    @staticmethod
    def _assign(workload, digest, instance=I1, host='host-a',
                expected=0, request_id='a1' * 16):
        return {'schemaVersion': 2, 'requestId': request_id,
                'workloadId': workload, 'revisionDigest': digest,
                'hostId': host, 'instanceId': instance,
                'expectedGeneration': expected}

    def _place_broker(self, reg, fake, broker, instance=I2,
                      host='host-a', request_id='a2' * 16):
        reg.assign(CONTROLLER, self._assign(
            'broker', broker['revisionDigest'], instance, host, 0,
            request_id))
        return reg.open_session(
            registry.Principal('urn:' + host, 'host', host),
            session_request(host))['sessionId']

    def _observe_broker(self, reg, fake, broker, session, sequence,
                        instance=I2, host='host-a', ready=('api',),
                        at=None):
        principal = registry.Principal('urn:' + host, 'host', host)
        endpoint = {'host-a': '192.168.140.2',
                  'host-b': '192.168.141.2'}[host]
        reg.observe(principal, observation(
            instance, host, session, sequence,
            fake.now if at is None else at, 'running', 'active', False,
            False, endpoint, list(ready),
            digest=broker['revisionDigest'], generation=1,
            workload='broker'))

    def test_assign_requires_placed_dependency(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, dependent, _broker = self._dep_config()
            reg, _fake = make_registry(tmp, config=config)
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.assign(CONTROLLER, self._assign(
                    'canary', dependent['revisionDigest']))
            self.assertEqual(ctx.exception.code,
                             'dependency-not-placed')

    def test_assign_requires_ready_dependency(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, dependent, broker = self._dep_config()
            reg, fake = make_registry(tmp, config=config)
            digest = dependent['revisionDigest']
            session = self._place_broker(reg, fake, broker)
            # Broker placed but never observed: not ready.
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.assign(CONTROLLER, self._assign('canary', digest))
            self.assertEqual(ctx.exception.code,
                             'dependency-not-ready')
            # Fresh running observation on the dep opens the assign.
            self._observe_broker(reg, fake, broker, session, 1)
            result = reg.assign(CONTROLLER, self._assign(
                'canary', digest))
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(result['generation'], 1)

    def test_assign_dependency_stale(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, dependent, broker = self._dep_config()
            reg, fake = make_registry(tmp, config=config)
            digest = dependent['revisionDigest']
            session = self._place_broker(reg, fake, broker)
            self._observe_broker(reg, fake, broker, session, 1)
            fake.now += 31
            fake.mono += 31
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.assign(CONTROLLER, self._assign('canary', digest))
            self.assertEqual(ctx.exception.code,
                             'dependency-not-ready')
            # A fresh dep sample re-opens the assign.
            self._observe_broker(reg, fake, broker, session, 2)
            result = reg.assign(CONTROLLER, self._assign(
                'canary', digest))
            self.assertEqual(result['status'], 'completed')

    def test_assign_dependency_missing_routed_service(self):
        with tempfile.TemporaryDirectory() as tmp:
            config, dependent, broker = self._dep_config(
                broker_route=True)
            reg, fake = make_registry(tmp, config=config)
            digest = dependent['revisionDigest']
            session = self._place_broker(reg, fake, broker)
            # Running but not listing the routed service 'api'.
            self._observe_broker(reg, fake, broker, session, 1,
                                 ready=())
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.assign(CONTROLLER, self._assign('canary', digest))
            self.assertEqual(ctx.exception.code,
                             'dependency-not-ready')
            self._observe_broker(reg, fake, broker, session, 2,
                                 ready=('api',))
            result = reg.assign(CONTROLLER, self._assign(
                'canary', digest))
            self.assertEqual(result['status'], 'completed')

    def test_successor_assign_rechecks_dependencies(self):
        """A generation-2 assign re-verifies deps: the dependent can
        retire while its dep is up, but the successor cannot land
        while the dep is down."""
        with tempfile.TemporaryDirectory() as tmp:
            config, dependent, broker = self._dep_config()
            reg, fake = make_registry(tmp, config=config)
            digest = dependent['revisionDigest']
            broker_session = self._place_broker(reg, fake, broker)
            self._observe_broker(reg, fake, broker, broker_session, 1)
            reg.assign(CONTROLLER, self._assign('canary', digest,
                                                I1, 'host-b'))
            dep_session = reg.open_session(
                P_HOST_B, session_request('host-b'))['sessionId']
            reg.observe(P_HOST_B, observation(
                I1, 'host-b', dep_session, 1, fake.now, 'stopped',
                'inactive', True, True, '192.168.141.2', (),
                digest=digest, generation=1, workload='canary'))
            fake.now += 31
            fake.mono += 31
            # Incumbent retired+drained but stale now? Re-observe the
            # retired evidence fresh while the dep is also stale.
            reg.observe(P_HOST_B, observation(
                I1, 'host-b', dep_session, 2, fake.now, 'stopped',
                'inactive', True, True, '192.168.141.2', (),
                digest=digest, generation=1, workload='canary'))
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.assign(CONTROLLER, self._assign(
                    'canary', digest, I3, 'host-a', 1, 'a3' * 16))
            self.assertEqual(ctx.exception.code,
                             'dependency-not-ready')
            self._observe_broker(reg, fake, broker, broker_session, 2)
            result = reg.assign(CONTROLLER, self._assign(
                'canary', digest, I3, 'host-a', 1, 'a3' * 16))
            self.assertEqual(result['status'], 'completed')
            self.assertEqual(result['generation'], 2)

    def test_publish_requires_dependencies_ready(self):
        """Publish re-verifies deps too: routes must not move to a
        workload whose dependency just died."""
        with tempfile.TemporaryDirectory() as tmp:
            config, dependent, broker = self._dep_config()
            reg, fake = make_registry(tmp, config=config)
            digest = dependent['revisionDigest']
            broker_session = self._place_broker(reg, fake, broker)
            self._observe_broker(reg, fake, broker, broker_session, 1)
            reg.assign(CONTROLLER, self._assign('canary', digest,
                                                I1, 'host-b'))
            dep_session = reg.open_session(
                P_HOST_B, session_request('host-b'))['sessionId']
            reg.observe(P_HOST_B, observation(
                I1, 'host-b', dep_session, 1, fake.now, 'running',
                'active', False, False, '192.168.141.2', ('web',),
                digest=digest, generation=1, workload='canary'))
            # Time passes: the dependent re-reports fresh but the dep
            # does not — the dep sample is stale at publish time.
            fake.now += 31
            fake.mono += 31
            reg.observe(P_HOST_B, observation(
                I1, 'host-b', dep_session, 2, fake.now, 'running',
                'active', False, False, '192.168.141.2', ('web',),
                digest=digest, generation=1, workload='canary'))
            with self.assertRaises(registry.RegistryError) as ctx:
                reg.publish(CONTROLLER, placement_request(1, 'c1' * 16))
            self.assertEqual(ctx.exception.code,
                             'dependency-not-ready')
            self._observe_broker(reg, fake, broker, broker_session, 2)
            result = reg.publish(CONTROLLER, placement_request(
                1, 'c1' * 16))
            self.assertEqual(result['status'], 'completed')
