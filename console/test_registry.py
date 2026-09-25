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


def observation(instance=I1, host='host-a', session='s', sequence=1, at=None,
                phase='running', unit='active', drained=False, retired=False,
                endpoint='192.168.140.2', ready=(), digest=DIGEST,
                generation=1):
    return {'schemaVersion': 2, 'hostId': host, 'sessionId': session,
            'sequence': sequence, 'instanceId': instance,
            'workloadId': 'canary', 'revisionDigest': digest,
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
