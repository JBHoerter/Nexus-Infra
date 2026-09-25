"""Tests for console/ingress.py — the expiry-enforced Traefik consumer."""
import copy
import fcntl
import http.client
import json
import os
import shutil
import ssl
import stat
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

import common
import ingress
import registry
import registry_api
import statefiles
import test_registry
import test_registry_api


DIGEST = test_registry.DIGEST
ROUTE = test_registry.ROUTE
EPOCH = 'ab' * 16
BACKEND = {'instanceId': test_registry.I2, 'generation': 2,
           'hostId': 'host-b', 'revisionDigest': DIGEST,
           'address': '192.168.141.2', 'port': 8080, 'protocol': 'http'}
BACKEND_A = {'instanceId': test_registry.I1, 'generation': 3,
             'hostId': 'host-a', 'revisionDigest': DIGEST,
             'address': '192.168.140.2', 'port': 8080, 'protocol': 'http'}


def ingress_config(state_dir, url='https://registry.test:9444'):
    return {'schemaVersion': 2, 'registryUrl': url,
            'registry': test_registry.make_config(),
            'listenPort': 9445, 'stateDir': state_dir}


def snapshot(nonce, version=1, now=1000.0, epoch=EPOCH, backend='default',
             rows=None, **overrides):
    if rows is None:
        rows = [dict(ROUTE,
                     backend=copy.deepcopy(BACKEND)
                     if backend == 'default' else backend)]
    result = {'schemaVersion': 2, 'registryEpoch': epoch,
              'version': version, 'nonce': nonce,
              'generatedAt': now, 'validUntil': now + 8,
              'routes': rows}
    result.update(overrides)
    return result


def route_token(backend=BACKEND, epoch=EPOCH):
    return ingress.route_token(epoch, dict(ROUTE, backend=backend))


def make_ingress(tmp, fake=None, fetcher=None, config=None):
    fake = fake or test_registry.FakeTime()
    fetcher = fetcher or (lambda nonce: snapshot(nonce, now=fake.now))
    instance = ingress.Ingress(config or ingress_config(tmp), None,
                               clock=lambda: fake.now,
                               monotonic=lambda: fake.mono,
                               fetcher=fetcher)
    return instance, fake


def backend_url(config, route_id='route-web'):
    return config['http']['services']['nexus-' + route_id][
        'loadBalancer']['servers'][0]['url']


def auth_url(config, route_id='route-web'):
    return config['http']['middlewares']['nexus-' + route_id + '-guard'][
        'forwardAuth']['address']


class ConfigTests(unittest.TestCase):
    def test_config_validation(self):
        good = ingress_config('/x')
        ingress.validate_config(good)
        for field, bad in (
                ('schemaVersion', 1), ('schemaVersion', '2'),
                ('listenPort', 0), ('listenPort', 'x'),
                ('stateDir', 'relative'), ('stateDir', '/a/../b'),
                ('registryUrl', 'http://registry.test'),
                ('registryUrl', 'https://registry.test/app'),
                ('registryUrl', 'https://user@registry.test'),
                ('registryUrl', 'https://registry.test?q=1'),
                ('registryUrl', 'https://registry.test#f'),
                ('registryUrl', 'https://registry%41.test'),
                ('registryUrl', 'ftp://registry.test'),
                ('registryUrl', 'https://bad host.test'),
                ('registryUrl', 'https://x:0'),
                ('registryUrl', 42)):
            mutated = dict(good)
            mutated[field] = bad
            with self.assertRaises(ingress.IngressError, msg=bad):
                ingress.validate_config(mutated)
        with self.assertRaises(ingress.IngressError):
            ingress.validate_config(dict(good, extra=1))
        with self.assertRaises(ingress.IngressError):
            ingress.validate_config(
                {k: v for k, v in good.items() if k != 'listenPort'})

    def test_snapshot_validation(self):
        config = ingress.validate_config(ingress_config('/x'))
        good = snapshot(test_registry.NONCE, now=1000.0)
        result = ingress.validate_snapshot(good, config,
                                           test_registry.NONCE,
                                           now=1000.0, highwater=0)
        self.assertIsNot(result, good)
        with self.assertRaises(ingress.IngressError) as ctx:
            ingress.validate_snapshot(good, config, test_registry.NONCE,
                                      now=1000.0, highwater=2)
        self.assertEqual(ctx.exception.code, 'version-stale')
        cases = []
        cases.append((dict(good, nonce='cd' * 16), 'nonce-mismatch'))
        cases.append((dict(good, generatedAt=1001.0), 'snapshot-future'))
        cases.append((dict(good, generatedAt=989.0), 'snapshot-stale'))
        cases.append((dict(good, validUntil=1000.0), 'invalid-validUntil'))
        cases.append((dict(good, validUntil=1011.0), 'invalid-validUntil'))
        cases.append((dict(good, validUntil=1005.0,
                           generatedAt=994.0), 'invalid-validUntil'))
        cases.append((dict(good, generatedAt=10**400),
                      'invalid-generatedAt'))
        cases.append((dict(good, validUntil=float('nan')),
                      'invalid-validUntil'))
        cases.append((dict(good, registryEpoch='zz' * 16),
                      'invalid-registryEpoch'))
        for mutated, code in cases:
            with self.assertRaises(ingress.IngressError, msg=code) as ctx:
                ingress.validate_snapshot(
                    mutated, config, test_registry.NONCE,
                    now=1000.0, highwater=0)
            self.assertEqual(ctx.exception.code, code)

    def test_snapshot_route_and_backend_forgery(self):
        config = ingress.validate_config(ingress_config('/x'))
        nonce = test_registry.NONCE
        forged = [
            dict(ROUTE, hostname='evil.example', backend=BACKEND),
            dict(ROUTE, workloadId='other', backend=BACKEND),
            dict(ROUTE, serviceId='other', backend=BACKEND),
            dict(ROUTE, backend=dict(BACKEND, address='192.168.140.2')),
            dict(ROUTE, backend=dict(BACKEND, address='10.0.0.9')),
            dict(ROUTE, backend=dict(BACKEND, port=9090)),
            dict(ROUTE, backend=dict(BACKEND, protocol='https')),
            dict(ROUTE, backend=dict(BACKEND, hostId='host-z')),
            dict(ROUTE, backend=dict(BACKEND, hostId='host-a')),
            dict(ROUTE, backend=dict(BACKEND, instanceId='zz' * 16)),
            dict(ROUTE, backend=dict(BACKEND,
                                     revisionDigest='sha256:' + '0' * 64)),
            dict(ROUTE, backend=dict(BACKEND, generation=0)),
            dict(ROUTE, backend=dict(BACKEND, port=8080.0)),
            dict(ROUTE, backend=dict(BACKEND, port='8080')),
            dict(ROUTE, backend=dict(BACKEND, port=0)),
            dict(ROUTE, backend=dict(BACKEND, extra=1)),
            dict(ROUTE, id=42, backend=None),
        ]
        for row in forged:
            snap = snapshot(nonce, rows=[row])
            with self.assertRaises(ingress.IngressError, msg=row):
                ingress.validate_snapshot(snap, config, nonce,
                                          now=1000.0, highwater=0)
        for rows in ([], [dict(ROUTE, backend=None),
                          dict(ROUTE, backend=None)],
                     [dict(ROUTE, backend=None),
                      dict(ROUTE, id='other', backend=None)]):
            snap = snapshot(nonce, rows=rows)
            with self.assertRaises(ingress.IngressError, msg=rows):
                ingress.validate_snapshot(snap, config, nonce,
                                          now=1000.0, highwater=0)

    def test_cross_route_owner_agreement(self):
        second = dict(ROUTE, id='route-two', hostname='two.internal')
        registry_config = test_registry.make_config(
            routes=[dict(ROUTE), second])
        config = ingress.validate_config(
            {'schemaVersion': 2, 'registryUrl': 'https://r.test',
             'registry': registry_config, 'listenPort': 9445,
             'stateDir': '/x'})
        nonce = test_registry.NONCE
        rows = [dict(ROUTE, backend=copy.deepcopy(BACKEND)),
                dict(second, backend=dict(BACKEND,
                                          instanceId=test_registry.I1))]
        with self.assertRaises(ingress.IngressError) as ctx:
            ingress.validate_snapshot(snapshot(nonce, rows=rows), config,
                                      nonce, now=1000.0, highwater=0)
        self.assertEqual(ctx.exception.code, 'invalid-backend')
        rows[1]['backend'] = copy.deepcopy(BACKEND)
        ingress.validate_snapshot(snapshot(nonce, rows=rows), config,
                                  nonce, now=1000.0, highwater=0)


class IngressTests(unittest.TestCase):
    def test_poll_install_authorize_expire(self):
        with tempfile.TemporaryDirectory() as tmp:
            ing, fake = make_ingress(tmp)
            config = ing.dynamic_config()
            self.assertEqual(backend_url(config),
                             'http://127.0.0.1:9445/unavailable')
            self.assertTrue(auth_url(config).endswith(
                '/authorize/route-web/' + '0' * 64))
            self.assertFalse(ing.authorize('route-web', '0' * 64))
            ing.poll()
            config = ing.dynamic_config()
            self.assertEqual(backend_url(config),
                             'http://192.168.141.2:8080')
            token = route_token()
            self.assertTrue(auth_url(config).endswith(
                '/authorize/route-web/' + token))
            self.assertTrue(ing.authorize('route-web', token))
            self.assertFalse(ing.authorize('route-web', '0' * 64))
            self.assertFalse(ing.authorize('route-two', token))
            self.assertFalse(ing.authorize('route-web', token.upper()))
            self.assertEqual(
                statefiles.read_json(
                    os.path.join(tmp, 'version.json'), 4096),
                {'schemaVersion': 2, 'version': 1})
            fake.now += 9
            self.assertFalse(ing.authorize('route-web', token))
            self.assertEqual(backend_url(ing.dynamic_config()),
                             'http://127.0.0.1:9445/unavailable')
            fake.now -= 9
            ing.poll()
            token = route_token()
            self.assertTrue(ing.authorize('route-web', token))
            fake.mono -= 1
            self.assertFalse(ing.authorize('route-web', token))
            fake.now = float('nan')
            self.assertFalse(ing.authorize('route-web', token))
            ing.close()

    def test_ownership_change_invalidates_cached_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            versions = {'v': snapshot('x', version=1)}

            def fetcher(nonce):
                if versions['v'] is None:
                    return snapshot(nonce, version=2, backend=BACKEND_A)
                return dict(versions['v'], nonce=nonce)

            ing, fake = make_ingress(tmp, fetcher=fetcher)
            ing.poll()
            old_token = route_token()
            self.assertTrue(ing.authorize('route-web', old_token))
            versions['v'] = None
            ing.poll()
            self.assertFalse(ing.authorize('route-web', old_token))
            self.assertEqual(backend_url(ing.dynamic_config()),
                             'http://192.168.140.2:8080')
            self.assertTrue(ing.authorize(
                'route-web', route_token(BACKEND_A)))
            ing.close()

    def test_null_backend_and_poll_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            ing, fake = make_ingress(
                tmp, fetcher=lambda nonce: snapshot(
                    nonce, now=fake.now, backend=None))
            ing.poll()
            self.assertEqual(backend_url(ing.dynamic_config()),
                             'http://127.0.0.1:9445/unavailable')
            self.assertFalse(ing.authorize('route-web', route_token(None)))
            calls = {'fail': False}

            def flaky(nonce):
                if calls['fail']:
                    raise ingress.IngressError('registry-fetch-failed')
                return snapshot(nonce, now=fake.now)

            os.mkdir(os.path.join(tmp, 'two'), 0o700)
            ing2, fake = make_ingress(tmp, fetcher=flaky,
                                      config=ingress_config(
                                          os.path.join(tmp, 'two')))
            ing2.poll()
            token = route_token()
            self.assertTrue(ing2.authorize('route-web', token))
            calls['fail'] = True
            with self.assertRaises(ingress.IngressError):
                ing2.poll()
            self.assertTrue(ing2.authorize('route-web', token))
            fake.now += 9
            self.assertFalse(ing2.authorize('route-web', token))
            ing.close()
            ing2.close()

    def test_highwater_persists_and_routes_never_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            ing, fake = make_ingress(
                tmp, fetcher=lambda nonce: snapshot(
                    nonce, version=5, now=fake.now))
            ing.poll()
            ing.close()
            ing, fake = make_ingress(
                tmp, fetcher=lambda nonce: snapshot(
                    nonce, version=4, now=fake.now))
            self.assertEqual(backend_url(ing.dynamic_config()),
                             'http://127.0.0.1:9445/unavailable')
            with self.assertRaises(ingress.IngressError) as ctx:
                ing.poll()
            self.assertEqual(ctx.exception.code, 'version-stale')
            ing.close()
            ing2, fake2 = make_ingress(
                tmp, fetcher=lambda nonce: snapshot(
                    nonce, version=5, now=fake2.now,
                    epoch='cd' * 16))
            ing2.poll()
            self.assertTrue(ing2.authorize(
                'route-web', route_token(epoch='cd' * 16)))
            self.assertFalse(ing.authorize('route-web', route_token()))
            ing2.close()

    def test_write_failure_leaves_state_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            ing, fake = make_ingress(tmp)
            original = statefiles.write_json

            def boom(*args):
                raise statefiles.PathError('path-unavailable')

            statefiles.write_json = boom
            try:
                with self.assertRaises(ingress.IngressError):
                    ing.poll()
            finally:
                statefiles.write_json = original
            self.assertFalse(os.path.exists(
                os.path.join(tmp, 'version.json')))
            self.assertFalse(ing.authorize('route-web', route_token()))
            ing.poll()
            self.assertTrue(ing.authorize('route-web', route_token()))
            ing.close()

    def test_second_writer_and_unsafe_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            ing, fake = make_ingress(tmp)
            with self.assertRaises(ingress.IngressError) as ctx:
                make_ingress(tmp)
            self.assertEqual(ctx.exception.code, 'ingress-in-use')
            ing.close()
            bad = os.path.join(tmp, 'bad')
            os.mkdir(bad, 0o700)
            os.symlink('/dev/null', os.path.join(bad, 'version.json'))
            with self.assertRaises(ingress.IngressError) as ctx:
                make_ingress(bad)
            self.assertEqual(ctx.exception.code, 'ingress-path-unsafe')
            corrupt = os.path.join(tmp, 'corrupt')
            os.mkdir(corrupt, 0o700)
            path = os.path.join(corrupt, 'version.json')
            with open(path, 'w') as handle:
                handle.write('{"schemaVersion":2,"version":"one"}')
            os.chmod(path, 0o600)
            with self.assertRaises(ingress.IngressError) as ctx:
                make_ingress(corrupt)
            self.assertEqual(ctx.exception.code, 'ingress-state-corrupt')
            for raw, code in (
                    ('{"schemaVersion": 2, "version": 1}',
                     'ingress-path-unsafe'),
                    ('{"schemaVersion":2.0,"version":1}',
                     'ingress-state-corrupt'),
                    ('{"schemaVersion":2,"version":9223372036854775808}',
                     'ingress-state-corrupt')):
                with open(path, 'w') as handle:
                    handle.write(raw)
                os.chmod(path, 0o600)
                with self.assertRaises(ingress.IngressError,
                                       msg=raw) as ctx:
                    make_ingress(corrupt)
                self.assertEqual(ctx.exception.code, code)

    def test_parent_fsync_failure_keeps_created_inode(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = statefiles._sync_dir

            def boom(path):
                raise OSError('fsync failed')

            statefiles._sync_dir = boom
            try:
                with self.assertRaises(ingress.IngressError) as ctx:
                    make_ingress(tmp)
                self.assertEqual(ctx.exception.code,
                                 'ingress-unavailable')
            finally:
                statefiles._sync_dir = original
            # The create failed its durability proof but the inode must
            # remain: another process may already hold a lock on it.
            lock_path = os.path.join(tmp, 'ingress.lock')
            first = os.lstat(lock_path)
            self.assertTrue(stat.S_ISREG(first.st_mode))
            self.assertEqual(stat.S_IMODE(first.st_mode), 0o600)
            held = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
            try:
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                # Retry with a healthy parent sync reuses the same
                # inode; a competing lock still conflicts, proving the
                # file was never replaced.
                self.assertFalse(
                    statefiles.ensure_private_file(lock_path))
                self.assertEqual(os.lstat(lock_path).st_ino,
                                 first.st_ino)
                contender = os.open(lock_path,
                                    os.O_RDWR | os.O_NOFOLLOW)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(contender,
                                    fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(contender)
            finally:
                os.close(held)
            ing, _ = make_ingress(tmp)
            ing.close()

    def test_close_blocks_inflight_poll(self):
        with tempfile.TemporaryDirectory() as tmp:
            gate = threading.Event()
            entered = threading.Event()

            def fetcher(nonce):
                entered.set()
                gate.wait(timeout=10)
                return snapshot(nonce, now=1000.0)

            ing, fake = make_ingress(tmp, fetcher=fetcher)
            results = []

            def polled():
                try:
                    ing.poll()
                    results.append('ok')
                except ingress.IngressError as error:
                    results.append(error.code)

            thread = threading.Thread(target=polled)
            thread.start()
            self.assertTrue(entered.wait(timeout=5))
            ing.close()
            gate.set()
            thread.join(timeout=10)
            self.assertEqual(results, ['ingress-closed'])
            self.assertFalse(ing.authorize('route-web', route_token()))
            self.assertFalse(os.path.exists(
                os.path.join(tmp, 'version.json')))
            with self.assertRaises(ingress.IngressError) as ctx:
                ing.poll()
            self.assertEqual(ctx.exception.code, 'ingress-closed')
            ing2, _ = make_ingress(tmp)
            ing2.close()

    def test_insecure_context_rejected_before_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with self.assertRaises(ingress.IngressError) as ctx:
                ingress.Ingress(ingress_config(tmp), context)
            self.assertEqual(ctx.exception.code, 'insecure-context')
            self.assertFalse(os.path.exists(
                os.path.join(tmp, 'ingress.lock')))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            with self.assertRaises(ingress.IngressError):
                ingress.Ingress(ingress_config(tmp), context)

    def test_fetch_requires_json_mime(self):
        with tempfile.TemporaryDirectory() as tmp:
            ing, fake = make_ingress(tmp)

            class Plain(common.Handler):
                def route(self, method):
                    self.send(200, b'{"schemaVersion":2}',
                              content_type='text/plain')

            server = common.Server(('127.0.0.1', 0), Plain)
            thread = threading.Thread(target=server.serve_forever,
                                      daemon=True)
            thread.start()
            try:
                ing._url = 'http://127.0.0.1:{}/v2/routes'.format(
                    server.server_address[1])
                ing._opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler({}))
                with self.assertRaises(ingress.IngressError) as ctx:
                    ing._fetch('ab' * 16)
                self.assertEqual(ctx.exception.code,
                                 'registry-fetch-failed')
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=10)
                ing.close()

    def test_guard_server(self):
        with tempfile.TemporaryDirectory() as tmp:
            ing, fake = make_ingress(tmp)
            ing.poll()
            server = ingress.make_server(ing, port=0)
            thread = threading.Thread(target=server.serve_forever,
                                      daemon=True)
            thread.start()
            port = server.server_address[1]
            try:
                token = route_token()
                conn = http.client.HTTPConnection('127.0.0.1', port,
                                                  timeout=10)
                conn.request('GET', '/authorize/route-web/' + token)
                response = conn.getresponse()
                response.read()
                self.assertEqual(response.status, 200)
                conn.request('GET', '/authorize/route-web/' + '0' * 64)
                response = conn.getresponse()
                body = response.read()
                self.assertEqual(response.status, 503)
                self.assertEqual(body,
                                 b'Service temporarily unavailable.')
                conn.request('GET', '/traefik')
                response = conn.getresponse()
                rendered = json.loads(response.read())
                self.assertEqual(response.status, 200)
                self.assertEqual(
                    backend_url(rendered), 'http://192.168.141.2:8080')
                for method, path in (
                        ('GET', '/unavailable'),
                        ('POST', '/unavailable'),
                        ('GET', '/authorize/route-web/nothex'),
                        ('GET', '/authorize//x'),
                        ('GET', '/traefik?x=1'),
                        ('PUT', '/traefik'),
                        ('GET', '/other')):
                    conn.request(method, path)
                    response = conn.getresponse()
                    response.read()
                    self.assertIn(response.status, (404, 503),
                                  (method, path))
                conn.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=10)
                ing.close()


class FetchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = tempfile.mkdtemp(prefix='nexus-ingress-pki-')
        os.chmod(cls.pki, 0o700)
        cls.ca_key, cls.ca_crt = test_registry_api._ca(
            cls.pki, 'ca', 'Nexus Test CA')
        cls.bad_ca_key, cls.bad_ca_crt = test_registry_api._ca(
            cls.pki, 'badca', 'Unrelated CA')
        cls.server_key, cls.server_crt = test_registry_api._leaf(
            cls.pki, 'server', 100, 'nexus-registry', cls.ca_crt,
            cls.ca_key, 'IP:127.0.0.1,DNS:localhost', 'serverAuth')
        cls.client_key, cls.client_crt = test_registry_api._leaf(
            cls.pki, 'ingress', 200, 'ingress', cls.ca_crt, cls.ca_key,
            'URI:urn:nexus:ingress:edge', 'clientAuth')
        cls.reader_key, cls.reader_crt = test_registry_api._leaf(
            cls.pki, 'reader', 201, 'reader', cls.ca_crt, cls.ca_key,
            'URI:urn:nexus:reader:audit', 'clientAuth')
        cls.controller_key, cls.controller_crt = test_registry_api._leaf(
            cls.pki, 'controller', 202, 'controller', cls.ca_crt,
            cls.ca_key, 'URI:urn:nexus:controller:ops', 'clientAuth')
        cls.host_key, cls.host_crt = test_registry_api._leaf(
            cls.pki, 'host-b', 203, 'host-b', cls.ca_crt, cls.ca_key,
            'URI:urn:nexus:host:host-b', 'clientAuth')
        cls.bad_server_key, cls.bad_server_crt = test_registry_api._leaf(
            cls.pki, 'badserver', 300, 'badserver', cls.bad_ca_crt,
            cls.bad_ca_key, 'IP:127.0.0.1', 'serverAuth')
        cls.wrong_server_key, cls.wrong_server_crt = \
            test_registry_api._leaf(
                cls.pki, 'wronghost', 301, 'wronghost', cls.ca_crt,
                cls.ca_key, 'DNS:wronghost.test', 'serverAuth')

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.pki)

    def client_context(self, crt, key, ca=None):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=ca or self.ca_crt)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if crt:
            context.load_cert_chain(crt, key)
        return context

    def server_context(self, crt=None, key=None, ca=None):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,
                                             cafile=ca or self.ca_crt)
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(crt or self.server_crt,
                                key or self.server_key)
        return context

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nexus-ingress-')
        os.chmod(self.tmp, 0o700)
        self.registry_config = test_registry.make_config()
        self.reg = registry.Registry(
            self.registry_config, os.path.join(self.tmp, 'registry.db'))
        clients = [
            {'identity': 'urn:nexus:controller:ops',
             'role': 'controller', 'hostId': None},
            {'identity': 'urn:nexus:reader:audit',
             'role': 'reader', 'hostId': None},
            {'identity': 'urn:nexus:ingress:edge',
             'role': 'ingress', 'hostId': None},
            {'identity': 'urn:nexus:host:host-b',
             'role': 'host', 'hostId': 'host-b'},
        ]
        self.server = registry_api.make_server(
            self.reg, clients, ('127.0.0.1', 0), self.server_context())
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=10)
        self.reg.close()
        shutil.rmtree(self.tmp)

    def call(self, context, method, path, body=None):
        conn = http.client.HTTPSConnection('127.0.0.1', self.port,
                                           context=context, timeout=10)
        try:
            conn.request(method, path, body=json.dumps(body).encode()
                         if body is not None else None,
                         headers={'Content-Type': 'application/json'}
                         if body is not None else {})
            response = conn.getresponse()
            data = response.read()
        finally:
            conn.close()
        return response.status, json.loads(data)

    def publish(self):
        controller = self.client_context(self.controller_crt,
                                         self.controller_key)
        status, payload = self.call(
            controller, 'POST', '/v2/placements/assign',
            test_registry.assign_request(
                instance=test_registry.I2, host='host-b'))
        self.assertEqual(status, 200, payload)
        host = self.client_context(self.host_crt, self.host_key)
        status, session = self.call(host, 'POST', '/v2/hosts/session',
                                    {'schemaVersion': 2,
                                     'hostId': 'host-b'})
        self.assertEqual(status, 200, session)
        status, payload = self.call(
            host, 'POST', '/v2/observations',
            test_registry.observation(
                test_registry.I2, 'host-b', session['sessionId'], 1,
                time.time(), 'running', 'active', False, False,
                '192.168.141.2', ('web',), generation=1))
        self.assertEqual(status, 200, payload)
        status, payload = self.call(
            controller, 'POST', '/v2/placements/publish',
            test_registry.placement_request(1))
        self.assertEqual(status, 200, payload)

    def test_mtls_fetch_rbac_and_tls_rejection(self):
        self.publish()
        state_dir = os.path.join(self.tmp, 'state')
        os.mkdir(state_dir, 0o700)
        config = ingress_config(
            state_dir, url='https://127.0.0.1:' + str(self.port))
        ing = ingress.Ingress(
            config, self.client_context(self.client_crt, self.client_key))
        try:
            ing.poll()
            rendered = ing.dynamic_config()
            self.assertEqual(backend_url(rendered),
                             'http://192.168.141.2:8080')
            token = auth_url(rendered).rsplit('/', 1)[1]
            self.assertTrue(ing.authorize('route-web', token))
        finally:
            ing.close()
        reader = ingress.Ingress(
            config, self.client_context(self.reader_crt,
                                        self.reader_key))
        try:
            with self.assertRaises(ingress.IngressError) as ctx:
                reader.poll()
            self.assertEqual(ctx.exception.code,
                             'registry-fetch-failed')
        finally:
            reader.close()
        foreign = ingress.Ingress(
            config, self.client_context(self.client_crt, self.client_key,
                                        ca=self.bad_ca_crt))
        try:
            with self.assertRaises(ingress.IngressError):
                foreign.poll()
        finally:
            foreign.close()

    def _extra_server(self, crt, key):
        clients = [{'identity': 'urn:nexus:ingress:edge',
                    'role': 'ingress', 'hostId': None}]
        server = registry_api.make_server(
            self.reg, clients, ('127.0.0.1', 0),
            self.server_context(crt, key))
        thread = threading.Thread(target=server.serve_forever,
                                  daemon=True)
        thread.start()
        return server, thread

    def test_wrong_ca_and_hostname_servers_rejected(self):
        state_dir = os.path.join(self.tmp, 'state')
        os.mkdir(state_dir, 0o700)
        for crt, key in ((self.bad_server_crt, self.bad_server_key),
                         (self.wrong_server_crt, self.wrong_server_key)):
            server, thread = self._extra_server(crt, key)
            try:
                config = ingress_config(
                    state_dir,
                    url='https://127.0.0.1:'
                        + str(server.server_address[1]))
                ing = ingress.Ingress(
                    config, self.client_context(self.client_crt,
                                                self.client_key))
                try:
                    with self.assertRaises(ingress.IngressError):
                        ing.poll()
                finally:
                    ing.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=10)

    def test_redirect_refused(self):
        hits = []

        class Redirector(common.Handler):
            def route(self, method):
                hits.append(self.path)
                if self.path == '/v2/routes':
                    self.send_response(302)
                    self.send_header('Location', '/v2/elsewhere')
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                else:
                    self.send(200, {'schemaVersion': 2})

        server = common.Server(('127.0.0.1', 0), Redirector)
        thread = threading.Thread(target=server.serve_forever,
                                  daemon=True)
        thread.start()
        try:
            url = 'http://127.0.0.1:' + str(server.server_address[1])
            opener = urllib.request.build_opener(
                ingress._NoRedirect(), urllib.request.ProxyHandler({}))
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                opener.open(urllib.request.Request(
                    url + '/v2/routes'), timeout=3)
            self.assertEqual(ctx.exception.code, 302)
            ctx.exception.close()
            self.assertEqual(hits, ['/v2/routes'])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=10)


if __name__ == '__main__':
    unittest.main()
