"""Real local-TLS integration tests for console/registry_api.py (M3).

Generates an ephemeral EC CA, a server certificate and per-role client
certificates with openssl inside a private temporary directory, then serves
a real Registry through make_server on loopback. Every authenticated
request presents a client certificate; principals come only from the
verified URI SAN. No private key material is printed.
"""
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error

import registry
import registry_api
import test_registry


def api_config(db_path):
    return {
        'schemaVersion': 2,
        'listenAddress': '127.0.0.1',
        'port': 9444,
        'dbPath': db_path,
        'registry': test_registry.make_config(),
        'clients': [
            {'identity': 'urn:nexus:controller:ops',
             'role': 'controller', 'hostId': None},
            {'identity': 'urn:nexus:reader:audit',
             'role': 'reader', 'hostId': None},
            {'identity': 'urn:nexus:ingress:edge',
             'role': 'ingress', 'hostId': None},
            {'identity': 'urn:nexus:host:host-a',
             'role': 'host', 'hostId': 'host-a'},
            {'identity': 'urn:nexus:host:host-b',
             'role': 'host', 'hostId': 'host-b'},
        ],
    }


CLIENTS = api_config('/x')['clients']


def _openssl(directory, *args):
    subprocess.run(('openssl',) + args, cwd=directory, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _ca(directory, name, cn):
    key = os.path.join(directory, name + '.key')
    crt = os.path.join(directory, name + '.crt')
    _openssl(directory, 'ecparam', '-genkey', '-name', 'prime256v1',
             '-out', key)
    _openssl(directory, 'req', '-x509', '-new', '-key', key, '-out', crt,
             '-days', '1', '-subj', '/CN=' + cn,
             '-addext', 'basicConstraints=critical,CA:TRUE',
             '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    return key, crt


def _leaf(directory, name, serial, cn, ca_crt, ca_key, san, eku):
    key = os.path.join(directory, name + '.key')
    csr = os.path.join(directory, name + '.csr')
    crt = os.path.join(directory, name + '.crt')
    ext = os.path.join(directory, name + '.ext')
    _openssl(directory, 'ecparam', '-genkey', '-name', 'prime256v1',
             '-out', key)
    _openssl(directory, 'req', '-new', '-key', key, '-out', csr,
             '-subj', '/CN=' + cn)
    with open(ext, 'w') as handle:
        handle.write('basicConstraints=critical,CA:FALSE\n'
                     'keyUsage=critical,digitalSignature\n'
                     'extendedKeyUsage=' + eku + '\n')
        if san:
            handle.write('subjectAltName=' + san + '\n')
    _openssl(directory, 'x509', '-req', '-in', csr, '-CA', ca_crt,
             '-CAkey', ca_key, '-set_serial', str(serial), '-days', '1',
             '-out', crt, '-extfile', ext)
    return key, crt


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = tempfile.mkdtemp(prefix='nexus-pki-')
        os.chmod(cls.pki, 0o700)
        cls.ca_key, cls.ca_crt = _ca(cls.pki, 'ca', 'Nexus Test CA')
        cls.bad_ca_key, cls.bad_ca_crt = _ca(cls.pki, 'badca',
                                             'Unrelated CA')
        cls.server_key, cls.server_crt = _leaf(
            cls.pki, 'server', 100, 'nexus-registry', cls.ca_crt, cls.ca_key,
            'IP:127.0.0.1,DNS:localhost,IP:0:0:0:0:0:0:0:1', 'serverAuth')
        serial = 200
        cls.certs = {}
        for name, uri in (
                ('controller', 'urn:nexus:controller:ops'),
                ('reader', 'urn:nexus:reader:audit'),
                ('ingress', 'urn:nexus:ingress:edge'),
                ('host-a', 'urn:nexus:host:host-a'),
                ('host-b', 'urn:nexus:host:host-b'),
                ('ghost', 'urn:nexus:reader:ghost')):
            cls.certs[name] = _leaf(
                cls.pki, name, serial, name, cls.ca_crt, cls.ca_key,
                'URI:' + uri + ',DNS:' + name + '.test', 'clientAuth')
            serial += 1
        cls.certs['cn-only'] = _leaf(
            cls.pki, 'cn-only', serial, 'urn:nexus:controller:ops',
            cls.ca_crt, cls.ca_key, None, 'clientAuth')
        serial += 1
        cls.certs['multi-uri'] = _leaf(
            cls.pki, 'multi-uri', serial, 'multi', cls.ca_crt, cls.ca_key,
            'URI:urn:nexus:controller:ops,URI:urn:nexus:reader:audit',
            'clientAuth')
        serial += 1
        cls.certs['rogue'] = _leaf(
            cls.pki, 'rogue', 1, 'rogue', cls.bad_ca_crt, cls.bad_ca_key,
            'URI:urn:nexus:controller:ops', 'clientAuth')

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.pki)

    def client_context(self, name=None, ca=None):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=ca or self.ca_crt)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        if name is not None:
            key, crt = self.certs[name]
            context.load_cert_chain(crt, key)
        return context

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nexus-api-')
        os.chmod(self.tmp, 0o700)
        self.db_path = os.path.join(self.tmp, 'registry.db')
        self.config = registry_api.validate_config(api_config(self.db_path))
        self._open_server()

    def _open_server(self):
        self.reg = registry.Registry(self.config['registry'], self.db_path)
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,
                                             cafile=self.ca_crt)
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.server_crt, self.server_key)
        self.server = registry_api.make_server(
            self.reg, self.config['clients'], ('127.0.0.1', 0), context)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()

    def _close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=10)
        self.reg.close()

    def tearDown(self):
        self._close_server()
        shutil.rmtree(self.tmp)

    def call(self, context, method, path, body=None, headers=(),
             content_type='application/json'):
        conn = http.client.HTTPSConnection('127.0.0.1', self.port,
                                           context=context, timeout=10)
        try:
            conn.putrequest(method, path)
            for name, value in headers:
                conn.putheader(name, value)
            if body is not None:
                conn.putheader('Content-Type', content_type)
                conn.putheader('Content-Length', str(len(body)))
            conn.endheaders()
            if body:
                conn.send(body)
            response = conn.getresponse()
            data = response.read()
        finally:
            conn.close()
        return response.status, json.loads(data) if data else {}

    def post_json(self, name, path, payload, **kwargs):
        return self.call(self.client_context(name), 'POST', path,
                         json.dumps(payload).encode(), **kwargs)

    def test_validate_config(self):
        config = api_config(self.db_path)
        self.assertEqual(
            registry_api.validate_config(config)['clients'], CLIENTS)
        for field, bad in (
                ('listenAddress', 'localhost'),
                ('listenAddress', '127.0.0.01'),
                ('port', 0), ('port', '9444'),
                ('dbPath', 'relative.db'),
                ('clients', []), ('clients', 'x')):
            mutated = dict(config)
            mutated[field] = bad
            with self.assertRaises(registry.RegistryError, msg=bad):
                registry_api.validate_config(mutated)
        for client, msg in (
                ({'identity': 'urn:nexus:controller:ops',
                  'role': 'reader', 'hostId': None}, 'role mismatch'),
                ({'identity': 'urn:nexus:host:host-a',
                  'role': 'host', 'hostId': 'host-b'}, 'host mismatch'),
                ({'identity': 'urn:nexus:host:host-z',
                  'role': 'host', 'hostId': 'host-z'}, 'unknown host'),
                ({'identity': 'urn:nexus:reader:audit',
                  'role': 'reader', 'hostId': 'host-a'}, 'hostId set'),
                ({'identity': 'urn:nexus:READER:audit',
                  'role': 'reader', 'hostId': None}, 'bad identity'),
                ({'identity': 42,
                  'role': 'reader', 'hostId': None}, 'nonstr identity'),
                ({'identity': None,
                  'role': 'reader', 'hostId': None}, 'null identity')):
            mutated = dict(config)
            mutated['clients'] = config['clients'][:1] + [client]
            with self.assertRaises(registry.RegistryError, msg=msg):
                registry_api.validate_config(mutated)

    def test_controller_assign(self):
        status, payload = self.post_json(
            'controller', '/v2/placements/assign',
            test_registry.assign_request())
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload['status'], 'completed')
        self.assertEqual(payload['generation'], 1)

    def test_reader_scope(self):
        context = self.client_context('reader')
        status, payload = self.call(context, 'GET', '/v2/state')
        self.assertEqual(status, 200, payload)
        status, payload = self.post_json(
            'reader', '/v2/placements/assign',
            test_registry.assign_request())
        self.assertEqual(status, 403, payload)
        self.assertEqual(payload['error'], 'forbidden')

    def test_ingress_scope(self):
        context = self.client_context('ingress')
        status, payload = self.call(
            context, 'GET', '/v2/routes',
            headers=(('X-Nexus-Nonce', test_registry.NONCE),))
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload['nonce'], test_registry.NONCE)
        for method, path in (('GET', '/v2/state'),
                             ('GET', '/v2/assignments')):
            status, payload = self.call(context, method, path)
            self.assertEqual(status, 403, payload)
            self.assertEqual(payload['error'], 'forbidden')
        status, payload = self.post_json(
            'ingress', '/v2/placements/assign',
            test_registry.assign_request())
        self.assertEqual(status, 403, payload)

    def test_host_scope(self):
        self.post_json('controller', '/v2/placements/assign',
                       test_registry.assign_request())
        status, session = self.post_json('host-b', '/v2/hosts/session',
                                         {'schemaVersion': 2,
                                          'hostId': 'host-b'})
        self.assertEqual(status, 200, session)
        status, payload = self.call(self.client_context('host-b'),
                                    'GET', '/v2/assignments')
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload['hostId'], 'host-b')
        status, payload = self.post_json(
            'host-b', '/v2/observations',
            test_registry.observation(
                test_registry.I1, 'host-b', session['sessionId'], 1,
                time.time(), 'stopped', 'inactive', True, True,
                '192.168.141.2', ()))
        self.assertEqual(status, 403, payload)
        self.assertEqual(payload['error'], 'instance-mismatch')
        status, payload = self.post_json('host-b', '/v2/hosts/session',
                                         {'schemaVersion': 2,
                                          'hostId': 'host-a'})
        self.assertEqual(status, 403, payload)
        self.assertEqual(payload['error'], 'host-mismatch')

    def test_make_server_context_invariants(self):
        weak = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        weak.load_cert_chain(self.server_crt, self.server_key)
        with self.assertRaises(registry.RegistryError) as ctx:
            registry_api.make_server(
                self.reg, self.config['clients'], ('127.0.0.1', 0), weak)
        self.assertEqual(ctx.exception.code, 'insecure-context')
        weak.verify_mode = ssl.CERT_REQUIRED
        weak.minimum_version = ssl.TLSVersion.TLSv1
        with self.assertRaises(registry.RegistryError) as ctx:
            registry_api.make_server(
                self.reg, self.config['clients'], ('127.0.0.1', 0), weak)
        self.assertEqual(ctx.exception.code, 'insecure-context')

    def test_ipv6_loopback(self):
        try:
            probe = socket.socket(socket.AF_INET6)
            probe.bind(('::1', 0))
            probe.close()
        except OSError:
            self.skipTest('no IPv6 loopback')
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,
                                             cafile=self.ca_crt)
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.server_crt, self.server_key)
        server = registry_api.make_server(
            self.reg, self.config['clients'], ('::1', 0), context)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            conn = http.client.HTTPSConnection(
                '::1', server.server_address[1],
                context=self.client_context('reader'), timeout=10)
            conn.request('GET', '/v2/state')
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
            conn.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=10)

    def test_certificate_authorization(self):
        for name in ('ghost', 'cn-only', 'multi-uri'):
            status, payload = self.call(
                self.client_context(name), 'GET', '/v2/state')
            self.assertEqual(status, 403, payload)
            self.assertEqual(payload['error'], 'client-not-authorized',
                             name)

    def test_missing_and_foreign_certificates_rejected(self):
        with self.assertRaises((ssl.SSLError, urllib.error.URLError,
                                ConnectionResetError)):
            self.call(self.client_context(), 'GET', '/v2/state')
        with self.assertRaises((ssl.SSLError, urllib.error.URLError,
                                ConnectionResetError)):
            self.call(self.client_context('rogue'), 'GET', '/v2/state')
        entry = self.reg.state(
            registry.Principal('local', 'reader'))['workloads'][0]
        self.assertEqual(entry['generation'], 0)

    def test_header_role_spoofing_rejected(self):
        status, payload = self.post_json(
            'reader', '/v2/placements/assign',
            test_registry.assign_request(),
            headers=(('X-Nexus-Role', 'controller'),
                     ('X-Nexus-Identity', 'urn:nexus:controller:ops'),
                     ('X-Forwarded-User', 'ops')))
        self.assertEqual(status, 403, payload)
        self.assertEqual(payload['error'], 'forbidden')

    def test_strict_json_bodies(self):
        base = {'schemaVersion': 2, 'hostId': 'host-a'}
        cases = (
            (b'{"schemaVersion":2,"schemaVersion":2,"hostId":"host-a"}',
             'duplicate keys'),
            (b'{"schemaVersion":NaN,"hostId":"host-a"}', 'NaN'),
            (('{"schemaVersion":' + str(2**70)
              + ',"hostId":"host-a"}').encode(), 'huge int'),
            (b'{"schemaVersion":2,"hostId":"host-\xffa"}', 'invalid utf8'),
            (b'x' * 16385, 'oversized'),
            (json.dumps(dict(base, extra=1)).encode(), 'extra field'),
        )
        context = self.client_context('host-a')
        for body, msg in cases:
            status, payload = self.call(context, 'POST',
                                        '/v2/hosts/session', body)
            self.assertEqual(status, 400, msg)
        status, payload = self.call(context, 'POST', '/v2/hosts/session',
                                    b'{}', content_type='text/plain')
        self.assertEqual(status, 415, payload)
        self.assertEqual(payload['error'], 'invalid-content-type')

    def test_framing_rejections(self):
        context = self.client_context('host-a')
        body = json.dumps({'schemaVersion': 2, 'hostId': 'host-a'}).encode()
        conn = http.client.HTTPSConnection('127.0.0.1', self.port,
                                           context=context, timeout=10)
        try:
            conn.putrequest('POST', '/v2/hosts/session')
            conn.putheader('Transfer-Encoding', 'chunked')
            conn.putheader('Content-Length', str(len(body)))
            conn.endheaders()
            conn.send(body)
            response = conn.getresponse()
            payload = json.loads(response.read())
            self.assertEqual(response.status, 400, payload)
        finally:
            conn.close()
        conn = http.client.HTTPSConnection('127.0.0.1', self.port,
                                           context=context, timeout=10)
        try:
            conn.putrequest('POST', '/v2/hosts/session')
            conn.putheader('Content-Type', 'application/json')
            conn.putheader('Content-Length', str(len(body)))
            conn.putheader('Content-Length', str(len(body)))
            conn.endheaders()
            conn.send(body)
            response = conn.getresponse()
            payload = json.loads(response.read())
            self.assertEqual(response.status, 400, payload)
        finally:
            conn.close()
        conn = http.client.HTTPSConnection('127.0.0.1', self.port,
                                           context=context, timeout=10)
        try:
            conn.putrequest('POST', '/v2/hosts/session')
            conn.putheader('Content-Type', 'application/json')
            conn.putheader('Content-Length', '9' * 20)
            conn.endheaders()
            conn.send(body)
            response = conn.getresponse()
            payload = json.loads(response.read())
            self.assertEqual(response.status, 400, payload)
        finally:
            conn.close()
        conn = http.client.HTTPSConnection('127.0.0.1', self.port,
                                           context=context, timeout=10)
        try:
            conn.putrequest('POST', '/v2/hosts/session')
            conn.putheader('Content-Type', 'application/json')
            conn.putheader('Content-Type', 'text/plain')
            conn.putheader('Content-Length', str(len(body)))
            conn.endheaders()
            conn.send(body)
            response = conn.getresponse()
            payload = json.loads(response.read())
            self.assertEqual(response.status, 415, payload)
        finally:
            conn.close()

    def test_browser_headers_rejected(self):
        context = self.client_context('reader')
        for header in (('Origin', 'https://evil.test'),
                       ('Cookie', 'session=1')):
            status, payload = self.call(context, 'GET', '/v2/state',
                                        headers=(header,))
            self.assertEqual(status, 403, payload)
            self.assertEqual(payload['error'], 'browser-request-forbidden')

    def test_operations_dispatch_flow(self):
        # Controller posts; owning host polls, claims, completes.
        self.post_json('controller', '/v2/placements/assign',
                       test_registry.assign_request())
        operation = test_registry.operation_request()
        status, payload = self.post_json('controller',
                                         '/v2/operations', operation)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload['status'], 'accepted')
        self.assertEqual(payload['operationId'], '11' * 16)
        # Replay on requestId is identical; a changed payload 409s.
        status, again = self.post_json('controller', '/v2/operations',
                                       operation)
        self.assertEqual((status, again), (200, payload))
        status, payload = self.post_json(
            'controller', '/v2/operations',
            test_registry.operation_request(step='start', payload={
                'schemaVersion': 1, 'operationId': '11' * 16,
                'action': 'start', 'workloadId': 'canary',
                'revisionDigest': test_registry.DIGEST,
                'instanceId': test_registry.I1, 'generation': 1}))
        self.assertEqual(status, 409, payload)
        # The host sees only its own pending operations.
        context = self.client_context('host-a')
        status, listed = self.call(context, 'GET',
                                   '/v2/operations?host=host-a&after=0')
        self.assertEqual(status, 200, listed)
        self.assertEqual(len(listed['operations']), 1)
        self.assertEqual(listed['operations'][0]['operationId'],
                         '11' * 16)
        status, empty = self.call(self.client_context('host-b'), 'GET',
                                  '/v2/operations?host=host-b&after=0')
        self.assertEqual((status, empty['operations']), (200, []))
        # Claim then complete over the wire.
        status, payload = self.post_json(
            'host-a', '/v2/operations/{}/receipt'.format('11' * 16),
            test_registry.receipt('claimed'))
        self.assertEqual((status, payload['receipt']),
                         (200, 'claimed'))
        status, payload = self.post_json(
            'host-a', '/v2/operations/{}/receipt'.format('11' * 16),
            test_registry.receipt('completed', '44' * 16,
                                  result={'appliedPhase': 'stopped'}))
        self.assertEqual(status, 200, payload)
        # Controller reads back the receipt for the op it posted.
        status, view = self.call(
            self.client_context('controller'), 'GET',
            '/v2/operations/{}?requestId={}'.format('11' * 16,
                                                  '22' * 16))
        self.assertEqual(status, 200, view)
        self.assertEqual(view['status'], 'completed')
        self.assertEqual(view['result'],
                         {'appliedPhase': 'stopped'})

    def test_operations_wrong_roles_and_foreign_host(self):
        self.post_json('controller', '/v2/placements/assign',
                       test_registry.assign_request())
        for name in ('reader', 'ingress', 'host-a'):
            status, payload = self.post_json(
                name, '/v2/operations',
                test_registry.operation_request())
            self.assertEqual(status, 403, (name, payload))
        self.post_json('controller', '/v2/operations',
                       test_registry.operation_request())
        # Wrong host cannot claim or complete.
        for body in (test_registry.receipt('claimed'),
                     test_registry.receipt('failed', '44' * 16,
                                           errorCode='x')):
            status, payload = self.post_json(
                'host-b',
                '/v2/operations/{}/receipt'.format('11' * 16), body)
            self.assertEqual(status, 403, payload)
            self.assertEqual(payload['error'], 'host-mismatch')
        # Host cannot poll another host's queue nor read op status.
        status, payload = self.call(
            self.client_context('host-b'), 'GET',
            '/v2/operations?host=host-a&after=0')
        self.assertEqual(status, 403, payload)
        status, payload = self.call(
            self.client_context('host-a'), 'GET',
            '/v2/operations/{}?requestId={}'.format('11' * 16,
                                                  '22' * 16))
        self.assertEqual(status, 403, payload)
        # Controller with a foreign requestId cannot read it either.
        status, payload = self.call(
            self.client_context('controller'), 'GET',
            '/v2/operations/{}?requestId={}'.format('11' * 16,
                                                  '88' * 16))
        self.assertEqual(status, 403, payload)

    def test_operations_strict_query(self):
        context = self.client_context('host-a')
        for path in ('/v2/operations?host=host-a&after=x',
                     '/v2/operations?host=host-a&bogus=1',
                     '/v2/operations?host=host-a&after=1&after=2',
                     '/v2/operations?' + 'a' * 200):
            status, payload = self.call(context, 'GET', path)
            self.assertEqual(status, 400, path)
        # Query strings on the legacy paths still 404.
        status, payload = self.call(
            self.client_context('reader'), 'GET', '/v2/state?x=1')
        self.assertEqual(status, 404, payload)
        # Unknown operation ids and malformed receipt paths.
        status, payload = self.post_json(
            'host-a', '/v2/operations/{}/receipt'.format('99' * 16),
            test_registry.receipt('claimed'))
        self.assertEqual(status, 404, payload)
        status, payload = self.call(
            context, 'GET', '/v2/operations/{}/receipt'.format(
                '11' * 16))
        self.assertEqual(status, 404, payload)

    def test_nonce_validation(self):
        context = self.client_context('ingress')
        for nonce in (None, 'xyz', test_registry.NONCE.upper()):
            headers = () if nonce is None \
                else (('X-Nexus-Nonce', nonce),)
            status, payload = self.call(context, 'GET', '/v2/routes',
                                        headers=headers)
            self.assertEqual(status, 400, msg=nonce)
            self.assertEqual(payload['error'], 'invalid-nonce')
        conn = http.client.HTTPSConnection('127.0.0.1', self.port,
                                           context=context, timeout=10)
        try:
            conn.putrequest('GET', '/v2/routes')
            conn.putheader('X-Nexus-Nonce', test_registry.NONCE)
            conn.putheader('X-Nexus-Nonce', test_registry.NONCE)
            conn.endheaders()
            response = conn.getresponse()
            payload = json.loads(response.read())
            self.assertEqual(response.status, 400, payload)
            self.assertEqual(payload['error'], 'invalid-nonce')
        finally:
            conn.close()

    def test_unknown_paths_and_queries(self):
        context = self.client_context('controller')
        for method, path in (
                ('GET', '/v1/state'), ('GET', '/v2/state/extra'),
                ('GET', '/v2/state?x=1'), ('POST', '/v2/exec'),
                ('PUT', '/v2/state'), ('DELETE', '/v2/assignments'),
                ('GET', 'http://example.com/v2/state')):
            status, payload = self.call(context, method, path)
            self.assertEqual(status, 404, (method, path))
            self.assertEqual(payload['error'], 'not-found')

    def test_restart_preserves_receipts_and_drops_sessions(self):
        request = test_registry.assign_request()
        status, first = self.post_json('controller',
                                       '/v2/placements/assign', request)
        self.assertEqual(first['status'], 'completed')
        status, session = self.post_json('host-a', '/v2/hosts/session',
                                         {'schemaVersion': 2,
                                          'hostId': 'host-a'})
        self.assertEqual(status, 200, session)
        self._close_server()
        self._open_server()
        status, replay = self.post_json('controller',
                                        '/v2/placements/assign', request)
        self.assertEqual(status, 200, replay)
        self.assertEqual(replay, first)
        status, payload = self.post_json(
            'host-a', '/v2/observations',
            test_registry.observation(
                test_registry.I1, 'host-a', session['sessionId'], 1,
                time.time(), 'stopped', 'inactive', True, True,
                '192.168.140.2', ()))
        self.assertEqual(status, 403, payload)
        self.assertEqual(payload['error'], 'session-mismatch')


    def test_fence_endpoint_over_tls(self):
        self.post_json('controller', '/v2/placements/assign',
                       test_registry.assign_request())
        fence = test_registry.fence_request()
        # Only the controller role may attest a fence.
        for name in ('reader', 'ingress', 'host-a', 'host-b'):
            status, payload = self.post_json(
                name, '/v2/placements/fence', fence)
            self.assertEqual(status, 403, (name, payload))
            self.assertEqual(payload['error'], 'forbidden')
        status, payload = self.post_json(
            'controller', '/v2/placements/fence', fence)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload['status'], 'accepted')
        self.assertEqual(payload['generation'], 1)
        # Identical replay returns the same receipt; a mutated body
        # under the same requestId conflicts.
        status, replay = self.post_json(
            'controller', '/v2/placements/fence', fence)
        self.assertEqual((status, replay), (200, payload))
        status, payload = self.post_json(
            'controller', '/v2/placements/fence',
            dict(fence, evidence='operator'))
        self.assertEqual(status, 409, payload)
        self.assertEqual(payload['error'], 'request-conflict')
        status, payload = self.post_json(
            'controller', '/v2/placements/fence',
            test_registry.fence_request(request_id='f2' * 16,
                                        evidence='bogus'))
        self.assertEqual(status, 400, payload)
        self.assertEqual(payload['error'], 'invalid-evidence')
        # The fence unblocks a successor assign with no observation at
        # all, and the projection is visible to readers.
        status, payload = self.post_json(
            'controller', '/v2/placements/assign',
            test_registry.assign_request(
                test_registry.I2, 'host-b', 1, 'a2' * 16))
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload['generation'], 2)
        status, state = self.call(self.client_context('reader'),
                                  'GET', '/v2/state')
        self.assertEqual(status, 200, state)
        self.assertEqual(len(state['fences']), 1)
        self.assertEqual(state['fences'][0]['hostId'], 'host-a')
        self.assertEqual(state['fences'][0]['attestedBy'],
                         'urn:nexus:controller:ops')


if __name__ == '__main__':
    unittest.main()
