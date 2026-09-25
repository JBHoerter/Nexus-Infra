#!/usr/bin/env python3
"""Opt-in local Traefik + ingress integration harness (M3).

Runs ONLY inside a rootless user+network namespace that already carries
192.168.140.2/32 and 192.168.141.2/32 on loopback, e.g.:

    unshare --user --map-root-user --mount --net bash -c '
        mount -t tmpfs tmpfs /tmp
        ip link set lo up
        ip addr add 192.168.140.2/32 dev lo
        ip addr add 192.168.141.2/32 dev lo
        exec python3 tests/workload-ingress-local.py \
            --traefik /abs/path/traefik --lab /abs/private/labdir'

Synthetic backends bind those two IPs:8080 inside the namespace; a real
registry_api mTLS server listens on 127.0.0.1:9444, the ingress guard on
127.0.0.1:9445 and Traefik on 127.0.0.1:18080. Host observations are
synthetic — this is NOT the worker or overlay VM proof, only the
route-handoff and expiry-enforcement proof.
"""
import argparse
import copy
import http.client
import http.server
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

CONSOLE = Path(__file__).resolve().parent.parent / 'console'
sys.path.insert(0, str(CONSOLE))
import common
import ingress
import registry
import registry_api
import test_registry
import test_registry_api

SOURCE_IP, TARGET_IP = '192.168.140.2', '192.168.141.2'
HOSTNAME = 'canary.internal'
REGISTRY_PORT, GUARD_PORT, TRAEFIK_PORT = 9444, 9445, 18080
RESULTS = []


def record(phase, result, **detail):
    entry = {'phase': phase, 'status': result}
    entry.update(detail)
    RESULTS.append(entry)
    print(json.dumps(entry, sort_keys=True), flush=True)


def fail(phase, **detail):
    record(phase, 'fail', **detail)
    raise SystemExit(1)


def wait_for(phase, fn, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            last = fn()
        except Exception:
            time.sleep(0.25)
            continue
        if last:
            return last
        time.sleep(0.25)
    return None


def require_lo_ips():
    output = subprocess.run(['ip', '-j', 'address', 'show', 'dev', 'lo'],
                            capture_output=True, check=True, text=True)
    addresses = {item['local'] for item in
                 json.loads(output.stdout)[0]['addr_info']
                 if item['family'] == 'inet'}
    if not {SOURCE_IP, TARGET_IP} <= addresses:
        print(json.dumps({'event': 'namespace-missing',
                          'required': sorted({SOURCE_IP, TARGET_IP})}))
        raise SystemExit('namespace private IPs not present on lo')


def backend(ip, body, counts):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            counts['hits'] += 1
            data = body.encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer((ip, 8080), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def client_context(crt, key, ca):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=ca)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(crt, key)
    return context


def server_context(crt, key, ca):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,
                                         cafile=ca)
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(crt, key)
    return context


def api_call(context, method, path, body=None, nonce=None):
    conn = http.client.HTTPSConnection('127.0.0.1', REGISTRY_PORT,
                                       context=context, timeout=10)
    headers = {}
    if body is not None:
        headers['Content-Type'] = 'application/json'
    if nonce is not None:
        headers['X-Nexus-Nonce'] = nonce
    try:
        conn.request(method, path,
                     body=json.dumps(body).encode()
                     if body is not None else None, headers=headers)
        response = conn.getresponse()
        data = response.read()
    finally:
        conn.close()
    return response.status, json.loads(data)


def must(result, phase, expect=200):
    status, payload = result
    if status != expect:
        fail(phase, httpStatus=status, payload=payload)
    return payload


def app_request(counts):
    conn = http.client.HTTPConnection('127.0.0.1', TRAEFIK_PORT,
                                      timeout=10)
    try:
        conn.request('GET', '/', headers={'Host': HOSTNAME})
        response = conn.getresponse()
        body = response.read()
        return response.status, body
    except OSError:
        return 0, b''
    finally:
        conn.close()


def provider_doc():
    conn = http.client.HTTPConnection('127.0.0.1', GUARD_PORT,
                                      timeout=10)
    try:
        conn.request('GET', '/traefik')
        response = conn.getresponse()
        return json.loads(response.read())
    finally:
        conn.close()


def provider_url(doc):
    return doc['http']['services']['nexus-route-web'][
        'loadBalancer']['servers'][0]['url']


def provider_token(doc):
    return doc['http']['middlewares']['nexus-route-web-guard'][
        'forwardAuth']['address'].rsplit('/', 1)[1]


def observation_for(instance, host, session, sequence, **fields):
    base = dict(phase='running', unit='active', drained=False,
                retired=False, ready=('web',))
    base.update(fields)
    return test_registry.observation(
        instance, host, session, sequence, time.time(),
        base['phase'], base['unit'], base['drained'], base['retired'],
        base.get('endpoint'), base['ready'], generation=base['generation'])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--traefik', required=True)
    parser.add_argument('--lab', required=True)
    args = parser.parse_args()
    traefik = os.path.abspath(args.traefik)
    lab = os.path.abspath(args.lab)
    if not os.path.isfile(traefik) or not os.access(traefik, os.X_OK):
        raise SystemExit('traefik executable missing: ' + traefik)
    require_lo_ips()
    if not os.path.isdir(os.path.dirname(lab)):
        raise SystemExit('lab parent missing: '
                         + os.path.dirname(lab))
    try:
        os.mkdir(lab, 0o700)
    except FileExistsError:
        raise SystemExit('lab directory already exists: ' + lab)
    logs = os.path.join(lab, 'logs')
    os.mkdir(logs, 0o700)
    work = tempfile.mkdtemp(prefix='nexus-ingress-')
    os.chmod(work, 0o700)
    version = subprocess.run([traefik, 'version'], capture_output=True,
                             check=True, text=True).stdout.splitlines()[0]
    record('environment', 'ok', traefik=version, work=work)

    pki = os.path.join(work, 'pki')
    os.mkdir(pki, 0o700)
    ca_key, ca_crt = test_registry_api._ca(pki, 'ca', 'Nexus Test CA')
    server_key, server_crt = test_registry_api._leaf(
        pki, 'server', 100, 'nexus-registry', ca_crt, ca_key,
        'IP:127.0.0.1,DNS:localhost', 'serverAuth')
    certs = {}
    serial = 200
    for name, uri in (
            ('controller', 'urn:nexus:controller:ops'),
            ('reader', 'urn:nexus:reader:audit'),
            ('ingress', 'urn:nexus:ingress:edge'),
            ('host-a', 'urn:nexus:host:host-a'),
            ('host-b', 'urn:nexus:host:host-b')):
        certs[name] = test_registry_api._leaf(
            pki, name, serial, name, ca_crt, ca_key,
            'URI:' + uri, 'clientAuth')
        serial += 1
    contexts = {name: client_context(crt, key, ca_crt)
                for name, (key, crt) in certs.items()}

    counts = {'source': {'hits': 0}, 'target': {'hits': 0}}
    servers = [
        backend(SOURCE_IP, 'source-canary', counts['source']),
        backend(TARGET_IP, 'target-canary', counts['target'])]
    registry_config = test_registry.make_config()
    reg = registry.Registry(
        registry_config, os.path.join(work, 'registry.db'))
    clients = [
        {'identity': 'urn:nexus:controller:ops', 'role': 'controller',
         'hostId': None},
        {'identity': 'urn:nexus:reader:audit', 'role': 'reader',
         'hostId': None},
        {'identity': 'urn:nexus:ingress:edge', 'role': 'ingress',
         'hostId': None},
        {'identity': 'urn:nexus:host:host-a', 'role': 'host',
         'hostId': 'host-a'},
        {'identity': 'urn:nexus:host:host-b', 'role': 'host',
         'hostId': 'host-b'},
    ]
    registry_server = registry_api.make_server(
        reg, clients, ('127.0.0.1', REGISTRY_PORT),
        server_context(server_crt, server_key, ca_crt))
    threading.Thread(target=registry_server.serve_forever,
                     daemon=True).start()

    state_dir = os.path.join(work, 'state')
    os.mkdir(state_dir, 0o700)
    ingress_config = {'schemaVersion': 2,
                      'registryUrl': 'https://127.0.0.1:'
                                     + str(REGISTRY_PORT),
                      'registry': registry_config,
                      'listenPort': GUARD_PORT, 'stateDir': state_dir}
    ing = ingress.Ingress(ingress_config, contexts['ingress'])
    guard = ingress.make_server(ing)
    threading.Thread(target=guard.serve_forever, daemon=True).start()

    log_path = os.path.join(logs, 'traefik.log')
    log_file = open(log_path, 'w')
    traefik_proc = subprocess.Popen(
        [traefik,
         '--entrypoints.web.address=127.0.0.1:' + str(TRAEFIK_PORT),
         '--providers.http.endpoint=http://127.0.0.1:'
         + str(GUARD_PORT) + '/traefik',
         '--providers.http.pollinterval=1s',
         '--global.checknewversion=false',
         '--global.sendanonymoususage=false'],
        stdout=log_file, stderr=subprocess.STDOUT)

    def cleanup():
        traefik_proc.terminate()
        try:
            traefik_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            traefik_proc.kill()
            traefik_proc.wait(timeout=10)
        guard.shutdown()
        guard.server_close()
        registry_server.shutdown()
        registry_server.server_close()
        ing.close()
        reg.close()
        for server in servers:
            server.shutdown()
            server.server_close()
        log_file.close()

    try:
        ready = wait_for('startup', lambda: app_request(counts)[0] != 0)
        if not ready:
            fail('startup', reason='traefik not listening')

        # Phase 1: no accepted snapshot — guard denies, backend untouched.
        status, body = app_request(counts)
        if status != 503 or counts['source']['hits']:
            fail('initial-deny', httpStatus=status)
        record('initial-deny', 'ok', httpStatus=status)

        # Phase 2: A assigned, ready, published — route serves source.
        must(api_call(
            contexts['controller'], 'POST', '/v2/placements/assign',
            test_registry.assign_request(instance=test_registry.I1,
                                         host='host-a')), 'assign-a')
        session_a = must(api_call(
            contexts['host-a'], 'POST', '/v2/hosts/session',
            {'schemaVersion': 2, 'hostId': 'host-a'}),
            'session-a')['sessionId']
        must(api_call(
            contexts['host-a'], 'POST', '/v2/observations',
            observation_for(test_registry.I1, 'host-a', session_a, 1,
                            endpoint=SOURCE_IP, generation=1)),
            'observe-a-1')
        must(api_call(
            contexts['controller'], 'POST', '/v2/placements/publish',
            test_registry.placement_request(1)), 'publish-a')
        ing.poll()
        rendered = ing.dynamic_config()
        served = wait_for('serve-source', lambda: app_request(counts)
                          == (200, b'source-canary'))
        if not served:
            fail('serve-source', httpStatus=app_request(counts)[0])
        record('serve-source', 'ok', hits=counts['source']['hits'])
        status, payload = api_call(
            contexts['reader'], 'POST', '/v2/placements/publish',
            test_registry.placement_request(1, 'e1' * 16))
        if status != 403:
            fail('reader-publish', httpStatus=status)
        record('reader-publish', 'ok', httpStatus=status)

        # Phase 3: successor requires retired+drained evidence.
        status, payload = api_call(
            contexts['controller'], 'POST', '/v2/placements/assign',
            test_registry.assign_request(instance=test_registry.I2,
                                         host='host-b', expected=1,
                                         request_id='b1' * 16))
        if status != 409:
            fail('assign-b-running', httpStatus=status, payload=payload)
        must(api_call(
            contexts['host-a'], 'POST', '/v2/observations',
            observation_for(test_registry.I1, 'host-a', session_a, 2,
                            phase='stopped', unit='inactive',
                            drained=True, endpoint=SOURCE_IP,
                            ready=(), generation=1)), 'observe-a-2')
        status, payload = api_call(
            contexts['controller'], 'POST', '/v2/placements/assign',
            test_registry.assign_request(instance=test_registry.I2,
                                         host='host-b', expected=1,
                                         request_id='b2' * 16))
        if status != 409:
            fail('assign-b-stopped', httpStatus=status, payload=payload)
        must(api_call(
            contexts['host-a'], 'POST', '/v2/observations',
            observation_for(test_registry.I1, 'host-a', session_a, 3,
                            phase='stopped', unit='inactive',
                            drained=True, retired=True,
                            endpoint=SOURCE_IP, ready=(),
                            generation=1)), 'observe-a-3')
        status, payload = api_call(
            contexts['controller'], 'POST', '/v2/placements/assign',
            test_registry.assign_request(instance=test_registry.I2,
                                         host='host-b', expected=1,
                                         request_id='b3' * 16))
        if status != 200 or payload['generation'] != 2:
            fail('assign-b-retired', httpStatus=status, payload=payload)
        record('assign-b-retired', 'ok', generation=2)
        ing.poll()
        old_token = rendered['http']['middlewares'][
            'nexus-route-web-guard']['forwardAuth']['address'].rsplit(
                '/', 1)[1]
        if ing.authorize('route-web', old_token):
            fail('old-token', reason='stale token still authorized')
        status, body = app_request(counts)
        if status != 503:
            fail('unpublished-b', httpStatus=status)
        record('unpublished-b', 'ok', httpStatus=status)
        session_b = must(api_call(
            contexts['host-b'], 'POST', '/v2/hosts/session',
            {'schemaVersion': 2, 'hostId': 'host-b'}),
            'session-b')['sessionId']
        must(api_call(
            contexts['host-b'], 'POST', '/v2/observations',
            observation_for(test_registry.I2, 'host-b', session_b, 1,
                            endpoint=TARGET_IP, generation=2)),
            'observe-b-1')
        must(api_call(
            contexts['controller'], 'POST', '/v2/placements/publish',
            test_registry.placement_request(2, 'c2' * 16)), 'publish-b')
        ing.poll()
        served = wait_for('serve-target', lambda: app_request(counts)
                          == (200, b'target-canary'))
        if not served:
            fail('serve-target', httpStatus=app_request(counts)[0])
        record('serve-target', 'ok', hits=counts['target']['hits'])
        status, payload = api_call(
            contexts['controller'], 'POST', '/v2/placements/publish',
            test_registry.placement_request(1, 'e2' * 16))
        if status != 409:
            fail('stale-publish', httpStatus=status, payload=payload)
        record('stale-publish', 'ok', httpStatus=status)

        # Phase 4: freeze the provider document to a deep copy of the
        # live render. Traefik then keeps routing to the real backend
        # from its cached doc — the only thing that can deny the next
        # request is the per-request guard token check.
        frozen = copy.deepcopy(ing.dynamic_config())
        if TARGET_IP + ':8080' not in provider_url(frozen):
            fail('freeze', url=provider_url(frozen))
        frozen_token = provider_token(frozen)
        ing.dynamic_config = lambda: copy.deepcopy(frozen)
        live = provider_doc()
        if TARGET_IP + ':8080' not in provider_url(live) \
                or provider_token(live) != frozen_token:
            fail('freeze-live-doc')
        target_before = counts['target']['hits']
        time.sleep(11)
        cached = provider_doc()
        if TARGET_IP + ':8080' not in provider_url(cached) \
                or provider_token(cached) != frozen_token:
            fail('frozen-doc')
        status, body = app_request(counts)
        if status != 503 or counts['target']['hits'] != target_before:
            fail('expired-deny', httpStatus=status,
                 hits=counts['target']['hits'])
        record('expired-deny', 'ok', httpStatus=status,
               cachedUrl=provider_url(cached))
        del ing.dynamic_config
        must(api_call(
            contexts['host-b'], 'POST', '/v2/observations',
            observation_for(test_registry.I2, 'host-b', session_b, 2,
                            endpoint=TARGET_IP, generation=2)),
            'observe-b-2')
        ing.poll()
        served = wait_for('resume-target', lambda: app_request(counts)
                          == (200, b'target-canary'))
        if not served:
            fail('resume-target', httpStatus=app_request(counts)[0])
        record('resume-target', 'ok')

        # Phase 5: dead guard fails closed; fresh ingress denies until poll.
        target_before = counts['target']['hits']
        guard.shutdown()
        guard.server_close()
        status, body = app_request(counts)
        if status not in (500, 502, 503) \
                or counts['target']['hits'] != target_before:
            fail('dead-guard', httpStatus=status,
                 hits=counts['target']['hits'])
        record('dead-guard', 'ok', httpStatus=status)
        ing.close()
        ing = ingress.Ingress(ingress_config, contexts['ingress'])
        guard = ingress.make_server(ing)
        threading.Thread(target=guard.serve_forever, daemon=True).start()
        status, body = app_request(counts)
        if status != 503:
            fail('restart-deny', httpStatus=status)
        record('restart-deny', 'ok', httpStatus=status)
        ing.poll()
        served = wait_for('resume-after-restart',
                          lambda: app_request(counts)
                          == (200, b'target-canary'))
        if not served:
            fail('resume-after-restart',
                 httpStatus=app_request(counts)[0])
        record('resume-after-restart', 'ok')
        record('complete', 'ok')
    finally:
        try:
            with open(os.path.join(logs, 'results.json'), 'w') \
                    as handle:
                json.dump(RESULTS, handle, indent=1)
        finally:
            cleanup()
    print(json.dumps({'result': 'pass', 'phases': len(RESULTS)}))


if __name__ == '__main__':
    main()
