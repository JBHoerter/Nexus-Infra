"""Expiry-enforced ingress consumer for the authenticated registry (M3).

Polls ``GET /v2/routes`` over mutual TLS and renders a Traefik dynamic
configuration plus a local forwardAuth guard. Every generated router
carries a forwardAuth check bound to the CURRENT fresh snapshot token, so
Traefik configuration cached across a guard outage can never route after
expiry — a dead or restarted guard fails closed until a new authenticated
nonce-bound snapshot arrives. The guard never proxies traffic, never sees
application bodies and has no writer-election power; snapshots are
ephemeral hints, never fences.
"""
import argparse
import copy
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import secrets
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import common
import registry
import statefiles
import worker


class IngressError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


_CONFIG_FIELDS = {'schemaVersion', 'registryUrl', 'registry', 'listenPort',
                  'stateDir'}
_SNAPSHOT_FIELDS = {'schemaVersion', 'registryEpoch', 'version', 'nonce',
                    'generatedAt', 'validUntil', 'routes'}
_ROUTE_FIELDS = {'id', 'hostname', 'workloadId', 'serviceId', 'backend'}
_BACKEND_FIELDS = {'instanceId', 'generation', 'hostId', 'revisionDigest',
                   'address', 'port', 'protocol'}
_VERSION_FIELDS = {'schemaVersion', 'version'}
_HOSTNAME_RE = re.compile(
    r'[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?'
    r'(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*')
_GUARD_ID_RE = re.compile(r'[a-z][a-z0-9-]{0,62}')
_GUARD_TOKEN_RE = re.compile(r'[0-9a-f]{64}')
_MAX_CONFIG = 2 * 1024 * 1024
_MAX_SNAPSHOT = 1024 * 1024
_FETCH_TIMEOUT = 3
_POLL_INTERVAL = 2
_MAX_VALIDITY = 10


def _check(fn, *args):
    try:
        fn(*args)
    except worker.WorkerError as error:
        raise IngressError(error.code) from None


def _time(value, code):
    try:
        return registry._bounded_time(value, code)
    except registry.RegistryError as error:
        raise IngressError(error.code) from None


def _paths(fn, *args):
    try:
        return fn(*args)
    except statefiles.PathError as error:
        code = {'path-unsafe': 'ingress-path-unsafe',
                'path-unavailable': 'ingress-unavailable'}[error.code]
        raise IngressError(code) from None


def _registry_url(url):
    if type(url) is not str or len(url) > 512 or '%' in url \
            or any(ord(char) < 0x21 for char in url):
        raise IngressError('invalid-registryUrl')
    try:
        parts = urllib.parse.urlsplit(url)
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        raise IngressError('invalid-registryUrl') from None
    if parts.scheme != 'https' or parts.username is not None \
            or parts.password is not None or parts.query \
            or parts.fragment or parts.path not in ('', '/'):
        raise IngressError('invalid-registryUrl')
    if hostname is None:
        raise IngressError('invalid-registryUrl')
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        if len(hostname) > 253 or not _HOSTNAME_RE.fullmatch(hostname):
            raise IngressError('invalid-registryUrl')
    if port is not None and not 1 <= port <= 65535:
        raise IngressError('invalid-registryUrl')


def validate_config(config):
    _check(worker._fields, config, _CONFIG_FIELDS, 'config')
    _check(worker._integer, config['schemaVersion'], 2, 2,
           'config-schemaVersion')
    _registry_url(config['registryUrl'])
    _check(worker._integer, config['listenPort'], 1, 65535, 'listenPort')
    _check(worker._path, config['stateDir'], 'stateDir')
    registry_config = registry.validate_config(config['registry'])
    return {'schemaVersion': 2, 'registryUrl': config['registryUrl'],
            'registry': registry_config, 'listenPort': config['listenPort'],
            'stateDir': config['stateDir']}


def route_token(epoch, route):
    canonical = json.dumps({'registryEpoch': epoch, 'id': route['id'],
                            'backend': route['backend']},
                           sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(canonical).hexdigest()


def _definitions(registry_config):
    return {(definition['workloadId'], definition['revisionDigest']):
            definition for definition in registry_config['definitions']}


def _executable(definition):
    """Whether the workload may legitimately back an ingress route.

    Declared ``dependencies`` are deliberately NOT re-checked here:
    cross-host dependency readiness is the control plane's gate (the
    controller's verified closure plus the worker's
    ``dependenciesResolved`` marker) — it already ran before the
    workload could be placed and reported running, and the registry
    only emits a backend on exactly that fresh ready evidence. Routing
    is not the layer that owns the dep gate."""
    return definition['category'] not in ('archive', 'infrastructure') \
        and 'start' in definition['allowedOperations'] \
        and definition['secretSetRef'] is None


def _backend(row, backend, definitions, hosts):
    _check(worker._fields, backend, _BACKEND_FIELDS, 'backend')
    _check(worker._hex32, backend['instanceId'], 'backend-instanceId')
    _check(worker._integer, backend['generation'], 1, worker._MAX_I64,
           'backend-generation')
    _check(worker._digest, backend['revisionDigest'],
           'backend-revisionDigest')
    _check(worker._identifier, backend['hostId'], 'backend-hostId')
    _check(worker._integer, backend['port'], 1, 65535, 'backend-port')
    if backend['protocol'] != 'http':
        raise IngressError('invalid-backend')
    definition = definitions.get(
        (row['workloadId'], backend['revisionDigest']))
    if definition is None or not _executable(definition):
        raise IngressError('invalid-backend')
    host = hosts.get(backend['hostId'])
    if host is None or host['architecture'] != definition['architecture']:
        raise IngressError('invalid-backend')
    if backend['address'] not in host['addresses']:
        raise IngressError('invalid-backend')
    service = next((item for item in definition['services']
                    if item['id'] == row['serviceId']), None)
    if service is None or service['protocol'] != 'http' \
            or service['port'] != backend['port']:
        raise IngressError('invalid-backend')


def validate_snapshot(snapshot, config, nonce, *, now, highwater):
    if type(snapshot) is not dict or set(snapshot) != _SNAPSHOT_FIELDS:
        raise IngressError('invalid-snapshot')
    _check(worker._integer, snapshot['schemaVersion'], 2, 2,
           'snapshot-schemaVersion')
    _check(worker._hex32, snapshot['registryEpoch'], 'registryEpoch')
    _check(worker._integer, snapshot['version'], 0, worker._MAX_I64,
           'version')
    if snapshot['version'] < highwater:
        raise IngressError('version-stale')
    if snapshot['nonce'] != nonce:
        raise IngressError('nonce-mismatch')
    generated = _time(snapshot['generatedAt'], 'invalid-generatedAt')
    valid_until = _time(snapshot['validUntil'], 'invalid-validUntil')
    if generated > now:
        raise IngressError('snapshot-future')
    if now - generated > _MAX_VALIDITY:
        raise IngressError('snapshot-stale')
    if not 0 < valid_until - now <= _MAX_VALIDITY \
            or valid_until > generated + _MAX_VALIDITY:
        raise IngressError('invalid-validUntil')
    routes = snapshot['routes']
    configured = config['registry']['routes']
    if type(routes) is not list or len(routes) != len(configured):
        raise IngressError('invalid-routes')
    expected = {route['id']: route for route in configured}
    definitions = _definitions(config['registry'])
    hosts = {host['hostId']: host for host in config['registry']['hosts']}
    seen = set()
    owners = {}
    for row in routes:
        _check(worker._fields, row, _ROUTE_FIELDS, 'route')
        _check(worker._identifier, row['id'], 'route-id')
        route = expected.get(row['id'])
        if route is None or row['id'] in seen:
            raise IngressError('invalid-routes')
        seen.add(row['id'])
        for field in ('hostname', 'workloadId', 'serviceId'):
            if row[field] != route[field]:
                raise IngressError('invalid-routes')
        backend = row['backend']
        if backend is not None:
            _backend(row, backend, definitions, hosts)
            owner = owners.setdefault(row['workloadId'], {
                key: backend[key] for key in
                ('instanceId', 'generation', 'hostId', 'revisionDigest',
                 'address')})
            if any(backend[key] != owner[key] for key in owner):
                raise IngressError('invalid-backend')
    if seen != set(expected):
        raise IngressError('invalid-routes')
    return copy.deepcopy(snapshot)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class Ingress:
    def __init__(self, config, context, *, clock=time.time,
                 monotonic=time.monotonic, fetcher=None):
        self.config = validate_config(config)
        self.clock, self.monotonic = clock, monotonic
        self.mutex = threading.RLock()
        self._snapshot = None
        self._received_wall = None
        self._received_mono = None
        self._closed = False
        self._lock_handle = None
        if fetcher is not None:
            self._fetcher = fetcher
        else:
            if context is None \
                    or context.verify_mode != ssl.CERT_REQUIRED \
                    or not context.check_hostname \
                    or context.minimum_version < ssl.TLSVersion.TLSv1_2:
                raise IngressError('insecure-context')
            self._url = self.config['registryUrl'].rstrip('/') \
                + '/v2/routes'
            self._opener = urllib.request.build_opener(
                _NoRedirect(), urllib.request.ProxyHandler({}),
                urllib.request.HTTPSHandler(context=context))
            self._fetcher = self._fetch
        state_dir = self.config['stateDir']
        _paths(statefiles.check_private_dir, state_dir)
        self._lock_path = os.path.join(state_dir, 'ingress.lock')
        self._version_path = os.path.join(state_dir, 'version.json')
        _paths(statefiles.ensure_private_file, self._lock_path)
        self._lock_handle = os.open(self._lock_path,
                                    os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(self._lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            stored = _paths(statefiles.read_json,
                            self._version_path, 4096)
            if stored is None:
                self._highwater = 0
            elif type(stored) is not dict \
                    or set(stored) != _VERSION_FIELDS \
                    or type(stored['schemaVersion']) is not int \
                    or stored['schemaVersion'] != 2 \
                    or type(stored['version']) is not int \
                    or not 0 <= stored['version'] <= worker._MAX_I64:
                raise IngressError('ingress-state-corrupt')
            else:
                self._highwater = stored['version']
        except BlockingIOError:
            os.close(self._lock_handle)
            self._lock_handle = None
            raise IngressError('ingress-in-use') from None
        except Exception:
            os.close(self._lock_handle)
            self._lock_handle = None
            raise

    def _fetch(self, nonce):
        request = urllib.request.Request(
            self._url, headers={'X-Nexus-Nonce': nonce}, method='GET')
        try:
            response = self._opener.open(request, timeout=_FETCH_TIMEOUT)
        except urllib.error.HTTPError as error:
            error.close()
            raise IngressError('registry-fetch-failed') from None
        except Exception:
            raise IngressError('registry-fetch-failed') from None
        try:
            if response.status != 200 \
                    or response.headers.get_content_type() \
                    != 'application/json':
                raise IngressError('registry-fetch-failed')
            raw = response.read(_MAX_SNAPSHOT + 1)
        finally:
            response.close()
        if len(raw) > _MAX_SNAPSHOT:
            raise IngressError('registry-fetch-failed')
        try:
            return worker.load_json_bytes(raw)
        except worker.WorkerError:
            raise IngressError('registry-fetch-failed') from None

    def poll(self):
        with self.mutex:
            if self._closed:
                raise IngressError('ingress-closed')
        nonce = secrets.token_hex(16)
        snapshot = self._fetcher(nonce)
        now = _time(self.clock(), 'clock-unavailable')
        mono = _time(self.monotonic(), 'clock-unavailable')
        with self.mutex:
            if self._closed:
                raise IngressError('ingress-closed')
            validated = validate_snapshot(
                snapshot, self.config, nonce, now=now,
                highwater=self._highwater)
            if validated['version'] > self._highwater:
                _paths(statefiles.write_json, self._version_path,
                       {'schemaVersion': 2,
                        'version': validated['version']})
                self._highwater = validated['version']
            self._snapshot = validated
            self._received_wall = now
            self._received_mono = mono

    def _fresh(self):
        if self._closed:
            return None
        try:
            now = _time(self.clock(), 'clock-unavailable')
            mono = _time(self.monotonic(), 'clock-unavailable')
        except IngressError:
            return None
        snapshot = self._snapshot
        if snapshot is None or self._received_wall is None:
            return None
        if not 0 <= now - self._received_wall:
            return None
        if now >= snapshot['validUntil']:
            return None
        if not 0 <= mono - self._received_mono \
                < snapshot['validUntil'] - self._received_wall:
            return None
        return snapshot

    def authorize(self, route_id, token):
        with self.mutex:
            snapshot = self._fresh()
            if snapshot is None or type(route_id) is not str \
                    or type(token) is not str:
                return False
            for row in snapshot['routes']:
                if row['id'] == route_id:
                    return row['backend'] is not None \
                        and token == route_token(
                            snapshot['registryEpoch'], row)
            return False

    def dynamic_config(self):
        port = self.config['listenPort']
        with self.mutex:
            snapshot = self._fresh()
            routers, services, middlewares = {}, {}, {}
            for route in self.config['registry']['routes']:
                name = 'nexus-' + route['id']
                backend = None
                if snapshot is not None:
                    row = next(item for item in snapshot['routes']
                               if item['id'] == route['id'])
                    backend = row['backend']
                    token = route_token(snapshot['registryEpoch'], row)
                else:
                    token = '0' * 64
                url = 'http://{}:{}'.format(backend['address'],
                                            backend['port']) \
                    if backend is not None \
                    else 'http://127.0.0.1:{}/unavailable'.format(port)
                routers[name] = {
                    'rule': "Host(`{}`)".format(route['hostname']),
                    'entryPoints': ['web'],
                    'service': name,
                    'middlewares': [name + '-guard'],
                }
                services[name] = {
                    'loadBalancer': {'servers': [{'url': url}]},
                }
                middlewares[name + '-guard'] = {
                    'forwardAuth': {
                        'address': 'http://127.0.0.1:{}/authorize/{}/{}'
                                   .format(port, route['id'], token),
                        'trustForwardHeader': False,
                        'authRequestHeaders': ['X-Nexus-Guard'],
                    },
                }
            return {'http': {'routers': routers, 'services': services,
                             'middlewares': middlewares}}

    def close(self):
        with self.mutex:
            self._closed = True
            self._snapshot = None
            self._received_wall = None
            self._received_mono = None
            if self._lock_handle is not None:
                os.close(self._lock_handle)
                self._lock_handle = None


def make_server(ingress, port=None):
    bound = ingress.config['listenPort'] if port is None else port

    class Guard(common.Handler):
        def route(self, method):
            path = self.path
            if '?' in path:
                return self.send(404, {'error': 'not-found'})
            if method == 'GET' and path == '/traefik':
                return self.send(200, ingress.dynamic_config())
            parts = path.split('/')
            if len(parts) == 4 and parts[1] == 'authorize' \
                    and _GUARD_ID_RE.fullmatch(parts[2]) \
                    and _GUARD_TOKEN_RE.fullmatch(parts[3]) \
                    and method == 'GET':
                if ingress.authorize(parts[2], parts[3]):
                    self.send_response(200)
                    self.send_header('Content-Length', '0')
                    self.send_header('Cache-Control', 'no-store')
                    self.end_headers()
                    return
                return self._deny()
            if len(parts) == 2 and parts[0] == '' \
                    and parts[1] == 'unavailable':
                return self._deny()
            return self.send(404, {'error': 'not-found'})

        def _deny(self):
            body = b'Service temporarily unavailable.'
            self.send_response(503)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)

    for verb in ('PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'):
        setattr(Guard, 'do_' + verb,
                lambda self, _verb=verb: self.dispatch(_verb))
    return common.Server(('127.0.0.1', bound), Guard)


def _run(ingress, server):
    stop = threading.Event()

    def polling():
        while not stop.is_set():
            try:
                ingress.poll()
            except Exception as error:
                print(json.dumps({'event': 'poll-error',
                                  'type': type(error).__name__}),
                      flush=True)
            stop.wait(_POLL_INTERVAL)

    thread = threading.Thread(target=polling, daemon=True)
    thread.start()
    try:
        server.serve_forever()
    finally:
        stop.set()
        thread.join(timeout=_FETCH_TIMEOUT + _POLL_INTERVAL + 1)
        server.server_close()
        ingress.close()


def main(argv=None):
    parser = argparse.ArgumentParser(prog='nexus-ingress')
    parser.add_argument('--config', required=True)
    args = parser.parse_args(argv)
    try:
        with open(args.config, 'rb') as handle:
            raw = handle.read(_MAX_CONFIG + 1)
        if len(raw) > _MAX_CONFIG:
            raise IngressError('config-too-large')
        config = worker.load_json_bytes(raw)
        credentials = Path(os.environ['CREDENTIALS_DIRECTORY'])
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=credentials / 'ca')
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(credentials / 'cert', credentials / 'key')
    except (IngressError, worker.WorkerError, OSError, KeyError,
            ValueError) as error:
        code = getattr(error, 'code', 'invalid-config')
        sys.stdout.write(json.dumps(
            {'schemaVersion': 2, 'status': 'error', 'error': code},
            sort_keys=True, separators=(',', ':')) + '\n')
        return 1
    try:
        service = Ingress(config, context)
    except IngressError as error:
        sys.stdout.write(json.dumps(
            {'schemaVersion': 2, 'status': 'error',
             'error': error.code}, sort_keys=True,
            separators=(',', ':')) + '\n')
        return 1
    server = None
    try:
        server = make_server(service)
        _run(service, server)
    finally:
        if server is not None:
            server.server_close()
        service.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
