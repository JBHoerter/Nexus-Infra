"""Authenticated mTLS transport for the durable registry core (M3).

Every request must present a client certificate chaining to the configured
CA whose subject alternative names contain exactly one URI SAN equal to a
configured client identity (`urn:nexus:<role>:<identifier>`). The principal
is derived ONLY from that verified certificate mapping — no HTTP header,
parameter or body field can select a role or subject. Certificate CN is
never consulted. There is no plaintext listener and no remote worker
mutation surface.
"""
import argparse
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import urllib.parse
from pathlib import Path

import common
import registry
import worker


_CONFIG_FIELDS = {'schemaVersion', 'listenAddress', 'port', 'dbPath',
                  'registry', 'clients'}
_CLIENT_FIELDS = {'identity', 'role', 'hostId'}
_IDENTITY_RE = re.compile(
    r'urn:nexus:(controller|host|reader|ingress):([a-z][a-z0-9-]{0,62})')
_MAX_BODY = 16384
_MAX_CONFIG = 2 * 1024 * 1024

_POST_ACTIONS = {
    '/v2/hosts/session': 'open_session',
    '/v2/observations': 'observe',
    '/v2/placements/assign': 'assign',
    '/v2/placements/fence': 'fence',
    '/v2/placements/publish': 'publish',
    '/v2/placements/withdraw': 'withdraw',
}


def _check(fn, *args):
    try:
        fn(*args)
    except worker.WorkerError as error:
        raise registry.RegistryError(error.code) from None


def validate_config(config):
    _check(worker._fields, config, _CONFIG_FIELDS, 'config')
    _check(worker._integer, config['schemaVersion'], 2, 2,
           'config-schemaVersion')
    listen = config['listenAddress']
    if type(listen) is not str:
        raise registry.RegistryError('invalid-listenAddress')
    try:
        parsed = ipaddress.ip_address(listen)
    except ValueError:
        raise registry.RegistryError('invalid-listenAddress') from None
    if str(parsed) != listen:
        raise registry.RegistryError('invalid-listenAddress')
    _check(worker._integer, config['port'], 1, 65535, 'port')
    _check(worker._path, config['dbPath'], 'dbPath')
    registry_config = registry.validate_config(config['registry'])
    clients = config['clients']
    if type(clients) is not list or not 1 <= len(clients) <= 1024:
        raise registry.RegistryError('invalid-clients')
    known_hosts = {host['hostId'] for host in registry_config['hosts']}
    seen = set()
    normalized = []
    for client in clients:
        _check(worker._fields, client, _CLIENT_FIELDS, 'client')
        role = client['role']
        if type(role) is not str or role not in registry._ROLES:
            raise registry.RegistryError('invalid-clients')
        identity = client['identity']
        match = _IDENTITY_RE.fullmatch(identity) \
            if type(identity) is str else None
        if match is None or match.group(1) != role:
            raise registry.RegistryError('invalid-clients')
        if identity in seen:
            raise registry.RegistryError('invalid-clients')
        seen.add(identity)
        host_id = client['hostId']
        if role == 'host':
            if host_id != match.group(2) or host_id not in known_hosts:
                raise registry.RegistryError('invalid-clients')
        elif host_id is not None:
            raise registry.RegistryError('invalid-clients')
        normalized.append({'identity': identity, 'role': role,
                           'hostId': host_id})
    return {'schemaVersion': 2, 'listenAddress': listen,
            'port': config['port'], 'dbPath': config['dbPath'],
            'registry': registry_config, 'clients': normalized}


def _client_map(clients):
    if type(clients) is dict:
        return clients
    return {client['identity']: client for client in clients}


def principal_for_certificate(certificate, clients):
    client_map = _client_map(clients)
    san = certificate.get('subjectAltName') \
        if type(certificate) is dict else None
    uris = [value for kind, value in san or () if kind == 'URI']
    if len(uris) != 1:
        raise registry.RegistryError('client-not-authorized', 403)
    record = client_map.get(uris[0])
    if record is None:
        raise registry.RegistryError('client-not-authorized', 403)
    return registry.Principal(record['identity'], record['role'],
                              record['hostId'])


def _error(status, code):
    return {'schemaVersion': 2, 'status': 'error', 'error': code}


def _handler(reg, clients):
    client_map = _client_map(clients)

    class API(common.Handler):
        def _body(self):
            if self.headers.get_all('Transfer-Encoding'):
                raise registry.RegistryError('invalid-request')
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) != 1 or len(lengths[0]) > 5 \
                    or not lengths[0].isdigit() \
                    or not 0 <= int(lengths[0]) <= _MAX_BODY:
                raise registry.RegistryError('invalid-request')
            content_types = self.headers.get_all('Content-Type', [])
            if len(content_types) != 1 \
                    or content_types[0].split(';')[0].strip() \
                    != 'application/json':
                raise registry.RegistryError('invalid-content-type', 415)
            size = int(lengths[0])
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise registry.RegistryError('invalid-request')
            try:
                value = worker.load_json_bytes(raw)
            except worker.WorkerError as error:
                raise registry.RegistryError(error.code) from None
            if type(value) is not dict:
                raise registry.RegistryError('invalid-request')
            return value

        def _query(self, allowed):
            """Strict query parsing for the operations endpoints — the
            only paths that may carry a query string at all."""
            query = self.path.partition('?')[2]
            try:
                pairs = urllib.parse.parse_qsl(
                    query, keep_blank_values=True, strict_parsing=True,
                    max_num_fields=8, errors='strict')
            except (ValueError, UnicodeError):
                raise registry.RegistryError('invalid-request') from None
            params = {}
            for key, value in pairs:
                if key not in allowed or key in params or len(key) > 32 \
                        or len(value) > 64:
                    raise registry.RegistryError('invalid-request')
                params[key] = value
            return params

        def _operations(self, method, principal, path):
            """The dispatch surface: /v2/operations collection plus
            /v2/operations/<operationId>[/receipt] members."""
            if path == '/v2/operations':
                if method == 'POST':
                    if '?' in self.path:
                        raise registry.RegistryError('not-found', 404)
                    return reg.post_operation(principal, self._body())
                if method != 'GET':
                    raise registry.RegistryError('not-found', 404)
                params = self._query({'host', 'after'})
                host = params.get('host')
                if host is None:
                    host = principal.host_id
                elif not worker._IDENTIFIER_RE.fullmatch(host):
                    raise registry.RegistryError('invalid-host')
                after_raw = params.get('after', '0')
                if not after_raw.isdigit() or len(after_raw) > 20:
                    raise registry.RegistryError('invalid-after')
                return reg.poll_operations(principal, host,
                                           int(after_raw))
            prefix = '/v2/operations/'
            if not path.startswith(prefix):
                raise registry.RegistryError('not-found', 404)
            rest = path[len(prefix):]
            if method == 'POST' and rest.endswith('/receipt') \
                    and '/' not in rest[:-len('/receipt')]:
                if '?' in self.path:
                    raise registry.RegistryError('not-found', 404)
                return reg.operation_receipt(
                    principal, rest[:-len('/receipt')], self._body())
            if method == 'GET' and '/' not in rest and rest:
                params = self._query({'requestId'})
                request_id = params.get('requestId')
                if request_id is None:
                    raise registry.RegistryError('invalid-request')
                return reg.operation_status(principal, rest, request_id)
            raise registry.RegistryError('not-found', 404)

        def _dispatch(self, method, principal):
            if self.headers.get('Origin') is not None \
                    or self.headers.get('Cookie') is not None:
                raise registry.RegistryError('browser-request-forbidden', 403)
            path = self.path.partition('?')[0]
            if path.startswith('/v2/operations'):
                return self._operations(method, principal, path)
            if '?' in self.path:
                raise registry.RegistryError('not-found', 404)
            if method == 'GET':
                if path == '/v2/state':
                    return reg.state(principal)
                if path == '/v2/assignments':
                    return reg.assignments(principal)
                if path == '/v2/routes':
                    nonces = self.headers.get_all('X-Nexus-Nonce', [])
                    if len(nonces) != 1:
                        raise registry.RegistryError('invalid-nonce')
                    return reg.routes(principal, nonces[0])
                raise registry.RegistryError('not-found', 404)
            if method == 'POST':
                action = _POST_ACTIONS.get(path)
                if action is None:
                    raise registry.RegistryError('not-found', 404)
                return getattr(reg, action)(principal, self._body())
            raise registry.RegistryError('not-found', 404)

        def route(self, method):
            try:
                principal = principal_for_certificate(
                    self.connection.getpeercert(), client_map)
                return self.send(200, self._dispatch(method, principal))
            except registry.RegistryError as error:
                return self.send(error.status, _error(error.status,
                                                    error.code))

    for verb in ('PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'):
        setattr(API, 'do_' + verb,
                lambda self, _verb=verb: self.dispatch(_verb))
    return API


def make_server(reg, clients, address, context):
    if context.verify_mode != ssl.CERT_REQUIRED \
            or context.minimum_version < ssl.TLSVersion.TLSv1_2:
        raise registry.RegistryError('insecure-context')
    try:
        family = socket.AF_INET6 \
            if ipaddress.ip_address(address[0]).version == 6 \
            else socket.AF_INET
    except ValueError:
        raise registry.RegistryError('invalid-listenAddress') from None

    class Listener(common.Server):
        address_family = family

    server = Listener(address, _handler(reg, clients))
    original = server.get_request

    def accept():
        sock, peer = original()
        try:
            return context.wrap_socket(sock, server_side=True), peer
        except Exception:
            sock.close()
            raise

    server.get_request = accept
    return server


def _response(response):
    sys.stdout.write(json.dumps(response, sort_keys=True,
                                separators=(',', ':')) + '\n')


def main(argv=None):
    parser = argparse.ArgumentParser(prog='nexus-registry')
    parser.add_argument('--config', required=True)
    args = parser.parse_args(argv)
    try:
        with open(args.config, 'rb') as handle:
            raw = handle.read(_MAX_CONFIG + 1)
        if len(raw) > _MAX_CONFIG:
            raise registry.RegistryError('config-too-large')
        config = validate_config(worker.load_json_bytes(raw))
        credentials = Path(os.environ['CREDENTIALS_DIRECTORY'])
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,
                                             cafile=credentials / 'ca')
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(credentials / 'cert', credentials / 'key')
    except (registry.RegistryError, worker.WorkerError, OSError, KeyError,
            ValueError) as error:
        code = getattr(error, 'code', 'invalid-config')
        _response(_error(400, code))
        return 1
    try:
        reg = registry.Registry(config['registry'], config['dbPath'])
    except registry.RegistryError as error:
        _response(_error(error.status, error.code))
        return 1
    server = None
    try:
        server = make_server(reg, config['clients'],
                             (config['listenAddress'], config['port']),
                             context)
        server.serve_forever()
    finally:
        if server is not None:
            server.server_close()
        reg.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
