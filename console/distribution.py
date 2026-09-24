import argparse
import base64
import binascii
import copy
import fcntl
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

import artifacts
import catalog
import worker


class DistributionError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


_CONFIG_FIELDS = {'schemaVersion', 'stateDir', 'trustedPublicKeys',
                  'sources', 'bundles'}
_REQUEST_FIELDS = {'schemaVersion', 'action', 'workloadId', 'revisionDigest',
                   'referenceId'}
_SOURCE_FIELDS = {'id', 'uri'}
_BUNDLE_FIELDS = {'workloadId', 'revisionDigest', 'bundlePath', 'sourceId'}
_KEY_NAME_RE = re.compile(r'[A-Za-z0-9._-]{1,128}')
_MAX_REQUEST_BYTES = 16384
_MAX_REF_BYTES = 16384
_MAX_MANIFEST_BYTES = 16 * 1024 * 1024
_MAX_DEFINITION_BYTES = 1024 * 1024
_MAX_DIGEST_BYTES = 128
_INTERNAL_ERRORS = (artifacts.ArtifactError, catalog.CatalogError, OSError,
                    subprocess.TimeoutExpired, ValueError)


def _source_uri(value):
    if type(value) is not str or not value or '%' in value \
            or '?' in value or '#' in value \
            or any(ord(char) <= 0x20 or ord(char) > 0x7e for char in value):
        raise worker.WorkerError('invalid-source-uri')
    try:
        parts = urlsplit(value)
        if parts.scheme == 'https':
            if not parts.hostname or parts.username is not None \
                    or parts.password is not None:
                raise worker.WorkerError('invalid-source-uri')
            parts.port
        elif parts.scheme == 'file':
            if parts.netloc:
                raise worker.WorkerError('invalid-source-uri')
        else:
            raise worker.WorkerError('invalid-source-uri')
    except ValueError:
        raise worker.WorkerError('invalid-source-uri') from None
    if parts.scheme == 'file':
        worker._path(parts.path, 'source-uri')


def validate_config(config):
    worker._fields(config, _CONFIG_FIELDS, 'config')
    worker._integer(config['schemaVersion'], 1, 1, 'config-schemaVersion')
    worker._path(config['stateDir'], 'config-stateDir')
    keys = config['trustedPublicKeys']
    if type(keys) is not list or not 1 <= len(keys) <= 16:
        raise worker.WorkerError('invalid-trustedPublicKeys')
    key_names = set()
    for key in keys:
        if type(key) is not str or ':' not in key:
            raise worker.WorkerError('invalid-trustedPublicKeys')
        name, _, encoded = key.partition(':')
        if _KEY_NAME_RE.fullmatch(name) is None \
                or name in key_names:
            raise worker.WorkerError('invalid-trustedPublicKeys')
        key_names.add(name)
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise worker.WorkerError('invalid-trustedPublicKeys') from None
        if len(decoded) != 32 \
                or base64.b64encode(decoded).decode() != encoded:
            raise worker.WorkerError('invalid-trustedPublicKeys')
    if len(set(keys)) != len(keys):
        raise worker.WorkerError('invalid-trustedPublicKeys')
    sources = config['sources']
    if type(sources) is not list or not 1 <= len(sources) <= 64:
        raise worker.WorkerError('invalid-sources')
    source_ids = set()
    for source in sources:
        worker._fields(source, _SOURCE_FIELDS, 'source')
        worker._identifier(source['id'], 'source-id')
        if source['id'] in source_ids:
            raise worker.WorkerError('invalid-sources')
        source_ids.add(source['id'])
        _source_uri(source['uri'])
    bundles = config['bundles']
    if type(bundles) is not list or not 1 <= len(bundles) <= 1024:
        raise worker.WorkerError('invalid-bundles')
    seen_pairs, seen_paths = set(), set()
    for bundle in bundles:
        worker._fields(bundle, _BUNDLE_FIELDS, 'bundle')
        worker._identifier(bundle['workloadId'], 'bundle-workloadId')
        worker._digest(bundle['revisionDigest'], 'bundle-revisionDigest')
        worker._store_path(bundle['bundlePath'], 'bundle-bundlePath')
        worker._identifier(bundle['sourceId'], 'bundle-sourceId')
        pair = (bundle['workloadId'], bundle['revisionDigest'])
        if pair in seen_pairs or bundle['bundlePath'] in seen_paths:
            raise worker.WorkerError('invalid-bundles')
        seen_pairs.add(pair)
        seen_paths.add(bundle['bundlePath'])
        if bundle['sourceId'] not in source_ids:
            raise worker.WorkerError('invalid-bundles')
    return copy.deepcopy(config)


def validate_request(request):
    if type(request) is not dict or set(request) != _REQUEST_FIELDS:
        raise worker.WorkerError('invalid-request-fields')
    worker._integer(request['schemaVersion'], 1, 1, 'schemaVersion')
    if request['action'] != 'fetch':
        raise worker.WorkerError('invalid-action')
    worker._identifier(request['workloadId'], 'workloadId')
    worker._digest(request['revisionDigest'], 'revisionDigest')
    worker._hex32(request['referenceId'], 'referenceId')
    return copy.deepcopy(request)


class Distribution(worker.SecurePaths):
    def __init__(self, config, *, runner=None, fs=None):
        self.config = validate_config(config)
        self.runner = runner or worker.Runner()
        self.fs = fs or worker.HostFilesystem()
        state_dir = self.config['stateDir']
        self._ensure_dir(state_dir, 0o700)
        self._roots_dir = os.path.join(state_dir, 'roots')
        self._refs_dir = os.path.join(state_dir, 'refs')
        self._ensure_dir(self._roots_dir, 0o700)
        self._ensure_dir(self._refs_dir, 0o700)
        self._lock_path = os.path.join(state_dir, 'lock')
        self._ensure_metadata_file(self._lock_path)

    def close(self):
        pass

    def _approved(self, request):
        pair = (request['workloadId'], request['revisionDigest'])
        for bundle in self.config['bundles']:
            if (bundle['workloadId'], bundle['revisionDigest']) == pair:
                return bundle
        raise worker.WorkerError('unknown-workload')

    def _source(self, source_id):
        for source in self.config['sources']:
            if source['id'] == source_id:
                return source
        raise worker.WorkerError('invalid-bundles')

    def _reference_path(self, reference_id):
        return os.path.join(self._refs_dir, reference_id + '.json')

    def _read_reference(self, path):
        st = self._lstat(path)
        if st is None:
            return None
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 \
                or stat.S_IMODE(st.st_mode) != 0o600:
            raise worker.WorkerError('path-unsafe')
        raw = self.fs.read_bounded(path, _MAX_REF_BYTES)
        if len(raw) > _MAX_REF_BYTES:
            raise worker.WorkerError('path-unsafe')
        try:
            record = worker.load_json_bytes(raw)
            if type(record) is not dict:
                raise worker.WorkerError('path-unsafe')
            status = record.get('status')
            fields = {'schemaVersion', 'request', 'bundlePath', 'sourceId',
                      'status'}
            if status == 'retained':
                fields = fields | {'manifestDigest'}
            elif status != 'pending':
                raise worker.WorkerError('path-unsafe')
            if set(record) != fields:
                raise worker.WorkerError('path-unsafe')
            worker._integer(record['schemaVersion'], 1, 1,
                            'ref-schemaVersion')
            validate_request(record['request'])
            worker._store_path(record['bundlePath'], 'ref-bundlePath')
            worker._identifier(record['sourceId'], 'ref-sourceId')
            if status == 'retained':
                worker._digest(record['manifestDigest'],
                               'ref-manifestDigest')
            if raw != artifacts.canonical_bytes(record):
                raise worker.WorkerError('path-unsafe')
        except worker.WorkerError:
            raise worker.WorkerError('path-unsafe') from None
        except _INTERNAL_ERRORS:
            raise worker.WorkerError('path-unsafe') from None
        return record

    def _run_checked(self, argv):
        result = self.runner.run(argv)
        if result.returncode != 0:
            raise DistributionError('command-failed')

    def _load_bundle_files(self, request, bundle):
        try:
            raw_manifest = self.fs.read_bounded(
                os.path.join(bundle, 'artifact.json'), _MAX_MANIFEST_BYTES)
            if len(raw_manifest) > _MAX_MANIFEST_BYTES:
                raise worker.WorkerError('invalid-bundle')
            manifest = artifacts.validate_manifest(
                worker.load_json_bytes(raw_manifest))
            if raw_manifest != artifacts.canonical_bytes(manifest):
                raise worker.WorkerError('invalid-bundle')
            digest_raw = self.fs.read_bounded(
                os.path.join(bundle, 'artifact.sha256'), _MAX_DIGEST_BYTES)
            if len(digest_raw) > _MAX_DIGEST_BYTES:
                raise worker.WorkerError('invalid-bundle')
            if digest_raw.decode('utf-8').strip() \
                    != artifacts.manifest_digest(manifest):
                raise worker.WorkerError('invalid-bundle')
            raw_definition = self.fs.read_bounded(
                os.path.join(bundle, 'definition.json'),
                _MAX_DEFINITION_BYTES)
            if len(raw_definition) > _MAX_DEFINITION_BYTES:
                raise worker.WorkerError('invalid-bundle')
            definition = catalog.validate_definition(
                worker.load_json_bytes(raw_definition))
            if raw_definition != artifacts.canonical_bytes(definition):
                raise worker.WorkerError('invalid-bundle')
        except worker.WorkerError:
            raise
        except _INTERNAL_ERRORS:
            raise worker.WorkerError('invalid-bundle') from None
        runtime = [a for a in definition['artifacts']
                   if a['id'] == definition['runtimeArtifactId']]
        if len(runtime) != 1 or runtime[0]['kind'] != 'nixos-closure' \
                or runtime[0]['digest'] \
                != artifacts.manifest_digest(manifest):
            raise worker.WorkerError('invalid-bundle')
        if manifest['runtimeVersion'] != definition['runtimeVersion'] \
                or manifest['architecture'] != definition['architecture']:
            raise worker.WorkerError('invalid-bundle')
        if (definition['workloadId'], definition['revisionDigest']) \
                != (request['workloadId'], request['revisionDigest']):
            raise worker.WorkerError('invalid-bundle')
        return manifest

    def _verify_root_membership(self, bundle, manifest):
        result = self.runner.run(
            ['nix', '--extra-experimental-features', 'nix-command',
             '--store', 'daemon', 'path-info', '--recursive', '--json',
             '--json-format', '1', bundle])
        if result.returncode != 0:
            raise DistributionError('command-failed')
        try:
            records = json.loads(result.stdout)
        except ValueError:
            raise DistributionError('store-schema-unexpected') from None
        if type(records) is dict:
            paths = set(records)
        elif type(records) is list:
            paths = set()
            for record in records:
                if type(record) is not dict \
                        or type(record.get('path')) is not str:
                    raise DistributionError('store-schema-unexpected')
                paths.add(record['path'])
        else:
            raise DistributionError('store-schema-unexpected')
        if bundle not in paths or manifest['root'] not in paths:
            raise worker.WorkerError('store-closure-mismatch')

    def _verify_and_retain(self, request, source, bundle):
        prefix = ['nix', '--extra-experimental-features', 'nix-command',
                  '--option', 'trusted-public-keys',
                  ' '.join(self.config['trustedPublicKeys']),
                  '--option', 'require-sigs', 'true']
        self._run_checked(prefix + ['copy', '--from', source['uri'],
                                    '--to', 'daemon', bundle])
        self._run_checked(prefix + ['--store', 'daemon', 'store', 'copy-sigs',
                                    '--substituter', source['uri'],
                                    '--recursive', bundle])
        self._run_checked(prefix + ['--store', 'daemon', 'store', 'verify',
                                    '--recursive', '--sigs-needed', '1',
                                    bundle])
        manifest = self._load_bundle_files(request, bundle)
        worker.verify_closure(manifest, self.runner)
        self._verify_root_membership(bundle, manifest)
        root_path = os.path.join(self._roots_dir, request['referenceId'])
        self._check_ancestors(root_path)
        existing = self._lstat(root_path)
        if existing is not None and not (
                stat.S_ISLNK(existing.st_mode) and existing.st_uid == 0
                and os.readlink(root_path) == bundle):
            raise worker.WorkerError('path-unsafe')
        self._run_checked(['nix-store', '--store', 'daemon', '--add-root',
                           root_path, '--indirect', '--realise', bundle])
        existing = self._lstat(root_path)
        if existing is None or not stat.S_ISLNK(existing.st_mode) \
                or existing.st_uid != 0 or os.readlink(root_path) != bundle:
            raise worker.WorkerError('path-unsafe')
        self.fs.sync_dir(self._roots_dir)
        self.fs.sync_dir('/nix/var/nix/gcroots/auto')
        return manifest

    def _fetch(self, request):
        approved = self._approved(request)
        source = self._source(approved['sourceId'])
        reference = self._reference_path(request['referenceId'])
        record = self._read_reference(reference)
        bound = {'schemaVersion': 1, 'request': request,
                 'bundlePath': approved['bundlePath'],
                 'sourceId': approved['sourceId'], 'status': 'pending'}
        if record is not None:
            for key in ('request', 'bundlePath', 'sourceId'):
                if record[key] != bound[key]:
                    raise worker.WorkerError('reference-conflict')
        self.fs.write_file(reference, artifacts.canonical_bytes(bound), 0o600)
        manifest = self._verify_and_retain(request, source,
                                           approved['bundlePath'])
        digest = artifacts.manifest_digest(manifest)
        bound['manifestDigest'] = digest
        bound['status'] = 'retained'
        self.fs.write_file(reference, artifacts.canonical_bytes(bound), 0o600)
        return {'schemaVersion': 1, 'status': 'retained',
                'workloadId': request['workloadId'],
                'revisionDigest': request['revisionDigest'],
                'referenceId': request['referenceId'],
                'bundlePath': approved['bundlePath'],
                'manifestDigest': digest}

    def fetch(self, request):
        request = validate_request(request)
        handle = open(self._lock_path, 'r')
        try:
            fcntl.flock(handle, fcntl.LOCK_EX)
            return self._fetch(request)
        finally:
            handle.close()


def _response(response):
    sys.stdout.write(artifacts.canonical_bytes(response).decode('utf-8') + '\n')


def main(argv=None):
    parser = argparse.ArgumentParser(prog='nexus-artifacts')
    parser.add_argument('--config', required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('execute')
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        _response({'schemaVersion': 1, 'status': 'error',
                   'error': 'requires-root'})
        return 1
    try:
        config = worker.load_json_bytes(Path(args.config).read_bytes())
        instance = Distribution(config)
    except (worker.WorkerError, OSError, catalog.CatalogError,
            artifacts.ArtifactError) as error:
        code = getattr(error, 'code', 'invalid-config')
        _response({'schemaVersion': 1, 'status': 'error', 'error': code})
        return 1
    try:
        raw = sys.stdin.buffer.read(_MAX_REQUEST_BYTES + 1)
        if len(raw) > _MAX_REQUEST_BYTES:
            _response({'schemaVersion': 1, 'status': 'error',
                       'error': 'request-too-large'})
            return 1
        request = worker.load_json_bytes(raw)
        response = instance.fetch(request)
    except (worker.WorkerError, DistributionError) as error:
        _response({'schemaVersion': 1, 'status': 'error', 'error': error.code})
        return 1
    except _INTERNAL_ERRORS:
        _response({'schemaVersion': 1, 'status': 'error',
                   'error': 'internal-error'})
        return 1
    finally:
        instance.close()
    _response(response)
    return 0 if response.get('status') == 'retained' else 1


if __name__ == '__main__':
    sys.exit(main())
