import argparse
import base64
import binascii
import copy
import hashlib
import json
import re
from pathlib import Path

import catalog


class ArtifactError(ValueError):
    pass


_STORE_PATH_RE = re.compile(r'/nix/store/[0123456789abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+')
_NIX_BASE32_RE = re.compile(r'[01][0123456789abcdfghijklmnpqrsvwxyz]{51}')
_HEX_RE = re.compile(r'[0-9a-f]{64}')
_ARCHITECTURES = {'x86_64-linux', 'aarch64-linux'}
_ENTRY_KEYS = {'path', 'narHash', 'narSize', 'references'}
_MANIFEST_KEYS = {'schemaVersion', 'kind', 'runtimeVersion', 'architecture', 'root', 'closure'}
_MAX_I64 = 2**63 - 1
_MAX_ENTRIES = 50000


def canonical_bytes(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (TypeError, ValueError, UnicodeError):
        raise ArtifactError('Value is not canonical JSON') from None


def _enum(value, choices, context):
    if type(value) is not str or value not in choices:
        raise ArtifactError('Invalid ' + context)


def _store_path(value, context):
    if type(value) is not str or _STORE_PATH_RE.fullmatch(value) is None:
        raise ArtifactError('Invalid ' + context)


def _nar_hash(value):
    if type(value) is not str:
        raise ArtifactError('Invalid narHash')
    if value.startswith('sha256:'):
        tail = value[7:]
        if _HEX_RE.fullmatch(tail) or _NIX_BASE32_RE.fullmatch(tail):
            return
    elif value.startswith('sha256-'):
        tail = value[7:]
        if len(tail) != 44:
            raise ArtifactError('Invalid narHash')
        try:
            decoded = base64.b64decode(tail, validate=True)
        except (ValueError, binascii.Error):
            raise ArtifactError('Invalid narHash') from None
        if len(decoded) == 32 and base64.b64encode(decoded).decode() == tail:
            return
    raise ArtifactError('Invalid narHash')


def _entry(record):
    if type(record) is not dict or set(record) != _ENTRY_KEYS:
        raise ArtifactError('Invalid closure entry fields')
    _store_path(record['path'], 'path')
    _nar_hash(record['narHash'])
    if type(record['narSize']) is not int or not 0 <= record['narSize'] <= _MAX_I64:
        raise ArtifactError('Invalid narSize')
    references = record['references']
    if type(references) is not list or len(references) > _MAX_ENTRIES:
        raise ArtifactError('Invalid references')
    for ref in references:
        _store_path(ref, 'references')
    if len(set(references)) != len(references):
        raise ArtifactError('Duplicate references')
    if references != sorted(references):
        raise ArtifactError('Invalid references order')


def build_manifest(root, architecture, graph):
    _enum(architecture, _ARCHITECTURES, 'architecture')
    _store_path(root, 'root')
    if type(graph) is not dict or type(graph.get('closure')) is not list:
        raise ArtifactError('Invalid closure graph')
    if not 1 <= len(graph['closure']) <= _MAX_ENTRIES:
        raise ArtifactError('Invalid closure')
    entries = []
    for record in graph['closure']:
        if type(record) is not dict or not _ENTRY_KEYS <= set(record):
            raise ArtifactError('Invalid closure entry')
        entry = {key: record[key] for key in _ENTRY_KEYS}
        _store_path(entry['path'], 'path')
        _nar_hash(entry['narHash'])
        if type(entry['narSize']) is not int or not 0 <= entry['narSize'] <= _MAX_I64:
            raise ArtifactError('Invalid narSize')
        references = entry['references']
        if type(references) is not list or len(references) > _MAX_ENTRIES:
            raise ArtifactError('Invalid references')
        for ref in references:
            _store_path(ref, 'references')
        if len(set(references)) != len(references):
            raise ArtifactError('Duplicate references')
        entry['references'] = sorted(references)
        entries.append(entry)
    entries.sort(key=lambda entry: entry['path'])
    manifest = {
        'schemaVersion': 1,
        'kind': 'nixos-closure',
        'runtimeVersion': 'nspawn-v1',
        'architecture': architecture,
        'root': root,
        'closure': entries,
    }
    return validate_manifest(manifest)


def validate_manifest(manifest):
    if type(manifest) is not dict or set(manifest) != _MANIFEST_KEYS:
        raise ArtifactError('Invalid manifest fields')
    if type(manifest['schemaVersion']) is not int or manifest['schemaVersion'] != 1:
        raise ArtifactError('Invalid schemaVersion')
    _enum(manifest['kind'], {'nixos-closure'}, 'kind')
    _enum(manifest['runtimeVersion'], {'nspawn-v1'}, 'runtimeVersion')
    _enum(manifest['architecture'], _ARCHITECTURES, 'architecture')
    _store_path(manifest['root'], 'root')
    closure = manifest['closure']
    if type(closure) is not list or not 1 <= len(closure) <= _MAX_ENTRIES:
        raise ArtifactError('Invalid closure')
    for record in closure:
        _entry(record)
    paths = [record['path'] for record in closure]
    if paths != sorted(set(paths)):
        raise ArtifactError('Invalid closure order')
    pathset = set(paths)
    if manifest['root'] not in pathset:
        raise ArtifactError('Missing root')
    for record in closure:
        for ref in record['references']:
            if ref not in pathset:
                raise ArtifactError('Unknown reference')
    by_path = {record['path']: record for record in closure}
    seen = set()
    stack = [manifest['root']]
    while stack:
        node = stack.pop()
        if node in seen:
            continue
        seen.add(node)
        stack.extend(by_path[node]['references'])
    if seen != pathset:
        raise ArtifactError('Unreachable closure entries')
    return copy.deepcopy(manifest)


def manifest_digest(manifest):
    return 'sha256:' + hashlib.sha256(canonical_bytes(validate_manifest(manifest))).hexdigest()


def seal_workload(definition, manifest):
    record = validate_manifest(manifest)
    if type(definition) is not dict:
        raise ArtifactError('Invalid definition')
    draft = copy.deepcopy(definition)
    if 'revisionDigest' in draft:
        raise ArtifactError('Invalid definition fields')
    if draft.get('architecture') != record['architecture']:
        raise ArtifactError('Architecture mismatch')
    if draft.get('runtimeVersion') != record['runtimeVersion']:
        raise ArtifactError('Runtime mismatch')
    runtime_id = draft.get('runtimeArtifactId')
    artifacts = draft.get('artifacts')
    if type(runtime_id) is not str or type(artifacts) is not list:
        raise ArtifactError('Invalid artifacts')
    for artifact in artifacts:
        if type(artifact) is dict and artifact.get('id') == runtime_id:
            raise ArtifactError('Duplicate runtime artifact')
    draft['artifacts'] = artifacts + [{
        'id': runtime_id,
        'kind': 'nixos-closure',
        'digest': manifest_digest(record),
    }]
    return catalog.seal_definition(draft)


def _reject_constant(value):
    raise ArtifactError('Invalid JSON constant')


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactError('Duplicate JSON key')
        result[key] = value
    return result


def _load_json(path):
    try:
        return json.loads(Path(path).read_bytes(), parse_constant=_reject_constant,
                          object_pairs_hook=_no_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise ArtifactError('Invalid JSON input') from None


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('build')
    build.add_argument('--graph', required=True)
    build.add_argument('--root', required=True)
    build.add_argument('--architecture', required=True)
    build.add_argument('--definition', required=True)
    build.add_argument('--output', required=True)
    args = parser.parse_args()
    if args.command == 'build':
        manifest = build_manifest(args.root, args.architecture, _load_json(args.graph))
        sealed = seal_workload(_load_json(args.definition), manifest)
        output = Path(args.output)
        output.mkdir(parents=True, exist_ok=True)
        (output / 'artifact.json').write_bytes(canonical_bytes(manifest))
        (output / 'artifact.sha256').write_text(manifest_digest(manifest) + '\n')
        (output / 'definition.json').write_bytes(canonical_bytes(sealed))


if __name__ == '__main__':
    main()
