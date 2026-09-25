"""Immutable workload-recovery-point manifest contract.

Defines the sealed metadata record produced at capture time: which sealed
definition, which provenance (host/instance/generation/uidBase), which
claimed capture barrier, and which logical state set a later restic
repository is expected to contain.

This module performs no backup. Content hashing binds metadata to its
identifier; it does not authenticate its author. Repository location,
snapshot ids, integrity and recoverability evidence are deliberately
separate records established by future authorized transport. A
'quiesced' capture records a claimed write barrier, not proof of
application-level consistency. Each state root's treeDigest declares
the SHA256 of the raw decrypted/uncompressed restic tree blob bytes
for that state root under restic-posix-v1 (restic's native tree id);
a future engine must derive and verify each tree id from the selected
snapshot before a point can be published as usable.
"""

import copy
import hashlib
import json
import re

import artifacts
import catalog


class RecoveryError(ValueError):
    pass


_SCHEMA_VERSION = 2
_KIND = 'workload-recovery-point'
_STATE_FORMAT = 'restic-posix-v1'
_ADAPTER = 'quiesce-v1'
_CONSISTENCY = 'quiesced'
_HEX32_RE = re.compile(r'[0-9a-f]{32}')
_FIELDS = ('schemaVersion', 'kind', 'recoveryPointId', 'definition',
           'source', 'capture', 'stateFormat', 'state', 'secretBundle')
_MAX_I64 = 2**63 - 1
_MAX_TIME = 2**53
_MAX_UID_BASE = 2**32 - 131072
_MAX_STATE = 64
_MAX_BYTES = 2 * 1024 * 1024
_MAX_RECORDS = 10000


def _fields(value, expected, context):
    try:
        catalog.fields(value, expected, context)
    except catalog.CatalogError as error:
        raise RecoveryError(str(error)) from None


def _integer(value, low, high, context):
    try:
        catalog.integer(value, low, high, context)
    except catalog.CatalogError as error:
        raise RecoveryError(str(error)) from None


def _identifier(value, context):
    try:
        catalog.identifier(value, context)
    except catalog.CatalogError as error:
        raise RecoveryError(str(error)) from None


def _digest(value, context):
    try:
        catalog._digest(value, context)
    except catalog.CatalogError as error:
        raise RecoveryError(str(error)) from None


def _hex32(value, context):
    if type(value) is not str or _HEX32_RE.fullmatch(value) is None:
        raise RecoveryError('Invalid ' + context)


def _uid_base(value):
    # Numeric user-namespace ownership provenance for later translation
    # onto a target host; not a placement binding. Published worker range.
    if type(value) is not int or value <= 0 \
            or value % 65536 != 0 or value > _MAX_UID_BASE:
        raise RecoveryError('Invalid uidBase')


def _point_digest(body):
    try:
        raw = artifacts.canonical_bytes(body)
    except artifacts.ArtifactError as error:
        raise RecoveryError(str(error)) from None
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _deepcopy(value):
    try:
        return copy.deepcopy(value)
    except RecursionError:
        raise RecoveryError('Value too deeply nested') from None


def _validated_definition(definition):
    try:
        record = catalog.validate_definition(definition)
    except catalog.CatalogError as error:
        raise RecoveryError(str(error)) from None
    except RecursionError:
        raise RecoveryError('Definition too deeply nested') from None
    if record['category'] == 'archive':
        raise RecoveryError('Archived definitions are not recovery points')
    if record['runtimeVersion'] != 'nspawn-v1':
        raise RecoveryError('Invalid runtimeVersion')
    if 'backup' not in record['allowedOperations']:
        raise RecoveryError('Definition does not allow backup')
    # Pin the only capture adapter this contract admits even if the
    # catalog later learns more.
    for mount in record['stateMounts']:
        if mount['consistencyAdapter'] != _ADAPTER:
            raise RecoveryError('Invalid consistencyAdapter')
    return record


def _validated_source(source):
    _fields(source, ('hostId', 'instanceId', 'generation', 'uidBase'),
            'source')
    _identifier(source['hostId'], 'hostId')
    _hex32(source['instanceId'], 'instanceId')
    _integer(source['generation'], 1, _MAX_I64, 'generation')
    _uid_base(source['uidBase'])
    return source


def _validated_capture(capture):
    _fields(capture,
            ('adapter', 'consistency', 'startedAt', 'completedAt'),
            'capture')
    if type(capture['adapter']) is not str \
            or capture['adapter'] != _ADAPTER:
        raise RecoveryError('Invalid capture adapter')
    if type(capture['consistency']) is not str \
            or capture['consistency'] != _CONSISTENCY:
        raise RecoveryError('Invalid capture consistency')
    _integer(capture['startedAt'], 0, _MAX_TIME, 'startedAt')
    _integer(capture['completedAt'], 0, _MAX_TIME, 'completedAt')
    if capture['completedAt'] < capture['startedAt']:
        raise RecoveryError('Invalid capture window')
    return capture


def _validated_tree_digests(digests, definition):
    if type(digests) is not dict:
        raise RecoveryError('Invalid state tree digests')
    expected = set(mount['id'] for mount in definition['stateMounts'])
    if set(digests) != expected:
        raise RecoveryError('Invalid state tree digests')
    for mount_id in expected:
        _digest(digests[mount_id], 'treeDigest')
    return digests


def _validated_state(state, definition):
    if type(state) is not list or len(state) > _MAX_STATE:
        raise RecoveryError('Invalid state')
    expected = sorted(mount['id'] for mount in definition['stateMounts'])
    seen = []
    for entry in state:
        _fields(entry, ('id', 'path', 'treeDigest'), 'state entry')
        _identifier(entry['id'], 'state id')
        if type(entry['path']) is not str \
                or entry['path'] != 'state/' + entry['id']:
            raise RecoveryError('Invalid state path')
        _digest(entry['treeDigest'], 'treeDigest')
        seen.append(entry['id'])
    if seen != expected:
        raise RecoveryError('Invalid state set')
    return state


def _validated_secret_bundle(bundle, definition):
    if definition['secretSetRef'] is None:
        if bundle is not None:
            raise RecoveryError('Unexpected secretBundle')
        return None
    _fields(bundle, ('secretSetRef', 'versionDigest', 'bundleDigest'),
            'secretBundle')
    _identifier(bundle['secretSetRef'], 'secretSetRef')
    if bundle['secretSetRef'] != definition['secretSetRef']:
        raise RecoveryError('Invalid secretSetRef')
    _digest(bundle['versionDigest'], 'versionDigest')
    _digest(bundle['bundleDigest'], 'bundleDigest')
    return bundle


def build_manifest(definition, source, capture, *, state_tree_digests,
                   secret_bundle=None):
    record = _validated_definition(_deepcopy(definition))
    src = _validated_source(_deepcopy(source))
    cap = _validated_capture(_deepcopy(capture))
    bundle = _validated_secret_bundle(_deepcopy(secret_bundle), record)
    digests = _validated_tree_digests(_deepcopy(state_tree_digests),
                                      record)
    body = {
        'schemaVersion': _SCHEMA_VERSION,
        'kind': _KIND,
        'definition': record,
        'source': src,
        'capture': cap,
        'stateFormat': _STATE_FORMAT,
        'state': [{'id': mid, 'path': 'state/' + mid,
                   'treeDigest': digests[mid]}
                  for mid in sorted(
                      mount['id'] for mount in record['stateMounts'])],
        'secretBundle': bundle,
    }
    body['recoveryPointId'] = _point_digest(body)
    return validate_manifest(body)


def validate_manifest(value):
    if type(value) is not dict:
        raise RecoveryError('Invalid manifest')
    candidate = _deepcopy(value)
    _fields(candidate, _FIELDS, 'manifest')
    _integer(candidate['schemaVersion'], _SCHEMA_VERSION, _SCHEMA_VERSION,
             'schemaVersion')
    if type(candidate['kind']) is not str or candidate['kind'] != _KIND:
        raise RecoveryError('Invalid kind')
    _digest(candidate['recoveryPointId'], 'recoveryPointId')
    candidate['definition'] = _validated_definition(
        candidate['definition'])
    candidate['source'] = _validated_source(candidate['source'])
    candidate['capture'] = _validated_capture(candidate['capture'])
    if type(candidate['stateFormat']) is not str \
            or candidate['stateFormat'] != _STATE_FORMAT:
        raise RecoveryError('Invalid stateFormat')
    candidate['state'] = _validated_state(candidate['state'],
                                          candidate['definition'])
    candidate['secretBundle'] = _validated_secret_bundle(
        candidate['secretBundle'], candidate['definition'])
    body = {key: value for key, value in candidate.items()
            if key != 'recoveryPointId'}
    if _point_digest(body) != candidate['recoveryPointId']:
        raise RecoveryError('Digest mismatch')
    return candidate


def encode_manifest(value):
    record = validate_manifest(value)
    try:
        raw = artifacts.canonical_bytes(record)
    except artifacts.ArtifactError as error:
        raise RecoveryError(str(error)) from None
    if len(raw) > _MAX_BYTES:
        raise RecoveryError('Manifest too large')
    return raw


def _reject_constant(value):
    raise RecoveryError('Invalid JSON constant')


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RecoveryError('Duplicate JSON key')
        result[key] = value
    return result


def decode_manifest(raw):
    if type(raw) is not bytes or not raw or len(raw) > _MAX_BYTES:
        raise RecoveryError('Invalid manifest encoding')
    try:
        value = json.loads(raw, parse_constant=_reject_constant,
                           object_pairs_hook=_no_duplicate_keys)
    except RecoveryError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError,
            ValueError):
        raise RecoveryError('Invalid manifest JSON') from None
    record = validate_manifest(value)
    if encode_manifest(record) != raw:
        raise RecoveryError('Non-canonical manifest encoding')
    return record


def catalog_from_manifests(records):
    if type(records) is not list or len(records) > _MAX_RECORDS:
        raise RecoveryError('Invalid manifest list')
    entries = {}
    for record in records:
        candidate = validate_manifest(record)
        point_id = candidate['recoveryPointId']
        existing = entries.get(point_id)
        if existing is not None:
            if existing != candidate:
                raise RecoveryError('Conflicting recovery point')
            continue
        entries[point_id] = candidate
    ordered = sorted(
        entries.values(),
        key=lambda manifest: (
            manifest['definition']['workloadId'],
            manifest['capture']['startedAt'],
            manifest['recoveryPointId']))
    return [_deepcopy(manifest) for manifest in ordered]
