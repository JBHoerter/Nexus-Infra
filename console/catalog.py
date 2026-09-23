import copy
import hashlib
import json
import re


class CatalogError(ValueError):
    pass


_SCHEMA_VERSION = 2
_ID_RE = re.compile(r'[a-z][a-z0-9-]{0,62}')
_DIGEST_RE = re.compile(r'sha256:[0-9a-f]{64}')
_MOUNT_SEGMENT_RE = re.compile(r'[A-Za-z0-9_.-]+')
_CATEGORIES = {'project', 'third-party', 'infrastructure', 'archive'}
_ARCHITECTURES = {'x86_64-linux', 'aarch64-linux'}
_ARTIFACT_KINDS = {'nixos-closure', 'oci-image', 'archive'}
_ADAPTERS = {'quiesce-v1'}
_PROTOCOLS = {'http', 'https', 'tcp', 'udp'}
_EXPOSURES = {'private', 'public', 'lan'}
_OPERATIONS = {'start', 'stop', 'restart', 'backup', 'restore', 'move'}
_RESERVED_ROOTS = {'etc', 'dev', 'proc', 'sys', 'run', 'nix'}
_RESOURCE_KEYS = ('memoryMiB', 'cpuMillis', 'stateBytes')
_MAX_I64 = 2**63 - 1
_MAX_I32 = 2**31 - 1


def fields(value, expected, context):
    if type(value) is not dict or set(value) != set(expected):
        raise CatalogError('Invalid ' + context + ' fields')


def integer(value, low, high, context):
    if type(value) is not int or not low <= value <= high:
        raise CatalogError('Invalid ' + context)


def identifier(value, context):
    if type(value) is not str or _ID_RE.fullmatch(value) is None:
        raise CatalogError('Invalid ' + context)


def _digest(value, context):
    if type(value) is not str or _DIGEST_RE.fullmatch(value) is None:
        raise CatalogError('Invalid ' + context)


def _enum(value, choices, context):
    if type(value) is not str or value not in choices:
        raise CatalogError('Invalid ' + context)


def _string(value, context, maximum):
    if type(value) is not str or not value or len(value) > maximum:
        raise CatalogError('Invalid ' + context)
    for char in value:
        code = ord(char)
        if code < 0x20 or 0x7F <= code <= 0x9F or 0xD800 <= code <= 0xDFFF:
            raise CatalogError('Invalid ' + context)


def _id_list(value, context):
    if type(value) is not list or len(value) > 64:
        raise CatalogError('Invalid ' + context)
    for entry in value:
        identifier(entry, context)
    if len(set(value)) != len(value):
        raise CatalogError('Invalid ' + context)
    return value


def _mount_point(value):
    context = 'mountPoint'
    if type(value) is not str or not value.startswith('/') or value == '/' or value.endswith('/') or len(value) > 4095:
        raise CatalogError('Invalid ' + context)
    segments = value[1:].split('/')
    for segment in segments:
        if segment in ('.', '..') or len(segment) > 255 or _MOUNT_SEGMENT_RE.fullmatch(segment) is None:
            raise CatalogError('Invalid ' + context)
    if segments[0] in _RESERVED_ROOTS:
        raise CatalogError('Invalid ' + context)
    return segments


def _resource_map(value, context):
    fields(value, _RESOURCE_KEYS, context)
    for key in _RESOURCE_KEYS:
        integer(value[key], 0, _MAX_I64, context + ' ' + key)


def _shape(definition):
    fields(definition, (
        'schemaVersion', 'workloadId', 'displayName', 'category', 'revisionDigest',
        'runtimeVersion', 'architecture', 'runtimeArtifactId', 'artifacts',
        'stateSchemaVersion', 'stateMounts', 'secretSetRef', 'dependencies',
        'services', 'requirements', 'allowedOperations', 'policyProfiles',
    ), 'definition')
    if type(definition['schemaVersion']) is not int or definition['schemaVersion'] != _SCHEMA_VERSION:
        raise CatalogError('Invalid schemaVersion')
    identifier(definition['workloadId'], 'workloadId')
    _string(definition['displayName'], 'displayName', 160)
    _enum(definition['category'], _CATEGORIES, 'category')
    archived = definition['category'] == 'archive'
    _digest(definition['revisionDigest'], 'revisionDigest')
    if archived:
        if definition['runtimeVersion'] is not None:
            raise CatalogError('Invalid runtimeVersion')
        if definition['runtimeArtifactId'] is not None:
            raise CatalogError('Invalid runtimeArtifactId')
    else:
        if definition['runtimeVersion'] != 'nspawn-v1':
            raise CatalogError('Invalid runtimeVersion')
        identifier(definition['runtimeArtifactId'], 'runtimeArtifactId')
    _enum(definition['architecture'], _ARCHITECTURES, 'architecture')
    artifacts = definition['artifacts']
    if type(artifacts) is not list or not 1 <= len(artifacts) <= 64:
        raise CatalogError('Invalid artifacts')
    artifact_ids = set()
    runtime_kind = None
    for artifact in artifacts:
        fields(artifact, ('id', 'kind', 'digest'), 'artifact')
        identifier(artifact['id'], 'artifact id')
        if artifact['id'] in artifact_ids:
            raise CatalogError('Duplicate artifact id')
        artifact_ids.add(artifact['id'])
        _enum(artifact['kind'], _ARTIFACT_KINDS, 'artifact kind')
        _digest(artifact['digest'], 'artifact digest')
        if artifact['id'] == definition['runtimeArtifactId']:
            runtime_kind = artifact['kind']
    if not archived and runtime_kind != 'nixos-closure':
        raise CatalogError('Invalid runtimeArtifactId')
    integer(definition['stateSchemaVersion'], 1, _MAX_I32, 'stateSchemaVersion')
    mounts = definition['stateMounts']
    if type(mounts) is not list or len(mounts) > 64:
        raise CatalogError('Invalid stateMounts')
    mount_ids = set()
    points = []
    for mount in mounts:
        fields(mount, ('id', 'mountPoint', 'ownerUid', 'ownerGid', 'consistencyAdapter'), 'stateMount')
        identifier(mount['id'], 'stateMount id')
        if mount['id'] in mount_ids:
            raise CatalogError('Duplicate stateMount id')
        mount_ids.add(mount['id'])
        points.append(tuple(_mount_point(mount['mountPoint'])))
        integer(mount['ownerUid'], 0, 65535, 'ownerUid')
        integer(mount['ownerGid'], 0, 65535, 'ownerGid')
        _enum(mount['consistencyAdapter'], _ADAPTERS, 'consistencyAdapter')
    for index, point in enumerate(points):
        for other in points[index + 1:]:
            shorter, longer = (point, other) if len(point) <= len(other) else (other, point)
            if longer[:len(shorter)] == shorter:
                raise CatalogError('Overlapping stateMounts')
    if definition['secretSetRef'] is not None:
        identifier(definition['secretSetRef'], 'secretSetRef')
    dependencies = _id_list(definition['dependencies'], 'dependencies')
    if definition['workloadId'] in dependencies:
        raise CatalogError('Self dependency')
    services = definition['services']
    if type(services) is not list or len(services) > 64:
        raise CatalogError('Invalid services')
    service_ids = set()
    for service in services:
        fields(service, ('id', 'protocol', 'port', 'exposure'), 'service')
        identifier(service['id'], 'service id')
        if service['id'] in service_ids:
            raise CatalogError('Duplicate service id')
        service_ids.add(service['id'])
        _enum(service['protocol'], _PROTOCOLS, 'protocol')
        integer(service['port'], 1, 65535, 'port')
        _enum(service['exposure'], _EXPOSURES, 'exposure')
    requirements = definition['requirements']
    fields(requirements, _RESOURCE_KEYS + ('capabilities',), 'requirements')
    minimum = 0 if archived else 1
    integer(requirements['memoryMiB'], minimum, _MAX_I64, 'requirements memoryMiB')
    integer(requirements['cpuMillis'], minimum, _MAX_I64, 'requirements cpuMillis')
    integer(requirements['stateBytes'], 0, _MAX_I64, 'requirements stateBytes')
    _id_list(requirements['capabilities'], 'capabilities')
    operations = definition['allowedOperations']
    if type(operations) is not list or len(operations) > 6:
        raise CatalogError('Invalid allowedOperations')
    for operation in operations:
        _enum(operation, _OPERATIONS, 'allowedOperations')
    if len(set(operations)) != len(operations):
        raise CatalogError('Invalid allowedOperations')
    _id_list(definition['policyProfiles'], 'policyProfiles')
    if definition['category'] == 'infrastructure' and any(operation != 'backup' for operation in operations):
        raise CatalogError('Invalid allowedOperations')
    if archived and operations:
        raise CatalogError('Invalid allowedOperations')


def revision_digest(definition):
    if type(definition) is not dict:
        raise CatalogError('Definition is not canonical JSON')
    body = {key: value for key, value in definition.items() if key != 'revisionDigest'}
    try:
        raw = json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (TypeError, ValueError, UnicodeError):
        raise CatalogError('Definition is not canonical JSON') from None
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def seal_definition(definition):
    if type(definition) is not dict or 'revisionDigest' in definition:
        raise CatalogError('Invalid definition fields')
    candidate = copy.deepcopy(definition)
    candidate['revisionDigest'] = revision_digest(candidate)
    return validate_definition(candidate)


def validate_definition(definition):
    candidate = copy.deepcopy(definition)
    _shape(candidate)
    if revision_digest(candidate) != candidate['revisionDigest']:
        raise CatalogError('Digest mismatch')
    return candidate


class Catalog:
    def __init__(self, definitions):
        if type(definitions) is not list or len(definitions) > 1024:
            raise CatalogError('Invalid catalog')
        entries = {}
        for definition in definitions:
            record = validate_definition(definition)
            workload_id = record['workloadId']
            if workload_id in entries:
                raise CatalogError('Duplicate workloadId')
            entries[workload_id] = record
        dependents = {}
        for workload_id, record in entries.items():
            for dependency in record['dependencies']:
                if dependency not in entries:
                    raise CatalogError('Unknown dependency')
                dependents.setdefault(dependency, []).append(workload_id)
        remaining = {wid: len(record['dependencies']) for wid, record in entries.items()}
        queue = [wid for wid, count in remaining.items() if count == 0]
        resolved = 0
        while queue:
            node = queue.pop()
            resolved += 1
            for dependent in dependents.get(node, ()):
                remaining[dependent] -= 1
                if remaining[dependent] == 0:
                    queue.append(dependent)
        if resolved != len(entries):
            raise CatalogError('Dependency cycle')
        self._canonical = {
            wid: json.dumps(record, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')
            for wid, record in entries.items()
        }

    def get(self, workload_id, revision_digest):
        identifier(workload_id, 'workloadId')
        _digest(revision_digest, 'revisionDigest')
        canonical = self._canonical.get(workload_id)
        if canonical is None or json.loads(canonical)['revisionDigest'] != revision_digest:
            raise CatalogError('Unknown workload revision')
        return json.loads(canonical)

    def document(self):
        return {
            'schemaVersion': _SCHEMA_VERSION,
            'workloads': [json.loads(self._canonical[wid]) for wid in sorted(self._canonical)],
        }


def _timestamp(value, context):
    if type(value) not in (int, float) or not 0 <= value <= _MAX_I64:
        raise CatalogError('Invalid ' + context)


def admit(definition, host, observation, *, now, reservations=None, max_age_seconds=20):
    record = validate_definition(definition)
    fields(host, ('schemaVersion', 'hostId', 'architecture', 'capabilities'), 'host')
    if type(host['schemaVersion']) is not int or host['schemaVersion'] != _SCHEMA_VERSION:
        raise CatalogError('Invalid schemaVersion')
    identifier(host['hostId'], 'hostId')
    _enum(host['architecture'], _ARCHITECTURES, 'architecture')
    _id_list(host['capabilities'], 'capabilities')
    _timestamp(now, 'now')
    if type(max_age_seconds) not in (int, float) or not 0 < max_age_seconds <= 3600:
        raise CatalogError('Invalid max_age_seconds')
    if reservations is None:
        reserved = {'memoryMiB': 0, 'cpuMillis': 0, 'stateBytes': 0}
    else:
        _resource_map(reservations, 'reservations')
        reserved = reservations
    reasons = []
    if record['category'] == 'archive':
        reasons.append('workload-archived')
    if record['architecture'] != host['architecture']:
        reasons.append('architecture-mismatch')
    for capability in record['requirements']['capabilities']:
        if capability not in host['capabilities']:
            reasons.append('capability-missing:' + capability)
    if observation is None:
        reasons.append('observation-missing')
    else:
        fields(observation, ('schemaVersion', 'hostId', 'observedAt', 'available'), 'observation')
        if type(observation['schemaVersion']) is not int or observation['schemaVersion'] != _SCHEMA_VERSION:
            raise CatalogError('Invalid schemaVersion')
        identifier(observation['hostId'], 'hostId')
        _timestamp(observation['observedAt'], 'observedAt')
        _resource_map(observation['available'], 'available')
        if observation['hostId'] != host['hostId']:
            reasons.append('observation-host-mismatch')
        elif observation['observedAt'] > now:
            reasons.append('observation-from-future')
        elif now - observation['observedAt'] > max_age_seconds:
            reasons.append('observation-stale')
        else:
            requirements = record['requirements']
            available = observation['available']
            for key, code in (('memoryMiB', 'insufficient-memory'),
                              ('cpuMillis', 'insufficient-cpu'),
                              ('stateBytes', 'insufficient-state')):
                if max(available[key] - reserved[key], 0) < requirements[key]:
                    reasons.append(code)
    return {
        'workloadId': record['workloadId'],
        'revisionDigest': record['revisionDigest'],
        'hostId': host['hostId'],
        'checkedAt': now,
        'eligible': not reasons,
        'reasons': reasons,
    }
