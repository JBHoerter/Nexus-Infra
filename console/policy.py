"""Deterministic per-workload backup policy evaluation (planning half).

Consumes a recovery-point catalog (sealed workload-recovery-point
manifests, console/recovery.py) plus caller-supplied protection
evidence and one ``workload-backup-policy`` record per workload, and
emits an explainable point classification, capture-due state and a
consolidated due-work plan for a scheduler.

This module never executes backups, uploads, deletes, forgets or
prunes anything and never reads a clock: ``now`` is a parameter and
identical inputs produce byte-identical output. Deletion remains
forbidden system-wide; 'retention' here is advisory point-status
classification only. ``expired-eligible`` is a report label, not a
request to drop data, and keepMinimum always wins over age.

Each ``points`` entry is either a bare manifest or a wrapper
``{'manifest': ..., 'record': ...}`` whose record carries the
caller-attested evidence ``{'uploadedCopies': int,
'verified': bool}`` (or ``None`` when no evidence exists). Evidence
is trusted as supplied; a point counts as protected only when the
record proves a verified uploaded copy, or the point id is pinned in
``protectedPointIds``.
"""

import copy
import hashlib

import artifacts
import catalog
import recovery


class PolicyError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


_SCHEMA_VERSION = 1
_KIND = 'workload-backup-policy'
_FIELDS = ('schemaVersion', 'kind', 'workloadId', 'revisionDigest',
           'captureIntervalSeconds', 'recoveryPointMaxAgeSeconds',
           'keepMinimum', 'protectedPointIds')
_MAX_INTERVAL = 7 * 24 * 3600
_MAX_AGE = 30 * 24 * 3600
_MAX_KEEP = 1024
_MAX_PINS = 1024
_MAX_COPIES = 1024
_MAX_POINTS = 10000
_MAX_EVALUATIONS = 1024
_MAX_TIME = 2**53
_EVALUATION_FIELDS = ('captureDue', 'evaluatedAt', 'freshestProtected',
                      'points', 'policyDigest', 'protectionStatus',
                      'workloadId')


def _deepcopy(value):
    try:
        return copy.deepcopy(value)
    except RecursionError:
        raise PolicyError('invalid-value') from None


def _identifier(value):
    try:
        catalog.identifier(value, 'identifier')
    except catalog.CatalogError:
        raise PolicyError('invalid-identifier') from None


def _digest(value):
    try:
        catalog._digest(value, 'digest')
    except catalog.CatalogError:
        raise PolicyError('invalid-digest') from None


def _timestamp(value, code):
    if type(value) is not int or not 0 <= value <= _MAX_TIME:
        raise PolicyError(code)


def validate_policy(value):
    if type(value) is not dict:
        raise PolicyError('invalid-policy')
    candidate = _deepcopy(value)
    if set(candidate) != set(_FIELDS):
        raise PolicyError('invalid-policy-fields')
    if type(candidate['schemaVersion']) is not int \
            or candidate['schemaVersion'] != _SCHEMA_VERSION:
        raise PolicyError('invalid-policy')
    if type(candidate['kind']) is not str or candidate['kind'] != _KIND:
        raise PolicyError('invalid-policy')
    try:
        catalog.identifier(candidate['workloadId'], 'workloadId')
    except catalog.CatalogError:
        raise PolicyError('invalid-policy') from None
    try:
        catalog._digest(candidate['revisionDigest'], 'revisionDigest')
    except catalog.CatalogError:
        raise PolicyError('invalid-policy') from None
    if type(candidate['captureIntervalSeconds']) is not int \
            or not 1 <= candidate['captureIntervalSeconds'] \
                    <= _MAX_INTERVAL:
        raise PolicyError('invalid-policy')
    if type(candidate['recoveryPointMaxAgeSeconds']) is not int \
            or not 1 <= candidate['recoveryPointMaxAgeSeconds'] \
                    <= _MAX_AGE:
        raise PolicyError('invalid-policy')
    if type(candidate['keepMinimum']) is not int \
            or not 0 <= candidate['keepMinimum'] <= _MAX_KEEP:
        raise PolicyError('invalid-policy')
    pins = candidate['protectedPointIds']
    if type(pins) is not list or len(pins) > _MAX_PINS:
        raise PolicyError('invalid-policy')
    for pin in pins:
        try:
            catalog._digest(pin, 'protectedPointIds')
        except catalog.CatalogError:
            raise PolicyError('invalid-policy') from None
    if len(set(pins)) != len(pins):
        raise PolicyError('invalid-policy')
    return candidate


def build_policy(workload_id, revision_digest, *,
                 capture_interval_seconds,
                 recovery_point_max_age_seconds,
                 keep_minimum=0, protected_point_ids=()):
    return validate_policy({
        'schemaVersion': _SCHEMA_VERSION,
        'kind': _KIND,
        'workloadId': workload_id,
        'revisionDigest': revision_digest,
        'captureIntervalSeconds': capture_interval_seconds,
        'recoveryPointMaxAgeSeconds': recovery_point_max_age_seconds,
        'keepMinimum': keep_minimum,
        'protectedPointIds': list(protected_point_ids),
    })


def policy_digest(value):
    record = validate_policy(value)
    try:
        raw = artifacts.canonical_bytes(record)
    except artifacts.ArtifactError:
        raise PolicyError('invalid-policy') from None
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def encode_evaluation(result):
    try:
        return artifacts.canonical_bytes(result)
    except artifacts.ArtifactError:
        raise PolicyError('invalid-evaluation') from None


def _record(value):
    if type(value) is not dict \
            or set(value) != {'uploadedCopies', 'verified'}:
        raise PolicyError('invalid-point-record')
    if type(value['verified']) is not bool \
            or type(value['uploadedCopies']) is not int \
            or not 0 <= value['uploadedCopies'] <= _MAX_COPIES:
        raise PolicyError('invalid-point-record')
    return dict(value)


def _point_entry(entry):
    if type(entry) is not dict:
        raise PolicyError('invalid-point')
    if 'manifest' in entry or 'record' in entry:
        if set(entry) != {'manifest', 'record'}:
            raise PolicyError('invalid-point')
        manifest, record = entry['manifest'], entry['record']
    else:
        manifest, record = entry, None
    try:
        manifest = recovery.validate_manifest(manifest)
    except recovery.RecoveryError:
        raise PolicyError('invalid-point') from None
    except RecursionError:
        raise PolicyError('invalid-point') from None
    return manifest, _record(record) if record is not None else None


def evaluate(policy, points, now, *, last_capture_completed_at=None):
    """Classify one workload's points and capture schedule, purely.

    Returns a fresh deterministic dict; inputs are never mutated.
    ``last_capture_completed_at`` is the caller's newest completed
    capture timestamp (e.g. a captured-but-never-uploaded job) and is
    combined with the cataloged points' completedAt values."""
    record = validate_policy(policy)
    _timestamp(now, 'invalid-now')
    if last_capture_completed_at is not None:
        _timestamp(last_capture_completed_at, 'invalid-last-capture')
        if last_capture_completed_at > now:
            raise PolicyError('invalid-last-capture')
    if type(points) is not list or len(points) > _MAX_POINTS:
        raise PolicyError('invalid-points')

    pins = set(record['protectedPointIds'])
    parsed = {}
    for entry in points:
        manifest, attached = _point_entry(entry)
        if manifest['definition']['workloadId'] \
                != record['workloadId']:
            raise PolicyError('foreign-workload')
        started = manifest['capture']['startedAt']
        if started > now:
            raise PolicyError('point-in-future')
        point_id = manifest['recoveryPointId']
        existing = parsed.get(point_id)
        if existing is not None:
            if existing['record'] != attached:
                raise PolicyError('conflicting-point')
            continue
        verified_copy = attached is not None and attached['verified'] \
            and attached['uploadedCopies'] >= 1
        parsed[point_id] = {
            'id': point_id,
            'startedAt': started,
            'completedAt': manifest['capture']['completedAt'],
            'legacy': manifest['schemaVersion']
                      == recovery._LEGACY_SCHEMA_VERSION,
            'pinned': point_id in pins,
            'record': attached,
            'verifiedCopy': verified_copy,
        }
    ordered = sorted(parsed.values(),
                     key=lambda p: (p['startedAt'], p['id']))

    protected = [p for p in ordered
                 if not p['legacy'] and (p['pinned'] or p['verifiedCopy'])]
    current = protected[-1] if protected else None
    keep_minimum = record['keepMinimum']
    max_age = record['recoveryPointMaxAgeSeconds']
    # Expire only unneeded unpinned over-age protected points, oldest
    # first; keepMinimum always wins over age.
    retained = len(protected)
    expired = set()
    for point in protected[:-1]:
        if point['pinned'] or now - point['startedAt'] <= max_age:
            continue
        if retained - 1 < keep_minimum:
            continue
        expired.add(point['id'])
        retained -= 1

    out_points = []
    for point in ordered:
        reasons = []
        if point['pinned']:
            reasons.append('pinned')
        if point['verifiedCopy']:
            reasons.append('verified-copy')
        elif point['record'] is None:
            if not point['pinned']:
                reasons.append('evidence-missing')
        else:
            if not point['record']['verified']:
                reasons.append('unverified')
            if point['record']['uploadedCopies'] < 1:
                reasons.append('no-uploaded-copy')
        if point['legacy']:
            reasons.append('legacy-format')
            classification = 'legacy-v2'
        elif not point['pinned'] and not point['verifiedCopy']:
            classification = 'unprotected'
        elif current is not None and point['id'] == current['id']:
            reasons.append('newest-protected')
            classification = 'current-protected'
        elif point['id'] in expired:
            reasons.append('older-than-max-age')
            classification = 'expired-eligible'
        elif point['pinned']:
            classification = 'retained'
        elif now - point['startedAt'] > max_age:
            reasons.append('keep-minimum')
            classification = 'retained'
        else:
            reasons.append('within-max-age')
            classification = 'retained'
        out_points.append({
            'recoveryPointId': point['id'],
            'captureStartedAt': point['startedAt'],
            'classification': classification,
            'reasons': reasons,
        })

    freshest = None
    if current is not None:
        freshest = {'recoveryPointId': current['id'],
                    'ageSeconds': now - current['startedAt']}

    completed = [p['completedAt'] for p in ordered]
    if last_capture_completed_at is not None:
        completed.append(last_capture_completed_at)
    last_completed = max(completed) if completed else None
    if last_completed is None:
        next_due = now
    else:
        next_due = last_completed + record['captureIntervalSeconds']
    overdue = max(0, now - next_due)
    if not ordered:
        reason = 'no-points'
    elif last_completed is None or now - last_completed \
            > record['captureIntervalSeconds']:
        reason = 'interval-elapsed'
    elif freshest is None:
        reason = 'no-protected-point'
    else:
        reason = 'not-due'

    status_reasons = []
    if freshest is None:
        status_reasons.append('no-protected-point')
    elif freshest['ageSeconds'] > max_age:
        status_reasons.append('protected-point-stale')
    if reason != 'not-due':
        status_reasons.append('capture-due')

    return {
        'policyDigest': policy_digest(record),
        'workloadId': record['workloadId'],
        'evaluatedAt': now,
        'captureDue': {
            'due': reason != 'not-due',
            'reason': reason,
            'overdueBySeconds': overdue,
            'nextDueAt': next_due,
        },
        'points': out_points,
        'freshestProtected': freshest,
        'protectionStatus': {
            'healthy': freshest is not None
                       and freshest['ageSeconds'] <= max_age
                       and reason == 'not-due',
            'reasons': status_reasons,
        },
    }


def _evaluation_entry(entry):
    if type(entry) is not dict or set(entry) != set(_EVALUATION_FIELDS):
        raise PolicyError('invalid-evaluation')
    try:
        catalog.identifier(entry['workloadId'], 'workloadId')
        catalog._digest(entry['policyDigest'], 'policyDigest')
    except catalog.CatalogError:
        raise PolicyError('invalid-evaluation') from None
    _timestamp(entry['evaluatedAt'], 'invalid-evaluation')
    due = entry['captureDue']
    if type(due) is not dict or set(due) != {'due', 'reason',
                                            'overdueBySeconds',
                                            'nextDueAt'}:
        raise PolicyError('invalid-evaluation')
    if type(due['due']) is not bool \
            or type(due['reason']) is not str \
            or type(due['overdueBySeconds']) is not int \
            or due['overdueBySeconds'] < 0 \
            or type(due['nextDueAt']) is not int:
        raise PolicyError('invalid-evaluation')
    freshest = entry['freshestProtected']
    if freshest is not None:
        if type(freshest) is not dict \
                or set(freshest) != {'recoveryPointId', 'ageSeconds'}:
            raise PolicyError('invalid-evaluation')
        try:
            catalog._digest(freshest['recoveryPointId'],
                            'recoveryPointId')
        except catalog.CatalogError:
            raise PolicyError('invalid-evaluation') from None
        if type(freshest['ageSeconds']) is not int \
                or freshest['ageSeconds'] < 0:
            raise PolicyError('invalid-evaluation')
    if type(entry['points']) is not list:
        raise PolicyError('invalid-evaluation')
    status = entry['protectionStatus']
    if type(status) is not dict or set(status) != {'healthy', 'reasons'} \
            or type(status['healthy']) is not bool \
            or type(status['reasons']) is not list \
            or any(type(code) is not str for code in status['reasons']):
        raise PolicyError('invalid-evaluation')
    return {
        'workloadId': entry['workloadId'],
        'policyDigest': entry['policyDigest'],
        'evaluatedAt': entry['evaluatedAt'],
        'due': due['due'],
        'reason': due['reason'],
        'overdueBySeconds': due['overdueBySeconds'],
        'nextDueAt': due['nextDueAt'],
        'freshestProtected': _deepcopy(freshest),
    }


def plan(evaluations):
    """Consolidate evaluations into one workload-ordered due-work list.

    Sorted by (overdueBySeconds desc, workloadId, policyDigest); pure,
    inputs untouched."""
    if type(evaluations) is not list \
            or len(evaluations) > _MAX_EVALUATIONS:
        raise PolicyError('invalid-plan')
    items = [_evaluation_entry(entry) for entry in evaluations]
    items.sort(key=lambda item: (-item['overdueBySeconds'],
                                 item['workloadId'],
                                 item['policyDigest']))
    return items
