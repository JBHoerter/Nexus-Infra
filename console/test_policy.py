import copy
import unittest

import artifacts
import policy
from test_catalog import sealed
from test_recovery import capture, legacy_manifest, manifest


def base_policy(**overrides):
    record = {
        'schemaVersion': 1,
        'kind': 'workload-backup-policy',
        'workloadId': 'demo',
        'revisionDigest': 'sha256:' + 'a' * 64,
        'captureIntervalSeconds': 3600,
        'recoveryPointMaxAgeSeconds': 86400,
        'keepMinimum': 0,
        'protectedPointIds': [],
    }
    record.update(overrides)
    return record


def point(started, completed=None, **kwargs):
    return manifest(capture=capture(
        startedAt=started,
        completedAt=started + 5 if completed is None else completed),
        **kwargs)


def uploaded(m, copies=1, verified=True):
    return {'manifest': m,
            'record': {'uploadedCopies': copies, 'verified': verified}}


def expect_policy_reject(value):
    try:
        policy.validate_policy(value)
    except policy.PolicyError:
        return
    raise AssertionError('policy unexpectedly accepted')


def expect_eval_reject(*args, **kwargs):
    try:
        policy.evaluate(*args, **kwargs)
    except policy.PolicyError:
        return
    raise AssertionError('evaluation unexpectedly accepted')


class PolicyValidationTests(unittest.TestCase):

    def test_accepts_and_returns_independent_copy(self):
        record = base_policy()
        checked = policy.validate_policy(record)
        self.assertEqual(checked, record)
        self.assertIsNot(checked, record)
        record['protectedPointIds'].append('sha256:' + 'f' * 64)
        self.assertEqual(checked['protectedPointIds'], [])

    def test_build_helper(self):
        record = policy.build_policy(
            'demo', 'sha256:' + 'a' * 64,
            capture_interval_seconds=60,
            recovery_point_max_age_seconds=600,
            keep_minimum=2,
            protected_point_ids=['sha256:' + 'b' * 64])
        self.assertEqual(record, base_policy(
            captureIntervalSeconds=60,
            recoveryPointMaxAgeSeconds=600,
            keepMinimum=2,
            protectedPointIds=['sha256:' + 'b' * 64]))

    def test_exact_fields(self):
        for key in ('schemaVersion', 'kind', 'workloadId',
                    'revisionDigest', 'captureIntervalSeconds',
                    'recoveryPointMaxAgeSeconds', 'keepMinimum',
                    'protectedPointIds'):
            record = base_policy()
            del record[key]
            with self.subTest(missing=key):
                expect_policy_reject(record)
        record = base_policy()
        record['repository'] = 's3:x'
        expect_policy_reject(record)
        expect_policy_reject('x')
        expect_policy_reject(None)

    def test_kind_and_schema(self):
        for key, bad in (('kind', 'workload-policy'),
                         ('kind', 1),
                         ('kind', None),
                         ('schemaVersion', 0),
                         ('schemaVersion', 2),
                         ('schemaVersion', '1'),
                         ('schemaVersion', True)):
            record = base_policy()
            record[key] = bad
            with self.subTest(key=key, bad=bad):
                expect_policy_reject(record)

    def test_identity_fields(self):
        for bad in ('Demo', '', 'x' * 64, 7, None):
            with self.subTest(workloadId=bad):
                expect_policy_reject(base_policy(workloadId=bad))
        for bad in ('a' * 64, 'md5:' + 'a' * 32, 'sha256:' + 'G' * 64,
                    'sha256:' + 'a' * 63, 7, None):
            with self.subTest(revisionDigest=bad):
                expect_policy_reject(base_policy(revisionDigest=bad))

    def test_numeric_bounds(self):
        for bad in (0, -1, 7 * 24 * 3600 + 1, True, 1.5, '60'):
            with self.subTest(interval=bad):
                expect_policy_reject(
                    base_policy(captureIntervalSeconds=bad))
        self.assertEqual(
            policy.validate_policy(base_policy(
                captureIntervalSeconds=7 * 24 * 3600)
            )['captureIntervalSeconds'], 7 * 24 * 3600)
        for bad in (0, -1, 30 * 24 * 3600 + 1, True, 1.5):
            with self.subTest(max_age=bad):
                expect_policy_reject(
                    base_policy(recoveryPointMaxAgeSeconds=bad))
        for bad in (-1, 1025, True, 1.5, '2'):
            with self.subTest(keep=bad):
                expect_policy_reject(base_policy(keepMinimum=bad))
        self.assertEqual(policy.validate_policy(
            base_policy(keepMinimum=1024))['keepMinimum'], 1024)

    def test_protected_point_ids(self):
        for bad in ('x', 7, {'x': 1},
                    ['sha256:' + 'a' * 64] * 2,
                    ['not-a-digest'],
                    ['sha256:' + 'a' * 64] * 1025):
            with self.subTest(pins=bad):
                expect_policy_reject(base_policy(protectedPointIds=bad))

    def test_policy_digest_stable(self):
        first = policy.policy_digest(base_policy())
        second = policy.policy_digest(dict(
            reversed(list(base_policy().items()))))
        self.assertEqual(first, second)
        self.assertTrue(first.startswith('sha256:'))
        self.assertNotEqual(first, policy.policy_digest(
            base_policy(keepMinimum=1)))


class ClassificationTests(unittest.TestCase):

    def _ids(self, result):
        return {p['recoveryPointId']: p['classification']
                for p in result['points']}

    def test_single_protected_is_current(self):
        m = point(1000)
        result = policy.evaluate(
            base_policy(), [uploaded(m)], 2000)
        self.assertEqual(self._ids(result), {
            m['recoveryPointId']: 'current-protected'})
        self.assertEqual(result['freshestProtected'], {
            'recoveryPointId': m['recoveryPointId'],
            'ageSeconds': 1000})
        self.assertEqual(result['points'][0]['reasons'],
                         ['verified-copy', 'newest-protected'])

    def test_retained_within_age(self):
        older = point(1000)
        newer = point(1500)
        result = policy.evaluate(
            base_policy(), [uploaded(older), uploaded(newer)], 2000)
        self.assertEqual(self._ids(result), {
            older['recoveryPointId']: 'retained',
            newer['recoveryPointId']: 'current-protected'})
        self.assertEqual(result['points'][0]['reasons'],
                         ['verified-copy', 'within-max-age'])

    def test_expired_eligible_beyond_keep_minimum(self):
        stale = [point(100 + i) for i in range(3)]
        result = policy.evaluate(
            base_policy(keepMinimum=2),
            [uploaded(m) for m in stale], 200000)
        classes = self._ids(result)
        self.assertEqual(classes[stale[2]['recoveryPointId']],
                         'current-protected')
        self.assertEqual(classes[stale[0]['recoveryPointId']],
                         'expired-eligible')
        self.assertEqual(classes[stale[1]['recoveryPointId']],
                         'retained')
        self.assertIn('keep-minimum', result['points'][1]['reasons'])
        self.assertIn('older-than-max-age',
                      result['points'][0]['reasons'])

    def test_keep_minimum_zero_expires_all_but_current(self):
        stale = [point(100 + i) for i in range(2)]
        result = policy.evaluate(
            base_policy(), [uploaded(m) for m in stale], 200000)
        classes = self._ids(result)
        self.assertEqual(classes[stale[0]['recoveryPointId']],
                         'expired-eligible')
        self.assertEqual(classes[stale[1]['recoveryPointId']],
                         'current-protected')

    def test_keep_minimum_covers_all(self):
        stale = [point(100 + i) for i in range(3)]
        result = policy.evaluate(
            base_policy(keepMinimum=3),
            [uploaded(m) for m in stale], 200000)
        self.assertEqual(set(self._ids(result).values()),
                         {'current-protected', 'retained'})

    def test_pinned_point_never_expires(self):
        old = point(100)
        pinned_id = old['recoveryPointId']
        newer = point(150)
        record = base_policy(keepMinimum=0,
                             protectedPointIds=[pinned_id])
        # Bare manifest, no evidence: the pin alone protects it.
        result = policy.evaluate(record, [old, uploaded(newer)],
                                 200000)
        self.assertEqual(self._ids(result)[pinned_id], 'retained')
        self.assertEqual(result['points'][0]['reasons'], ['pinned'])

    def test_pin_satisfies_keep_minimum(self):
        old = [point(100 + i) for i in range(2)]
        pinned = old[0]['recoveryPointId']
        newest = point(150)
        record = base_policy(keepMinimum=2,
                             protectedPointIds=[pinned])
        result = policy.evaluate(
            record, [old[0], uploaded(old[1]), uploaded(newest)],
            200000)
        classes = self._ids(result)
        # The pin counts toward keepMinimum; the unpinned stale
        # point may expire since two protected points remain.
        self.assertEqual(classes[old[0]['recoveryPointId']],
                         'retained')
        self.assertEqual(classes[old[1]['recoveryPointId']],
                         'expired-eligible')
        self.assertEqual(classes[newest['recoveryPointId']],
                         'current-protected')

    def test_unprotected_reasons(self):
        missing = point(100)
        unverified = point(150)
        empty = point(200)
        result = policy.evaluate(base_policy(), [
            missing,
            uploaded(unverified, copies=1, verified=False),
            uploaded(empty, copies=0, verified=True),
        ], 2000)
        classes = self._ids(result)
        self.assertEqual(set(classes.values()), {'unprotected'})
        by_id = {p['recoveryPointId']: p['reasons']
                 for p in result['points']}
        self.assertEqual(by_id[missing['recoveryPointId']],
                         ['evidence-missing'])
        self.assertEqual(by_id[unverified['recoveryPointId']],
                         ['unverified'])
        self.assertEqual(by_id[empty['recoveryPointId']],
                         ['no-uploaded-copy'])
        self.assertIsNone(result['freshestProtected'])

    def test_captured_never_uploaded_not_protected(self):
        m = point(1000)
        result = policy.evaluate(
            base_policy(),
            [{'manifest': m,
              'record': {'uploadedCopies': 0, 'verified': True}}],
            2000)
        self.assertEqual(self._ids(result)[m['recoveryPointId']],
                         'unprotected')
        self.assertIsNone(result['freshestProtected'])
        self.assertEqual(result['captureDue']['reason'],
                         'no-protected-point')
        self.assertFalse(result['protectionStatus']['healthy'])

    def test_pinned_without_upload_is_protected(self):
        m = point(1000)
        result = policy.evaluate(
            base_policy(protectedPointIds=[m['recoveryPointId']]),
            [m], 2000)
        self.assertEqual(self._ids(result)[m['recoveryPointId']],
                         'current-protected')
        self.assertEqual(result['freshestProtected']['ageSeconds'],
                         1000)

    def test_legacy_v2_classification(self):
        legacy = legacy_manifest(capture=capture(startedAt=100,
                                                 completedAt=105))
        current = point(1000)
        result = policy.evaluate(
            base_policy(),
            [uploaded(legacy), uploaded(current)], 2000)
        self.assertEqual(self._ids(result)[legacy['recoveryPointId']],
                         'legacy-v2')
        self.assertIn('legacy-format', result['points'][0]['reasons'])
        self.assertEqual(self._ids(result)[current['recoveryPointId']],
                         'current-protected')

    def test_legacy_does_not_satisfy_protection(self):
        legacy = legacy_manifest(capture=capture(startedAt=100,
                                                 completedAt=105))
        result = policy.evaluate(
            base_policy(), [uploaded(legacy)], 2000)
        self.assertIsNone(result['freshestProtected'])
        self.assertEqual(result['captureDue']['reason'],
                         'no-protected-point')


class CaptureDueTests(unittest.TestCase):

    def test_no_points(self):
        result = policy.evaluate(base_policy(), [], 5000)
        due = result['captureDue']
        self.assertTrue(due['due'])
        self.assertEqual(due['reason'], 'no-points')
        self.assertEqual(due['nextDueAt'], 5000)
        self.assertEqual(due['overdueBySeconds'], 0)
        self.assertEqual(result['points'], [])
        self.assertFalse(result['protectionStatus']['healthy'])
        self.assertEqual(result['protectionStatus']['reasons'],
                         ['no-protected-point', 'capture-due'])

    def test_interval_elapsed(self):
        m = point(1000, completed=1005)
        result = policy.evaluate(
            base_policy(captureIntervalSeconds=100),
            [uploaded(m)], 2000)
        due = result['captureDue']
        self.assertTrue(due['due'])
        self.assertEqual(due['reason'], 'interval-elapsed')
        self.assertEqual(due['nextDueAt'], 1105)
        self.assertEqual(due['overdueBySeconds'], 895)

    def test_no_protected_point(self):
        m = point(1900, completed=1905)
        result = policy.evaluate(
            base_policy(captureIntervalSeconds=3600), [m], 2000)
        due = result['captureDue']
        self.assertTrue(due['due'])
        self.assertEqual(due['reason'], 'no-protected-point')
        self.assertEqual(due['nextDueAt'], 5505)
        self.assertEqual(due['overdueBySeconds'], 0)

    def test_not_due(self):
        m = point(1900, completed=1905)
        result = policy.evaluate(
            base_policy(captureIntervalSeconds=3600),
            [uploaded(m)], 2000)
        due = result['captureDue']
        self.assertFalse(due['due'])
        self.assertEqual(due['reason'], 'not-due')
        self.assertEqual(due['overdueBySeconds'], 0)
        self.assertTrue(result['protectionStatus']['healthy'])
        self.assertEqual(result['protectionStatus']['reasons'], [])

    def test_interval_reason_beats_unprotected(self):
        m = point(100, completed=105)
        result = policy.evaluate(
            base_policy(captureIntervalSeconds=100), [m], 2000)
        self.assertEqual(result['captureDue']['reason'],
                         'interval-elapsed')

    def test_last_capture_completed_at_extends_interval(self):
        m = point(100, completed=105)
        result = policy.evaluate(
            base_policy(captureIntervalSeconds=3600),
            [uploaded(m)], 2000,
            last_capture_completed_at=1990)
        self.assertEqual(result['captureDue']['reason'], 'not-due')
        self.assertEqual(result['captureDue']['nextDueAt'], 5590)

    def test_last_capture_completed_at_validation(self):
        expect_eval_reject(base_policy(), [], 2000,
                           last_capture_completed_at=-1)
        expect_eval_reject(base_policy(), [], 2000,
                           last_capture_completed_at=2001)
        expect_eval_reject(base_policy(), [], 2000,
                           last_capture_completed_at=2**53 + 1)
        expect_eval_reject(base_policy(), [], 2000,
                           last_capture_completed_at=100.5)


class ClockAndInputTests(unittest.TestCase):

    def test_now_rejects_bad_values(self):
        m = point(100)
        for bad in (-1, 100.5, '2000', True, None, 2**53 + 1):
            with self.subTest(now=bad):
                expect_eval_reject(base_policy(), [uploaded(m)], bad)

    def test_point_in_future_rejected(self):
        m = point(5000)
        with self.assertRaises(policy.PolicyError) as ctx:
            policy.evaluate(base_policy(), [uploaded(m)], 2000)
        self.assertEqual(ctx.exception.code, 'point-in-future')

    def test_foreign_workload_rejected(self):
        m = manifest(definition=sealed(workloadId='other'),
                     capture=capture(startedAt=100, completedAt=105))
        with self.assertRaises(policy.PolicyError) as ctx:
            policy.evaluate(base_policy(), [uploaded(m)], 2000)
        self.assertEqual(ctx.exception.code, 'foreign-workload')

    def test_invalid_manifest_rejected(self):
        bad = point(100)
        bad['capture']['completedAt'] = 'later'
        with self.assertRaises(policy.PolicyError) as ctx:
            policy.evaluate(base_policy(), [bad], 2000)
        self.assertEqual(ctx.exception.code, 'invalid-point')
        for entry in ('x', [], 7, {'manifest': point(100)},
                      {'manifest': point(100), 'record': None,
                       'extra': 1},
                      {'manifest': point(100), 'record': {}},
                      {'manifest': point(100),
                       'record': {'uploadedCopies': -1,
                                  'verified': True}},
                      {'manifest': point(100),
                       'record': {'uploadedCopies': 1,
                                  'verified': 'yes'}}):
            with self.subTest(entry=type(entry)):
                expect_eval_reject(base_policy(), [entry], 2000)

    def test_points_container_validation(self):
        for bad in ('x', 7, {}):
            with self.subTest(points=bad):
                expect_eval_reject(base_policy(), bad, 2000)

    def test_duplicate_point_deduped(self):
        m = point(100)
        result = policy.evaluate(
            base_policy(), [uploaded(m), uploaded(m)], 2000)
        self.assertEqual(len(result['points']), 1)

    def test_conflicting_evidence_rejected(self):
        m = point(100)
        with self.assertRaises(policy.PolicyError) as ctx:
            policy.evaluate(base_policy(), [
                uploaded(m, copies=1),
                uploaded(m, copies=2)], 2000)
        self.assertEqual(ctx.exception.code, 'conflicting-point')
        with self.assertRaises(policy.PolicyError):
            policy.evaluate(base_policy(), [m, uploaded(m)], 2000)

    def test_inputs_not_mutated(self):
        record = base_policy()
        m = point(100)
        entry = uploaded(m)
        snapshot = copy.deepcopy({'policy': record, 'entry': entry})
        policy.evaluate(record, [entry], 2000)
        self.assertEqual({'policy': record, 'entry': entry}, snapshot)

    def test_zero_state_definition(self):
        definition = sealed(stateMounts=[])
        m = manifest(definition=definition,
                     state_tree_digests={},
                     capture=capture(startedAt=100, completedAt=105))
        result = policy.evaluate(base_policy(), [uploaded(m)], 2000)
        self.assertEqual(self._classes(result)[m['recoveryPointId']],
                         'current-protected')

    def _classes(self, result):
        return {p['recoveryPointId']: p['classification']
                for p in result['points']}


class DeterminismTests(unittest.TestCase):

    def test_shuffled_input_byte_identical(self):
        points = [point(100 + i * 10) for i in range(6)]
        record = base_policy(keepMinimum=2)
        entries = [uploaded(m, verified=(i % 2 == 0),
                            copies=i % 3)
                   for i, m in enumerate(points)]
        first = policy.encode_evaluation(
            policy.evaluate(record, entries, 2000))
        reordered = list(reversed(entries))
        second = policy.encode_evaluation(
            policy.evaluate(record, reordered, 2000))
        self.assertEqual(first, second)

    def test_repeated_calls_identical(self):
        m = point(100)
        first = policy.evaluate(base_policy(), [uploaded(m)], 2000)
        second = policy.evaluate(base_policy(), [uploaded(m)], 2000)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertEqual(policy.encode_evaluation(first),
                         artifacts.canonical_bytes(first))

    def test_output_sorted_by_capture(self):
        a = point(300)
        b = point(100)
        result = policy.evaluate(base_policy(),
                                 [uploaded(a), uploaded(b)], 2000)
        starts = [p['captureStartedAt'] for p in result['points']]
        self.assertEqual(starts, [100, 300])


class PlanTests(unittest.TestCase):

    def _eval(self, workload, overdue):
        m = manifest(
            definition=sealed(workloadId=workload),
            capture=capture(startedAt=100, completedAt=105))
        record = base_policy(workloadId=workload,
                             captureIntervalSeconds=overdue)
        return policy.evaluate(record, [uploaded(m)], 2000)

    def test_orders_by_overdue_then_workload(self):
        zebra = self._eval('zebra', 100)
        aardvark_slow = self._eval('aardvark', 200)
        aardvark_fast = self._eval('aardvark', 50)
        result = policy.plan(
            [aardvark_fast, zebra, aardvark_slow])
        # nextDueAt = completedAt(105) + interval; overdue at now=2000.
        self.assertEqual(
            [(i['workloadId'], i['overdueBySeconds']) for i in result],
            [('aardvark', 1845), ('zebra', 1795), ('aardvark', 1695)])

    def test_plan_record_shape(self):
        result = policy.plan([self._eval('demo', 100)])
        self.assertEqual(len(result), 1)
        item = result[0]
        self.assertEqual(set(item), {
            'workloadId', 'policyDigest', 'evaluatedAt', 'due',
            'reason', 'overdueBySeconds', 'nextDueAt',
            'freshestProtected'})
        self.assertEqual(item['workloadId'], 'demo')
        self.assertTrue(item['due'])

    def test_plan_empty_and_invalid(self):
        self.assertEqual(policy.plan([]), [])
        for bad in ('x', 7, [{'bogus': True}],
                    [policy.evaluate(base_policy(), [], 1),
                     'x']):
            with self.subTest(bad=bad):
                with self.assertRaises(policy.PolicyError):
                    policy.plan(bad)

    def test_plan_does_not_mutate(self):
        ev = self._eval('demo', 100)
        snapshot = copy.deepcopy(ev)
        policy.plan([ev])
        self.assertEqual(ev, snapshot)


if __name__ == '__main__':
    unittest.main()
