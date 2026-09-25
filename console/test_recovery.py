import copy
import hashlib
import json
import unittest

import artifacts
import catalog
import recovery
from test_catalog import base_definition, sealed


INSTANCE = 'ab' * 16


def source(**overrides):
    record = {'hostId': 'host-a', 'instanceId': INSTANCE,
              'generation': 1, 'uidBase': 65536}
    record.update(overrides)
    return record


def capture(**overrides):
    record = {'adapter': 'quiesce-v1', 'consistency': 'quiesced',
              'startedAt': 1000, 'completedAt': 1005}
    record.update(overrides)
    return record


def tree_digests(definition):
    return {mount['id']: 'sha256:' + '%064x' % (index + 1)
            for index, mount in enumerate(definition['stateMounts'])}


def manifest(**kwargs):
    definition = kwargs.get('definition') or sealed()
    digests = kwargs.get('state_tree_digests')
    if digests is None:
        digests = tree_digests(definition)
    return recovery.build_manifest(
        definition,
        kwargs.get('source') or source(),
        kwargs.get('capture') or capture(),
        state_tree_digests=digests,
        secret_bundle=kwargs.get('secret_bundle'))


def reseal(record):
    body = {key: value for key, value in record.items()
            if key != 'recoveryPointId'}
    record['recoveryPointId'] = 'sha256:' + hashlib.sha256(
        artifacts.canonical_bytes(body)).hexdigest()
    return record


def expect_reject(value):
    try:
        recovery.validate_manifest(value)
    except recovery.RecoveryError:
        return
    raise AssertionError('manifest unexpectedly accepted')


def secret_definition():
    return sealed(secretSetRef='demo-secrets')


def secret_bundle(**overrides):
    record = {'secretSetRef': 'demo-secrets',
              'versionDigest': 'sha256:' + 'd' * 64,
              'bundleDigest': 'sha256:' + 'e' * 64}
    record.update(overrides)
    return record


class BuildTests(unittest.TestCase):

    def test_exact_roundtrip(self):
        record = manifest()
        raw = recovery.encode_manifest(record)
        decoded = recovery.decode_manifest(raw)
        self.assertEqual(decoded, record)
        self.assertIsNot(decoded, record)
        self.assertTrue(raw.startswith(b'{'))
        self.assertEqual(raw, json.dumps(
            record, sort_keys=True, separators=(',', ':'),
            ensure_ascii=False).encode('utf-8'))

    def test_dictionary_order_independent_seal(self):
        first = manifest()
        # Same content, deliberately different insertion order.
        source_rev = dict(reversed(list(source().items())))
        capture_rev = dict(reversed(list(capture().items())))
        definition = sealed()
        definition_rev = dict(reversed(list(definition.items())))
        second = recovery.build_manifest(
            definition_rev, source_rev, capture_rev,
            state_tree_digests=dict(reversed(list(
                tree_digests(definition_rev).items()))))
        self.assertEqual(
            first['recoveryPointId'], second['recoveryPointId'])
        self.assertEqual(first, second)

    def test_multi_state_sorts_and_restores(self):
        definition = sealed(stateMounts=[
            {'id': 'zulu', 'mountPoint': '/var/lib/zulu', 'ownerUid': 33,
             'ownerGid': 0, 'consistencyAdapter': 'quiesce-v1'},
            {'id': 'alpha', 'mountPoint': '/var/lib/alpha',
             'ownerUid': 100, 'ownerGid': 7,
             'consistencyAdapter': 'quiesce-v1'},
            {'id': 'mid', 'mountPoint': '/var/lib/mid', 'ownerUid': 0,
             'ownerGid': 0, 'consistencyAdapter': 'quiesce-v1'},
        ])
        record = manifest(definition=definition)
        self.assertEqual(
            [entry['id'] for entry in record['state']],
            ['alpha', 'mid', 'zulu'])
        self.assertEqual(
            [entry['path'] for entry in record['state']],
            ['state/alpha', 'state/mid', 'state/zulu'])
        digests = tree_digests(definition)
        for entry in record['state']:
            self.assertEqual(entry['treeDigest'], digests[entry['id']])
        decoded = recovery.decode_manifest(
            recovery.encode_manifest(record))
        self.assertEqual(decoded['definition']['stateMounts'],
                         record['definition']['stateMounts'])
        owners = {mount['id']: mount['ownerUid']
                  for mount in decoded['definition']['stateMounts']}
        self.assertEqual(owners,
                         {'alpha': 100, 'mid': 0, 'zulu': 33})

    def test_zero_state_definition_accepted(self):
        definition = sealed(stateMounts=[])
        record = manifest(definition=definition)
        self.assertEqual(record['state'], [])
        recovery.decode_manifest(recovery.encode_manifest(record))

    def test_builder_does_not_mutate_inputs(self):
        definition = sealed()
        src = source()
        cap = capture()
        snapshot = copy.deepcopy(
            {'definition': definition, 'source': src, 'capture': cap})
        recovery.build_manifest(definition, src, cap,
            state_tree_digests=tree_digests(definition))
        self.assertEqual(
            {'definition': definition, 'source': src, 'capture': cap},
            snapshot)

    def test_validate_returns_independent_copy(self):
        record = manifest()
        checked = recovery.validate_manifest(record)
        record['source']['generation'] = 99
        record['definition']['workloadId'] = 'changed'
        self.assertEqual(checked['source']['generation'], 1)
        self.assertEqual(checked['definition']['workloadId'], 'demo')


class SealTests(unittest.TestCase):

    def test_changed_recovery_point_id_refused(self):
        record = manifest()
        record['recoveryPointId'] = 'sha256:' + '0' * 64
        expect_reject(record)

    def test_changed_body_refused(self):
        record = manifest()
        record['source']['generation'] = 2
        expect_reject(record)

    def test_changed_definition_refused(self):
        record = manifest()
        record['definition']['displayName'] = 'Tampered'
        expect_reject(record)

    def test_extra_manifest_field_refused(self):
        record = manifest()
        record['snapshotId'] = 'sha256:' + 'f' * 64
        expect_reject(record)
        record = manifest()
        record['repository'] = 's3:bucket/path'
        expect_reject(record)
        record = manifest()
        record['available'] = True
        expect_reject(record)

    def test_missing_manifest_field_refused(self):
        for key in ('definition', 'source', 'capture', 'state',
                    'secretBundle', 'stateFormat', 'kind',
                    'schemaVersion', 'recoveryPointId'):
            record = manifest()
            del record[key]
            expect_reject(record)

    def test_wrong_kind_schema_and_format_refused(self):
        for key, bad in (('kind', 'backup-snapshot'),
                         ('kind', 2),
                         ('schemaVersion', 1),
                         ('schemaVersion', 3),
                         ('schemaVersion', True),
                         ('stateFormat', 'restic-s3-v1'),
                         ('stateFormat', None)):
            record = manifest()
            record[key] = bad
            reseal(record)
            expect_reject(record)


class DefinitionTests(unittest.TestCase):

    def test_malformed_revision_refused(self):
        definition = sealed()
        definition['revisionDigest'] = 'sha256:' + '0' * 64
        with self.assertRaises(recovery.RecoveryError):
            recovery.build_manifest(definition, source(), capture(),
                                    state_tree_digests=
                                    tree_digests(definition))

    def test_archive_category_refused(self):
        definition = base_definition(
            category='archive', runtimeVersion=None,
            runtimeArtifactId=None, allowedOperations=[],
            artifacts=[{'id': 'bundle', 'kind': 'archive',
                        'digest': 'sha256:' + 'c' * 64}],
            requirements={'memoryMiB': 0, 'cpuMillis': 0,
                          'stateBytes': 0, 'capabilities': []})
        definition = catalog.seal_definition(definition)
        with self.assertRaises(recovery.RecoveryError):
            recovery.build_manifest(definition, source(), capture(),
                                    state_tree_digests=
                                    tree_digests(definition))

    def test_backup_disallowed_refused(self):
        definition = sealed(allowedOperations=['start', 'stop'])
        with self.assertRaises(recovery.RecoveryError):
            recovery.build_manifest(definition, source(), capture(),
                                    state_tree_digests=
                                    tree_digests(definition))

    def test_infrastructure_with_backup_accepted(self):
        definition = sealed(category='infrastructure',
                            allowedOperations=['backup'])
        record = manifest(definition=definition)
        recovery.decode_manifest(recovery.encode_manifest(record))

    def test_infrastructure_without_backup_refused(self):
        definition = base_definition(
            category='infrastructure', allowedOperations=[])
        definition = catalog.seal_definition(definition)
        with self.assertRaises(recovery.RecoveryError):
            recovery.build_manifest(definition, source(), capture(),
                                    state_tree_digests=
                                    tree_digests(definition))


class SourceTests(unittest.TestCase):

    def test_source_field_errors(self):
        cases = [
            {'hostId': 'Host A'},
            {'hostId': 7},
            {'instanceId': INSTANCE.upper()},
            {'instanceId': INSTANCE[:-1] + 'g'},
            {'instanceId': INSTANCE[:-2]},
            {'instanceId': 'ab' * 17},
            {'generation': 0},
            {'generation': True},
            {'generation': 1.5},
            {'generation': '1'},
            {'generation': 2**63},
            {'uidBase': 0},
            {'uidBase': True},
            {'uidBase': 65537},
            {'uidBase': 65536.0},
            {'uidBase': 2**32 - 131072 + 65536},
            {'uidBase': -65536},
        ]
        for overrides in cases:
            record = manifest()
            record['source'].update(overrides)
            reseal(record)
            with self.subTest(overrides=overrides):
                expect_reject(record)

    def test_source_exact_fields(self):
        record = manifest()
        record['source']['extra'] = '/host/path'
        reseal(record)
        expect_reject(record)
        record = manifest()
        del record['source']['uidBase']
        reseal(record)
        expect_reject(record)

    def test_uid_base_upper_bound_accepted(self):
        record = recovery.build_manifest(
            sealed(), source(uidBase=2**32 - 131072), capture(),
            state_tree_digests=tree_digests(sealed()))
        recovery.validate_manifest(record)


class CaptureTests(unittest.TestCase):

    def test_capture_field_errors(self):
        cases = [
            {'adapter': 'agent-v2'},
            {'adapter': 1},
            {'consistency': 'crash-consistent'},
            {'consistency': 'application'},
            {'consistency': None},
            {'startedAt': -1},
            {'startedAt': True},
            {'startedAt': 1000.5},
            {'startedAt': '1000'},
            {'startedAt': 2**53 + 1},
            {'completedAt': True},
            {'completedAt': 1005.5},
            {'completedAt': '1005'},
            {'completedAt': 999},
        ]
        for overrides in cases:
            record = manifest()
            record['capture'].update(overrides)
            reseal(record)
            with self.subTest(overrides=overrides):
                expect_reject(record)

    def test_capture_exact_fields(self):
        record = manifest()
        record['capture']['nodeId'] = 'host-a'
        reseal(record)
        expect_reject(record)


def two_mount_definition():
    return sealed(stateMounts=[
        {'id': 'alpha', 'mountPoint': '/var/lib/alpha',
         'ownerUid': 0, 'ownerGid': 0,
         'consistencyAdapter': 'quiesce-v1'},
        {'id': 'data', 'mountPoint': '/var/lib/demo',
         'ownerUid': 0, 'ownerGid': 0,
         'consistencyAdapter': 'quiesce-v1'},
    ])


def good_state(definition=None):
    definition = definition or two_mount_definition()
    digests = tree_digests(definition)
    return [{'id': mid, 'path': 'state/' + mid,
             'treeDigest': digests[mid]}
            for mid in sorted(
                mount['id'] for mount in definition['stateMounts'])]


class StateTests(unittest.TestCase):

    def _record_with_state(self, entries):
        definition = two_mount_definition()
        record = manifest(definition=definition)
        record['state'] = entries
        reseal(record)
        return record

    def test_malicious_paths_refused(self):
        for bad_path in ('/var/lib/demo', 'state/../data',
                         'state/data/../alpha', '../data', 'data',
                         'state//data', 'state/data/', 'state/DATA',
                         'state/data\x00', 'state/data.link'):
            entries = good_state()
            entries[1]['path'] = bad_path
            with self.subTest(bad_path=bad_path):
                expect_reject(self._record_with_state(entries))

    def test_state_entry_metadata_refused(self):
        entries = good_state()
        entries[0]['hostPath'] = '/srv/x'
        expect_reject(self._record_with_state(entries))
        entries = good_state()
        del entries[1]['path']
        expect_reject(self._record_with_state(entries))
        entries = good_state()
        del entries[1]['treeDigest']
        expect_reject(self._record_with_state(entries))
        entries = good_state()
        entries[1]['symlink'] = 'target'
        expect_reject(self._record_with_state(entries))
        entries = good_state()
        entries[1]['treeDigest'] = 'sha256:' + 'G' * 64
        expect_reject(self._record_with_state(entries))
        entries = good_state()
        entries[1]['treeDigest'] = 'md5:' + '0' * 32
        expect_reject(self._record_with_state(entries))

    def test_incomplete_extra_duplicate_and_unsorted_refused(self):
        good = good_state()
        expect_reject(self._record_with_state(good[:1]))
        expect_reject(self._record_with_state(
            good + [{'id': 'beta', 'path': 'state/beta',
                     'treeDigest': 'sha256:' + '9' * 64}]))
        expect_reject(self._record_with_state(
            good + [{'id': 'data', 'path': 'state/data',
                     'treeDigest': 'sha256:' + '8' * 64}]))
        expect_reject(self._record_with_state(list(reversed(good))))
        expect_reject(self._record_with_state('state/data'))
        entries = copy.deepcopy(good)
        entries[0]['id'] = 7
        expect_reject(self._record_with_state(entries))
        entries = copy.deepcopy(good)
        entries[0]['path'] = 7
        expect_reject(self._record_with_state(entries))
        entries = copy.deepcopy(good)
        entries[0]['treeDigest'] = 7
        expect_reject(self._record_with_state(entries))

    def test_tree_digest_map_refused(self):
        definition = two_mount_definition()
        digests = tree_digests(definition)
        for bad in ('x', [], None,
                    {k: v for k, v in digests.items() if k != 'data'},
                    dict(digests, extra='sha256:' + '0' * 64),
                    dict(digests, data='sha256:' + 'G' * 64),
                    dict(digests, data='not-a-digest'),
                    dict(digests, data=7)):
            with self.subTest(bad=bad):
                with self.assertRaises(recovery.RecoveryError):
                    recovery.build_manifest(
                        definition, source(), capture(),
                        state_tree_digests=bad)
        # Zero-state definitions require exactly {}.
        zero = sealed(stateMounts=[])
        for bad in (None, {'data': 'sha256:' + '0' * 64}):
            with self.subTest(zero_bad=bad):
                with self.assertRaises(recovery.RecoveryError):
                    recovery.build_manifest(
                        zero, source(), capture(),
                        state_tree_digests=bad)

    def test_tree_digest_binds_identity(self):
        definition = two_mount_definition()
        first = manifest(definition=definition)
        digests = tree_digests(definition)
        digests['data'] = 'sha256:' + 'f' * 64
        second = recovery.build_manifest(
            definition, source(), capture(),
            state_tree_digests=digests)
        self.assertNotEqual(first['recoveryPointId'],
                            second['recoveryPointId'])
        # Identical capture metadata, different content: both points
        # must survive catalog reconstruction.
        rebuilt = recovery.catalog_from_manifests([second, first])
        self.assertEqual(
            {m['recoveryPointId'] for m in rebuilt},
            {first['recoveryPointId'], second['recoveryPointId']})

    def test_mutated_tree_digest_rejected(self):
        record = manifest(definition=two_mount_definition())
        record['state'][0]['treeDigest'] = 'sha256:' + '0' * 64
        expect_reject(record)
        record = manifest(definition=two_mount_definition())
        record['state'][1]['treeDigest'] = 'sha256:' + 'f' * 64
        expect_reject(record)

    def test_consistency_adapter_pinned(self):
        # A hypothetical catalog-accepted future adapter must still be
        # rejected by this contract.
        record = manifest()
        record['definition']['stateMounts'][0] = dict(
            record['definition']['stateMounts'][0],
            consistencyAdapter='agent-v9')
        expect_reject(record)


class SecretBundleTests(unittest.TestCase):

    def test_secretless_definition_rejects_bundle(self):
        with self.assertRaises(recovery.RecoveryError):
            manifest(secret_bundle=secret_bundle(
                secretSetRef='any-thing'))
        record = manifest()
        record['secretBundle'] = secret_bundle(
            secretSetRef='any-thing')
        reseal(record)
        expect_reject(record)

    def test_secret_definition_requires_bundle(self):
        with self.assertRaises(recovery.RecoveryError):
            manifest(definition=secret_definition())

    def test_secret_bundle_roundtrip(self):
        record = manifest(definition=secret_definition(),
                          secret_bundle=secret_bundle())
        decoded = recovery.decode_manifest(
            recovery.encode_manifest(record))
        self.assertEqual(decoded['secretBundle'], secret_bundle())

    def test_secret_bundle_mismatches(self):
        good = manifest(definition=secret_definition(),
                        secret_bundle=secret_bundle())
        cases = [
            secret_bundle(secretSetRef='other-secrets'),
            dict(secret_bundle(), **{'value': 'plaintext'}),
            dict(secret_bundle(), **{'password': 'x'}),
            {k: v for k, v in secret_bundle().items()
             if k != 'versionDigest'},
            {'secretSetRef': 'demo-secrets'},
            secret_bundle(versionDigest='not-a-digest'),
            secret_bundle(bundleDigest='sha256:' + 'G' * 64),
            'demo-secrets',
        ]
        for bundle in cases:
            record = copy.deepcopy(good)
            record['secretBundle'] = bundle
            reseal(record)
            with self.subTest(bundle=bundle):
                expect_reject(record)


class DecodeTests(unittest.TestCase):

    def test_non_bytes_and_empty_refused(self):
        record = manifest()
        raw = recovery.encode_manifest(record)
        for bad in (raw.decode('utf-8'), b'', 0, None, [],
                    raw + b' ' * (2 * 1024 * 1024)):
            with self.subTest(bad=type(bad)):
                with self.assertRaises(recovery.RecoveryError):
                    recovery.decode_manifest(bad)

    def test_oversized_refused(self):
        with self.assertRaises(recovery.RecoveryError):
            recovery.decode_manifest(b'x' * (2 * 1024 * 1024 + 1))

    def test_invalid_utf8_refused(self):
        record = manifest()
        raw = bytearray(recovery.encode_manifest(record))
        raw[100:101] = b'\xff'
        with self.assertRaises(recovery.RecoveryError):
            recovery.decode_manifest(bytes(raw))

    def test_duplicate_keys_refused(self):
        record = manifest()
        raw = recovery.encode_manifest(record).decode('utf-8')
        dup = raw.replace(
            '"kind":"workload-recovery-point"',
            '"kind":"workload-recovery-point",'
            '"kind":"workload-recovery-point"', 1)
        with self.assertRaises(recovery.RecoveryError):
            recovery.decode_manifest(dup.encode('utf-8'))
        nested = raw.replace(
            '"hostId":"host-a"',
            '"hostId":"host-a","hostId":"host-a"', 1)
        with self.assertRaises(recovery.RecoveryError):
            recovery.decode_manifest(nested.encode('utf-8'))

    def test_nonfinite_refused(self):
        record = manifest()
        raw = recovery.encode_manifest(record).decode('utf-8')
        bad = raw.replace('"generation":1', '"generation":NaN', 1)
        with self.assertRaises(recovery.RecoveryError):
            recovery.decode_manifest(bad.encode('utf-8'))
        bad = raw.replace('"startedAt":1000', '"startedAt":Infinity', 1)
        with self.assertRaises(recovery.RecoveryError):
            recovery.decode_manifest(bad.encode('utf-8'))

    def test_noncanonical_encoding_refused(self):
        record = manifest()
        raw = recovery.encode_manifest(record)
        spaced = raw.replace(b'":', b'": ', 1)
        with self.assertRaises(recovery.RecoveryError):
            recovery.decode_manifest(spaced)
        reordered = json.loads(raw)
        reordered = dict(reversed(list(reordered.items())))
        reorder = json.dumps(reordered, sort_keys=False,
                             separators=(',', ':')).encode('utf-8')
        with self.assertRaises(recovery.RecoveryError):
            recovery.decode_manifest(reorder)
        escaped = raw.replace(b'"displayName":"Demo"',
                              b'"displayName":"Dem\\u006f"', 1)
        with self.assertRaises(recovery.RecoveryError):
            recovery.decode_manifest(escaped)

    def test_wrong_digest_encoded_refused(self):
        record = manifest()
        record['recoveryPointId'] = 'sha256:' + '0' * 64
        raw = artifacts.canonical_bytes(record)
        with self.assertRaises(recovery.RecoveryError):
            recovery.decode_manifest(raw)

    def test_undecodable_json_refused(self):
        for bad in (b'{', b'[1,2]', b'"x"', b'7', b'true',
                    b'\xef\xbb\xbf{}'):
            with self.subTest(bad=bad):
                with self.assertRaises(recovery.RecoveryError):
                    recovery.decode_manifest(bad)

    def test_max_digit_integer_refused(self):
        # json.loads raises plain ValueError (not JSONDecodeError)
        # past the interpreter int-digit limit.
        raw = b'{"x":' + b'1' * 5000 + b'}'
        with self.assertRaises(recovery.RecoveryError):
            recovery.decode_manifest(raw)

    def test_deeply_nested_refused(self):
        raw = b'[' * 5000 + b']' * 5000
        with self.assertRaises(recovery.RecoveryError):
            recovery.decode_manifest(raw)
        nested = {}
        cursor = nested
        for _ in range(5000):
            cursor['a'] = {}
            cursor = cursor['a']
        with self.assertRaises(recovery.RecoveryError):
            recovery.validate_manifest(nested)
        record = manifest()
        cursor = record['definition']
        for _ in range(5000):
            cursor['x'] = {}
            cursor = cursor['x']
        expect_reject(record)


class CatalogReconstructionTests(unittest.TestCase):

    def test_two_historical_revisions_reconstructed(self):
        older = manifest(capture=capture(startedAt=1000,
                                         completedAt=1005))
        newer_definition = sealed(displayName='Demo rev2')
        newer = manifest(definition=newer_definition,
                         capture=capture(startedAt=2000,
                                         completedAt=2005))
        catalog_view = recovery.catalog_from_manifests(
            [newer, older, copy.deepcopy(older)])
        self.assertEqual(catalog_view,
                         [older, newer])
        ids = {m['recoveryPointId'] for m in catalog_view}
        self.assertEqual(len(ids), 2)

    def test_deterministic_order_across_workloads(self):
        a1 = manifest(
            definition=sealed(workloadId='aardvark'),
            capture=capture(startedAt=10, completedAt=11))
        a2 = manifest(
            definition=sealed(workloadId='aardvark',
                              displayName='Aardvark rev2'),
            capture=capture(startedAt=20, completedAt=21))
        z1 = manifest(
            definition=sealed(workloadId='zebra'),
            capture=capture(startedAt=5, completedAt=6))
        result = recovery.catalog_from_manifests([z1, a2, a1])
        self.assertEqual(
            [(m['definition']['workloadId'],
              m['capture']['startedAt']) for m in result],
            [('aardvark', 10), ('aardvark', 20), ('zebra', 5)])

    def test_corrupt_record_refuses_whole_list(self):
        good = manifest()
        bad = manifest()
        bad['capture']['completedAt'] = 'later'
        reseal(bad)
        with self.assertRaises(recovery.RecoveryError):
            recovery.catalog_from_manifests([good, bad])

    def test_same_identity_different_body_refused(self):
        first = manifest()
        second = copy.deepcopy(first)
        second['capture']['completedAt'] = 9999
        # Same claimed identity, different body: whichever check fires,
        # the list must not be reconstructed.
        with self.assertRaises(recovery.RecoveryError):
            recovery.catalog_from_manifests([first, second])

    def test_input_and_output_independence(self):
        record = manifest()
        result = recovery.catalog_from_manifests([record])
        result[0]['source']['generation'] = 42
        self.assertEqual(record['source']['generation'], 1)
        again = recovery.catalog_from_manifests([record])
        self.assertEqual(again[0]['source']['generation'], 1)
        self.assertIsNot(again[0], result[0])

    def test_empty_and_boundary_lists(self):
        self.assertEqual(recovery.catalog_from_manifests([]), [])
        with self.assertRaises(recovery.RecoveryError):
            recovery.catalog_from_manifests('x')
        with self.assertRaises(recovery.RecoveryError):
            recovery.catalog_from_manifests([manifest()] * 10001)


if __name__ == '__main__':
    unittest.main()
