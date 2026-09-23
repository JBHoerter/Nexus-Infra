import copy
import json
import unittest

import catalog


def base_definition(**overrides):
    definition = {
        'schemaVersion': 2,
        'workloadId': 'demo',
        'displayName': 'Demo',
        'category': 'project',
        'runtimeVersion': 'nspawn-v1',
        'architecture': 'x86_64-linux',
        'runtimeArtifactId': 'runtime',
        'artifacts': [
            {'id': 'runtime', 'kind': 'nixos-closure', 'digest': 'sha256:' + 'a' * 64},
            {'id': 'image', 'kind': 'oci-image', 'digest': 'sha256:' + 'b' * 64},
        ],
        'stateSchemaVersion': 1,
        'stateMounts': [
            {'id': 'data', 'mountPoint': '/var/lib/demo', 'ownerUid': 0, 'ownerGid': 0,
             'consistencyAdapter': 'quiesce-v1'},
        ],
        'secretSetRef': None,
        'dependencies': [],
        'services': [
            {'id': 'web', 'protocol': 'http', 'port': 8080, 'exposure': 'private'},
        ],
        'requirements': {
            'memoryMiB': 256, 'cpuMillis': 1000, 'stateBytes': 1048576,
            'capabilities': ['userns', 'nspawn-v1'],
        },
        'allowedOperations': ['start', 'stop', 'restart', 'backup', 'restore', 'move'],
        'policyProfiles': ['normal-hourly'],
    }
    definition.update(overrides)
    return definition


def sealed(**overrides):
    return catalog.seal_definition(base_definition(**overrides))


def archive_definition(**overrides):
    definition = base_definition(
        category='archive',
        runtimeVersion=None,
        runtimeArtifactId=None,
        allowedOperations=[],
        artifacts=[{'id': 'bundle', 'kind': 'archive', 'digest': 'sha256:' + 'c' * 64}],
        requirements={'memoryMiB': 0, 'cpuMillis': 0, 'stateBytes': 0, 'capabilities': []},
    )
    definition.update(overrides)
    return definition


def host(**overrides):
    record = {'schemaVersion': 2, 'hostId': 'host-a', 'architecture': 'x86_64-linux',
              'capabilities': ['userns', 'nspawn-v1']}
    record.update(overrides)
    return record


def observation(**overrides):
    record = {'schemaVersion': 2, 'hostId': 'host-a', 'observedAt': 100.0,
              'available': {'memoryMiB': 1024, 'cpuMillis': 2000, 'stateBytes': 10485760}}
    record.update(overrides)
    return record


def mutate(definition, *path, **kwargs):
    target = definition
    for key in path[:-1]:
        target = target[key]
    if 'delete' in kwargs:
        del target[path[-1]]
    else:
        target[path[-1]] = kwargs['value']
    return catalog.seal_definition(definition)


class DigestTests(unittest.TestCase):
    def test_seal_is_deterministic_regardless_of_key_order(self):
        first = sealed()
        reordered = dict(reversed(list(base_definition().items())))
        second = catalog.seal_definition(reordered)
        self.assertEqual(first['revisionDigest'], second['revisionDigest'])
        self.assertTrue(first['revisionDigest'].startswith('sha256:'))

    def test_unicode_display_name_canonical_utf8(self):
        record = sealed(displayName='Demo Ünïçødé')
        self.assertEqual(record['displayName'], 'Demo Ünïçødé')
        self.assertEqual(catalog.revision_digest(record), record['revisionDigest'])

    def test_revision_changes_with_content(self):
        self.assertNotEqual(sealed()['revisionDigest'], sealed(displayName='Other')['revisionDigest'])

    def test_supplied_digest_rejected(self):
        with self.assertRaises(catalog.CatalogError):
            catalog.seal_definition(base_definition(revisionDigest='sha256:' + '0' * 64))
        for invalid in (None, 'not-a-dict', ['x']):
            with self.assertRaises(catalog.CatalogError):
                catalog.seal_definition(invalid)

    def test_validation_rejects_digest_mismatch(self):
        record = sealed()
        record['displayName'] = 'Changed'
        with self.assertRaises(catalog.CatalogError):
            catalog.validate_definition(record)
        record = sealed()
        record['revisionDigest'] = 'sha256:' + '0' * 64
        with self.assertRaises(catalog.CatalogError):
            catalog.validate_definition(record)

    def test_noncanonical_values_rejected(self):
        for value in (float('nan'), float('inf'), -float('inf'), object()):
            with self.assertRaises(catalog.CatalogError, msg=repr(value)):
                mutate(base_definition(), 'displayName', value=value)
        with self.assertRaises(catalog.CatalogError):
            mutate(base_definition(), 'displayName', value='lone\ud800surrogate')
        with self.assertRaises(catalog.CatalogError):
            mutate(base_definition(), 'displayName', value='ctrl\x07char')
        with self.assertRaises(catalog.CatalogError):
            mutate(base_definition(), 'displayName', value='')
        with self.assertRaises(catalog.CatalogError):
            mutate(base_definition(), 'displayName', value='x' * 161)
        for char in ('\x7f', '\x80', '\x9f'):
            with self.assertRaises(catalog.CatalogError, msg=repr(char)):
                mutate(base_definition(), 'displayName', value='a' + char + 'b')
        self.assertIsNotNone(sealed(displayName='x' * 160))


class ShapeTests(unittest.TestCase):
    def test_missing_and_extra_fields_rejected_everywhere(self):
        with self.assertRaises(catalog.CatalogError):
            mutate(base_definition(), 'displayName', delete=True)
        with self.assertRaises(catalog.CatalogError):
            mutate(base_definition(), 'injectedSecret', value='supersecret-marker')
        for mutate_fn in (
            lambda d: d['artifacts'][0].pop('kind'),
            lambda d: d['artifacts'][0].update(extra='x'),
            lambda d: d['stateMounts'][0].pop('ownerUid'),
            lambda d: d['stateMounts'][0].update(extra='x'),
            lambda d: d['services'][0].pop('protocol'),
            lambda d: d['services'][0].update(extra='x'),
            lambda d: d['requirements'].pop('memoryMiB'),
            lambda d: d['requirements'].update(extra='x'),
            lambda d: d.pop('services'),
            lambda d: d.update(unexpected='x'),
        ):
            definition = base_definition()
            mutate_fn(definition)
            with self.assertRaises(catalog.CatalogError, msg=mutate_fn):
                catalog.seal_definition(definition)

    def test_secret_command_hostpath_url_fields_rejected(self):
        for key in ('password', 'secret', 'command', 'hostPath', 'url', 'token'):
            with self.assertRaises(catalog.CatalogError, msg=key):
                mutate(base_definition(), key, value='injected-secret-marker')

    def test_schema_and_enum_boundaries(self):
        for version in (1, 3, True, '2', 2.0):
            with self.assertRaises(catalog.CatalogError, msg=repr(version)):
                mutate(base_definition(), 'schemaVersion', value=version)
        for category in ('Project', 'system', '', 1, [], {}, None, True):
            with self.assertRaises(catalog.CatalogError, msg=repr(category)):
                mutate(base_definition(), 'category', value=category)
        self.assertIsNotNone(catalog.seal_definition(archive_definition()))
        for arch in ('x86_64', 'linux', '', 1, [], {}, None, True):
            with self.assertRaises(catalog.CatalogError, msg=repr(arch)):
                mutate(base_definition(), 'architecture', value=arch)
        self.assertIsNotNone(sealed(architecture='aarch64-linux'))
        for runtime in ('nspawn-v2', 'docker', 1, None, [], True):
            with self.assertRaises(catalog.CatalogError, msg=repr(runtime)):
                mutate(base_definition(), 'runtimeVersion', value=runtime)
        for value in ([], {}, None, True, 1):
            for path in (('artifacts', 0, 'kind'), ('stateMounts', 0, 'consistencyAdapter'),
                         ('services', 0, 'protocol'), ('services', 0, 'exposure')):
                with self.assertRaises(catalog.CatalogError, msg=(path, value)):
                    mutate(base_definition(), *path, value=value)
                definition = sealed()
                target = definition
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(catalog.CatalogError, msg=('validate', path, value)):
                    catalog.validate_definition(definition)
        for ops in ([[]], ['start', ['stop']], 'startstop', 42, None, {'start': True},
                    ['start'] * 7):
            with self.assertRaises(catalog.CatalogError, msg=repr(ops)):
                mutate(base_definition(), 'allowedOperations', value=ops)

    def test_integer_boundaries_and_booleans(self):
        cases = [
            (('stateSchemaVersion',), 0), (('stateSchemaVersion',), 2**31),
            (('stateSchemaVersion',), True), (('stateSchemaVersion',), 1.5),
            (('stateMounts', 0, 'ownerUid'), -1), (('stateMounts', 0, 'ownerUid'), 65536),
            (('stateMounts', 0, 'ownerUid'), False),
            (('services', 0, 'port'), 0), (('services', 0, 'port'), 65536),
            (('services', 0, 'port'), True),
            (('requirements', 'memoryMiB'), 0), (('requirements', 'memoryMiB'), 2**63),
            (('requirements', 'memoryMiB'), False), (('requirements', 'cpuMillis'), 0),
            (('requirements', 'stateBytes'), -1),
        ]
        for path, value in cases:
            with self.assertRaises(catalog.CatalogError, msg=(path, value)):
                mutate(base_definition(), *path, value=value)
        self.assertIsNotNone(sealed(stateSchemaVersion=2**31 - 1))
        self.assertIsNotNone(sealed(requirements={'memoryMiB': 1, 'cpuMillis': 1, 'stateBytes': 0, 'capabilities': []}))

    def test_identifier_and_digest_syntax(self):
        for wid in ('Demo', '-demo', 'demo_workload', 'demo.work', '', 1, 'a' * 64):
            with self.assertRaises(catalog.CatalogError, msg=repr(wid)):
                mutate(base_definition(), 'workloadId', value=wid)
        for digest in ('sha256:' + 'A' * 64, 'sha256:' + 'a' * 63, 'md5:' + 'a' * 32, 'a' * 64, 1):
            with self.assertRaises(catalog.CatalogError, msg=repr(digest)):
                mutate(base_definition(), 'artifacts', 0, 'digest', value=digest)
        self.assertIsNotNone(sealed(secretSetRef='lab-secrets'))
        for ref in ('Bad Ref', 'UPPER', 42):
            with self.assertRaises(catalog.CatalogError, msg=repr(ref)):
                mutate(base_definition(), 'secretSetRef', value=ref)


class MountTests(unittest.TestCase):
    def mount(self, point):
        return sealed(stateMounts=[{'id': 'data', 'mountPoint': point, 'ownerUid': 0,
                                    'ownerGid': 0, 'consistencyAdapter': 'quiesce-v1'}])

    def test_invalid_mount_points_rejected(self):
        for point in ('/', '/var/lib/demo/', 'relative/path', '//var', '/var//lib',
                      '/var/./lib', '/var/../lib', '/etc', '/etc/app', '/dev/x', '/proc',
                      '/sys/fs', '/run/x', '/nix/store', '/var/lib/has space',
                      '/var/lib/colon:path', '/var/lib/glob*', '/var/lib/dollar$x',
                      '/var/lib/semicol;on', '/var/lib/unicode-ü', '', 42, None):
            with self.assertRaises(catalog.CatalogError, msg=repr(point)):
                self.mount(point)

    def test_valid_and_near_prefix_paths(self):
        self.assertIsNotNone(self.mount('/var/lib/docker'))
        self.assertIsNotNone(self.mount('/data'))
        sealed(stateMounts=[
            {'id': 'one', 'mountPoint': '/var/lib/demo', 'ownerUid': 0, 'ownerGid': 0, 'consistencyAdapter': 'quiesce-v1'},
            {'id': 'two', 'mountPoint': '/var/lib/demo2', 'ownerUid': 0, 'ownerGid': 0, 'consistencyAdapter': 'quiesce-v1'},
        ])

    def test_overlapping_and_equal_mounts_rejected(self):
        for mounts in (
            [{'id': 'a', 'mountPoint': '/var/lib', 'ownerUid': 0, 'ownerGid': 0, 'consistencyAdapter': 'quiesce-v1'},
             {'id': 'b', 'mountPoint': '/var/lib/demo', 'ownerUid': 0, 'ownerGid': 0, 'consistencyAdapter': 'quiesce-v1'}],
            [{'id': 'a', 'mountPoint': '/var/lib/demo', 'ownerUid': 0, 'ownerGid': 0, 'consistencyAdapter': 'quiesce-v1'},
             {'id': 'b', 'mountPoint': '/var/lib/demo', 'ownerUid': 0, 'ownerGid': 0, 'consistencyAdapter': 'quiesce-v1'}],
        ):
            with self.assertRaises(catalog.CatalogError):
                sealed(stateMounts=mounts)

    def test_path_length_bounds(self):
        self.assertIsNotNone(self.mount('/' + 'a' * 255))
        with self.assertRaises(catalog.CatalogError):
            self.mount('/' + 'a' * 256)
        self.assertIsNotNone(self.mount('/' + '/'.join(['a' * 255] * 7)))
        with self.assertRaises(catalog.CatalogError):
            self.mount('/' + '/'.join(['a' * 255] * 16))
        with self.assertRaises(catalog.CatalogError):
            self.mount('/' + 'b' * 4095)

    def test_adapter_enum(self):
        with self.assertRaises(catalog.CatalogError):
            sealed(stateMounts=[{'id': 'data', 'mountPoint': '/var/lib/demo', 'ownerUid': 0,
                                 'ownerGid': 0, 'consistencyAdapter': 'shell-hook'}])


class CollectionTests(unittest.TestCase):
    def test_duplicate_ids_rejected(self):
        artifact = {'id': 'runtime', 'kind': 'nixos-closure', 'digest': 'sha256:' + 'c' * 64}
        with self.assertRaises(catalog.CatalogError):
            sealed(artifacts=[artifact, dict(artifact)])
        service = {'id': 'web', 'protocol': 'http', 'port': 8080, 'exposure': 'private'}
        with self.assertRaises(catalog.CatalogError):
            sealed(services=[service, dict(service)])
        mount = {'id': 'data', 'mountPoint': '/var/lib/demo', 'ownerUid': 0, 'ownerGid': 0, 'consistencyAdapter': 'quiesce-v1'}
        other = dict(mount, mountPoint='/var/lib/other')
        with self.assertRaises(catalog.CatalogError):
            sealed(stateMounts=[mount, other])
        for field in ('dependencies', 'policyProfiles'):
            with self.assertRaises(catalog.CatalogError, msg=field):
                sealed(**{field: ['dup', 'dup']})
        requirements = base_definition()['requirements'] | {'capabilities': ['userns', 'userns']}
        with self.assertRaises(catalog.CatalogError):
            sealed(requirements=requirements)
        with self.assertRaises(catalog.CatalogError):
            sealed(allowedOperations=['start', 'start'])

    def test_artifact_rules(self):
        with self.assertRaises(catalog.CatalogError):
            sealed(artifacts=[])
        with self.assertRaises(catalog.CatalogError):
            sealed(artifacts=[{'id': 'a', 'kind': 'git-repo', 'digest': 'sha256:' + 'a' * 64}])
        with self.assertRaises(catalog.CatalogError):
            sealed(runtimeArtifactId='image')
        with self.assertRaises(catalog.CatalogError):
            sealed(runtimeArtifactId='missing')

    def test_service_rules(self):
        for protocol in ('HTTP', 'grpc', 'websocket'):
            with self.assertRaises(catalog.CatalogError, msg=protocol):
                sealed(services=[{'id': 'web', 'protocol': protocol, 'port': 8080, 'exposure': 'private'}])
        for exposure in ('internet', 'internal'):
            with self.assertRaises(catalog.CatalogError, msg=exposure):
                sealed(services=[{'id': 'web', 'protocol': 'http', 'port': 8080, 'exposure': exposure}])
        for exposure in ('private', 'public', 'lan'):
            self.assertIsNotNone(sealed(services=[{'id': 'web', 'protocol': 'https', 'port': 443, 'exposure': exposure}]))

    def test_category_operation_restrictions(self):
        self.assertIsNotNone(sealed(category='infrastructure', allowedOperations=['backup']))
        self.assertIsNotNone(sealed(category='infrastructure', allowedOperations=[]))
        for ops in (['start'], ['backup', 'stop'], ['move']):
            with self.assertRaises(catalog.CatalogError, msg=ops):
                sealed(category='infrastructure', allowedOperations=ops)
        self.assertIsNotNone(catalog.seal_definition(archive_definition()))
        with self.assertRaises(catalog.CatalogError):
            catalog.seal_definition(archive_definition(allowedOperations=['backup']))
        with self.assertRaises(catalog.CatalogError):
            sealed(allowedOperations=['delete'])
        with self.assertRaises(catalog.CatalogError):
            sealed(dependencies=['demo'])


class ArchiveTests(unittest.TestCase):
    def test_archive_only_record_seals(self):
        record = catalog.seal_definition(archive_definition())
        self.assertIsNone(record['runtimeVersion'])
        self.assertIsNone(record['runtimeArtifactId'])
        self.assertEqual(record['artifacts'][0]['kind'], 'archive')
        self.assertEqual(record['allowedOperations'], [])
        self.assertEqual(record['requirements']['memoryMiB'], 0)

    def test_archive_rejects_executable_runtime(self):
        for overrides in ({'runtimeVersion': 'nspawn-v1'}, {'runtimeArtifactId': 'bundle'},
                          {'runtimeVersion': 'nspawn-v1', 'runtimeArtifactId': 'bundle'},
                          {'allowedOperations': ['start']}):
            with self.assertRaises(catalog.CatalogError, msg=overrides):
                catalog.seal_definition(archive_definition(**overrides))

    def test_nonarchive_rejects_null_runtime_and_zero_compute(self):
        with self.assertRaises(catalog.CatalogError):
            sealed(runtimeVersion=None)
        with self.assertRaises(catalog.CatalogError):
            sealed(runtimeArtifactId=None)
        with self.assertRaises(catalog.CatalogError):
            sealed(requirements={'memoryMiB': 0, 'cpuMillis': 1, 'stateBytes': 0, 'capabilities': []})
        with self.assertRaises(catalog.CatalogError):
            sealed(requirements={'memoryMiB': 1, 'cpuMillis': 0, 'stateBytes': 0, 'capabilities': []})

    def test_archive_artifact_kind_is_reference_not_runtime(self):
        artifacts = base_definition()['artifacts'] + [
            {'id': 'legacy', 'kind': 'archive', 'digest': 'sha256:' + 'd' * 64}]
        self.assertIsNotNone(sealed(artifacts=artifacts))
        with self.assertRaises(catalog.CatalogError):
            sealed(artifacts=artifacts, runtimeArtifactId='legacy')

    def test_archive_admission_is_always_archived(self):
        record = catalog.seal_definition(archive_definition())
        result = catalog.admit(record, host(), observation(), now=105.0)
        self.assertEqual(result['reasons'], ['workload-archived'])
        self.assertFalse(result['eligible'])


class CatalogTests(unittest.TestCase):
    def test_duplicate_workload_ids_rejected(self):
        with self.assertRaises(catalog.CatalogError):
            catalog.Catalog([sealed(), sealed()])
        with self.assertRaises(catalog.CatalogError):
            catalog.Catalog([sealed(), sealed(displayName='Other')])

    def test_unknown_and_self_dependencies_rejected(self):
        with self.assertRaises(catalog.CatalogError):
            catalog.Catalog([sealed(dependencies=['missing'])])

    def test_dependency_cycles_rejected(self):
        first = sealed(workloadId='first', dependencies=['second'])
        second = sealed(workloadId='second', dependencies=['first'])
        with self.assertRaises(catalog.CatalogError):
            catalog.Catalog([first, second])

    def test_deep_chain_and_size_limit(self):
        chain = [catalog.seal_definition(base_definition(
            workloadId=f'w{index:04d}',
            dependencies=[] if index == 0 else [f'w{index - 1:04d}']))
            for index in range(1024)]
        registry = catalog.Catalog(chain)
        self.assertEqual(registry.get(workload_id='w1023', revision_digest=chain[-1]['revisionDigest'])['workloadId'], 'w1023')
        with self.assertRaises(catalog.CatalogError):
            catalog.Catalog(chain + [sealed(workloadId='w1024')])

    def test_dependency_chain_accepted(self):
        store = sealed(workloadId='store')
        app = sealed(workloadId='app', dependencies=['store'])
        document = catalog.Catalog([app, store]).document()
        self.assertEqual([entry['workloadId'] for entry in document['workloads']], ['app', 'store'])
        self.assertEqual(document['schemaVersion'], 2)

    def test_get_requires_exact_revision(self):
        record = sealed()
        other = sealed(displayName='Other')
        registry = catalog.Catalog([record])
        self.assertEqual(registry.get('demo', record['revisionDigest'])['displayName'], 'Demo')
        self.assertEqual(registry.get(workload_id='demo', revision_digest=record['revisionDigest'])['workloadId'], 'demo')
        for wid, digest in (('demo', other['revisionDigest']), ('missing', record['revisionDigest']),
                            ('demo', 'sha256:' + 'f' * 64), ('demo', 'not-a-digest'), ('Bad ID', record['revisionDigest'])):
            with self.assertRaises(catalog.CatalogError, msg=(wid, digest)):
                registry.get(wid, digest)

    def test_copies_are_defensive(self):
        original = base_definition()
        record = sealed()
        registry = catalog.Catalog([record])
        fetched = registry.get('demo', record['revisionDigest'])
        fetched['displayName'] = 'Mutated'
        fetched['services'][0]['port'] = 1
        again = registry.get('demo', record['revisionDigest'])
        self.assertEqual(again['displayName'], 'Demo')
        self.assertEqual(again['services'][0]['port'], 8080)
        document = registry.document()
        document['workloads'][0]['displayName'] = 'Mutated'
        self.assertEqual(registry.document()['workloads'][0]['displayName'], 'Demo')
        record['services'][0]['port'] = 1
        self.assertEqual(registry.document()['workloads'][0]['services'][0]['port'], 8080)
        self.assertNotIn('revisionDigest', original)


class AdmissionTests(unittest.TestCase):
    def admit(self, **kwargs):
        kwargs.setdefault('now', 105.0)
        observed = kwargs.pop('observation', observation())
        return catalog.admit(sealed(), host(), observed, **kwargs)

    def test_normal_admission_eligible(self):
        result = self.admit()
        self.assertTrue(result['eligible'])
        self.assertEqual(result['reasons'], [])
        self.assertEqual(result['workloadId'], 'demo')
        self.assertEqual(result['hostId'], 'host-a')
        self.assertEqual(result['checkedAt'], 105.0)
        self.assertEqual(result['revisionDigest'], sealed()['revisionDigest'])

    def test_boundary_capacity_and_age(self):
        exact = {'memoryMiB': 256, 'cpuMillis': 1000, 'stateBytes': 1048576}
        self.assertTrue(self.admit(observation=observation(available=exact))['eligible'])
        tight = dict(exact, memoryMiB=255)
        result = self.admit(observation=observation(available=tight))
        self.assertEqual(result['reasons'], ['insufficient-memory'])
        self.assertFalse(result['eligible'])
        self.assertTrue(self.admit(observation=observation(observedAt=85.0))['eligible'])
        self.assertEqual(self.admit(observation=observation(observedAt=84.0))['reasons'], ['observation-stale'])

    def test_architecture_and_capability_mismatch(self):
        result = catalog.admit(sealed(), host(architecture='aarch64-linux'), observation(), now=105.0)
        self.assertEqual(result['reasons'], ['architecture-mismatch'])
        result = catalog.admit(sealed(), host(capabilities=['userns']), observation(), now=105.0)
        self.assertEqual(result['reasons'], ['capability-missing:nspawn-v1'])
        self.assertFalse(result['eligible'])

    def test_observation_absence_and_badness(self):
        self.assertEqual(self.admit(observation=None)['reasons'], ['observation-missing'])
        self.assertEqual(self.admit(observation=observation(hostId='host-b'))['reasons'], ['observation-host-mismatch'])
        self.assertEqual(self.admit(observation=observation(observedAt=200.0))['reasons'], ['observation-from-future'])
        for obs in (observation(schemaVersion=1), observation(extra='x'), observation(observedAt=True),
                    observation(observedAt=-1), observation(observedAt=float('nan')),
                    observation(available={'memoryMiB': -1, 'cpuMillis': 1, 'stateBytes': 0}),
                    observation(available={'memoryMiB': 1, 'cpuMillis': 1})):
            with self.assertRaises(catalog.CatalogError, msg=obs):
                self.admit(observation=obs)

    def test_no_capacity_check_on_bad_observation(self):
        empty = {'memoryMiB': 0, 'cpuMillis': 0, 'stateBytes': 0}
        result = self.admit(observation=observation(hostId='host-b', available=empty))
        self.assertEqual(result['reasons'], ['observation-host-mismatch'])
        result = self.admit(observation=observation(observedAt=1.0, available=empty))
        self.assertEqual(result['reasons'], ['observation-stale'])

    def test_reservation_math(self):
        available = {'memoryMiB': 400, 'cpuMillis': 1500, 'stateBytes': 1048576}
        self.assertTrue(self.admit(observation=observation(available=available))['eligible'])
        reserved = {'memoryMiB': 100, 'cpuMillis': 0, 'stateBytes': 0}
        self.assertTrue(self.admit(observation=observation(available=available), reservations=reserved)['eligible'])
        reserved = {'memoryMiB': 500, 'cpuMillis': 0, 'stateBytes': 0}
        self.assertEqual(self.admit(observation=observation(available=available), reservations=reserved)['reasons'], ['insufficient-memory'])
        for bad in ({'memoryMiB': -1, 'cpuMillis': 0, 'stateBytes': 0},
                    {'memoryMiB': True, 'cpuMillis': 0, 'stateBytes': 0},
                    {'memoryMiB': 1, 'cpuMillis': 0}, {'memoryMiB': 1.5, 'cpuMillis': 0, 'stateBytes': 0}):
            with self.assertRaises(catalog.CatalogError, msg=bad):
                self.admit(reservations=bad)

    def test_invalid_now_and_max_age(self):
        for now in (True, 'now', -1, float('nan'), float('inf'), -float('inf'), None,
                    10**1000, 2**63, -10**1000):
            with self.assertRaises(catalog.CatalogError, msg=now):
                self.admit(now=now)
        for age in (0, -5, True, 'x', float('inf'), -float('inf'), float('nan'), 3601,
                    10**1000, None):
            with self.assertRaises(catalog.CatalogError, msg=age):
                self.admit(max_age_seconds=age)
        for stamp in (True, 't', -1, float('nan'), float('inf'), 10**1000, None):
            with self.assertRaises(catalog.CatalogError, msg=stamp):
                self.admit(observation=observation(observedAt=stamp))
        self.assertTrue(self.admit(now=3700, max_age_seconds=3600, observation=observation(observedAt=100.0))['eligible'])

    def test_invalid_host_and_definition_inputs(self):
        for bad_host in (host(schemaVersion=1), host(architecture='x86'), host(capabilities=['bad cap']),
                         host(extra='x'), 'host', host(architecture=[]), host(architecture=None),
                         host(architecture=True), host(capabilities=[[]])):
            with self.assertRaises(catalog.CatalogError, msg=bad_host):
                catalog.admit(sealed(), bad_host, observation(), now=105.0)
        with self.assertRaises(catalog.CatalogError):
            catalog.admit(base_definition(), host(), observation(), now=105.0)

    def test_deterministic_reason_order_and_archived(self):
        record = catalog.seal_definition(archive_definition(
            architecture='aarch64-linux',
            requirements={'memoryMiB': 99999, 'cpuMillis': 1, 'stateBytes': 0,
                          'capabilities': ['userns', 'magic-cap']}))
        result = catalog.admit(record, host(), observation(), now=105.0)
        self.assertEqual(result['reasons'], ['workload-archived', 'architecture-mismatch',
                                             'capability-missing:magic-cap', 'insufficient-memory'])
        self.assertFalse(result['eligible'])
        self.assertTrue(catalog.admit(sealed(category='infrastructure', allowedOperations=['backup']),
                                      host(), observation(), now=105.0)['eligible'])

    def test_result_is_detached_and_never_ready(self):
        result = self.admit()
        self.assertNotIn('ready', result)
        self.assertNotIn('recoverable', result)
        self.assertNotIn('eventReady', result)
        self.assertNotIn('password', json.dumps(result).lower())

    def test_errors_do_not_echo_input_values(self):
        marker = 'inj3cted-s3cret-marker'
        with self.assertRaises(catalog.CatalogError) as caught:
            mutate(base_definition(), marker, value='x')
        self.assertNotIn(marker, str(caught.exception))
        with self.assertRaises(catalog.CatalogError) as caught:
            mutate(base_definition(), 'workloadId', value=marker.upper())
        self.assertNotIn(marker.upper(), str(caught.exception))


if __name__ == '__main__':
    unittest.main()
