import base64
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CONSOLE = Path(__file__).resolve().parent
sys.path.insert(0, str(CONSOLE))
import artifacts
import catalog


def store_path(name, marker):
    alphabet = '0123456789abcdfghijklmnpqrsvwxyz'
    return '/nix/store/' + alphabet[marker % 32] * 32 + '-' + name


def record(path, references=(), nar='sha256:' + 'ab' * 32, size=10, extra=None):
    entry = {'path': path, 'narHash': nar, 'narSize': size, 'references': list(references)}
    if extra:
        entry.update(extra)
    return entry


PATH_A = store_path('a', 1)
PATH_B = store_path('b', 2)
PATH_C = store_path('c', 3)
PATH_D = store_path('d', 4)


def graph_fixture():
    return {'closure': [record(PATH_C, [PATH_B]), record(PATH_B, [PATH_A]), record(PATH_A)]}


def manifest_fixture(**overrides):
    manifest = {
        'schemaVersion': 1,
        'kind': 'nixos-closure',
        'runtimeVersion': 'nspawn-v1',
        'architecture': 'x86_64-linux',
        'root': PATH_C,
        'closure': [
            record(PATH_A),
            record(PATH_B, [PATH_A]),
            record(PATH_C, [PATH_B]),
        ],
    }
    manifest.update(overrides)
    return manifest


def draft_fixture(**overrides):
    definition = {
        'schemaVersion': 2,
        'workloadId': 'demo',
        'displayName': 'Demo',
        'category': 'project',
        'runtimeVersion': 'nspawn-v1',
        'architecture': 'x86_64-linux',
        'runtimeArtifactId': 'runtime',
        'artifacts': [{'id': 'image', 'kind': 'oci-image', 'digest': 'sha256:' + 'b' * 64}],
        'stateSchemaVersion': 1,
        'stateMounts': [{'id': 'data', 'mountPoint': '/var/lib/demo', 'ownerUid': 0,
                         'ownerGid': 0, 'consistencyAdapter': 'quiesce-v1'}],
        'secretSetRef': None,
        'dependencies': [],
        'services': [{'id': 'web', 'protocol': 'http', 'port': 8080, 'exposure': 'private'}],
        'requirements': {'memoryMiB': 256, 'cpuMillis': 1000, 'stateBytes': 1048576,
                         'capabilities': ['userns', 'nspawn-v1']},
        'allowedOperations': ['start', 'stop', 'restart', 'backup', 'restore', 'move'],
        'policyProfiles': ['normal-hourly'],
    }
    definition.update(overrides)
    return definition


class CanonicalTests(unittest.TestCase):
    def test_canonical_bytes_sorted_compact_utf8(self):
        raw = artifacts.canonical_bytes({'b': 1, 'a': 'Ü'})
        self.assertEqual(raw, '{"a":"Ü","b":1}'.encode('utf-8'))
        self.assertFalse(raw.endswith(b'\n'))
        for value in (float('nan'), float('inf'), object(), '\ud800'):
            with self.assertRaises(artifacts.ArtifactError, msg=repr(value)):
                artifacts.canonical_bytes(value)

    def test_determinism_independent_of_graph_order(self):
        graph = {'closure': [
            record(PATH_A),
            record(PATH_B, [PATH_A]),
            record(PATH_C, [PATH_A, PATH_B]),
        ]}
        reordered = {'closure': [
            record(PATH_C, [PATH_B, PATH_A]),
            record(PATH_B, [PATH_A]),
            record(PATH_A),
        ]}
        first = artifacts.build_manifest(PATH_C, 'x86_64-linux', graph)
        second = artifacts.build_manifest(PATH_C, 'x86_64-linux', reordered)
        self.assertEqual(artifacts.canonical_bytes(first), artifacts.canonical_bytes(second))

    def test_digest_tracks_exact_bytes(self):
        manifest = manifest_fixture()
        digest = artifacts.manifest_digest(manifest)
        raw = artifacts.canonical_bytes(manifest)
        self.assertEqual(digest, 'sha256:' + hashlib.sha256(raw).hexdigest())
        changed = manifest_fixture()
        changed['closure'][0]['narSize'] += 1
        self.assertNotEqual(artifacts.manifest_digest(changed), digest)

    def test_results_are_detached(self):
        manifest = manifest_fixture()
        validated = artifacts.validate_manifest(manifest)
        validated['closure'][0]['narSize'] = 999
        self.assertEqual(manifest['closure'][0]['narSize'], 10)
        manifest['closure'][0]['narSize'] = 777
        self.assertEqual(validated['closure'][0]['narSize'], 999)


class ManifestShapeTests(unittest.TestCase):
    def test_exact_fields_at_every_level(self):
        for change in (
            lambda m: m.pop('root'),
            lambda m: m.update(extra='x'),
            lambda m: m['closure'][0].pop('narHash'),
            lambda m: m['closure'][0].update(extra='x'),
        ):
            manifest = manifest_fixture()
            change(manifest)
            with self.assertRaises(artifacts.ArtifactError, msg=change):
                artifacts.validate_manifest(manifest)
        for value in (None, [], 'x'):
            with self.assertRaises(artifacts.ArtifactError, msg=repr(value)):
                artifacts.validate_manifest(value)

    def test_scalar_types_and_bounds(self):
        cases = [
            ('schemaVersion', 2), ('schemaVersion', True), ('schemaVersion', '1'),
            ('kind', 'oci-image'), ('kind', []), ('runtimeVersion', 'nspawn-v2'),
            ('runtimeVersion', None), ('architecture', 'x86'), ('architecture', {}),
            ('architecture', 'aarch64-linux-'),
        ]
        for key, value in cases:
            manifest = manifest_fixture(**{key: value})
            with self.assertRaises(artifacts.ArtifactError, msg=(key, value)):
                artifacts.validate_manifest(manifest)
        self.assertIsNotNone(artifacts.validate_manifest(manifest_fixture(architecture='aarch64-linux')))
        for size in (True, -1, 2**63, '10', 1.5):
            manifest = manifest_fixture()
            manifest['closure'][0]['narSize'] = size
            with self.assertRaises(artifacts.ArtifactError, msg=size):
                artifacts.validate_manifest(manifest)
        manifest = manifest_fixture()
        manifest['closure'][0]['narSize'] = 0
        self.assertIsNotNone(artifacts.validate_manifest(manifest))

    def test_store_path_syntax(self):
        for path in ('/nix/store/short-a', '/nix/store/' + 'a' * 33 + '-x',
                     '/etc/passwd', '/nix/store/' + 'e' * 32 + '-x',
                     '/nix/store/' + '1' * 32 + '-x/evil', 'relative/path',
                     PATH_A + '/', '', 42, None, '/nix/store/' + '1' * 32 + '-x/../y'):
            manifest = manifest_fixture(root=path)
            with self.assertRaises(artifacts.ArtifactError, msg=repr(path)):
                artifacts.validate_manifest(manifest)
            manifest = manifest_fixture()
            manifest['closure'][0]['path'] = path
            manifest['closure'][0]['references'] = []
            with self.assertRaises(artifacts.ArtifactError, msg=repr(path)):
                artifacts.validate_manifest(manifest)

    def test_closure_integrity(self):
        duplicate = manifest_fixture()
        duplicate['closure'].append(dict(duplicate['closure'][0]))
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.validate_manifest(duplicate)
        dup_ref = manifest_fixture()
        dup_ref['closure'][1]['references'] = [PATH_A, PATH_A]
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.validate_manifest(dup_ref)
        missing_root = manifest_fixture(root=PATH_D)
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.validate_manifest(missing_root)
        dangling = manifest_fixture()
        dangling['closure'][1]['references'] = [PATH_D]
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.validate_manifest(dangling)
        unreachable = manifest_fixture()
        unreachable['closure'].append(record(PATH_D))
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.validate_manifest(unreachable)
        unsorted = manifest_fixture()
        unsorted['closure'] = list(reversed(unsorted['closure']))
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.validate_manifest(unsorted)
        unsorted_ref = manifest_fixture()
        unsorted_ref['closure'][2]['references'] = [PATH_B, PATH_A]
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.validate_manifest(unsorted_ref)

    def test_self_reference_and_cycle_accepted(self):
        manifest = manifest_fixture()
        manifest['closure'][0]['references'] = [PATH_A]
        manifest['closure'][1]['references'] = sorted([PATH_A, PATH_C])
        manifest['closure'][2]['references'] = [PATH_B]
        self.assertIsNotNone(artifacts.validate_manifest(manifest))

    def test_nar_hash_formats(self):
        good = [
            'sha256:' + 'ab' * 32,
            'sha256:' + '0' * 52,
            'sha256:' + '01' * 26,
            'sha256-' + base64.b64encode(b'x' * 32).decode(),
        ]
        for nar in good:
            manifest = manifest_fixture()
            manifest['closure'][0]['narHash'] = nar
            self.assertIsNotNone(artifacts.validate_manifest(manifest), nar)
        bad = [
            'sha256:' + 'ab' * 31,
            'sha256:' + 'AB' * 32,
            'sha1:' + 'ab' * 20,
            'sha256:' + 'e' * 52,
            'sha256:' + '2' + '0' * 51,
            'sha256:' + '9' + '0' * 51,
            'sha256-' + base64.b64encode(b'x' * 32).decode()[:-1] + 'A',
            'sha256-' + base64.b64encode(b'x' * 32).decode()[:-1],
            'sha256-' + base64.b64encode(b'x' * 31).decode(),
            'sha256-' + '!!!!',
            'sha256-' + base64.b64encode(b'x' * 32).decode() + ' ',
            '', None, 42, {},
        ]
        for nar in bad:
            manifest = manifest_fixture()
            manifest['closure'][0]['narHash'] = nar
            with self.assertRaises(artifacts.ArtifactError, msg=repr(nar)):
                artifacts.validate_manifest(manifest)


class BuildManifestTests(unittest.TestCase):
    def test_selects_four_keys_and_sorts(self):
        graph = {'closure': [
            record(PATH_C, [PATH_B, PATH_A], extra={'extraUpstreamKey': 'ignored'}),
            record(PATH_A),
            record(PATH_B, [PATH_A]),
        ]}
        manifest = artifacts.build_manifest(PATH_C, 'x86_64-linux', graph)
        self.assertEqual([entry['path'] for entry in manifest['closure']], [PATH_A, PATH_B, PATH_C])
        self.assertEqual(manifest['closure'][2]['references'], [PATH_A, PATH_B])
        for entry in manifest['closure']:
            self.assertEqual(set(entry), {'path', 'narHash', 'narSize', 'references'})

    def test_invalid_graph_inputs(self):
        for graph in (None, [], {}, {'closure': 'x'}, {'closure': []}, {'closure': [{}]},
                      {'closure': [{'path': PATH_A, 'narHash': 'sha256:' + 'ab' * 32, 'narSize': 1}]},
                      {'closure': [record(PATH_A, [['unhashable']])]}):
            with self.assertRaises(artifacts.ArtifactError, msg=repr(graph)[:80]):
                artifacts.build_manifest(PATH_C, 'x86_64-linux', graph)
        for args in ((PATH_C, 'linux', graph_fixture()), ('/etc/x', 'x86_64-linux', graph_fixture())):
            with self.assertRaises(artifacts.ArtifactError):
                artifacts.build_manifest(*args)


class SealWorkloadTests(unittest.TestCase):
    def test_seal_inserts_runtime_artifact_digest(self):
        manifest = manifest_fixture()
        sealed = artifacts.seal_workload(draft_fixture(), manifest)
        runtime = [a for a in sealed['artifacts'] if a['id'] == 'runtime']
        self.assertEqual(len(runtime), 1)
        self.assertEqual(runtime[0]['kind'], 'nixos-closure')
        self.assertEqual(runtime[0]['digest'], artifacts.manifest_digest(manifest))
        self.assertEqual(catalog.revision_digest(sealed), sealed['revisionDigest'])
        self.assertEqual(len(sealed['artifacts']), 2)

    def test_rejects_presupplied_or_conflicting_fields(self):
        manifest = manifest_fixture()
        draft = draft_fixture(revisionDigest='sha256:' + '0' * 64)
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.seal_workload(draft, manifest)
        draft = draft_fixture(artifacts=[{'id': 'runtime', 'kind': 'oci-image', 'digest': 'sha256:' + 'e' * 64}])
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.seal_workload(draft, manifest)
        draft = draft_fixture(architecture='aarch64-linux')
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.seal_workload(draft, manifest)
        draft = draft_fixture(runtimeVersion='other')
        with self.assertRaises(artifacts.ArtifactError):
            artifacts.seal_workload(draft, manifest)
        for draft in (None, [], 'x'):
            with self.assertRaises(artifacts.ArtifactError, msg=repr(draft)):
                artifacts.seal_workload(draft, manifest)

    def test_definition_errors_propagate_as_catalog_error(self):
        for mutate in (lambda d: d.update(password='injected-secret'),
                       lambda d: d.update(secretSetRef='UPPER CASE'),
                       lambda d: d.pop('services')):
            draft = draft_fixture()
            mutate(draft)
            with self.assertRaises(catalog.CatalogError, msg=mutate):
                artifacts.seal_workload(draft, manifest_fixture())

    def test_no_host_paths_or_credentials(self):
        sealed = artifacts.seal_workload(draft_fixture(), manifest_fixture())
        raw = artifacts.canonical_bytes(sealed)
        for leak in (b'/srv/host', b'192.168.', b'password'):
            self.assertNotIn(leak, raw)
        draft = draft_fixture(secretSetRef='lab-secrets')
        self.assertIsNotNone(artifacts.seal_workload(draft, manifest_fixture()))


class CliTests(unittest.TestCase):
    def test_build_writes_exact_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'graph.json').write_text(json.dumps(graph_fixture()))
            (root / 'definition.json').write_text(json.dumps(draft_fixture()))
            output = root / 'out'
            subprocess.run(
                [sys.executable, str(CONSOLE / 'artifacts.py'), 'build',
                 '--graph', str(root / 'graph.json'), '--root', PATH_C,
                 '--architecture', 'x86_64-linux', '--definition', str(root / 'definition.json'),
                 '--output', str(output)],
                check=True, capture_output=True,
            )
            raw = (output / 'artifact.json').read_bytes()
            manifest = artifacts.validate_manifest(json.loads(raw))
            self.assertEqual(raw, artifacts.canonical_bytes(manifest))
            self.assertFalse(raw.endswith(b'\n'))
            digest = (output / 'artifact.sha256').read_text()
            self.assertTrue(digest.endswith('\n'))
            self.assertEqual(digest.strip(), artifacts.manifest_digest(manifest))
            sealed_raw = (output / 'definition.json').read_bytes()
            sealed = catalog.validate_definition(json.loads(sealed_raw))
            self.assertFalse(sealed_raw.endswith(b'\n'))
            runtime = [a for a in sealed['artifacts'] if a['id'] == 'runtime']
            self.assertEqual(runtime[0]['digest'], digest.strip())

    def test_cli_rejects_invalid_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'graph.json').write_text('{"closure": NaN}')
            (root / 'definition.json').write_text(json.dumps(draft_fixture()))
            result = subprocess.run(
                [sys.executable, str(CONSOLE / 'artifacts.py'), 'build',
                 '--graph', str(root / 'graph.json'), '--root', PATH_C,
                 '--architecture', 'x86_64-linux', '--definition', str(root / 'definition.json'),
                 '--output', str(root / 'out')],
                capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('ArtifactError', result.stderr)

    def test_cli_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for graph_text, definition_text in (
                ('{"closure": [], "closure": []}', json.dumps(draft_fixture())),
                (json.dumps(graph_fixture()), '{"schemaVersion": 2, "schemaVersion": 2}'),
            ):
                (root / 'graph.json').write_text(graph_text)
                (root / 'definition.json').write_text(definition_text)
                result = subprocess.run(
                    [sys.executable, str(CONSOLE / 'artifacts.py'), 'build',
                     '--graph', str(root / 'graph.json'), '--root', PATH_C,
                     '--architecture', 'x86_64-linux', '--definition', str(root / 'definition.json'),
                     '--output', str(root / 'out')],
                    capture_output=True, text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('ArtifactError', result.stderr)


if __name__ == '__main__':
    unittest.main()
