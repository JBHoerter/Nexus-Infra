import base64
import copy
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import artifacts
import catalog
import distribution
import worker
import test_worker
from test_worker import (FAKE_BUNDLE, FakeFilesystem, Result, draft_fixture,
                         manifest_fixture, sealed_fixture, write_bundle)


KEY = 'cache-key:' + base64.b64encode(b'k' * 32).decode()
REF = 'cd' * 16


class DistRunner(test_worker.FakeRunner):
    def __init__(self, manifest=None, bundle=FAKE_BUNDLE):
        super().__init__(manifest)
        self.bundle = bundle
        self.copy_rc = 0
        self.copy_sigs_rc = 0
        self.verify_rc = 0
        self.add_root_rc = 0
        self.bundle_closure = None
        self.membership_output = None
        self.link_root = True
        self.crash_after_root = False

    def _nix(self, argv):
        if argv[0] == 'nix':
            if 'copy-sigs' in argv:
                return Result(argv, self.copy_sigs_rc, '',
                              'copy-sigs failed')
            if 'copy' in argv:
                return Result(argv, self.copy_rc)
            if 'verify' in argv:
                return Result(argv, self.verify_rc)
            if 'path-info' in argv and argv[-1] == self.bundle:
                if self.membership_output is not None:
                    return Result(argv, 0, self.membership_output)
                paths = self.bundle_closure
                if paths is None:
                    paths = [self.bundle] + [
                        entry['path'] for entry in self.manifest['closure']]
                return Result(argv, 0,
                              json.dumps({path: {} for path in paths}))
            return super()._nix(argv)
        if argv[0] == 'nix-store':
            if '--add-root' in argv:
                if self.add_root_rc != 0:
                    return Result(argv, self.add_root_rc, '',
                                  'add-root failed')
                if self.link_root:
                    root = argv[argv.index('--add-root') + 1]
                    if os.path.lexists(root):
                        os.unlink(root)
                    os.symlink(argv[-1], root)
                if self.crash_after_root:
                    self.crash_after_root = False
                    raise KeyboardInterrupt()
                return Result(argv, 0)
            return super()._nix(argv)
        return super()._nix(argv)


def base_config(**overrides):
    definition, _ = sealed_fixture()
    config = {'schemaVersion': 1, 'stateDir': '/var/lib/nexus-artifacts',
              'trustedPublicKeys': [KEY],
              'sources': [{'id': 'cache', 'uri': 'https://cache.example.com'}],
              'bundles': [{'workloadId': 'canary',
                           'revisionDigest': definition['revisionDigest'],
                           'bundlePath': FAKE_BUNDLE,
                           'sourceId': 'cache'}]}
    config.update(overrides)
    return config


def make_config(tmp):
    config = base_config(stateDir=os.path.join(tmp, 'artifact-state'))
    bundle_dir = os.path.join(tmp, 'bundle')
    os.makedirs(bundle_dir)
    write_bundle(bundle_dir)
    definition, manifest = sealed_fixture()
    return config, definition, manifest, bundle_dir


def make_distribution(tmp, runner=None, fs=None, **config_overrides):
    config, definition, manifest, bundle_dir = make_config(tmp)
    config.update(config_overrides)
    runner = runner or DistRunner(manifest, bundle=FAKE_BUNDLE)
    fs = fs or FakeFilesystem()
    fs.bundle_dir = bundle_dir
    instance = distribution.Distribution(config, runner=runner, fs=fs)
    return instance, runner, fs, definition, manifest


def fetch_request(**overrides):
    definition, _ = sealed_fixture()
    req = {'schemaVersion': 1, 'action': 'fetch', 'workloadId': 'canary',
           'revisionDigest': definition['revisionDigest'],
           'referenceId': REF}
    req.update(overrides)
    return req


def ref_record(tmp, reference=REF):
    path = os.path.join(tmp, 'artifact-state', 'refs', reference + '.json')
    return json.loads(Path(path).read_bytes())


class ConfigValidationTests(unittest.TestCase):
    def test_source_uri_rejected(self):
        for uri in ('http://cache.example.com',
                    'https://user@cache.example.com',
                    'https://user:pw@cache.example.com',
                    'https://cache.example.com:bad/path',
                    'ssh://cache.example.com',
                    'file://host/path',
                    'file://relative',
                    'file:///ok?x=1',
                    'file:///ok#f',
                    'https://cache.example.com/p%20x',
                    'https://cache.example.com/pa th',
                    'cache.example.com'):
            with self.assertRaises(worker.WorkerError) as ctx:
                distribution.validate_config(
                    base_config(sources=[{'id': 'cache', 'uri': uri}]))
            self.assertEqual(ctx.exception.code, 'invalid-source-uri', uri)
        good = base_config(sources=[
            {'id': 'cache', 'uri': 'https://cache.example.com:443/p'},
            {'id': 'local', 'uri': 'file:///srv/cache'}])
        validated = distribution.validate_config(good)
        self.assertIsNot(validated, good)

    def test_trusted_keys_rejected(self):
        for keys in ([], ['noname'], ['bad name:' + 'a' * 44],
                     ['k:' + 'a' * 43], ['k:!!!!'],
                     ['k:' + base64.b64encode(b'x' * 31).decode()]):
            with self.assertRaises(worker.WorkerError) as ctx:
                distribution.validate_config(
                    base_config(trustedPublicKeys=keys))
            self.assertEqual(ctx.exception.code,
                             'invalid-trustedPublicKeys', keys)
        with self.assertRaises(worker.WorkerError):
            distribution.validate_config(
                base_config(trustedPublicKeys=[KEY, KEY]))
        other_bytes = 'cache-key:' + base64.b64encode(b'x' * 32).decode()
        with self.assertRaises(worker.WorkerError) as ctx:
            distribution.validate_config(
                base_config(trustedPublicKeys=[KEY, other_bytes]))
        self.assertEqual(ctx.exception.code, 'invalid-trustedPublicKeys')
        too_many = ['k%d:%s' % (i, base64.b64encode(b'k' * 32).decode())
                    for i in range(17)]
        with self.assertRaises(worker.WorkerError):
            distribution.validate_config(
                base_config(trustedPublicKeys=too_many))

    def test_bundle_records_rejected(self):
        definition, _ = sealed_fixture()
        digest = definition['revisionDigest']
        for bundles in (
                [],
                [{'workloadId': 'canary', 'revisionDigest': digest,
                  'bundlePath': '/tmp/bundle', 'sourceId': 'cache'}],
                [{'workloadId': 'canary', 'revisionDigest': digest,
                  'bundlePath': FAKE_BUNDLE, 'sourceId': 'missing'}],
                [{'workloadId': 'canary', 'revisionDigest': digest,
                  'bundlePath': FAKE_BUNDLE, 'sourceId': 'cache',
                  'extra': 1}],
                [{'workloadId': 'canary', 'revisionDigest': digest,
                  'bundlePath': FAKE_BUNDLE, 'sourceId': 'cache'},
                 {'workloadId': 'canary', 'revisionDigest': digest,
                  'bundlePath': FAKE_BUNDLE + '2', 'sourceId': 'cache'}]):
            with self.assertRaises(worker.WorkerError):
                distribution.validate_config(base_config(bundles=bundles))

    def test_state_dir_and_fields_rejected(self):
        for config in (
                base_config(schemaVersion=2),
                base_config(stateDir='relative/path'),
                base_config(stateDir='/bad//path'),
                base_config(sources=[{'id': 'cache',
                                      'uri': 'https://x.example.com',
                                      'extra': 1}])):
            with self.assertRaises(worker.WorkerError):
                distribution.validate_config(config)


class RequestValidationTests(unittest.TestCase):
    def test_rejects_before_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist, runner, fs, definition, manifest = make_distribution(tmp)
            for overrides, code in (
                    ({'workloadId': 'nope'}, 'unknown-workload'),
                    ({'revisionDigest': 'sha256:' + '0' * 64},
                     'unknown-workload'),
                    ({'referenceId': 'GG' * 16}, 'invalid-referenceId'),
                    ({'action': 'release'}, 'invalid-action'),
                    ({'action': 'fetch', 'extra': 1},
                     'invalid-request-fields'),
                    ({'schemaVersion': 2}, 'invalid-schemaVersion')):
                with self.assertRaises(worker.WorkerError) as ctx:
                    dist.fetch(fetch_request(**overrides))
                self.assertEqual(ctx.exception.code, code, overrides)
            self.assertEqual(runner.calls, [])


class FetchTests(unittest.TestCase):
    def test_fetch_retains_and_replays(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist, runner, fs, definition, manifest = make_distribution(tmp)
            request = fetch_request(
                revisionDigest=definition['revisionDigest'])
            result = dist.fetch(request)
            self.assertEqual(result['status'], 'retained')
            self.assertEqual(result['workloadId'], 'canary')
            self.assertEqual(result['referenceId'], REF)
            self.assertEqual(result['bundlePath'], FAKE_BUNDLE)
            self.assertEqual(result['manifestDigest'],
                             artifacts.manifest_digest(manifest))
            copy_i = next(i for i, c in enumerate(runner.calls)
                          if 'copy' in c)
            copy_sigs_i = next(i for i, c in enumerate(runner.calls)
                               if 'copy-sigs' in c)
            verify_i = next(i for i, c in enumerate(runner.calls)
                            if 'verify' in c)
            root_i = next(i for i, c in enumerate(runner.calls)
                          if '--add-root' in c)
            self.assertLess(copy_i, copy_sigs_i)
            self.assertLess(copy_sigs_i, verify_i)
            self.assertLess(verify_i, root_i)
            self.assertIn('--substituter',
                          runner.calls[copy_sigs_i])
            self.assertIn('https://cache.example.com',
                          runner.calls[copy_sigs_i])
            for call in runner.calls:
                if call[0] == 'nix' and ('copy' in call or 'copy-sigs' in call
                                         or 'verify' in call):
                    self.assertIn('require-sigs', call)
                    self.assertIn('true', call)
                    self.assertIn('trusted-public-keys', call)
                    self.assertIn(KEY, call)
            sig = runner.calls[verify_i]
            self.assertIn('--sigs-needed', sig)
            self.assertIn('1', sig)
            root_link = os.path.join(tmp, 'artifact-state', 'roots', REF)
            self.assertTrue(os.path.islink(root_link))
            self.assertEqual(os.readlink(root_link), FAKE_BUNDLE)
            self.assertIn('/nix/var/nix/gcroots/auto', fs.synced_dirs)
            record = ref_record(tmp)
            self.assertEqual(record['status'], 'retained')
            self.assertEqual(record['bundlePath'], FAKE_BUNDLE)
            self.assertEqual(record['sourceId'], 'cache')
            self.assertEqual(record['request'], request)
            count = len(runner.calls)
            result2 = dist.fetch(request)
            self.assertEqual(result2, result)
            self.assertGreater(len(runner.calls), count)

    def test_reference_conflict_rejects_without_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist, runner, fs, definition, manifest = make_distribution(tmp)
            request = fetch_request(
                revisionDigest=definition['revisionDigest'])
            dist.fetch(request)
            ref_file = os.path.join(tmp, 'artifact-state', 'refs',
                                    REF + '.json')
            before = Path(ref_file).read_bytes()
            config2 = copy.deepcopy(dist.config)
            config2['sources'] = [{'id': 'other', 'uri': 'file:///srv/cache'}]
            config2['bundles'] = [
                {'workloadId': 'canary',
                 'revisionDigest': definition['revisionDigest'],
                 'bundlePath': FAKE_BUNDLE, 'sourceId': 'other'}]
            dist2 = distribution.Distribution(config2, runner=runner, fs=fs)
            with self.assertRaises(worker.WorkerError) as ctx:
                dist2.fetch(request)
            self.assertEqual(ctx.exception.code, 'reference-conflict')
            self.assertEqual(Path(ref_file).read_bytes(), before)

    def test_command_failures_never_retain(self):
        for name, attr in (('copy', 'copy_rc'), ('copy-sigs', 'copy_sigs_rc'),
                           ('sigs', 'verify_rc'), ('addroot', 'add_root_rc')):
            with self.subTest(failure=name):
                with tempfile.TemporaryDirectory() as tmp:
                    runner = DistRunner(manifest_fixture(),
                                        bundle=FAKE_BUNDLE)
                    setattr(runner, attr, 1)
                    dist, runner, fs, definition, manifest = \
                        make_distribution(tmp, runner=runner)
                    request = fetch_request(
                        revisionDigest=definition['revisionDigest'])
                    with self.assertRaises(distribution.DistributionError) \
                            as ctx:
                        dist.fetch(request)
                    self.assertEqual(ctx.exception.code, 'command-failed')
                    record = ref_record(tmp)
                    self.assertEqual(record['status'], 'pending')
                    self.assertNotIn('manifestDigest', record)
                    self.assertFalse(os.path.exists(os.path.join(
                        tmp, 'artifact-state', 'roots', REF)))

    def test_bad_bundle_files_never_retain(self):
        for name in ('manifest-noncanonical', 'digest-mismatch',
                     'wrong-definition', 'missing-manifest'):
            with self.subTest(case=name):
                with tempfile.TemporaryDirectory() as tmp:
                    config, definition, manifest, bundle_dir = \
                        make_config(tmp)
                    if name == 'manifest-noncanonical':
                        write_bundle(bundle_dir, canonical=False)
                    elif name == 'digest-mismatch':
                        Path(bundle_dir, 'artifact.sha256').write_text(
                            'sha256:' + '0' * 64 + '\n')
                    elif name == 'wrong-definition':
                        other = sealed_fixture(workloadId='other')[0]
                        Path(bundle_dir, 'definition.json').write_bytes(
                            artifacts.canonical_bytes(other))
                    else:
                        os.unlink(os.path.join(bundle_dir,
                                               'artifact.json'))
                    runner = DistRunner(manifest, bundle=FAKE_BUNDLE)
                    fs = FakeFilesystem()
                    fs.bundle_dir = bundle_dir
                    dist = distribution.Distribution(
                        config, runner=runner, fs=fs)
                    request = fetch_request(
                        revisionDigest=definition['revisionDigest'])
                    with self.assertRaises(worker.WorkerError) as ctx:
                        dist.fetch(request)
                    self.assertEqual(ctx.exception.code, 'invalid-bundle')
                    record = ref_record(tmp)
                    self.assertEqual(record['status'], 'pending')
                    self.assertFalse(any('--add-root' in c
                                         for c in runner.calls))

    def test_missing_runtime_in_bundle_closure_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist, runner, fs, definition, manifest = make_distribution(tmp)
            runner.bundle_closure = [
                entry['path'] for entry in manifest['closure']
                if entry['path'] != manifest['root']]
            request = fetch_request(
                revisionDigest=definition['revisionDigest'])
            with self.assertRaises(worker.WorkerError) as ctx:
                dist.fetch(request)
            self.assertEqual(ctx.exception.code, 'store-closure-mismatch')
            self.assertFalse(os.path.exists(os.path.join(
                tmp, 'artifact-state', 'roots', REF)))
            self.assertFalse(any('--add-root' in c for c in runner.calls))

    def test_hostile_root_rejected_never_unlinked(self):
        for kind in ('regular', 'wrong-target', 'nonroot'):
            with self.subTest(kind=kind):
                with tempfile.TemporaryDirectory() as tmp:
                    dist, runner, fs, definition, manifest = \
                        make_distribution(tmp)
                    root_path = os.path.join(tmp, 'artifact-state',
                                             'roots', REF)
                    if kind == 'regular':
                        Path(root_path).write_text('x')
                    elif kind == 'wrong-target':
                        os.symlink(
                            '/nix/store/' + 'b' * 32 + '-other', root_path)
                    else:
                        os.symlink(FAKE_BUNDLE, root_path)
                        fs.owners[root_path] = (1000, 0)
                    request = fetch_request(
                        revisionDigest=definition['revisionDigest'])
                    with self.assertRaises(worker.WorkerError) as ctx:
                        dist.fetch(request)
                    self.assertEqual(ctx.exception.code, 'path-unsafe')
                    self.assertTrue(os.path.lexists(root_path))
                    self.assertFalse(any('--add-root' in c
                                         for c in runner.calls))

    def test_metadata_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist, runner, fs, definition, manifest = make_distribution(tmp)
            refs = os.path.join(tmp, 'artifact-state', 'refs')
            target = os.path.join(tmp, 'evil.json')
            Path(target).write_text('{}')
            os.symlink(target, os.path.join(refs, REF + '.json'))
            request = fetch_request(
                revisionDigest=definition['revisionDigest'])
            with self.assertRaises(worker.WorkerError) as ctx:
                dist.fetch(request)
            self.assertEqual(ctx.exception.code, 'path-unsafe')
            self.assertEqual(runner.calls, [])

    def test_writable_ancestor_rejected(self):
        with tempfile.TemporaryDirectory() as outer:
            tmp = os.path.join(outer, 'lab')
            os.makedirs(tmp)
            os.chmod(tmp, 0o777)
            config, definition, manifest, bundle_dir = make_config(tmp)
            with self.assertRaises(worker.WorkerError) as ctx:
                distribution.Distribution(config, fs=FakeFilesystem())
            self.assertEqual(ctx.exception.code, 'path-unsafe')

    def test_crash_after_add_root_retry_preserves_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist, runner, fs, definition, manifest = make_distribution(tmp)
            runner.crash_after_root = True
            request = fetch_request(
                revisionDigest=definition['revisionDigest'])
            with self.assertRaises(KeyboardInterrupt):
                dist.fetch(request)
            root_link = os.path.join(tmp, 'artifact-state', 'roots', REF)
            self.assertEqual(os.readlink(root_link), FAKE_BUNDLE)
            self.assertEqual(ref_record(tmp)['status'], 'pending')
            result = dist.fetch(request)
            self.assertEqual(result['status'], 'retained')
            self.assertEqual(os.readlink(root_link), FAKE_BUNDLE)
            self.assertEqual(ref_record(tmp)['status'], 'retained')

    def test_malformed_reference_rejected_before_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist, runner, fs, definition, manifest = make_distribution(tmp)
            request = fetch_request(
                revisionDigest=definition['revisionDigest'])
            pending = {'schemaVersion': 1, 'request': request,
                       'bundlePath': FAKE_BUNDLE, 'sourceId': 'cache',
                       'status': 'pending'}
            cases = [
                b'{',
                artifacts.canonical_bytes(dict(pending, status='unknown')),
                artifacts.canonical_bytes(dict(pending, extra=1)),
                artifacts.canonical_bytes(
                    {'schemaVersion': 2, 'request': request,
                     'bundlePath': FAKE_BUNDLE, 'sourceId': 'cache',
                     'status': 'retained',
                     'manifestDigest': 'sha256:' + '0' * 64}),
                json.dumps(pending, indent=2).encode(),
            ]
            ref_path = os.path.join(tmp, 'artifact-state', 'refs',
                                    REF + '.json')
            for raw in cases:
                Path(ref_path).write_bytes(raw)
                os.chmod(ref_path, 0o600)
                with self.assertRaises(worker.WorkerError) as ctx:
                    dist.fetch(request)
                self.assertEqual(ctx.exception.code, 'path-unsafe', raw)
            self.assertEqual(runner.calls, [])

    def test_retained_downgrades_to_pending_on_failed_reverify(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist, runner, fs, definition, manifest = make_distribution(tmp)
            request = fetch_request(
                revisionDigest=definition['revisionDigest'])
            result = dist.fetch(request)
            self.assertEqual(result['status'], 'retained')
            root_link = os.path.join(tmp, 'artifact-state', 'roots', REF)
            self.assertEqual(os.readlink(root_link), FAKE_BUNDLE)
            runner.verify_rc = 1
            with self.assertRaises(distribution.DistributionError):
                dist.fetch(request)
            record = ref_record(tmp)
            self.assertEqual(record['status'], 'pending')
            self.assertNotIn('manifestDigest', record)
            self.assertEqual(os.readlink(root_link), FAKE_BUNDLE)
            runner.verify_rc = 0
            result = dist.fetch(request)
            self.assertEqual(result['status'], 'retained')
            self.assertEqual(ref_record(tmp)['status'], 'retained')

    def test_manifest_architecture_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = manifest_fixture()
            draft = draft_fixture(architecture='aarch64-linux')
            draft['artifacts'] = [
                {'id': 'runtime', 'kind': 'nixos-closure',
                 'digest': artifacts.manifest_digest(manifest)}]
            definition = catalog.seal_definition(draft)
            config = base_config(
                stateDir=os.path.join(tmp, 'artifact-state'),
                bundles=[{'workloadId': 'canary',
                          'revisionDigest': definition['revisionDigest'],
                          'bundlePath': FAKE_BUNDLE, 'sourceId': 'cache'}])
            bundle_dir = os.path.join(tmp, 'bundle')
            os.makedirs(bundle_dir)
            write_bundle(bundle_dir, manifest=manifest,
                         definition=definition)
            runner = DistRunner(manifest, bundle=FAKE_BUNDLE)
            fs = FakeFilesystem()
            fs.bundle_dir = bundle_dir
            dist = distribution.Distribution(config, runner=runner, fs=fs)
            request = fetch_request(
                revisionDigest=definition['revisionDigest'])
            with self.assertRaises(worker.WorkerError) as ctx:
                dist.fetch(request)
            self.assertEqual(ctx.exception.code, 'invalid-bundle')
            self.assertFalse(any('--add-root' in c for c in runner.calls))

    def test_membership_output_malformed_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist, runner, fs, definition, manifest = make_distribution(tmp)
            request = fetch_request(
                revisionDigest=definition['revisionDigest'])
            runner.membership_output = json.dumps(
                [{'path': FAKE_BUNDLE}, 'garbage'])
            with self.assertRaises(distribution.DistributionError) as ctx:
                dist.fetch(request)
            self.assertEqual(ctx.exception.code, 'store-schema-unexpected')
            runner.membership_output = json.dumps(
                [{'path': manifest['root']}])
            with self.assertRaises(worker.WorkerError) as ctx:
                dist.fetch(request)
            self.assertEqual(ctx.exception.code, 'store-closure-mismatch')
            runner.membership_output = json.dumps(
                [{'path': FAKE_BUNDLE}])
            with self.assertRaises(worker.WorkerError) as ctx:
                dist.fetch(request)
            self.assertEqual(ctx.exception.code, 'store-closure-mismatch')
            self.assertFalse(any('--add-root' in c for c in runner.calls))


class CliTests(unittest.TestCase):
    def _run_cli(self, argv, stdin=b'', euid=0):
        out = io.StringIO()
        fake_stdin = SimpleNamespace(
            buffer=SimpleNamespace(read=lambda n: stdin))
        with mock.patch.object(distribution.os, 'geteuid',
                               return_value=euid), \
                mock.patch.object(sys, 'stdin', fake_stdin), \
                mock.patch.object(sys, 'stdout', out):
            code = distribution.main(argv)
        return code, out.getvalue()

    def test_unprivileged_cli_fails_before_file_access(self):
        out = io.StringIO()
        with mock.patch.object(distribution.os, 'geteuid',
                               return_value=1000), \
                mock.patch.object(distribution.Path, 'read_bytes',
                                  side_effect=AssertionError('config read')), \
                mock.patch.object(sys, 'stdout', out):
            code = distribution.main(['--config', '/nonexistent/config.json',
                                      'execute'])
        self.assertEqual(code, 1)
        response = json.loads(out.getvalue())
        self.assertEqual(response['error'], 'requires-root')
        self.assertNotIn('/nonexistent', out.getvalue())

    def test_cli_invalid_and_oversized_input(self):
        class FakeDistribution:
            def __init__(self, config):
                pass

            def fetch(self, request):
                return {'status': 'retained'}

            def close(self):
                pass

        with tempfile.TemporaryDirectory() as tmp:
            config_path = os.path.join(tmp, 'config.json')
            Path(config_path).write_text('{}')
            with mock.patch.object(distribution, 'Distribution',
                                   FakeDistribution):
                code, out = self._run_cli(
                    ['--config', config_path, 'execute'], b'\xff\xfe{}')
                self.assertEqual(code, 1)
                self.assertEqual(json.loads(out)['error'], 'invalid-json')
                code, out = self._run_cli(
                    ['--config', config_path, 'execute'],
                    b' ' * (distribution._MAX_REQUEST_BYTES + 1))
                self.assertEqual(code, 1)
                self.assertEqual(json.loads(out)['error'],
                                 'request-too-large')
                code, out = self._run_cli(
                    ['--config', config_path, 'execute'],
                    json.dumps(fetch_request()).encode())
                self.assertEqual(code, 0)
                self.assertEqual(json.loads(out)['status'], 'retained')

    def test_duplicate_keys_rejected(self):
        class FakeDistribution:
            def __init__(self, config):
                pass

            def fetch(self, request):
                return {'status': 'retained'}

            def close(self):
                pass

        with tempfile.TemporaryDirectory() as tmp:
            config_path = os.path.join(tmp, 'config.json')
            Path(config_path).write_text('{}')
            payload = (b'{"schemaVersion":1,"action":"fetch","workloadId":"c",'
                       b'"schemaVersion":1,"revisionDigest":"sha256:'
                       + b'0' * 64 + b'","referenceId":"' + b'0' * 32 + b'"}')
            with mock.patch.object(distribution, 'Distribution',
                                   FakeDistribution):
                code, out = self._run_cli(
                    ['--config', config_path, 'execute'], payload)
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(out)['error'],
                             'invalid-json-duplicate')

    def test_no_release_verb(self):
        with self.assertRaises(SystemExit):
            distribution.main(['--config', '/nonexistent.json', 'release'])


if __name__ == '__main__':
    unittest.main()
