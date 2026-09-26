"""Read-only workload console tests; run with -W error::ResourceWarning."""
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

import catalog
import console_api
import controller
from test_catalog import archive_definition, sealed
from test_policy import base_policy
from test_recovery import capture, manifest

NOW = 1_800_000_000
INSTANCE = 'ab' * 16


def write(path, value):
    Path(path).write_text(json.dumps(value))
    return str(path)


def base_config(directory, **overrides):
    config = {
        'schemaVersion': 1,
        'listenAddress': '127.0.0.1',
        'port': 0,
        'catalogFile': write(os.path.join(directory, 'catalog.json'),
                             [sealed()]),
    }
    config.update(overrides)
    return console_api.validate_config(config)


def evidence_file(directory, host_id='host-a', observed_at=NOW - 5):
    return write(os.path.join(directory, 'evidence-' + host_id + '.json'),
                 {'schemaVersion': 2, 'hostId': host_id,
                  'observedAt': observed_at,
                  'available': {'memoryMiB': 4096, 'cpuMillis': 8000,
                                'stateBytes': 10 ** 9}})


def make_worker_db(directory):
    """A minimal worker.db fixture in rollback mode; the console reader
    must not create or modify anything."""
    state_dir = os.path.join(directory, 'worker')
    os.mkdir(state_dir)
    db = sqlite3.connect(os.path.join(state_dir, 'worker.db'))
    try:
        db.executescript('''
        CREATE TABLE instances(instance_id TEXT PRIMARY KEY,
            workload_id TEXT NOT NULL, revision_digest TEXT NOT NULL,
            generation INTEGER NOT NULL, slot_id TEXT NOT NULL,
            machine_name TEXT NOT NULL, phase TEXT NOT NULL,
            requirements TEXT NOT NULL DEFAULT '{}',
            binding_json TEXT, boot_id TEXT, permit_deadline REAL,
            permit INTEGER NOT NULL DEFAULT 0,
            retired INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE generations(workload_id TEXT PRIMARY KEY,
            generation INTEGER NOT NULL);
        CREATE TABLE operations(operation_id TEXT PRIMARY KEY,
            request TEXT NOT NULL, status TEXT NOT NULL, result TEXT);
        CREATE TABLE captures(capture_id TEXT PRIMARY KEY,
            instance_id TEXT NOT NULL, workload_id TEXT NOT NULL,
            revision_digest TEXT NOT NULL, generation INTEGER NOT NULL,
            status TEXT NOT NULL);
        ''')
        db.execute(
            'INSERT INTO instances(instance_id, workload_id,'
            ' revision_digest, generation, slot_id, machine_name, phase,'
            ' retired) VALUES(?,?,?,?,?,?,?,?)',
            (INSTANCE, 'demo', 'sha256:' + 'a' * 64, 1, 'slot-1',
             'nzzzzzzzzzz', 'stopped', 1))
        db.execute('INSERT INTO generations VALUES(?,?)', ('demo', 1))
        db.execute('INSERT INTO operations VALUES(?,?,?,?)',
                   ('cd' * 16, json.dumps(
                       {'schemaVersion': 1, 'action': 'retire',
                        'operationId': 'cd' * 16, 'workloadId': 'demo',
                        'revisionDigest': 'sha256:' + 'a' * 64,
                        'instanceId': INSTANCE, 'generation': 1}),
                    'completed', None))
        db.execute('INSERT INTO captures VALUES(?,?,?,?,?,?)',
                   ('ef' * 16, INSTANCE, 'demo', 'sha256:' + 'a' * 64,
                    1, 'held'))
        db.commit()
    finally:
        db.close()
    return state_dir


def backup_job(m, **overrides):
    job = {
        'schemaVersion': 1,
        'request': {'schemaVersion': 1, 'action': 'capture',
                    'captureId': 'aa' * 16, 'workloadId': 'demo',
                    'revisionDigest':
                        m['definition']['revisionDigest'],
                    'instanceId': INSTANCE, 'generation': 1},
        'configDigest': 'f' * 64,
        'sourceBinding': {'hostId': 'host-a',
                          'architecture': 'x86_64-linux',
                          'storage': {'root': '/srv/state',
                                      'mountPoint': '/srv/state',
                                      'uuid': 'AABB-CCDD'},
                          'slot': {'id': 'slot-1', 'uidBase': 65536,
                                   'hostAddress': '10.0.0.1',
                                   'localAddress': '10.0.0.2'}},
        'definition': m['definition'], 'source': m['source'],
        'capture': m['capture'], 'phase': 'captured',
        'cache': {'schemaVersion': 1, 'repositoryId': 'cache',
                  'repositoryIdentity': 'e' * 64,
                  'snapshotId': 'd' * 64, 'manifest': m},
        'copies': {'repo-b': {'record': {
            'schemaVersion': 1, 'repositoryId': 'repo-b',
            'repositoryIdentity': 'c' * 64, 'snapshotId': 'b' * 64,
            'manifest': m}, 'verifiedAt': m['capture']['completedAt']
            + 10}},
    }
    job.update(overrides)
    return job


def restore_job(m, **overrides):
    job = {
        'schemaVersion': 1,
        'request': {'schemaVersion': 1, 'action': 'stage',
                    'restoreId': 'bb' * 16, 'repositoryId': 'repo-b',
                    'snapshotId': 'b' * 64,
                    'target': {'workloadId': 'demo',
                               'revisionDigest':
                                   m['definition']['revisionDigest'],
                               'instanceId': 'cd' * 16, 'generation': 1,
                               'slotId': 'slot-2'}},
        'configDigest': 'f' * 64,
        'record': {'schemaVersion': 1, 'repositoryId': 'repo-b',
                   'repositoryIdentity': 'c' * 64,
                   'snapshotId': 'b' * 64, 'manifest': m},
        'translation': {'sourceUidBase': 65536, 'targetUidBase': 131072},
        'phase': 'committed', 'stagedAt': NOW - 50,
        'committedAt': NOW - 40,
    }
    job.update(overrides)
    return job


class FakeReader:
    """Stand-in for RegistryReader returning canned endpoint data."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get(self, path, nonce=None):
        self.calls.append((path, nonce))
        return self.responses.get(
            path, {'available': False, 'error': 'unavailable'})


def state_response(workloads, fences=()):
    return {'available': True, 'data': {
        'schemaVersion': 2, 'registryEpoch': 'e' * 32, 'version': 7,
        'workloads': workloads, 'fences': list(fences)}}


def fence(workload_id='demo', generation=1, host_id='host-a',
          **overrides):
    record = {'workloadId': workload_id, 'generation': generation,
              'hostId': host_id, 'evidence': 'operator',
              'attestedBy': 'operator@console', 'requestId': 'aa' * 16,
              'recordedAt': NOW - 20}
    record.update(overrides)
    return record


def placed_on(host_id, workload_id='neighbor', instance_id='cd' * 16):
    """A second workload placed on another host with a fresh
    observation — proves the target host's session is live."""
    item = placed(workloadId=workload_id, hostId=host_id,
                  instanceId=instance_id)
    item['observation'] = dict(item['observation'], hostId=host_id,
                               instanceId=instance_id,
                               workloadId=workload_id)
    return item


def placed(observed_state='running', observed_at=NOW - 4, **overrides):
    item = {'workloadId': 'demo', 'generation': 1,
            'instanceId': INSTANCE, 'hostId': 'host-a',
            'revisionDigest': 'sha256:' + 'a' * 64, 'published': False,
            'observedState': observed_state,
            'observation': {'schemaVersion': 2, 'hostId': 'host-a',
                            'sessionId': 'f' * 16, 'sequence': 3,
                            'instanceId': INSTANCE, 'workloadId': 'demo',
                            'revisionDigest': 'sha256:' + 'a' * 64,
                            'generation': 1, 'observedAt': observed_at,
                            'phase': 'running',
                            'unitActiveState': 'active',
                            'unitDrained': False, 'retired': False,
                            'endpointAddress': '10.0.0.2',
                            'readyServices': ['web'],
                            'receivedAt': observed_at}}
    item.update(overrides)
    return item


class ConfigTests(unittest.TestCase):
    def test_minimal_config(self):
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(directory)
            self.assertEqual(config['listenAddress'], '127.0.0.1')
            self.assertIsNone(config['registry'])
            self.assertEqual(config['hosts'], {})

    def test_rejects_public_and_unspecified_binds(self):
        with tempfile.TemporaryDirectory() as directory:
            for address in ('8.8.8.8', '0.0.0.0', '::', '2606:4700::1111',
                            'ff02::1', 'not-an-ip', 8080, '127.0.0.1 '):
                with self.subTest(address=address):
                    with self.assertRaises(console_api.ConsoleError):
                        base_config(directory, listenAddress=address)
            for address in ('127.0.0.1', '::1', '192.168.1.20',
                            '10.20.0.5', 'fe80::1'):
                with self.subTest(address=address):
                    base_config(directory, listenAddress=address)

    def test_rejects_unknown_and_missing_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            good = base_config(directory)
            path = good['catalogFile']
            for bad in ({'schemaVersion': 1, 'listenAddress': '127.0.0.1',
                         'port': 8080},
                        {'schemaVersion': 1, 'listenAddress': '127.0.0.1',
                         'port': 8080, 'catalogFile': path, 'shell': 1},
                        {'schemaVersion': 2, 'listenAddress': '127.0.0.1',
                         'port': 8080, 'catalogFile': path},
                        {'schemaVersion': 1, 'listenAddress': '127.0.0.1',
                         'port': 70000, 'catalogFile': path},
                        {'schemaVersion': 1, 'listenAddress': '127.0.0.1',
                         'port': 8080, 'catalogFile': 'relative/path'},
                        'not-a-dict'):
                with self.subTest(bad=bad):
                    with self.assertRaises(console_api.ConsoleError):
                        console_api.validate_config(bad)

    def test_registry_url_must_be_plain_https(self):
        with tempfile.TemporaryDirectory() as directory:
            for url in ('http://registry:9000',
                        'https://user:pw@registry:9000',
                        'https://registry:9000/path',
                        'https://registry:9000/?q=1', 5):
                registry = {'url': url, 'caFile': '/c/ca',
                            'certFile': '/c/cert', 'keyFile': '/c/key',
                            'timeoutSeconds': 2}
                with self.subTest(url=url):
                    with self.assertRaises(console_api.ConsoleError):
                        base_config(directory, registry=registry)


class FileReadTests(unittest.TestCase):
    def test_bounded_strict_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'doc.json')
            Path(path).write_text('{"a": 1}')
            self.assertEqual(console_api.read_json_file(path), {'a': 1})
            Path(path).write_text('{"a": 1, "a": 2}')
            with self.assertRaises(console_api.ConsoleError):
                console_api.read_json_file(path)
            Path(path).write_text('{"a": NaN}')
            with self.assertRaises(console_api.ConsoleError):
                console_api.read_json_file(path)
            Path(path).write_text('{"a":' + '1' * 64 + '}')
            with self.assertRaises(console_api.ConsoleError):
                console_api.read_json_file(path, limit=8)
            link = os.path.join(directory, 'link.json')
            os.symlink(path, link)
            with self.assertRaises(OSError):
                console_api.read_json_file(link)
            with self.assertRaises(OSError):
                console_api.read_json_file(
                    os.path.join(directory, 'missing.json'))

    def test_worker_journal_is_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            state_dir = make_worker_db(directory)
            before = os.listdir(state_dir)
            content = Path(state_dir, 'worker.db').read_bytes()
            journal = console_api.read_worker_journal(state_dir)
            self.assertTrue(journal['available'])
            self.assertEqual(journal['generations'], {'demo': 1})
            self.assertEqual(journal['instances'][0]['workloadId'],
                             'demo')
            self.assertEqual(journal['instances'][0]['phase'], 'stopped')
            self.assertTrue(journal['instances'][0]['retired'])
            self.assertNotIn('binding_json', journal['instances'][0])
            self.assertEqual(journal['operations'][0]['action'], 'retire')
            self.assertEqual(journal['captures'][0]['status'], 'held')
            # Read-only: identical bytes and no WAL/journal/lock files.
            self.assertEqual(Path(state_dir, 'worker.db').read_bytes(),
                             content)
            self.assertEqual(sorted(os.listdir(state_dir)),
                             sorted(before))

    def test_worker_journal_missing_and_wrong_type(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = console_api.read_worker_journal(directory)
            self.assertFalse(missing['available'])
            self.assertEqual(missing['error'], 'missing')
            os.mkdir(os.path.join(directory, 'worker.db'))
            self.assertFalse(
                console_api.read_worker_journal(directory)['available'])

    def test_backup_and_restore_job_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            point = manifest(capture=capture(startedAt=NOW - 100,
                                             completedAt=NOW - 95))
            jobs = os.path.join(directory, 'jobs')
            os.mkdir(jobs)
            write(os.path.join(jobs, 'aa' * 16 + '.json'),
                  backup_job(point))
            write(os.path.join(jobs, 'ff' * 16 + '.json'), {'junk': 1})
            Path(jobs, 'not-a-job.txt').write_text('ignored')
            result = console_api.read_backup_jobs(directory)
            self.assertTrue(result['available'])
            self.assertEqual(len(result['jobs']), 2)
            job = result['jobs'][0]
            self.assertEqual(job['id'], 'aa' * 16)
            self.assertEqual(job['phase'], 'captured')
            self.assertEqual(job['recoveryPointId'],
                             point['recoveryPointId'])
            self.assertEqual(job['copies'][0]['repositoryId'], 'repo-b')
            self.assertTrue(result['jobs'][1]['invalid'])
            # No filesystem paths from sourceBinding leak into summaries.
            encoded = json.dumps(result)
            self.assertNotIn('/srv/state', encoded)
            self.assertNotIn('sourceBinding', encoded)

            restore_dir = os.path.join(directory, 'restore')
            os.makedirs(os.path.join(restore_dir, 'jobs'))
            write(os.path.join(restore_dir, 'jobs', 'bb' * 16 + '.json'),
                  restore_job(point))
            result = console_api.read_restore_jobs(restore_dir)
            self.assertEqual(result['jobs'][0]['phase'], 'committed')
            self.assertEqual(result['jobs'][0]['slotId'], 'slot-2')
            self.assertEqual(result['jobs'][0]['recoveryPointId'],
                             point['recoveryPointId'])


class FakeResponse:
    def __init__(self, raw=b'{"ok":true}', status=200):
        self.raw = raw
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, _n=-1):
        return self.raw


class RegistryReaderTests(unittest.TestCase):
    def _reader(self):
        reader = object.__new__(console_api.RegistryReader)
        reader._base = 'https://registry:9000'
        reader._timeout = 1
        reader._context = None
        return reader

    def test_get_success_and_nonce(self):
        seen = {}

        def fake(request, **_):
            seen['nonce'] = request.headers.get('X-nexus-nonce')
            return FakeResponse(b'{"schemaVersion":2,"routes":[]}')

        reader = self._reader()
        with patch('urllib.request.urlopen', fake):
            result = reader.get('/v2/routes', nonce='ab' * 16)
        self.assertTrue(result['available'])
        self.assertEqual(result['data']['routes'], [])
        self.assertEqual(seen['nonce'], 'ab' * 16)

    def test_denied_unavailable_and_invalid(self):
        reader = self._reader()
        with patch('urllib.request.urlopen',
                   side_effect=urllib.error.HTTPError(
                       'https://registry:9000/v2/assignments', 403,
                       'Forbidden', None, None)):
            self.assertEqual(reader.get('/v2/assignments'),
                             {'available': False, 'error': 'denied'})
        with patch('urllib.request.urlopen',
                   side_effect=OSError('refused')):
            self.assertEqual(reader.get('/v2/state'),
                             {'available': False, 'error': 'unavailable'})
        with patch('urllib.request.urlopen',
                   lambda *_, **__: FakeResponse(b'{"dup":1,"dup":2}')):
            self.assertEqual(
                reader.get('/v2/state'),
                {'available': False, 'error': 'invalid-response'})


class ViewTests(unittest.TestCase):
    def _snapshot(self, directory, workloads=None, fences=(),
                  **config_overrides):
        work = tempfile.mkdtemp(dir=directory)
        point = manifest(capture=capture(startedAt=NOW - 100,
                                         completedAt=NOW - 95))
        backup_dir = os.path.join(work, 'backup')
        restore_dir = os.path.join(work, 'restore')
        os.makedirs(os.path.join(backup_dir, 'jobs'))
        write(os.path.join(backup_dir, 'jobs', 'aa' * 16 + '.json'),
              backup_job(point))
        os.makedirs(os.path.join(restore_dir, 'jobs'))
        write(os.path.join(restore_dir, 'jobs', 'bb' * 16 + '.json'),
              restore_job(point))
        overrides = {
            'manifestsFile': write(
                os.path.join(work, 'manifests.json'), [point]),
            'policiesFile': write(
                os.path.join(work, 'policies.json'),
                [base_policy(revisionDigest=
                             sealed()['revisionDigest'])]),
            'hosts': [{'hostId': 'host-a',
                       'architecture': 'x86_64-linux',
                       'capabilities': ['userns', 'nspawn-v1'],
                       'evidenceFile': evidence_file(work)},
                      {'hostId': 'host-b',
                       'architecture': 'x86_64-linux',
                       'capabilities': ['userns', 'nspawn-v1'],
                       'evidenceFile': evidence_file(work, 'host-b')}],
            'backupStateDir': backup_dir,
            'restoreStateDir': restore_dir,
        }
        overrides.update(config_overrides)
        config = base_config(work, **overrides)
        reader = FakeReader({
            '/v2/state': state_response(
                [placed()] if workloads is None else workloads,
                fences),
            '/v2/assignments': {'available': False, 'error': 'denied'},
            '/v2/routes': {'available': False, 'error': 'denied'}})
        return console_api.collect(config, reader=reader, now=NOW), point

    def test_collect_degrades_and_reports_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(directory)
            snapshot = console_api.collect(config, now=NOW)
            self.assertEqual(snapshot['sources']['catalog'],
                             {'status': 'ok'})
            self.assertEqual(
                snapshot['registry']['state'],
                {'available': False, 'error': 'not-configured'})
            row = console_api.workload_rows(snapshot)[0]
            self.assertEqual(row['workloadId'], 'demo')
            self.assertEqual(row['observedState'], 'unknown')
            self.assertIsNone(row['evaluation'])

    def test_workload_row_merges_registry_policy_and_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot, point = self._snapshot(directory)
            row = console_api.workload_rows(snapshot)[0]
            self.assertEqual(row['hostId'], 'host-a')
            self.assertEqual(row['generation'], 1)
            self.assertEqual(row['observedState'], 'running')
            self.assertTrue(row['observationFresh'])
            self.assertEqual(row['readyServices'], ['web'])
            evaluation = row['evaluation']
            self.assertTrue(evaluation['protectionStatus']['healthy'])
            self.assertEqual(evaluation['captureDue']['reason'],
                             'not-due')
            self.assertEqual(
                evaluation['freshestProtected']['recoveryPointId'],
                point['recoveryPointId'])
            classified = evaluation['points'][0]
            self.assertEqual(classified['classification'],
                             'current-protected')
            self.assertIn('verified-copy', classified['reasons'])
            # The workload occupies its own host; admission excludes its
            # own reservation and has fresh capacity evidence.
            self.assertTrue(row['admission']['eligible'])

    def test_workload_detail_renders_points_instances_operations(self):
        with tempfile.TemporaryDirectory() as directory:
            overrides = {'workers': [{'hostId': 'host-a',
                                      'stateDir': make_worker_db(
                                          directory)}]}
            snapshot, point = self._snapshot(directory, **overrides)
            detail = console_api.workload_detail(snapshot, 'demo')
            self.assertEqual(detail['points'][0]['classification'],
                             'current-protected')
            self.assertEqual(detail['stateMounts'][0]['mountPoint'],
                             '/var/lib/demo')
            self.assertEqual(detail['instances'][0]['phase'], 'stopped')
            actions = {op.get('action') or op['source']
                       for op in detail['operations']}
            self.assertEqual(actions, {'retire', 'backup', 'restore'})
            self.assertIsNone(console_api.workload_detail(snapshot,
                                                        'missing'))

    def test_host_rows_report_evidence_and_journals(self):
        with tempfile.TemporaryDirectory() as directory:
            overrides = {'workers': [{'hostId': 'host-a',
                                      'stateDir': make_worker_db(
                                          directory)}]}
            snapshot, _ = self._snapshot(directory, **overrides)
            rows = {r['hostId']: r for r in
                    console_api.host_rows(snapshot)}
            self.assertTrue(rows['host-a']['evidenceFresh'])
            self.assertEqual(rows['host-a']['available']['memoryMiB'],
                             4096)
            self.assertEqual(rows['host-a']['observedInstances'], 1)
            self.assertEqual(rows['host-a']['journal']['heldCaptures'],
                             1)
            self.assertIsNone(rows['host-b']['journal'])

    def test_move_check_explains_every_blocker(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot, _ = self._snapshot(directory)
            result = console_api.move_check(snapshot, 'demo', 'host-b')
            codes = {(r['code'], r['severity'], r['source'])
                     for r in result['reasons']}
            # Source still running: successor requires retirement proof.
            self.assertFalse(result['eligible'])
            self.assertIn(('retirement-required', 'blocker',
                           'placement'), codes)
            retired, _ = self._snapshot(
                directory,
                workloads=[placed(observed_state='retired')])
            result = console_api.move_check(retired, 'demo', 'host-b')
            self.assertEqual(result['reasons'], [])
            self.assertTrue(result['eligible'])

    def test_move_check_admission_and_definition_reasons(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot, _ = self._snapshot(
                directory,
                workloads=[placed(observed_state='retired')])
            snapshot['hosts']['host-b']['capabilities'] = []
            result = console_api.move_check(snapshot, 'demo', 'host-b')
            codes = {r['code'] for r in result['reasons']}
            self.assertIn('capability-missing:userns', codes)
            self.assertIn('capability-missing:nspawn-v1', codes)
            result = console_api.move_check(snapshot, 'demo', 'host-a')
            self.assertIn('already-on-target',
                          {r['code'] for r in result['reasons']})
            result = console_api.move_check(snapshot, 'missing',
                                            'host-b')
            self.assertIn('unknown-workload',
                          {r['code'] for r in result['reasons']})
            result = console_api.move_check(snapshot, 'demo', 'missing')
            self.assertIn('unknown-host',
                          {r['code'] for r in result['reasons']})

    def test_move_check_archived_and_secret_definitions(self):
        with tempfile.TemporaryDirectory() as directory:
            archived = catalog.seal_definition(
                archive_definition(workloadId='old-app'))
            secret = sealed(workloadId='vaulted',
                            secretSetRef='app-secrets')
            catalog_file = write(
                os.path.join(directory, 'catalog.json'),
                [sealed(), archived, secret])
            snapshot, _ = self._snapshot(
                directory, catalogFile=catalog_file,
                workloads=[placed(observed_state='retired')])
            result = console_api.move_check(snapshot, 'old-app',
                                            'host-b')
            self.assertTrue({'workload-archived',
                             'operation-not-allowed:move'} <=
                            {r['code'] for r in result['reasons']})
            self.assertFalse(result['eligible'])
            # A secrets-bearing definition is no longer a blocker —
            # provisioning capability is per-host worker config the
            # console cannot see — but the preview honestly reports it
            # cannot verify that capability; the worker stays
            # fail-closed when the secrets trio is absent.
            result = console_api.move_check(snapshot, 'vaulted',
                                            'host-b')
            reasons = {(r['code'], r['severity'], r['source'])
                       for r in result['reasons']}
            self.assertIn(('secret-provisioning-unverifiable',
                           'warning', 'definition'), reasons)
            self.assertNotIn('secret-provisioning-unavailable',
                             {r['code'] for r in result['reasons']})
            self.assertTrue(result['eligible'])

    def test_move_check_dependency_readiness(self):
        """A dep-having workload reports the controller's typed dep
        blockers naming the failing dependency — not a blanket
        unavailable reason."""
        with tempfile.TemporaryDirectory() as directory:
            dependent = sealed(workloadId='dependent',
                               dependencies=['broker'])
            broker = sealed(workloadId='broker')
            catalog_file = write(
                os.path.join(directory, 'dep-catalog.json'),
                [sealed(), dependent, broker])
            dep_row = placed_on('host-b', workload_id='broker',
                                instance_id='ef' * 16)
            routes = {'available': True, 'data': {'routes': [
                {'id': 'route-broker', 'workloadId': 'broker',
                 'serviceId': 'web', 'hostname': 'broker.internal',
                 'backend': None}]}}

            # Serving dep: placed, fresh, running, routed service
            # ready — the move preview stays clean.
            snapshot, _ = self._snapshot(
                directory, catalogFile=catalog_file,
                workloads=[dep_row])
            snapshot['registry']['routes'] = routes
            result = console_api.move_check(snapshot, 'dependent',
                                            'host-b')
            self.assertEqual(
                [r for r in result['reasons']
                 if r['source'] == 'dependency'], [])
            self.assertTrue(result['eligible'])

            # Not placed at all: typed blocker naming the dep.
            unplaced, _ = self._snapshot(
                directory, catalogFile=catalog_file, workloads=[])
            result = console_api.move_check(unplaced, 'dependent',
                                            'host-b')
            self.assertIn(('dependency-not-placed:broker', 'blocker'),
                          {(r['code'], r['severity'])
                           for r in result['reasons']})
            self.assertFalse(result['eligible'])

            # Placed but stale evidence.
            stale, _ = self._snapshot(
                directory, catalogFile=catalog_file,
                workloads=[dict(dep_row, observedState='stale')])
            result = console_api.move_check(stale, 'dependent',
                                            'host-b')
            self.assertIn('dependency-stale:broker',
                          {r['code'] for r in result['reasons']})
            self.assertFalse(result['eligible'])

            # Fresh and running but the routed service is not ready.
            bare = dict(dep_row)
            bare['observation'] = dict(dep_row['observation'],
                                       readyServices=[])
            not_ready, _ = self._snapshot(
                directory, catalogFile=catalog_file,
                workloads=[bare])
            not_ready['registry']['routes'] = routes
            result = console_api.move_check(not_ready, 'dependent',
                                            'host-b')
            self.assertIn('dependency-not-ready:broker',
                          {r['code'] for r in result['reasons']})
            self.assertFalse(result['eligible'])

    def test_move_check_dependency_closure_and_degraded_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            store = sealed(workloadId='store')
            app = sealed(workloadId='app', dependencies=['store'])
            dependent = sealed(workloadId='dependent',
                               dependencies=['app'])
            catalog_file = write(
                os.path.join(directory, 'dep-catalog.json'),
                [sealed(), dependent, app, store])
            app_row = placed_on('host-b', workload_id='app',
                                instance_id='ef' * 16)
            snapshot, _ = self._snapshot(
                directory, catalogFile=catalog_file,
                workloads=[app_row])
            # The transitive closure is evaluated dep-first: 'app'
            # serves but 'store' was never placed.
            result = console_api.move_check(snapshot, 'dependent',
                                            'host-b')
            codes = {r['code'] for r in result['reasons']}
            self.assertIn('dependency-not-placed:store', codes)
            self.assertNotIn('dependency-not-placed:app', codes)
            self.assertFalse(result['eligible'])
            # A reader denied /v2/routes still evaluates placement and
            # freshness but cannot prove service coverage — an
            # explicit warning, not a verdict.
            serving, _ = self._snapshot(
                directory, catalogFile=catalog_file,
                workloads=[app_row,
                           placed_on('host-b', workload_id='store',
                                     instance_id='f0' * 16)])
            result = console_api.move_check(serving, 'dependent',
                                            'host-b')
            dep = {(r['code'], r['severity'])
                   for r in result['reasons']
                   if r['source'] == 'dependency'}
            self.assertEqual(
                dep, {('dependency-evidence-unavailable:app',
                       'warning'),
                      ('dependency-evidence-unavailable:store',
                       'warning')})
            self.assertTrue(result['eligible'])
            # No registry state at all: the dep check degrades to one
            # honest warning, never a fabricated not-placed.
            config = base_config(
                directory, catalogFile=catalog_file, hosts=[{
                    'hostId': 'host-a',
                    'architecture': 'x86_64-linux',
                    'capabilities': ['userns', 'nspawn-v1'],
                    'evidenceFile': evidence_file(directory)}])
            bare = console_api.collect(config, now=NOW)
            result = console_api.move_check(bare, 'dependent',
                                            'host-a')
            self.assertIn(('dependency-evidence-unavailable',
                           'warning'),
                          {(r['code'], r['severity'])
                           for r in result['reasons']})

    def test_move_check_warns_without_registry_or_protection(self):
        with tempfile.TemporaryDirectory() as directory:
            config = base_config(directory, hosts=[{
                'hostId': 'host-a', 'architecture': 'x86_64-linux',
                'capabilities': ['userns', 'nspawn-v1'],
                'evidenceFile': evidence_file(directory)}])
            snapshot = console_api.collect(config, now=NOW)
            result = console_api.move_check(snapshot, 'demo', 'host-a')
            codes = {(r['code'], r['severity'])
                     for r in result['reasons']}
            self.assertIn(('registry-state-unavailable', 'warning'),
                          codes)
            self.assertIn(('no-protected-recovery-point', 'warning'),
                          codes)
            self.assertTrue(result['eligible'])

    def test_plan_request_renders_runnable_input(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot, _ = self._snapshot(
                directory,
                workloads=[placed(observed_state='retired'),
                           placed_on('host-b')])
            model = console_api.plan_request(snapshot, 'demo', 'host-b')
            self.assertTrue(model['viable'])
            self.assertEqual(model['reasons'], [])
            self.assertEqual(model['sourceHostId'], 'host-a')
            self.assertEqual(model['targetHostId'], 'host-b')
            request = model['input']
            self.assertEqual(
                set(request), {'schemaVersion', 'action',
                               'operationId', 'workloadId',
                               'revisionDigest', 'fromInstanceId',
                               'toHostId', 'toSlotId', 'repositoryId'})
            self.assertEqual(request['action'], 'plan')
            self.assertEqual(request['workloadId'], 'demo')
            self.assertEqual(request['toHostId'], 'host-b')
            self.assertEqual(request['fromInstanceId'], INSTANCE)
            self.assertEqual(request['revisionDigest'],
                             sealed()['revisionDigest'])
            self.assertEqual(request['repositoryId'], 'repo-b')
            self.assertIsNone(request['toSlotId'])
            self.assertRegex(request['operationId'], r'[0-9a-f]{32}\Z')
            # The rendered body is exactly what the controller accepts.
            controller._validate_plan_request(request)
            # Re-rendering the same move derives the same operationId —
            # a replay hits the controller's idempotent plan path.
            replay = console_api.plan_request(snapshot, 'demo',
                                              'host-b')
            self.assertEqual(replay['input']['operationId'],
                             request['operationId'])
            commands = model['commands']
            self.assertIn('nexus-controller', commands['plan'])
            self.assertIn('execute', commands['execute'])
            self.assertIn(request['operationId'], commands['status'])
            page = console_api.plan_request_page(snapshot, 'demo',
                                                 'host-b')
            self.assertIn(request['operationId'].encode(), page)
            self.assertIn(b'nexus-controller', page)

    def test_plan_request_reports_nonviable_reasons(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot, _ = self._snapshot(directory)
            model = console_api.plan_request(snapshot, 'demo', 'host-b')
            codes = {(r['code'], r['severity'], r['source'])
                     for r in model['reasons']}
            self.assertFalse(model['viable'])
            self.assertIn(('retirement-required', 'blocker',
                           'placement'), codes)
            # Controller-mirrored check: nothing observed live on the
            # target, so its session cannot be proven.
            self.assertIn(('target-session-unproven', 'blocker',
                           'controller'), codes)
            # The canonical input still renders — ids are real.
            self.assertIsNotNone(model['input'])
            self.assertEqual(model['input']['fromInstanceId'], INSTANCE)

    def test_plan_request_unplaced_and_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot, _ = self._snapshot(directory, workloads=[])
            model = console_api.plan_request(snapshot, 'demo', 'host-b')
            codes = {r['code'] for r in model['reasons']}
            self.assertFalse(model['viable'])
            self.assertIn('workload-not-placed', codes)
            self.assertIn('plan-input-incomplete', codes)
            self.assertIsNone(model['input'])
            self.assertIsNone(model['commands'])
            model = console_api.plan_request(snapshot, 'missing',
                                             'host-b')
            self.assertIn('unknown-workload',
                          {r['code'] for r in model['reasons']})

    def test_plan_request_without_backup_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            # An empty jobs dir: no uploaded copies means the request
            # cannot name an upload repository.
            empty = os.path.join(directory, 'empty-backup')
            os.makedirs(os.path.join(empty, 'jobs'))
            snapshot, _ = self._snapshot(
                directory,
                workloads=[placed(observed_state='retired'),
                           placed_on('host-b')],
                backupStateDir=empty)
            model = console_api.plan_request(snapshot, 'demo', 'host-b')
            self.assertFalse(model['viable'])
            self.assertIn('repository-unresolved',
                          {r['code'] for r in model['reasons']})
            self.assertIsNone(model['input']['repositoryId'])

    def test_fences_projection_rendered_on_views(self):
        with tempfile.TemporaryDirectory() as directory:
            snapshot, _ = self._snapshot(directory,
                                         fences=[fence()])
            self.assertTrue(snapshot['fences']['available'])
            self.assertEqual(len(snapshot['fences']['fences']), 1)
            row = console_api.workload_rows(snapshot)[0]
            self.assertEqual(row['fence']['evidence'], 'operator')
            detail = console_api.workload_detail(snapshot, 'demo')
            self.assertEqual(detail['fencesStatus'], 'ok')
            self.assertEqual(detail['fences'][0]['attestedBy'],
                             'operator@console')
            self.assertEqual(detail['fences'][0]['requestId'],
                             'aa' * 16)
            rows = {r['hostId']: r
                    for r in console_api.host_rows(snapshot)}
            self.assertEqual(len(rows['host-a']['fences']), 1)
            self.assertEqual(rows['host-b']['fences'], [])
            page = console_api.workload_detail_page(snapshot, 'demo')
            self.assertIn(b'Fence records', page)
            self.assertIn(b'operator@console', page)

    def test_fences_tampered_or_unexpected_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            for bad in ({'workloadId': 'demo'},           # missing fields
                        dict(fence(), extra=1),            # unexpected field
                        dict(fence(), evidence='forged'),  # unknown evidence
                        dict(fence(), generation=0),       # out of range
                        dict(fence(), requestId='xyz'),    # not hex32
                        dict(fence(), attestedBy=''),
                        'not-a-dict'):
                with self.subTest(bad=bad):
                    snapshot, _ = self._snapshot(directory,
                                                 fences=[bad])
                    self.assertFalse(snapshot['fences']['available'])
                    self.assertEqual(snapshot['fences']['error'],
                                     'invalid')
                    self.assertEqual(snapshot['fences']['fences'], [])
                    detail = console_api.workload_detail(snapshot,
                                                         'demo')
                    self.assertEqual(detail['fencesStatus'], 'invalid')
                    self.assertEqual(detail['fences'], [])
            # A non-list fences field rejects the projection likewise.
            snapshot, _ = self._snapshot(directory, fences='tampered')
            self.assertEqual(snapshot['fences']['error'], 'invalid')
            # A registry that predates the projection (no key) is a
            # legitimately empty view, not an error.
            legacy = console_api._fence_records(
                {'available': True, 'data': {'workloads': []}})
            self.assertTrue(legacy['available'])
            self.assertEqual(legacy['fences'], [])


class HttpTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        directory = self._tmp.name
        definition = sealed(displayName='<script>alert(1)</script>')
        self.config = console_api.validate_config({
            'schemaVersion': 1, 'listenAddress': '127.0.0.1', 'port': 0,
            'catalogFile': write(
                os.path.join(directory, 'catalog.json'), [definition]),
            'hosts': [{'hostId': 'host-a',
                       'architecture': 'x86_64-linux',
                       'capabilities': ['userns', 'nspawn-v1'],
                       'evidenceFile': evidence_file(
                           directory, observed_at=time.time())}]})
        self.server = console_api.make_server(self.config)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)
        self._tmp.cleanup()

    def get(self, path, method='GET'):
        url = 'http://127.0.0.1:%d%s' % (self.port, path)
        request = urllib.request.Request(
            url, method=method,
            data=b'{}' if method == 'POST' else None)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, response.read(), dict(
                    response.headers)
        except urllib.error.HTTPError as error:
            body = error.read()
            headers = dict(error.headers)
            error.close()
            return error.code, body, headers

    def test_pages_and_security_headers(self):
        status, body, headers = self.get('/workloads')
        self.assertEqual(status, 200)
        self.assertIn(b'&lt;script&gt;alert(1)&lt;/script&gt;', body)
        self.assertNotIn(b'<script>alert', body)
        self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
        self.assertIn("default-src 'self'",
                      headers['Content-Security-Policy'])
        self.assertEqual(headers['Cache-Control'], 'no-store')
        for path in ('/hosts', '/operations'):
            status, _, _ = self.get(path)
            self.assertEqual(status, 200, path)
        status, _, _ = self.get('/')
        # urllib follows the redirect to /workloads.
        self.assertEqual(status, 200)
        status, body, _ = self.get('/workloads/demo')
        self.assertEqual(status, 200)
        self.assertIn(b'State mounts', body)
        self.assertIn(b'Recovery points', body)
        status, body, _ = self.get('/move-check?workloadId=demo'
                                   '&hostId=host-a')
        self.assertEqual(status, 200)
        self.assertIn(b'registry-state-unavailable', body)
        self.assertIn(b'plan preview', body)
        status, body, _ = self.get('/plan-request?workloadId=demo'
                                   '&hostId=host-a')
        self.assertEqual(status, 200)
        self.assertIn(b'Plan request', body)
        self.assertIn(b'nexus-controller', body)

    def test_json_surface(self):
        status, body, _ = self.get('/api/v1/workloads')
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data['workloads'][0]['workloadId'], 'demo')
        status, body, _ = self.get('/api/v1/workloads/demo')
        self.assertEqual(status, 200)
        status, body, _ = self.get(
            '/api/v1/move-check?workloadId=demo&hostId=host-a')
        data = json.loads(body)
        self.assertTrue(data['eligible'])
        self.assertIn('registry-state-unavailable',
                      {r['code'] for r in data['reasons']})
        status, body, _ = self.get('/api/v1/sources')
        data = json.loads(body)
        self.assertEqual(data['sources']['catalog']['status'], 'ok')
        self.assertFalse(data['registry']['state']['available'])
        status, body, _ = self.get(
            '/api/v1/plan-request?workloadId=demo&hostId=host-a')
        self.assertEqual(status, 200)
        data = json.loads(body)
        request = data['request']
        self.assertEqual(request['targetHostId'], 'host-a')
        # No registry configured: the request stays unrenderable and
        # the reason is visible.
        self.assertFalse(request['viable'])
        self.assertIsNone(request['input'])
        self.assertIn('registry-state-unavailable',
                      {r['code'] for r in request['reasons']})

    def test_rejects_mutations_queries_and_unknown_paths(self):
        for method in ('POST', 'PUT', 'DELETE'):
            status, _, _ = self.get('/workloads', method=method)
            self.assertEqual(status, 404, method)
            status, _, _ = self.get(
                '/plan-request?workloadId=demo&hostId=host-a',
                method=method)
            self.assertEqual(status, 404, method)
        for path in ('/workloads/nonexistent', '/etc/passwd',
                     '/api/v1/move-check?workloadId=%3Cscript%3E'
                     '&hostId=h',
                     '/move-check?workloadId=demo',
                     '/plan-request?hostId=host-a',
                     '/api/v1/plan-request?workloadId=%3Cx%3E'
                     '&hostId=host-a',
                     '/workloads/' + 'a' * 100):
            with self.subTest(path=path):
                status, _, _ = self.get(path)
                self.assertIn(status, (400, 404))
        status, body, _ = self.get('/healthz')
        self.assertEqual(status, 200)


if __name__ == '__main__':
    unittest.main()
