import copy
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('mailcow_lab', Path(__file__).with_name('mailcow-lab.py'))
assert spec is not None and spec.loader is not None
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class ComposeRoundtripTests(unittest.TestCase):
    def setUp(self):
        self.expected = {'services': {'netfilter-mailcow': {
            'image': 'fixture:1', 'privileged': False, 'volumes': [],
            'cap_add': ['NET_ADMIN', 'NET_RAW'],
            'labels': {'job': 'echo $${VALUE}'},
            'environment': {'TOKEN': 'synthetic-placeholder'},
            'ulimits': {'nproc': {'soft': 65535, 'hard': 65535}},
        }}}

    def test_omitted_safe_defaults_are_equivalent(self):
        actual = copy.deepcopy(self.expected)
        actual['services']['netfilter-mailcow'].pop('privileged')
        actual['services']['netfilter-mailcow'].pop('volumes')
        lab.assert_compose_roundtrip(self.expected, actual)

    def test_new_privilege_is_rejected(self):
        actual = copy.deepcopy(self.expected)
        actual['services']['netfilter-mailcow']['privileged'] = True
        with self.assertRaisesRegex(RuntimeError, 'privileged'):
            lab.assert_compose_roundtrip(self.expected, actual)

    def test_reintroduced_mount_is_rejected(self):
        actual = copy.deepcopy(self.expected)
        actual['services']['netfilter-mailcow']['volumes'] = [{'source': '/lib/modules', 'target': '/lib/modules'}]
        with self.assertRaisesRegex(RuntimeError, 'volumes'):
            lab.assert_compose_roundtrip(self.expected, actual)

    def test_changed_capabilities_are_rejected(self):
        actual = copy.deepcopy(self.expected)
        actual['services']['netfilter-mailcow']['cap_add'].append('SYS_ADMIN')
        with self.assertRaisesRegex(RuntimeError, 'cap_add'):
            lab.assert_compose_roundtrip(self.expected, actual)

    def test_interpolated_label_is_rejected(self):
        actual = copy.deepcopy(self.expected)
        actual['services']['netfilter-mailcow']['labels']['job'] = 'echo '
        with self.assertRaisesRegex(RuntimeError, 'labels'):
            lab.assert_compose_roundtrip(self.expected, actual)

    def test_changed_environment_does_not_leak_values(self):
        actual = copy.deepcopy(self.expected)
        actual['services']['netfilter-mailcow']['environment']['TOKEN'] = 'different-placeholder'
        with self.assertRaisesRegex(RuntimeError, 'environment') as caught:
            lab.assert_compose_roundtrip(self.expected, actual)
        self.assertNotIn('synthetic-placeholder', str(caught.exception))
        self.assertNotIn('different-placeholder', str(caught.exception))

    def test_resource_limits_cannot_be_stripped(self):
        actual = copy.deepcopy(self.expected)
        actual['services']['netfilter-mailcow'].pop('ulimits')
        with self.assertRaisesRegex(RuntimeError, 'ulimits'):
            lab.assert_compose_roundtrip(self.expected, actual)

    def test_service_set_is_preserved(self):
        actual = copy.deepcopy(self.expected)
        actual['services']['unexpected'] = {'image': 'fixture:2'}
        with self.assertRaisesRegex(RuntimeError, 'service set'):
            lab.assert_compose_roundtrip(self.expected, actual)


class ReadinessTests(unittest.TestCase):
    def row(self, service, **changes):
        return {'service': service, 'state': 'running', 'health': 'healthy', 'privileged': False, 'runtime': 'crun', **changes}

    def test_service_without_upstream_healthcheck_is_allowed(self):
        self.assertTrue(lab.services_ready([self.row('nginx-mailcow', health='none')], {'nginx-mailcow'}))

    def test_required_healthchecks_cannot_be_absent(self):
        for service in ('unbound-mailcow', 'clamd-mailcow'):
            for health in ('none', 'starting', 'unhealthy'):
                with self.subTest(service=service, health=health):
                    self.assertFalse(lab.services_ready([self.row(service, health=health)], {service}))

    def test_runtime_privilege_and_process_state_are_enforced(self):
        for change in ({'privileged': True}, {'runtime': 'runc'}, {'state': 'restarting'}):
            with self.subTest(change=change):
                self.assertFalse(lab.services_ready([self.row('nginx-mailcow', **change)], {'nginx-mailcow'}))

    def test_missing_duplicate_and_extra_services_are_rejected(self):
        row = self.row('nginx-mailcow')
        self.assertFalse(lab.services_ready([], {'nginx-mailcow'}))
        self.assertFalse(lab.services_ready([row, row], {'nginx-mailcow', 'sogo-mailcow'}))
        self.assertFalse(lab.services_ready([row, self.row('sogo-mailcow')], {'nginx-mailcow'}))


class EnsureDhparamsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.source = Path(self.tmp.name) / 'source-dhparams.pem'
        self.source.write_text('PUBLIC-DH-PARAMS')
        self.tls = Path(self.tmp.name) / 'ssl'
        self.tls.mkdir()
        self.target = self.tls / 'dhparams.pem'

    def test_missing_target_is_copied_and_checked(self):
        with patch.object(lab, 'run') as mocked:
            lab.ensure_dhparams(self.source, self.tls)
        self.assertEqual(self.target.read_bytes(), b'PUBLIC-DH-PARAMS')
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o644)
        mocked.assert_called_once_with(['openssl', 'dhparam', '-in', str(self.target), '-check', '-noout'])

    def test_identical_target_is_idempotent(self):
        self.target.write_bytes(b'PUBLIC-DH-PARAMS')
        with patch.object(lab, 'run') as mocked:
            lab.ensure_dhparams(self.source, self.tls)
        self.assertEqual(self.target.read_bytes(), b'PUBLIC-DH-PARAMS')
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o644)
        mocked.assert_called_once()

    def test_different_target_is_rejected_and_preserved(self):
        self.target.write_bytes(b'OTHER-PARAMS')
        with self.assertRaisesRegex(RuntimeError, 'differ'):
            lab.ensure_dhparams(self.source, self.tls)
        self.assertEqual(self.target.read_bytes(), b'OTHER-PARAMS')

    def test_symlink_target_is_rejected_and_preserved(self):
        real = Path(self.tmp.name) / 'real.pem'
        real.write_bytes(b'REAL-CONTENT')
        self.target.symlink_to(real)
        with self.assertRaisesRegex(RuntimeError, 'symlink'):
            lab.ensure_dhparams(self.source, self.tls)
        self.assertTrue(self.target.is_symlink())
        self.assertEqual(real.read_bytes(), b'REAL-CONTENT')


class EnsureAppInfoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        (self.work / 'data/web/inc').mkdir(parents=True)
        self.target = self.work / 'data/web/inc/app_info.inc.php'
        self.revision = 'a' * 40

    def test_missing_file_is_created_with_expected_content(self):
        lab.ensure_app_info(self.work, self.revision)
        self.assertIn('a' * 40, self.target.read_text())
        self.assertIn('MAILCOW_UPDATEDAT = 0', self.target.read_text())
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o644)

    def test_mode_repair_is_idempotent_and_preserves_siblings(self):
        lab.ensure_app_info(self.work, self.revision)
        self.target.chmod(0o600)
        expected = self.target.read_bytes()
        sibling = self.work / 'mailcow.conf'
        sibling.write_text('PRIVATE=secret')
        sibling.chmod(0o600)
        lab.ensure_app_info(self.work, self.revision)
        self.assertEqual(self.target.read_bytes(), expected)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o644)
        self.assertEqual(sibling.read_text(), 'PRIVATE=secret')
        self.assertEqual(sibling.stat().st_mode & 0o777, 0o600)

    def test_unexpected_content_is_rejected_and_preserved(self):
        self.target.write_text('<?php // tampered\n')
        self.target.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, 'differs'):
            lab.ensure_app_info(self.work, self.revision)
        self.assertEqual(self.target.read_text(), '<?php // tampered\n')
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o600)

    def test_symlink_is_rejected_and_preserved(self):
        real = self.work / 'real.php'
        real.write_text('<?php echo 1;\n')
        real.chmod(0o600)
        self.target.symlink_to(real)
        with self.assertRaisesRegex(RuntimeError, 'symlink'):
            lab.ensure_app_info(self.work, self.revision)
        self.assertTrue(self.target.is_symlink())
        self.assertEqual(real.read_text(), '<?php echo 1;\n')
        self.assertEqual(real.stat().st_mode & 0o777, 0o600)


class DomainResponseTests(unittest.TestCase):
    def test_upstream_empty_sentinels_and_domain_records(self):
        for value in ({}, [], [{'domain_name': 'nexus.test'}]):
            with self.subTest(value=value):
                self.assertTrue(lab.domain_list_response_ready(value))

    def test_unexpected_shapes_are_rejected(self):
        for value in (None, False, '', 0, {'type': 'error'}, {'unexpected': []}, ['not-a-record']):
            with self.subTest(value=value):
                self.assertFalse(lab.domain_list_response_ready(value))

    def test_api_error_is_not_an_empty_domain_result(self):
        with patch.object(lab, 'state', return_value={'secrets': {'API_KEY': 'fixture'}}), patch.object(lab, 'tls_context', return_value=None), patch.object(lab.urllib.request, 'urlopen', return_value=io.BytesIO(b'{"type":"error","msg":"denied"}')):
            with self.assertRaisesRegex(RuntimeError, 'API rejected'):
                lab.api('get/domain/all')


if __name__ == '__main__':
    unittest.main()
