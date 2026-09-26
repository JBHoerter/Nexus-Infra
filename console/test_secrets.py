import base64
import hashlib
import hmac
import io
import json
import os
import stat
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import artifacts
import recovery
import secrets
from test_catalog import sealed
from test_repository import make_private_dir, write_private_file


SENTINEL = b'nxs-sentinel-S3CR3T-value-9f2c'
KEY = b'k' * 32
WRONG_KEY = b'x' * 32


class ToySealer(secrets.Sealer):
    """TEST DOUBLE ONLY — deterministic keyed XOR stream plus an
    HMAC tag over scheme/AAD/ciphertext. This is NOT an AEAD cipher
    and makes no confidentiality claim; it exists to exercise the
    envelope contract, manifest binding and provisioning pipeline
    until a pinned AEAD primitive lands behind the ``Sealer`` seam."""
    scheme = 'test-only-v1'
    MAGIC = b'NXST1\x00'

    def _stream(self, key, aad, length):
        out = bytearray()
        counter = 0
        while len(out) < length:
            out += hashlib.sha256(
                key + b'\x00' + aad + counter.to_bytes(8, 'big')
            ).digest()
            counter += 1
        return bytes(out[:length])

    def seal(self, key, plaintext, aad):
        mask = self._stream(key, aad, len(plaintext))
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, mask))
        tag = hmac.new(key, b't1' + aad + ciphertext,
                       hashlib.sha256).digest()
        return self.MAGIC + tag + ciphertext

    def open(self, key, blob, aad):
        if type(blob) is not bytes \
                or not blob.startswith(self.MAGIC) \
                or len(blob) < len(self.MAGIC) + 32:
            raise secrets.SecretsError('unseal-failed')
        tag = blob[len(self.MAGIC):len(self.MAGIC) + 32]
        ciphertext = blob[len(self.MAGIC) + 32:]
        expect = hmac.new(key, b't1' + aad + ciphertext,
                          hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expect):
            raise secrets.SecretsError('unseal-failed')
        mask = self._stream(key, aad, len(ciphertext))
        return bytes(a ^ b for a, b in zip(ciphertext, mask))


class OtherSchemeSealer(ToySealer):
    scheme = 'other-scheme-v1'


class SecretsFixture(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        self.private = make_private_dir(self.root, 'private')
        self.key_path = write_private_file(
            os.path.join(self.private, 'key'), KEY)
        self.config = {'schemaVersion': 1, 'keyFile': self.key_path}
        self.sealer = ToySealer()
        self.source = make_private_dir(self.root, 'secret-source')
        write_private_file(os.path.join(self.source, 'api-token'),
                           SENTINEL)
        write_private_file(os.path.join(self.source, '.env'),
                           b'DB=nxs-sentinel-db-pass\n')
        self.bundle_file = os.path.join(self.private, 'bundle.bin')
        self.target = os.path.join(self.private, 'provisioned')

    def service(self, **kwargs):
        config = dict(self.config)
        config.update(kwargs.pop('config', {}))
        return secrets.SecretsService(
            config, sealer=kwargs.pop('sealer', self.sealer),
            clock=kwargs.pop('clock', lambda: 1700))

    def seal(self, **kwargs):
        return secrets.seal(kwargs.pop('source', self.source),
                            kwargs.pop('ref', 'demo-secrets'),
                            key=kwargs.pop('key', KEY),
                            sealer=kwargs.pop('sealer', self.sealer),
                            clock=kwargs.pop('clock', lambda: 1700))

    def sealed_pair(self, **kwargs):
        blob, envelope = self.seal(**kwargs)
        return envelope, blob

    def provision_args(self, **kwargs):
        envelope, blob = self.sealed_pair(**kwargs.pop('seal', {}))
        args = {'envelope': envelope, 'blob': blob,
                'target': os.path.join(self.private, 'target'),
                'key': KEY, 'sealer': self.sealer,
                'binding': secrets.manifest_binding(envelope)}
        args.update(kwargs)
        return args

    def expect_blocked(self, response, code):
        self.assertEqual(response['status'], 'blocked', response)
        self.assertEqual(response['error'], code, response)

    def assert_no_leak(self, *values):
        for value in values:
            if type(value) is bytes:
                self.assertNotIn(SENTINEL, value)
            else:
                self.assertNotIn(SENTINEL.decode(), str(value))


def envelope_record(**overrides):
    record = {'schemaVersion': 1, 'kind': 'workload-secret-bundle',
              'secretSetRef': 'demo-secrets',
              'versionDigest': 'sha256:' + 'a' * 64,
              'bundleDigest': 'sha256:' + 'b' * 64,
              'sealingScheme': 'test-only-v1', 'createdAt': 1700}
    record.update(overrides)
    return record


class EnvelopeTests(unittest.TestCase):

    def test_roundtrip(self):
        record = envelope_record()
        raw = secrets.encode_envelope(record)
        self.assertEqual(secrets.decode_envelope(raw), record)

    def test_field_set_strict(self):
        for bad in ('schemaVersion', 'kind', 'secretSetRef',
                    'versionDigest', 'bundleDigest', 'sealingScheme',
                    'createdAt'):
            value = envelope_record()
            del value[bad]
            with self.subTest(missing=bad), \
                    self.assertRaises(secrets.SecretsError) as ctx:
                secrets.validate_envelope(value)
            self.assertEqual(ctx.exception.code, 'invalid-envelope')
        for extra in ({'extra': 1}, {'files': []}, {'key': 'x'}):
            value = envelope_record(**extra)
            with self.subTest(extra=extra), \
                    self.assertRaises(secrets.SecretsError) as ctx:
                secrets.validate_envelope(value)
            self.assertEqual(ctx.exception.code, 'invalid-envelope')

    def test_field_values_strict(self):
        bads = [
            {'schemaVersion': 0}, {'schemaVersion': 2},
            {'schemaVersion': '1'}, {'schemaVersion': True},
            {'kind': 'secret-bundle'}, {'kind': 1},
            {'secretSetRef': 'Demo'}, {'secretSetRef': ''},
            {'secretSetRef': '-bad'}, {'secretSetRef': 5},
            {'versionDigest': 'a' * 64}, {'versionDigest': 'sha256:gg' + '0' * 62},
            {'versionDigest': 'sha256:' + 'a' * 63},
            {'bundleDigest': 'sha256:' + 'b' * 65},
            {'bundleDigest': 'sha1:' + 'b' * 40},
            {'sealingScheme': 'SCHEME'}, {'sealingScheme': ''},
            {'sealingScheme': 'has space'}, {'sealingScheme': None},
            {'createdAt': -1}, {'createdAt': 2**53 + 1},
            {'createdAt': '1700'}, {'createdAt': 17.5},
            {'createdAt': True},
        ]
        for overrides in bads:
            with self.subTest(overrides=overrides), \
                    self.assertRaises(secrets.SecretsError) as ctx:
                secrets.validate_envelope(envelope_record(**overrides))
            self.assertEqual(ctx.exception.code, 'invalid-envelope')

    def test_decode_rejects_noncanonical(self):
        record = envelope_record()
        pretty = json.dumps(record, indent=2).encode()
        with self.assertRaises(secrets.SecretsError) as ctx:
            secrets.decode_envelope(pretty)
        self.assertEqual(ctx.exception.code, 'invalid-envelope')

    def test_decode_rejects_duplicate_keys(self):
        raw = (b'{"schemaVersion":1,"schemaVersion":1,"kind":'
               b'"workload-secret-bundle","secretSetRef":"demo-secrets",'
               b'"versionDigest":"sha256:' + b'a' * 64 + b'",'
               b'"bundleDigest":"sha256:' + b'b' * 64 + b'",'
               b'"sealingScheme":"test-only-v1","createdAt":1700}')
        with self.assertRaises(secrets.SecretsError):
            secrets.decode_envelope(raw)

    def test_decode_rejects_garbage(self):
        for raw in (b'', b'null', b'[1]', b'{', b'"x"',
                    b'x' * (secrets._MAX_ENVELOPE_BYTES + 1),
                    '{"a":NaN}'.encode(), 'notbytes'):
            with self.subTest(raw=raw[:20] if isinstance(raw, bytes)
                              else raw), \
                    self.assertRaises(secrets.SecretsError):
                secrets.decode_envelope(raw)

    def test_manifest_binding_triple(self):
        binding = secrets.manifest_binding(envelope_record())
        self.assertEqual(set(binding),
                         {'secretSetRef', 'versionDigest',
                          'bundleDigest'})
        # The triple is exactly the recovery-manifest secretBundle
        # shape: extra or missing keys break it.
        for bad in ('secretSetRef', 'versionDigest', 'bundleDigest'):
            value = dict(binding)
            del value[bad]
            with self.assertRaises(secrets.SecretsError):
                secrets.validate_binding(value)
        with self.assertRaises(secrets.SecretsError):
            secrets.validate_binding(dict(binding, extra=1))
        with self.assertRaises(secrets.SecretsError):
            secrets.validate_binding(
                dict(binding, secretSetRef='BAD-REF'))

    def test_binding_slots_into_recovery_manifest(self):
        """The manifest's secretBundle is exactly the envelope triple:
        building a sealed recovery point around it must validate."""
        envelope = envelope_record(
            versionDigest='sha256:' + 'd' * 64,
            bundleDigest='sha256:' + 'e' * 64)
        binding = secrets.manifest_binding(envelope)
        definition = sealed(secretSetRef='demo-secrets')
        digests = {mount['id']: 'sha256:' + '%064x' % 1
                   for mount in definition['stateMounts']}
        manifest = recovery.build_manifest(
            definition,
            {'hostId': 'host-a', 'instanceId': 'ab' * 16,
             'generation': 1, 'uidBase': 65536},
            {'adapter': 'quiesce-v1', 'consistency': 'quiesced',
             'startedAt': 1000, 'completedAt': 1005},
            state_tree_digests=digests,
            state_set_digest='sha256:' + '5' * 64,
            secret_bundle=binding)
        self.assertEqual(manifest['secretBundle'], binding)
        # A mismatched secretSetRef is rejected by the manifest.
        wrong = dict(binding, secretSetRef='other-secrets')
        with self.assertRaises(recovery.RecoveryError):
            recovery.build_manifest(
                definition,
                {'hostId': 'host-a', 'instanceId': 'ab' * 16,
                 'generation': 1, 'uidBase': 65536},
                {'adapter': 'quiesce-v1', 'consistency': 'quiesced',
                 'startedAt': 1000, 'completedAt': 1005},
                state_tree_digests=digests,
                state_set_digest='sha256:' + '5' * 64,
                secret_bundle=wrong)


class SealTests(SecretsFixture):

    def test_seal_produces_bound_envelope(self):
        envelope, blob = self.sealed_pair()
        self.assertIsInstance(blob, bytes)
        self.assertEqual(envelope['bundleDigest'],
                         'sha256:' + hashlib.sha256(blob).hexdigest())
        self.assertEqual(envelope['sealingScheme'], 'test-only-v1')
        self.assertEqual(envelope['secretSetRef'], 'demo-secrets')
        self.assertEqual(envelope['createdAt'], 1700)
        secrets.validate_envelope(envelope)
        # The sealed bytes carry no plaintext sentinel.
        self.assert_no_leak(blob)

    def test_version_digest_binds_plaintext(self):
        envelope, blob = self.sealed_pair()
        payload = self.sealer.open(
            KEY, blob, secrets._aad(envelope))
        self.assertEqual(envelope['versionDigest'],
                         'sha256:' + hashlib.sha256(payload).hexdigest())
        # And the plaintext payload really is the secret-set
        # document (sentinel survives the round trip inside it).
        inner = secrets._decode_inner(payload)
        self.assertEqual(inner['files'],
                         [('.env', b'DB=nxs-sentinel-db-pass\n'),
                          ('api-token', SENTINEL)])

    def test_seal_refuses_without_sealer(self):
        with self.assertRaises(secrets.SecretsError) as ctx:
            self.seal(sealer=secrets.UnavailableSealer())
        self.assertEqual(ctx.exception.code, 'sealer-unavailable')

    def test_seal_refuses_bad_scheme(self):
        sealer = ToySealer()
        sealer.scheme = 'BAD'
        with self.assertRaises(secrets.SecretsError) as ctx:
            self.seal(sealer=sealer)
        self.assertEqual(ctx.exception.code, 'sealer-unavailable')
        sealer.scheme = None
        with self.assertRaises(secrets.SecretsError):
            self.seal(sealer=sealer)

    def test_seal_refuses_weak_key(self):
        for bad in (b'', b'k' * 31, 'k' * 32, b'k' * 5000, None):
            with self.subTest(key=type(bad)), \
                    self.assertRaises(secrets.SecretsError) as ctx:
                self.seal(key=bad)
            self.assertEqual(ctx.exception.code, 'key-invalid')

    def test_seal_clock_validation(self):
        for bad in (lambda: -1, lambda: 2**53 + 1, lambda: 'x',
                    lambda: float('nan'), lambda: float('inf'),
                    lambda: True, lambda: 1 / 0):
            with self.subTest(clock=bad), \
                    self.assertRaises(secrets.SecretsError) as ctx:
                self.seal(clock=bad)
            self.assertEqual(ctx.exception.code, 'clock-invalid')

    def test_seal_source_must_be_private(self):
        os.chmod(self.source, 0o755)
        with self.assertRaises(secrets.SecretsError) as ctx:
            self.seal()
        self.assertEqual(ctx.exception.code, 'path-unsafe')

    def test_seal_source_missing(self):
        with self.assertRaises(secrets.SecretsError) as ctx:
            self.seal(source=os.path.join(self.root, 'absent'))
        self.assertEqual(ctx.exception.code, 'path-unavailable')

    def test_seal_source_under_store_refused(self):
        with self.assertRaises(secrets.SecretsError) as ctx:
            self.seal(source='/nix/store/' + 'a' * 32 + '-x')
        self.assertIn(ctx.exception.code,
                      ('path-unsafe', 'path-unavailable'))

    def test_seal_rejects_unsafe_entries(self):
        # World/group-readable secret file.
        loose = os.path.join(self.source, 'api-token')
        os.chmod(loose, 0o644)
        with self.assertRaises(secrets.SecretsError) as ctx:
            self.seal()
        self.assertEqual(ctx.exception.code, 'path-unsafe')
        os.chmod(loose, 0o600)
        # A subdirectory is not a secret file.
        os.mkdir(os.path.join(self.source, 'nested'), 0o700)
        with self.assertRaises(secrets.SecretsError) as ctx:
            self.seal()
        self.assertEqual(ctx.exception.code, 'path-unsafe')
        os.rmdir(os.path.join(self.source, 'nested'))
        # A symlink is never followed.
        os.symlink('/etc/hostname',
                   os.path.join(self.source, 'linked'))
        with self.assertRaises(secrets.SecretsError) as ctx:
            self.seal()
        self.assertEqual(ctx.exception.code, 'path-unsafe')
        os.unlink(os.path.join(self.source, 'linked'))
        # Empty set seals nothing.
        empty = make_private_dir(self.root, 'empty-secrets')
        with self.assertRaises(secrets.SecretsError) as ctx:
            self.seal(source=empty)
        self.assertEqual(ctx.exception.code, 'invalid-secret-set')

    def test_seal_rejects_bad_names(self):
        # Names the safe-name regex rejects are refused, not escaped.
        for name in ('has space', 'under_score?',
                     'semi;colon', 'naïve'):
            write_private_file(os.path.join(self.source, name))
            with self.subTest(name=name), \
                    self.assertRaises(secrets.SecretsError) as ctx:
                self.seal()
            self.assertEqual(ctx.exception.code, 'invalid-secret-set')
            os.unlink(os.path.join(self.source, name))

    def test_seal_rejects_too_many_files(self):
        for index in range(70):
            write_private_file(
                os.path.join(self.source, 'f%02d' % index))
        with self.assertRaises(secrets.SecretsError) as ctx:
            self.seal()
        self.assertEqual(ctx.exception.code, 'invalid-secret-set')

    def test_seal_rejects_oversized_file(self):
        write_private_file(os.path.join(self.source, 'huge'),
                           b'x' * (secrets._MAX_FILE_BYTES + 1))
        with self.assertRaises(secrets.SecretsError) as ctx:
            self.seal()
        self.assertEqual(ctx.exception.code, 'invalid-secret-set')

    def test_sealer_exception_text_never_escapes(self):
        class LeakySealer(ToySealer):
            def seal(self, key, plaintext, aad):
                raise ValueError(plaintext.decode())

        with self.assertRaises(secrets.SecretsError) as ctx:
            self.seal(sealer=LeakySealer())
        self.assertEqual(ctx.exception.code, 'sealer-failed')
        self.assert_no_leak(str(ctx.exception),
                            repr(ctx.exception.__context__))


class VerifyTests(SecretsFixture):

    def test_verify_ok(self):
        envelope, blob = self.sealed_pair()
        self.assertEqual(secrets.verify(envelope, blob), envelope)

    def test_verify_digest_mismatch(self):
        envelope, blob = self.sealed_pair()
        bad = bytearray(blob)
        bad[-1] ^= 0x01
        with self.assertRaises(secrets.SecretsError) as ctx:
            secrets.verify(envelope, bytes(bad))
        self.assertEqual(ctx.exception.code, 'bundle-digest-mismatch')

    def test_verify_rejects_malformed(self):
        envelope, blob = self.sealed_pair()
        with self.assertRaises(secrets.SecretsError):
            secrets.verify(envelope_record(kind='nope'), blob)
        for blob in (b'', 'text', None,
                     b'x' * (secrets._MAX_BLOB_BYTES + 1)):
            with self.assertRaises(secrets.SecretsError):
                secrets.verify(envelope, blob)


class ProvisionTests(SecretsFixture):

    def provision(self, **kwargs):
        args = self.provision_args(**kwargs)
        return secrets.provision(
            args['envelope'], args['blob'], args['target'],
            key=args['key'], sealer=args['sealer'],
            binding=args['binding'])

    def test_provision_restores_exact_files(self):
        record = self.provision()
        target = self.provision_args()['target']
        st = os.lstat(target)
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o700)
        self.assertEqual(st.st_uid, os.geteuid())
        for name, expected in (('api-token', SENTINEL),
                               ('.env', b'DB=nxs-sentinel-db-pass\n')):
            path = os.path.join(target, name)
            fst = os.lstat(path)
            self.assertEqual(stat.S_IMODE(fst.st_mode), 0o600)
            self.assertEqual(fst.st_uid, os.geteuid())
            with open(path, 'rb') as handle:
                self.assertEqual(handle.read(), expected)
        self.assertEqual(record['fileCount'], 2)
        # Response carries metadata only — never names or contents.
        self.assert_no_leak(json.dumps(record),
                            json.dumps(sorted(record)))

    def test_provision_into_existing_private_empty_dir(self):
        target = make_private_dir(self.private, 'pre-made')
        record = self.provision(target=target)
        self.assertEqual(record['fileCount'], 2)

    def test_provision_rejects_unsafe_targets(self):
        # Existing non-private modes are refused, never repaired.
        # (chmod after mkdir: mkdir honors the process umask.)
        for mode in (0o755, 0o770, 0o711, 0o700 | 0o040):
            target = make_private_dir(self.root, 't%o' % mode)
            os.chmod(target, mode)
            with self.subTest(mode=oct(mode)), \
                    self.assertRaises(secrets.SecretsError) as ctx:
                self.provision(target=target)
            self.assertEqual(ctx.exception.code, 'path-unsafe')
            self.assertEqual(stat.S_IMODE(os.lstat(target).st_mode),
                             mode)
        # A regular file at the target is never replaced.
        file_target = write_private_file(
            os.path.join(self.private, 'afile'))
        with self.assertRaises(secrets.SecretsError) as ctx:
            self.provision(target=file_target)
        self.assertEqual(ctx.exception.code, 'path-unsafe')
        # A symlink target is never followed.
        link = os.path.join(self.private, 'link')
        os.symlink(self.private, link)
        with self.assertRaises(secrets.SecretsError) as ctx:
            self.provision(target=link)
        self.assertEqual(ctx.exception.code, 'path-unsafe')
        # Non-empty dir refuses the merge.
        busy = make_private_dir(self.private, 'busy')
        write_private_file(os.path.join(busy, 'old'))
        with self.assertRaises(secrets.SecretsError) as ctx:
            self.provision(target=busy)
        self.assertEqual(ctx.exception.code, 'target-not-empty')
        # Unsafe ancestor (world-writable non-root).
        open_parent = os.path.join(self.root, 'open')
        os.mkdir(open_parent)
        os.chmod(open_parent, 0o777)
        with self.assertRaises(secrets.SecretsError) as ctx:
            self.provision(target=os.path.join(open_parent, 'x'))
        self.assertEqual(ctx.exception.code, 'path-unsafe')
        # The Nix store is never written to.
        with self.assertRaises(secrets.SecretsError) as ctx:
            self.provision(target='/nix/store/' + 'a' * 32 + '-x/s')
        self.assertEqual(ctx.exception.code, 'path-unsafe')
        with self.assertRaises(secrets.SecretsError) as ctx:
            self.provision(target='/nix/store/x')
        self.assertEqual(ctx.exception.code, 'path-unsafe')

    def test_provision_rejects_bad_target_paths(self):
        for target in ('relative/dir', '/tmp//x', '/tmp/x/',
                       '/tmp/x/../y', ''):
            with self.subTest(target=target), \
                    self.assertRaises(secrets.SecretsError) as ctx:
                self.provision(target=target)
            self.assertEqual(ctx.exception.code, 'invalid-request')

    def test_provision_replay_refuses_occupied_target(self):
        args = self.provision_args()
        secrets.provision(args['envelope'], args['blob'],
                          args['target'], key=args['key'],
                          sealer=args['sealer'], binding=args['binding'])
        # Replaying into the now-occupied dir fails closed; a fresh
        # target replays cleanly.
        with self.assertRaises(secrets.SecretsError) as ctx:
            secrets.provision(
                args['envelope'], args['blob'], args['target'],
                key=args['key'], sealer=args['sealer'],
                binding=args['binding'])
        self.assertEqual(ctx.exception.code, 'target-not-empty')
        second = os.path.join(self.private, 'second')
        record = secrets.provision(
            args['envelope'], args['blob'], second,
            key=args['key'], sealer=args['sealer'],
            binding=args['binding'])
        self.assertEqual(record['fileCount'], 2)

    def test_provision_binding_must_match(self):
        base = secrets.manifest_binding(self.sealed_pair()[0])
        for field in ('secretSetRef', 'versionDigest', 'bundleDigest'):
            binding = dict(base)
            if field == 'secretSetRef':
                binding[field] = 'other-secrets'
            else:
                binding[field] = 'sha256:' + '0' * 64
            with self.subTest(field=field), \
                    self.assertRaises(secrets.SecretsError) as ctx:
                self.provision(binding=binding)
            self.assertEqual(ctx.exception.code,
                             'bundle-binding-mismatch')
        # Malformed bindings are rejected before comparison.
        for binding in ({}, {'secretSetRef': 'x'}, 'x', 5,
                        dict(base, extra=1),
                        dict(base, bundleDigest='nothex')):
            with self.subTest(binding=binding), \
                    self.assertRaises(secrets.SecretsError) as ctx:
                self.provision(binding=binding)
            self.assertIn(ctx.exception.code,
                          ('invalid-binding', 'invalid-request'))
        # No binding supplied means no manifest linkage was claimed.
        record = self.provision(binding=None)
        self.assertEqual(record['fileCount'], 2)

    def test_provision_wrong_key_and_tamper(self):
        args = self.provision_args()
        with self.assertRaises(secrets.SecretsError) as ctx:
            secrets.provision(args['envelope'], args['blob'],
                              args['target'], key=WRONG_KEY,
                              sealer=args['sealer'],
                              binding=args['binding'])
        self.assertEqual(ctx.exception.code, 'unseal-failed')
        tampered = bytearray(args['blob'])
        tampered[-1] ^= 0x01
        with self.assertRaises(secrets.SecretsError) as ctx:
            secrets.provision(args['envelope'], bytes(tampered),
                              args['target'], key=args['key'],
                              sealer=args['sealer'],
                              binding=args['binding'])
        self.assertEqual(ctx.exception.code,
                         'bundle-digest-mismatch')
        # Tamper under the recorded digest: rebind the envelope to
        # the tampered blob so the AEAD open itself must catch it.
        envelope = dict(args['envelope'])
        envelope['bundleDigest'] = 'sha256:' + hashlib.sha256(
            bytes(tampered)).hexdigest()
        with self.assertRaises(secrets.SecretsError) as ctx:
            secrets.provision(envelope, bytes(tampered),
                              args['target'], key=args['key'],
                              sealer=args['sealer'], binding=None)
        self.assertEqual(ctx.exception.code, 'unseal-failed')
        # Nothing was provisioned on any failure path.
        self.assertFalse(os.path.exists(args['target']))

    def test_provision_rejects_foreign_scheme(self):
        args = self.provision_args()
        for sealer in (secrets.UnavailableSealer(),
                       OtherSchemeSealer()):
            with self.subTest(sealer=sealer.scheme), \
                    self.assertRaises(secrets.SecretsError) as ctx:
                secrets.provision(
                    args['envelope'], args['blob'], args['target'],
                    key=args['key'], sealer=sealer,
                    binding=args['binding'])
            self.assertIn(ctx.exception.code,
                          ('sealer-unavailable',
                           'sealing-scheme-unknown'))

    def test_provision_rebound_envelope_fails(self):
        """A blob sealed for one envelope cannot satisfy another."""
        args = self.provision_args()
        envelope, blob = self.sealed_pair(ref='demo-secrets')
        # A bundle sealed for a different secretSetRef is a different
        # blob: cross-pair verify fails on the digest alone.
        other = self.sealed_pair(ref='other-secrets')
        with self.assertRaises(secrets.SecretsError) as ctx:
            secrets.verify(other[0], blob)
        self.assertEqual(ctx.exception.code, 'bundle-digest-mismatch')
        # Forged envelope carrying the real digest but a different
        # secretSetRef dies at the AAD/inner-binding check.
        forged = dict(envelope)
        forged['secretSetRef'] = 'other-secrets'
        with self.assertRaises(secrets.SecretsError) as ctx:
            secrets.provision(forged, blob, args['target'],
                              key=args['key'], sealer=args['sealer'],
                              binding=None)
        self.assertEqual(ctx.exception.code, 'unseal-failed')
        self.assertFalse(os.path.exists(args['target']))

    def _craft(self, inner_value_or_raw, **envelope_overrides):
        """Hand-build a blob+envelope around arbitrary plaintext so
        inner-decode defenses are exercised under a valid tag."""
        if type(inner_value_or_raw) is bytes:
            raw = inner_value_or_raw
        else:
            raw = artifacts.canonical_bytes(inner_value_or_raw)
        ref = 'demo-secrets'
        scheme = 'test-only-v1'
        version = 'sha256:' + hashlib.sha256(raw).hexdigest()
        aad = artifacts.canonical_bytes({
            'kind': secrets._KIND, 'secretSetRef': ref,
            'sealingScheme': scheme, 'versionDigest': version})
        blob = self.sealer.seal(KEY, raw, aad)
        envelope = {'schemaVersion': 1, 'kind': secrets._KIND,
                    'secretSetRef': ref, 'versionDigest': version,
                    'bundleDigest': 'sha256:'
                    + hashlib.sha256(blob).hexdigest(),
                    'sealingScheme': scheme, 'createdAt': 1700}
        envelope.update(envelope_overrides)
        return envelope, blob

    def test_provision_inner_decode_attacks(self):
        target = os.path.join(self.private, 'craft')
        good_files = [{'name': 'api-token',
                       'data': base64.b64encode(SENTINEL).decode()}]
        inner = {'schemaVersion': 1, 'kind': 'workload-secret-set',
                 'secretSetRef': 'demo-secrets', 'files': good_files}
        bads = [
            b'not json',
            b'{"schemaVersion":1}',
            dict(inner, schemaVersion=2),
            dict(inner, kind='secret-set'),
            dict(inner, secretSetRef='BAD'),
            dict(inner, files=[]),
            dict(inner, extra=1),
            dict(inner, files=[{'name': 'a',
                              'data': '!!!notb64'}]),
            dict(inner, files=[{'name': '../up',
                              'data': 'eA=='}]),
            dict(inner, files=[{'name': 'a b',
                              'data': 'eA=='}]),
            dict(inner, files=[{'name': 'x', 'data': 'eA==',
                                'x': 1}]),
            dict(inner, files=[{'name': 'x'},
                               {'name': 'x', 'data': 'eA=='},
                               {'name': 'x', 'data': 'eA=='}]),
        ]
        # Duplicate names are rejected (dict construction can't make
        # duplicates, build the list directly).
        dup = dict(inner)
        dup['files'] = [{'name': 'x', 'data': 'eA=='},
                        {'name': 'x', 'data': 'eA=='}]
        bads.append(dup)
        for index, inner_value in enumerate(bads):
            envelope, blob = self._craft(inner_value)
            with self.subTest(index=index), \
                    self.assertRaises(secrets.SecretsError) as ctx:
                secrets.provision(envelope, blob,
                                  '%s-%d' % (target, index),
                                  key=KEY, sealer=self.sealer,
                                  binding=None)
            self.assertEqual(ctx.exception.code, 'unseal-failed')
            self.assertFalse(
                os.path.exists('%s-%d' % (target, index)))

    def test_provision_inner_secret_set_ref_mismatch(self):
        # A correctly sealed payload for a DIFFERENT secretSetRef is
        # still rejected against this envelope's binding.
        inner = {'schemaVersion': 1, 'kind': 'workload-secret-set',
                 'secretSetRef': 'other-secrets',
                 'files': [{'name': 'a',
                            'data': base64.b64encode(b'v').decode()}]}
        raw = artifacts.canonical_bytes(inner)
        ref = 'demo-secrets'
        scheme = 'test-only-v1'
        version = 'sha256:' + hashlib.sha256(raw).hexdigest()
        aad = artifacts.canonical_bytes({
            'kind': secrets._KIND, 'secretSetRef': ref,
            'sealingScheme': scheme, 'versionDigest': version})
        blob = self.sealer.seal(KEY, raw, aad)
        envelope = {'schemaVersion': 1, 'kind': secrets._KIND,
                    'secretSetRef': ref, 'versionDigest': version,
                    'bundleDigest': 'sha256:'
                    + hashlib.sha256(blob).hexdigest(),
                    'sealingScheme': scheme, 'createdAt': 1700}
        target = os.path.join(self.private, 'mismatched')
        with self.assertRaises(secrets.SecretsError) as ctx:
            secrets.provision(envelope, blob, target, key=KEY,
                              sealer=self.sealer, binding=None)
        self.assertEqual(ctx.exception.code, 'unseal-failed')
        self.assertFalse(os.path.exists(target))


class ConfigTests(SecretsFixture):

    def test_config_shape(self):
        for config in ({}, {'schemaVersion': 1},
                       {'schemaVersion': 2, 'keyFile': None},
                       {'schemaVersion': '1', 'keyFile': None},
                       {'schemaVersion': 1, 'keyFile': 'rel/path'},
                       {'schemaVersion': 1, 'keyFile': None,
                        'extra': 1}):
            with self.subTest(config=config), \
                    self.assertRaises(secrets.SecretsError) as ctx:
                secrets.SecretsService(config)
            self.assertEqual(ctx.exception.code, 'invalid-config')
        # keyFile may be null (verify/inspect-only hosts).
        secrets.SecretsService({'schemaVersion': 1, 'keyFile': None})

    def test_config_file_must_be_root_owned(self):
        config_path = write_private_file(
            os.path.join(self.private, 'cfg.json'),
            artifacts.canonical_bytes(self.config))
        # Unrooted test environment: a uid-1000-owned file is not the
        # root-owned config the contract pins.
        with self.assertRaises(secrets.SecretsError) as ctx:
            secrets._check_config_path(config_path)
        self.assertEqual(ctx.exception.code, 'path-unsafe')
        with self.assertRaises(secrets.SecretsError) as ctx:
            secrets._read_config_file(config_path)
        self.assertEqual(ctx.exception.code, 'path-unsafe')

    def _as_root(self):
        """Stat wrappers reporting uid 0 with the real mode/inode —
        lets the root-owned-config contract run under an unrooted
        suite."""
        real_lstat = os.lstat
        real_fstat = os.fstat

        def lstat(path):
            st = real_lstat(path)
            return SimpleNamespace(st_mode=st.st_mode, st_uid=0,
                                   st_ino=st.st_ino, st_dev=st.st_dev)

        def fstat(fd):
            st = real_fstat(fd)
            return SimpleNamespace(st_mode=st.st_mode, st_uid=0,
                                   st_ino=st.st_ino, st_dev=st.st_dev)

        return mock.patch.object(secrets, '_lstat', lstat), \
            mock.patch.object(secrets, '_fstat', fstat)

    def test_config_read_rejects_oversized_and_symlink(self):
        big = write_private_file(
            os.path.join(self.private, 'big.json'),
            b' ' * (secrets._MAX_CONFIG_BYTES + 1))
        lstat_mock, fstat_mock = self._as_root()
        with lstat_mock, fstat_mock:
            with self.assertRaises(secrets.SecretsError) as ctx:
                secrets._read_config_file(big)
            self.assertEqual(ctx.exception.code, 'invalid-config')
            # A root-owned symlink config is refused outright.
            link = os.path.join(self.private, 'link.json')
            os.symlink(big, link)
            with self.assertRaises(secrets.SecretsError) as ctx:
                secrets._read_config_file(link)
            self.assertEqual(ctx.exception.code, 'path-unsafe')
            # A well-formed root-owned config reads cleanly.
            good = write_private_file(
                os.path.join(self.private, 'cfg.json'),
                artifacts.canonical_bytes(self.config))
            self.assertEqual(secrets._read_config_file(good),
                             artifacts.canonical_bytes(self.config))

    def test_key_file_rules(self):
        # Missing file.
        missing = os.path.join(self.private, 'absent-key')
        with self.assertRaises(secrets.SecretsError) as ctx:
            secrets._read_key_file(missing)
        self.assertEqual(ctx.exception.code, 'key-missing')
        # Wrong mode is never silently repaired.
        loose = write_private_file(
            os.path.join(self.private, 'loose-key'), KEY, mode=0o640)
        with self.assertRaises(secrets.SecretsError) as ctx:
            secrets._read_key_file(loose)
        self.assertEqual(ctx.exception.code, 'path-unsafe')
        # Short / oversized material.
        short = write_private_file(
            os.path.join(self.private, 'short-key'), b'x' * 10)
        with self.assertRaises(secrets.SecretsError) as ctx:
            secrets._read_key_file(short)
        self.assertEqual(ctx.exception.code, 'key-invalid')
        # Happy path.
        self.assertEqual(secrets._read_key_file(self.key_path), KEY)
        # A null keyFile means keyless service: verify/inspect still
        # work while seal/provision refuse.
        service = self.service(config={'keyFile': None})
        envelope, blob = self.sealed_pair()
        response = service.execute(
            {'schemaVersion': 1, 'action': 'inspect',
             'envelope': envelope})
        self.assertEqual(response['status'], 'completed')
        response = service.execute(
            {'schemaVersion': 1, 'action': 'seal',
             'secretSetRef': 'demo-secrets', 'sourceDir': self.source,
             'bundleFile': self.bundle_file})
        self.expect_blocked(response, 'key-unavailable')


class ExecuteTests(SecretsFixture):

    def request(self, **overrides):
        envelope, blob = self.sealed_pair()
        write_private_file(self.bundle_file, blob)
        req = {'schemaVersion': 1, 'action': 'provision',
               'envelope': envelope, 'bundleFile': self.bundle_file,
               'targetDir': os.path.join(self.private, 'cli-target'),
               'binding': secrets.manifest_binding(envelope)}
        req.update(overrides)
        return req

    def test_request_envelope_and_shape(self):
        service = self.service()
        for bad in (None, [], 'x', {'action': 'seal'},
                    {'schemaVersion': '1', 'action': 'seal'},
                    {'schemaVersion': 1, 'action': 'unknown'},
                    {'schemaVersion': 1, 'action': 'seal',
                     'secretSetRef': 'demo-secrets',
                     'sourceDir': self.source}):
            with self.subTest(bad=bad):
                self.expect_blocked(service.execute(bad),
                                    'invalid-request')

    def test_seal_verb_writes_blob(self):
        service = self.service()
        response = service.execute(
            {'schemaVersion': 1, 'action': 'seal',
             'secretSetRef': 'demo-secrets', 'sourceDir': self.source,
             'bundleFile': self.bundle_file})
        self.assertEqual(response['status'], 'completed', response)
        envelope = response['envelope']
        with open(self.bundle_file, 'rb') as handle:
            blob = handle.read()
        self.assertEqual(envelope['bundleDigest'],
                         'sha256:' + hashlib.sha256(blob).hexdigest())
        self.assertEqual(
            stat.S_IMODE(os.lstat(self.bundle_file).st_mode), 0o600)
        self.assert_no_leak(blob, json.dumps(response))
        # Replay against the occupied bundle file fails closed.
        replay = service.execute(
            {'schemaVersion': 1, 'action': 'seal',
             'secretSetRef': 'demo-secrets', 'sourceDir': self.source,
             'bundleFile': self.bundle_file})
        self.expect_blocked(replay, 'path-unsafe')

    def test_seal_verb_rejects_bundle_inside_source(self):
        service = self.service()
        response = service.execute(
            {'schemaVersion': 1, 'action': 'seal',
             'secretSetRef': 'demo-secrets', 'sourceDir': self.source,
             'bundleFile': os.path.join(self.source, 'bundle.bin')})
        self.expect_blocked(response, 'invalid-request')

    def test_verify_and_inspect_verbs(self):
        envelope, blob = self.sealed_pair()
        write_private_file(self.bundle_file, blob)
        service = self.service()
        response = service.execute(
            {'schemaVersion': 1, 'action': 'verify',
             'envelope': envelope, 'bundleFile': self.bundle_file})
        self.assertEqual(response['status'], 'completed', response)
        self.assertEqual(response['envelope'], envelope)
        response = service.execute(
            {'schemaVersion': 1, 'action': 'inspect',
             'envelope': envelope})
        self.assertEqual(response['status'], 'completed', response)
        response = service.execute(
            {'schemaVersion': 1, 'action': 'inspect',
             'envelope': envelope, 'bundleFile': self.bundle_file})
        self.assertEqual(response['status'], 'completed', response)
        self.assertTrue(response['digestMatches'])
        self.assertEqual(response['bundleBytes'], len(blob))
        # Metadata only: nothing in the response carries contents.
        self.assert_no_leak(json.dumps(response))
        # Tampered blob: verify refuses, inspect still validates the
        # envelope itself but reports the mismatch as blocked.
        write_private_file(
            os.path.join(self.private, 'bad.bin'), blob + b'x')
        response = service.execute(
            {'schemaVersion': 1, 'action': 'verify',
             'envelope': envelope,
             'bundleFile': os.path.join(self.private, 'bad.bin')})
        self.expect_blocked(response, 'bundle-digest-mismatch')

    def test_provision_verb(self):
        service = self.service()
        response = service.execute(self.request())
        self.assertEqual(response['status'], 'completed', response)
        self.assertEqual(response['fileCount'], 2)
        self.assertEqual(
            set(response),
            {'schemaVersion', 'status', 'action', 'secretSetRef',
             'versionDigest', 'bundleDigest', 'fileCount'})
        self.assert_no_leak(json.dumps(response))
        with open(os.path.join(self.private, 'cli-target',
                               'api-token'), 'rb') as handle:
            self.assertEqual(handle.read(), SENTINEL)

    def test_provision_verb_binding_required_field(self):
        request = self.request()
        del request['binding']
        self.expect_blocked(self.service().execute(request),
                            'invalid-request')
        request = self.request(binding='notadict')
        self.expect_blocked(self.service().execute(request),
                            'invalid-request')

    def test_unavailable_sealer_blocks_end_to_end(self):
        service = self.service(sealer=secrets.UnavailableSealer())
        seal_target = os.path.join(self.private, 'unsealed.bin')
        for request in (
                {'schemaVersion': 1, 'action': 'seal',
                 'secretSetRef': 'demo-secrets',
                 'sourceDir': self.source,
                 'bundleFile': seal_target},
                self.request()):
            response = service.execute(request)
            self.assertEqual(response['error'],
                             'sealer-unavailable', response)
        # The refused seal wrote nothing.
        self.assertFalse(os.path.exists(seal_target))

    def test_internal_error_never_leaks(self):
        class OddSealer(ToySealer):
            def seal(self, key, plaintext, aad):
                raise RuntimeError(plaintext.decode())

        service = self.service(sealer=OddSealer())
        response = service.execute(
            {'schemaVersion': 1, 'action': 'seal',
             'secretSetRef': 'demo-secrets', 'sourceDir': self.source,
             'bundleFile': self.bundle_file})
        self.expect_blocked(response, 'sealer-failed')
        self.assert_no_leak(json.dumps(response))


class CliTests(SecretsFixture):

    def _run_main(self, stdin_raw, config):
        """Exercise main() end to end with the root/config-file gates
        stubbed: the suite runs unrooted, so the root-owned-config
        read is replaced by its byte payload (covered separately in
        ConfigTests) and euid is patched to 0 for the gate only —
        every fs-touching path still sees real ownership, so verbs
        that read key/source files are exercised through
        SecretsService.execute instead."""
        out = io.StringIO()
        with mock.patch('os.geteuid', return_value=0), \
                mock.patch.object(
                    secrets, '_read_config_file',
                    return_value=artifacts.canonical_bytes(config)):
            rc = secrets.main(
                ['--config', '/etc/nexus-secrets.json', 'inspect'],
                sealer=self.sealer, stdin=io.BytesIO(stdin_raw),
                stdout=out)
        return rc, out.getvalue()

    def test_requires_root(self):
        # Unrooted test environment — the real euid is not 0.
        if os.geteuid() == 0:
            self.skipTest('requires an unprivileged euid')
        out = io.StringIO()
        rc = secrets.main(['--config', '/x', 'inspect'],
                          stdin=io.BytesIO(b'{}'), stdout=out)
        self.assertEqual(rc, 1)
        response = json.loads(out.getvalue())
        self.assertEqual(response['error'], 'requires-root')

    def test_request_bounds_and_json(self):
        for stdin_raw, code in (
                (b' ' * (secrets._MAX_REQUEST_BYTES + 1),
                 'request-too-large'),
                (b'{bad json', 'invalid-json'),
                (b'{"schemaVersion":1,"action":"bogus"}',
                 'invalid-request'),
                (b'[1,2]', 'invalid-request')):
            rc, raw = self._run_main(stdin_raw, self.config)
            self.assertEqual(rc, 1)
            self.assertEqual(json.loads(raw)['error'], code)

    def test_inspect_verb_over_cli(self):
        envelope, blob = self.sealed_pair()
        request = {'schemaVersion': 1, 'action': 'inspect',
                   'envelope': envelope}
        rc, raw = self._run_main(json.dumps(request).encode(),
                                 self.config)
        self.assertEqual(rc, 0)
        response = json.loads(raw)
        self.assertEqual(response['status'], 'completed')
        self.assertEqual(response['envelope'], envelope)
        self.assert_no_leak(raw)

    def test_invalid_config_response(self):
        rc, raw = self._run_main(b'{}', {'schemaVersion': 9})
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(raw)['error'], 'invalid-config')


class StdlibShadowTests(unittest.TestCase):
    """This module's name shadows stdlib ``secrets`` for sibling
    console modules; the delegation must preserve their API."""

    def test_stdlib_functions_delegate(self):
        self.assertEqual(len(secrets.token_hex(16)), 32)
        self.assertTrue(secrets.token_urlsafe(24))
        self.assertTrue(secrets.compare_digest(b'a', b'a'))
        self.assertFalse(secrets.compare_digest(b'a', b'b'))
        self.assertEqual(len(secrets.token_bytes(4)), 4)
        self.assertIsInstance(secrets.randbelow(10), int)
        self.assertTrue(secrets.SystemRandom is not None)
        self.assertEqual(secrets.DEFAULT_ENTROPY, 32)


if __name__ == '__main__':
    unittest.main()
