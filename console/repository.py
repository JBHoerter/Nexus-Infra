"""Verified restic repository adapter (trusted-caller library).

Stores and inspects durable recovery points in a pinned restic
repository over a local or SFTP transport. A point is a restic
snapshot whose root tree contains exactly ``state`` and
``manifest.json``: the manifest is a sealed recovery manifest
(console/recovery.py) and the state subtree roots are the declared
state mounts keyed by id, each bound to its restic native tree id
(SHA256 of the raw decrypted tree-blob bytes).

This module is deliberately narrow: it never initializes, forgets,
prunes, unlocks or deletes anything; snapshots are selected by full
hex id, never ``latest``. It performs no workload stop, no barrier
acquisition, no application-consistency or fencing claim, and no
availability/recoverability assertion: the caller supplies an
already-quiesced private staging directory and receives back an
identity record only. ``restore`` performs an isolated verified
extraction into a fresh directory with original numeric UIDs; it is
not installation into a worker instance, ownership remapping,
readiness or fencing. A ``local`` transport asserts nothing about
off-host protection.

All external file and repository conditions are reported as
RepositoryError with a machine-readable ``code``; process stdout,
stderr and secret material are never copied into error text.
"""

import copy
import hashlib
import ipaddress
import json
import os
import re
import selectors
import shlex
import signal
import stat
import subprocess
import time

import catalog
import recovery
import statefiles
import worker


class RepositoryError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


_SCHEMA_VERSION = 1
_FINAL_TAG = 'nexus-recovery-v2'
_DRAFT_TAG = 'nexus-capture-v1'
_MANIFEST_NAME = 'manifest.json'
_STATE_NAME = 'state'
_CONFIG_MAX = 16 * 1024
_MANIFEST_MAX = 2 * 1024 * 1024
_METADATA_MAX = 32 * 1024 * 1024
_STDERR_MAX = 64 * 1024
_METADATA_TIMEOUT = 60
_BULK_TIMEOUT = 3600
_MAX_SNAPSHOTS = 10000
_MAX_TREE_NODES = 4096
_HEX64_RE = re.compile(r'[0-9a-f]{64}')
_HEX32_RE = re.compile(r'[0-9a-f]{32}')
_HOST_LABEL = r'[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
_HOST_RE = re.compile(
    r'({label})(\.{label})*$'.format(label=_HOST_LABEL))
_NODE_NAME_RE = re.compile(r'[^/]+')
_RC_CODES = {3: 'capture-incomplete', 10: 'repository-missing',
             11: 'repository-locked', 12: 'repository-key-unavailable'}


def _lstat(path):
    return os.lstat(path)


def _hex64(value, context):
    if type(value) is not str or _HEX64_RE.fullmatch(value) is None:
        raise RepositoryError('invalid-' + context)


def _subprocess_env():
    # Explicit minimal environment: no inherited RESTIC_*, SSH agent,
    # proxy or password-command overrides can reach the child.
    return {'PATH': os.environ.get('PATH', os.defpath),
            'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}


def _reject_constant(value):
    raise RepositoryError('repository-output-invalid')


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RepositoryError('repository-output-invalid')
        result[key] = value
    return result


def _load_json(raw):
    if type(raw) is bytes:
        try:
            raw = raw.decode('utf-8')
        except UnicodeDecodeError:
            raise RepositoryError('repository-output-invalid') from None
    try:
        return json.loads(raw, parse_constant=_reject_constant,
                          object_pairs_hook=_no_duplicate_keys)
    except RepositoryError:
        raise
    except (json.JSONDecodeError, RecursionError, ValueError):
        raise RepositoryError('repository-output-invalid') from None


def _json_dict(raw):
    value = _load_json(raw)
    if type(value) is not dict:
        raise RepositoryError('repository-output-invalid')
    return value


def _host(value):
    if type(value) is not str or len(value) > 253:
        raise RepositoryError('invalid-config')
    # All-numeric hosts must be a canonical IPv4 address; anything
    # else must be a bounded DNS name. Forms like '010.0.0.1' or
    # '999.1.1.1' are neither and are rejected outright.
    if all(char in '0123456789.' for char in value):
        try:
            address = ipaddress.IPv4Address(value)
        except ValueError:
            raise RepositoryError('invalid-config') from None
        if str(address) != value:
            raise RepositoryError('invalid-config')
        return
    if _HOST_RE.fullmatch(value) is None:
        raise RepositoryError('invalid-config')


def _config_path(value, context):
    try:
        worker._path(value, context)
    except worker.WorkerError:
        raise RepositoryError('invalid-config') from None


def _check_private_file(path, missing_code):
    try:
        statefiles.check_private_dir(os.path.dirname(path))
        present = statefiles.check_private_file(path)
    except FileNotFoundError:
        raise RepositoryError(missing_code) from None
    except statefiles.PathError as error:
        raise RepositoryError(error.code) from None
    except OSError:
        raise RepositoryError('path-unavailable') from None
    if not present:
        raise RepositoryError(missing_code)


def _check_private_dir(path, missing_code):
    try:
        statefiles.check_private_dir(path)
    except FileNotFoundError:
        raise RepositoryError(missing_code) from None
    except statefiles.PathError as error:
        raise RepositoryError(error.code) from None
    except OSError:
        raise RepositoryError('path-unavailable') from None


def _validate_config(config):
    try:
        catalog.fields(config, ('schemaVersion', 'id',
                                'repositoryIdentity', 'passwordFile',
                                'transport'), 'repository config')
    except catalog.CatalogError:
        raise RepositoryError('invalid-config-fields') from None
    if type(config['schemaVersion']) is not int \
            or config['schemaVersion'] != _SCHEMA_VERSION:
        raise RepositoryError('invalid-config')
    try:
        catalog.identifier(config['id'], 'repository id')
    except catalog.CatalogError:
        raise RepositoryError('invalid-config') from None
    _hex64(config['repositoryIdentity'], 'config')
    _config_path(config['passwordFile'], 'config')
    transport = config['transport']
    if type(transport) is not dict:
        raise RepositoryError('invalid-config')
    kind = transport.get('kind')
    if kind == 'local':
        if set(transport) != {'kind', 'path'}:
            raise RepositoryError('invalid-config-fields')
        _config_path(transport['path'], 'config')
    elif kind == 'sftp':
        if set(transport) != {'kind', 'host', 'port', 'user', 'path',
                              'identityFile', 'knownHostsFile'}:
            raise RepositoryError('invalid-config-fields')
        _host(transport['host'])
        try:
            catalog.identifier(transport['user'], 'sftp user')
        except catalog.CatalogError:
            raise RepositoryError('invalid-config') from None
        if type(transport['port']) is not int \
                or not 1 <= transport['port'] <= 65535:
            raise RepositoryError('invalid-config')
        _config_path(transport['path'], 'config')
        _config_path(transport['identityFile'], 'config')
        _config_path(transport['knownHostsFile'], 'config')
    else:
        raise RepositoryError('invalid-config')
    # The adapter retains its own approved copy: later mutation of the
    # caller's dict cannot rewrite argv, paths or the expected id.
    return copy.deepcopy(config)


class BoundedRunner:
    """Bounded fixed-environment subprocess runner.

    Runs argv without a shell in its own session/process group with a
    fixed environment, a monotonic deadline and byte caps on both
    output streams. Any limit breach kills and reaps the whole process
    group (including an ssh child spawned by restic) and raises a
    typed RepositoryError; command output never reaches error text.
    """

    def __init__(self, env=None):
        self.env = dict(_subprocess_env() if env is None else env)

    def _reap(self, proc):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            pass
        for stream in (proc.stdout, proc.stderr):
            try:
                stream.close()
            except OSError:
                pass

    def run(self, argv, *, cwd=None, max_bytes=_METADATA_MAX,
            timeout=_METADATA_TIMEOUT):
        try:
            proc = subprocess.Popen(
                argv, shell=False, cwd=cwd, env=self.env,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True)
        except OSError:
            raise RepositoryError('repository-command-failed') from None
        deadline = time.monotonic() + timeout
        completed = None
        selector = None
        try:
            selector = selectors.DefaultSelector()
            streams = {}
            selector.register(proc.stdout, selectors.EVENT_READ,
                              ('out', bytearray(), max_bytes))
            selector.register(proc.stderr, selectors.EVENT_READ,
                              ('err', bytearray(), _STDERR_MAX))
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RepositoryError('repository-timeout')
                events = selector.select(min(remaining, 1.0))
                for key, _mask in events:
                    which, buffer, cap = key.data
                    try:
                        chunk = os.read(key.fileobj.fileno(), 65536)
                    except OSError:
                        raise RepositoryError(
                            'repository-output-invalid') from None
                    buffer += chunk
                    if len(buffer) > cap:
                        raise RepositoryError(
                            'repository-output-too-large')
                    if not chunk:
                        selector.unregister(key.fileobj)
                    streams[which] = buffer
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RepositoryError('repository-timeout')
                try:
                    code = proc.wait(timeout=min(remaining, 1.0))
                    break
                except subprocess.TimeoutExpired:
                    continue
            completed = subprocess.CompletedProcess(
                argv, code, bytes(streams.get('out', b'')),
                bytes(streams.get('err', b'')))
            return completed
        except OSError:
            raise RepositoryError('repository-command-failed') from None
        finally:
            # Any exception or interruption (including
            # KeyboardInterrupt, which propagates after this cleanup)
            # leaves no live child, no live process-group member and
            # no open pipe or selector behind.
            if completed is None:
                self._reap(proc)
            else:
                for stream in (proc.stdout, proc.stderr):
                    try:
                        stream.close()
                    except OSError:
                        pass
            if selector is not None:
                try:
                    selector.close()
                except OSError:
                    pass


def _stage_lstat(path):
    try:
        return _lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        raise RepositoryError('path-unavailable') from None


class ResticRepository:
    def __init__(self, config, *, runner=None, restic_binary='restic'):
        self._config = _validate_config(config)
        self._transport = self._config['transport']
        if self._transport['kind'] == 'local':
            self._location = self._transport['path']
            _check_private_dir(self._transport['path'],
                               'repository-missing')
        else:
            t = self._transport
            self._location = 'sftp:{}@{}:{}'.format(
                t['user'], t['host'], t['path'])
            ssh_argv = [
                'ssh', '-F', '/dev/null',
                '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                '-o', 'IdentityAgent=none',
                '-o', 'StrictHostKeyChecking=yes',
                '-o', 'UserKnownHostsFile=' + t['knownHostsFile'],
                '-o', 'GlobalKnownHostsFile=/dev/null',
                '-i', t['identityFile'],
                '-p', str(t['port']),
                '-s', t['user'] + '@' + t['host'], 'sftp']
            self._sftp_option = 'sftp.command=' + shlex.join(ssh_argv)
        _check_private_file(self._config['passwordFile'],
                            'repository-key-missing')
        if self._transport['kind'] == 'sftp':
            _check_private_file(self._transport['identityFile'],
                                'repository-transport-unavailable')
            _check_private_file(self._transport['knownHostsFile'],
                                'repository-transport-unavailable')
        self._binary = restic_binary
        self.runner = runner if runner is not None else BoundedRunner()

    # -- transport ---------------------------------------------------

    def _argv(self, *args):
        argv = [self._binary, '--no-cache', '--repo', self._location,
                '--password-file', self._config['passwordFile']]
        if self._transport['kind'] == 'sftp':
            argv += ['-o', self._sftp_option]
        return argv + list(args)

    def _run(self, args, *, cwd=None, max_bytes=_METADATA_MAX,
             timeout=_METADATA_TIMEOUT):
        result = self.runner.run(self._argv(*args), cwd=cwd,
                                 max_bytes=max_bytes, timeout=timeout)
        if result.returncode == 0:
            return result
        raise RepositoryError(
            _RC_CODES.get(result.returncode,
                          'repository-command-failed'))

    def _check_files(self):
        _check_private_file(self._config['passwordFile'],
                            'repository-key-missing')
        if self._transport['kind'] == 'sftp':
            _check_private_file(self._transport['identityFile'],
                                'repository-transport-unavailable')
            _check_private_file(self._transport['knownHostsFile'],
                                'repository-transport-unavailable')
        if self._transport['kind'] == 'local':
            _check_private_dir(self._transport['path'],
                               'repository-missing')

    # -- repository identity -----------------------------------------

    def verify_identity(self):
        """Re-read ``cat config`` and require the pinned repository id.

        Called before every public operation so no upload or restore
        runs against a different repository. Returns the hex64 id."""
        self._check_files()
        result = self._run(['cat', 'config'], max_bytes=_CONFIG_MAX)
        value = _json_dict(result.stdout)
        version = value.get('version')
        identity = value.get('id')
        if type(version) is not int or version not in (1, 2) \
                or type(identity) is not str \
                or _HEX64_RE.fullmatch(identity) is None \
                or identity != self._config['repositoryIdentity']:
            raise RepositoryError('repository-identity-mismatch')
        return identity

    # -- restic object reads ------------------------------------------

    def _tree(self, tree_id):
        _hex64(tree_id, 'snapshot-id')
        result = self._run(['cat', 'blob', tree_id],
                           max_bytes=_METADATA_MAX)
        raw = result.stdout
        if hashlib.sha256(raw).hexdigest() != tree_id:
            raise RepositoryError('repository-point-invalid')
        value = _load_json(raw)
        if type(value) is not dict or type(value.get('nodes')) is not list \
                or len(value['nodes']) > _MAX_TREE_NODES:
            raise RepositoryError('repository-point-invalid')
        nodes = {}
        for node in value['nodes']:
            if type(node) is not dict or type(node.get('name')) is not str \
                    or _NODE_NAME_RE.fullmatch(node['name']) is None \
                    or node['name'] in ('.', '..') \
                    or node['name'] in nodes:
                raise RepositoryError('repository-point-invalid')
            nodes[node['name']] = node
        return nodes

    def _snapshot(self, snapshot_id, required_tag):
        _hex64(snapshot_id, 'snapshot-id')
        result = self._run(['cat', 'snapshot', snapshot_id],
                           max_bytes=_METADATA_MAX)
        value = _json_dict(result.stdout)
        if 'id' in value and value['id'] != snapshot_id:
            raise RepositoryError('repository-point-invalid')
        tags = value.get('tags')
        if type(tags) is not list \
                or any(type(tag) is not str for tag in tags) \
                or required_tag not in tags:
            raise RepositoryError('repository-point-invalid')
        tree_id = value.get('tree')
        if type(tree_id) is not str \
                or _HEX64_RE.fullmatch(tree_id) is None:
            raise RepositoryError('repository-point-invalid')
        return value

    def _state_nodes(self, state_node):
        if type(state_node.get('subtree')) is not str \
                or _HEX64_RE.fullmatch(state_node['subtree']) is None:
            raise RepositoryError('repository-point-invalid')
        nodes = self._tree(state_node['subtree'])
        for node in nodes.values():
            if node.get('type') != 'dir' \
                    or type(node.get('subtree')) is not str \
                    or _HEX64_RE.fullmatch(node['subtree']) is None \
                    or type(node.get('uid')) is not int \
                    or type(node.get('gid')) is not int:
                raise RepositoryError('repository-point-invalid')
        return nodes

    def _check_state_binding(self, nodes, definition, source):
        mounts = {mount['id']: mount
                  for mount in definition['stateMounts']}
        if set(nodes) != set(mounts):
            raise RepositoryError('repository-point-invalid')
        for mount_id, mount in mounts.items():
            node = nodes[mount_id]
            if node['uid'] != source['uidBase'] + mount['ownerUid'] \
                    or node['gid'] != source['uidBase'] + mount['ownerGid']:
                raise RepositoryError('repository-point-invalid')
        return {mount_id: nodes[mount_id]['subtree']
                for mount_id in mounts}

    def _receipt(self, snapshot_id, manifest):
        return {'schemaVersion': _SCHEMA_VERSION,
                'repositoryId': self._config['id'],
                'repositoryIdentity':
                    self._config['repositoryIdentity'],
                'snapshotId': snapshot_id,
                'manifest': manifest}

    def _inspect_final(self, snapshot_id, capture_tag=None):
        snapshot = self._snapshot(snapshot_id, _FINAL_TAG)
        if capture_tag is not None \
                and capture_tag not in snapshot['tags']:
            raise RepositoryError('repository-point-invalid')
        nodes = self._tree(snapshot['tree'])
        if set(nodes) != {_STATE_NAME, _MANIFEST_NAME}:
            raise RepositoryError('repository-point-invalid')
        manifest_node = nodes[_MANIFEST_NAME]
        if nodes[_STATE_NAME].get('type') != 'dir' \
                or manifest_node.get('type') != 'file':
            raise RepositoryError('repository-point-invalid')
        size = manifest_node.get('size')
        if type(size) is not int or not 0 <= size <= _MANIFEST_MAX:
            raise RepositoryError('repository-point-invalid')
        result = self._run(['dump', snapshot_id, '/' + _MANIFEST_NAME],
                           max_bytes=_MANIFEST_MAX)
        try:
            manifest = recovery.decode_manifest(result.stdout)
        except recovery.RecoveryError:
            raise RepositoryError('repository-point-invalid') from None
        children = self._state_nodes(nodes[_STATE_NAME])
        subtrees = self._check_state_binding(
            children, manifest['definition'], manifest['source'])
        digests = {entry['id']: entry['treeDigest']
                   for entry in manifest['state']}
        for mount_id, subtree in subtrees.items():
            if digests[mount_id] != 'sha256:' + subtree:
                raise RepositoryError('repository-point-invalid')
            # The mount-root tree blob itself must exist and hash to
            # the accepted id; this verifies mount metadata only, not
            # payload blobs (full check/restore cover those).
            self._tree(subtree)
        if manifest['schemaVersion'] == recovery._SCHEMA_VERSION \
                and manifest['stateSetDigest'] \
                != 'sha256:' + nodes[_STATE_NAME]['subtree']:
            raise RepositoryError('repository-point-invalid')
        return manifest

    def _snapshot_state_digest(self, snapshot_id, required_tag):
        """Native digest of a tagged snapshot's ``state`` subtree blob.

        Read through hashed tree blobs only; the returned value binds
        every state root's own metadata and child ids even for legacy
        manifests that never recorded a stateSetDigest."""
        snapshot = self._snapshot(snapshot_id, required_tag)
        nodes = self._tree(snapshot['tree'])
        state_node = nodes.get(_STATE_NAME)
        if state_node is None or state_node.get('type') != 'dir' \
                or type(state_node.get('subtree')) is not str \
                or _HEX64_RE.fullmatch(state_node['subtree']) is None:
            raise RepositoryError('repository-point-invalid')
        # Prove the blob itself exists and hashes to the claimed id.
        self._tree(state_node['subtree'])
        return 'sha256:' + state_node['subtree']

    # -- public operations ---------------------------------------------

    def inspect(self, snapshot_id):
        """Return the receipt record for a final tagged snapshot."""
        self.verify_identity()
        _hex64(snapshot_id, 'snapshot-id')
        manifest = self._inspect_final(snapshot_id)
        return self._receipt(snapshot_id, manifest)

    def list_points(self):
        """Return receipt records for every final tagged snapshot.

        Sorted by (recoveryPointId, snapshotId); multiple snapshot
        copies of the same point are all retained. A corrupt record
        fails the whole call rather than being silently skipped."""
        self.verify_identity()
        result = self._run(
            ['snapshots', '--json', '--tag', _FINAL_TAG],
            max_bytes=_METADATA_MAX)
        entries = self._snapshot_ids(result.stdout)
        records = []
        for snapshot_id in entries:
            records.append(
                self._receipt(snapshot_id,
                              self._inspect_final(snapshot_id)))
        records.sort(key=lambda record: (
            record['manifest']['recoveryPointId'], record['snapshotId']))
        return records

    def check(self):
        """Full ``restic check --read-data``; None on success."""
        self.verify_identity()
        self._run(['check', '--read-data'], timeout=_BULK_TIMEOUT)
        return None

    def _snapshot_ids(self, raw):
        entries = _load_json(raw)
        if type(entries) is not list or len(entries) > _MAX_SNAPSHOTS:
            raise RepositoryError('repository-output-invalid')
        ids = []
        for entry in entries:
            if type(entry) is not dict \
                    or type(entry.get('id')) is not str \
                    or _HEX64_RE.fullmatch(entry['id']) is None:
                raise RepositoryError('repository-output-invalid')
            ids.append(entry['id'])
        return ids

    def _parse_summary(self, raw):
        lines = [line for line in raw.split(b'\n') if line.strip()]
        if len(lines) != 1:
            raise RepositoryError('repository-output-invalid')
        value = _json_dict(lines[0])
        snapshot_id = value.get('snapshot_id')
        if value.get('message_type') != 'summary' \
                or type(snapshot_id) is not str \
                or _HEX64_RE.fullmatch(snapshot_id) is None:
            raise RepositoryError('repository-output-invalid')
        return snapshot_id

    # -- staging -------------------------------------------------------

    def _check_stage(self, stage_dir, definition, source):
        try:
            worker._path(stage_dir, 'stage')
        except worker.WorkerError:
            raise RepositoryError('invalid-stage') from None
        _check_private_dir(stage_dir, 'invalid-stage')
        try:
            names = os.listdir(stage_dir)
        except OSError:
            raise RepositoryError('path-unavailable') from None
        if not set(names) <= {_STATE_NAME, _MANIFEST_NAME}:
            raise RepositoryError('invalid-stage')
        if _MANIFEST_NAME in names:
            # A caller-supplied manifest must be a private euid-owned
            # 0600 regular file before any upload is considered.
            manifest_path = os.path.join(stage_dir, _MANIFEST_NAME)
            try:
                present = statefiles.check_private_file(manifest_path)
            except statefiles.PathError:
                raise RepositoryError('invalid-stage') from None
            if not present:
                raise RepositoryError('invalid-stage')
        state_path = os.path.join(stage_dir, _STATE_NAME)
        if _STATE_NAME not in names:
            raise RepositoryError('invalid-stage')
        state = _stage_lstat(state_path)
        if state is None or not stat.S_ISDIR(state.st_mode) \
                or stat.S_ISLNK(state.st_mode) \
                or state.st_uid != os.geteuid() \
                or stat.S_IMODE(state.st_mode) & 0o077:
            raise RepositoryError('invalid-stage')
        try:
            children = os.listdir(state_path)
        except OSError:
            raise RepositoryError('path-unavailable') from None
        mounts = {mount['id']: mount
                  for mount in definition['stateMounts']}
        if set(children) != set(mounts):
            raise RepositoryError('invalid-stage')
        for mount_id, mount in mounts.items():
            st = _stage_lstat(os.path.join(state_path, mount_id))
            if st is None or not stat.S_ISDIR(st.st_mode) \
                    or stat.S_ISLNK(st.st_mode) \
                    or st.st_uid != source['uidBase'] + mount['ownerUid'] \
                    or st.st_gid != source['uidBase'] + mount['ownerGid']:
                raise RepositoryError('invalid-stage')

    def _read_bounded(self, path, limit):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        except OSError:
            raise RepositoryError('path-unavailable') from None
        try:
            with os.fdopen(fd, 'rb') as handle:
                data = handle.read(limit + 1)
        except OSError:
            raise RepositoryError('path-unavailable') from None
        if len(data) > limit:
            raise RepositoryError('repository-point-invalid')
        return data

    # -- store ----------------------------------------------------------

    def store(self, stage_dir, definition, source, capture, *,
              capture_id, secret_bundle=None, capture_finished=None):
        """Upload staged state plus a sealed manifest as one point.

        The caller supplies an already-quiesced private staging tree
        containing only ``state`` (and optionally a matching
        ``manifest.json``); this method never stops the workload and
        asserts no consistency beyond the captured tree ids. A draft
        data-only snapshot is written first to derive the restic tree
        ids, then the manifest, then a final tagged snapshot that is
        inspected and compared before the receipt is returned. When
        ``capture_finished`` is provided it is invoked once — after
        the draft tree ids verify and before the final manifest is
        constructed — and its returned capture dict is what the
        sealed manifest binds; a failing callback aborts the store
        before any final tag exists."""
        if type(capture_id) is not str \
                or _HEX32_RE.fullmatch(capture_id) is None:
            raise RepositoryError('invalid-capture-id')
        try:
            placeholder = {mount['id']: 'sha256:' + '0' * 64
                           for mount in definition['stateMounts']}
            probe = recovery.build_manifest(
                definition, source, capture,
                state_tree_digests=placeholder,
                state_set_digest='sha256:' + '0' * 64,
                secret_bundle=secret_bundle)
        except (KeyError, TypeError, recovery.RecoveryError):
            raise RepositoryError('invalid-capture') from None
        definition = probe['definition']
        source = probe['source']
        self._check_stage(stage_dir, definition, source)
        self.verify_identity()

        # Data-only draft upload derives the tree ids; it never
        # carries the final tag, whatever happens later.
        draft_tag = _DRAFT_TAG + ':' + capture_id
        result = self._run(
            ['backup', '--json', '--quiet',
             '--host', source['hostId'],
             '--tag', draft_tag, _STATE_NAME],
            cwd=stage_dir, timeout=_BULK_TIMEOUT)
        draft_id = self._parse_summary(result.stdout)
        draft = self._snapshot(draft_id, draft_tag)
        nodes = self._tree(draft['tree'])
        if set(nodes) != {_STATE_NAME} \
                or nodes[_STATE_NAME].get('type') != 'dir':
            raise RepositoryError('repository-point-invalid')
        children = self._state_nodes(nodes[_STATE_NAME])
        subtrees = self._check_state_binding(children, definition,
                                             source)
        for mount_id, subtree in subtrees.items():
            # The mount-root tree blob must exist and hash to the id
            # the manifest will bind as its treeDigest.
            self._tree(subtree)
        if capture_finished is not None:
            try:
                capture = capture_finished()
            except Exception:
                raise RepositoryError(
                    'capture-checkpoint-failed') from None
        digests = {mount_id: 'sha256:' + subtree
                   for mount_id, subtree in subtrees.items()}
        try:
            manifest = recovery.build_manifest(
                definition, source, capture,
                state_tree_digests=digests,
                # The state's own subtree blob carries every state
                # root's metadata; binding its native tree id keeps
                # captures distinct when only root mode/ACLs change.
                state_set_digest='sha256:' + nodes[_STATE_NAME]['subtree'],
                secret_bundle=secret_bundle)
            expected_raw = recovery.encode_manifest(manifest)
        except recovery.RecoveryError:
            raise RepositoryError('invalid-capture') from None

        manifest_path = os.path.join(stage_dir, _MANIFEST_NAME)
        try:
            existing = self._read_bounded(manifest_path, _MANIFEST_MAX)
        except RepositoryError:
            # A present manifest that cannot be read back canonically
            # cannot be proven to match the expected point.
            raise RepositoryError('capture-conflict') from None
        if existing is not None:
            if existing != expected_raw:
                raise RepositoryError('capture-conflict')
        else:
            try:
                statefiles.write_json(manifest_path, manifest)
            except statefiles.PathError as error:
                raise RepositoryError(error.code) from None
            except OSError:
                # mkstemp/write/replace failures (ENOSPC, EIO, …)
                # leave the partial stage and draft in place and must
                # never reach the final-tag backup.
                raise RepositoryError('path-unavailable') from None

        tag_filter = _FINAL_TAG + ',' + draft_tag
        result = self._run(
            ['snapshots', '--json', '--tag', tag_filter],
            max_bytes=_METADATA_MAX)
        matching = []
        for candidate_id in self._snapshot_ids(result.stdout):
            record = self._receipt(
                candidate_id,
                self._inspect_final(candidate_id, draft_tag))
            if record['manifest'] != manifest:
                raise RepositoryError('capture-conflict')
            matching.append(record)
        if matching:
            matching.sort(key=lambda record: record['snapshotId'])
            return matching[0]

        result = self._run(
            ['backup', '--json', '--quiet',
             '--host', source['hostId'],
             '--tag', _FINAL_TAG, '--tag', draft_tag,
             _STATE_NAME, _MANIFEST_NAME],
            cwd=stage_dir, timeout=_BULK_TIMEOUT)
        snapshot_id = self._parse_summary(result.stdout)
        record = self._receipt(
            snapshot_id, self._inspect_final(snapshot_id, draft_tag))
        if record['manifest'] != manifest:
            raise RepositoryError('repository-point-invalid')
        return record

    # -- copy -----------------------------------------------------------

    def copy_from(self, source_repository, snapshot_id):
        """Copy one verified final point from a local source repo.

        Both identities are verified first; the source must be a
        ``local`` transport so its path and password file can be
        passed to the target's ``copy`` argv directly. An existing
        identical point under the same capture tag is replayed after a
        full target check; a different manifest under that tag is a
        conflict. The target snapshot id is never assumed to equal
        the source id — finals are re-queried after copy."""
        if type(source_repository) is not ResticRepository \
                or source_repository._transport['kind'] != 'local':
            raise RepositoryError('invalid-transport')
        self.verify_identity()
        source_repository.verify_identity()
        _hex64(snapshot_id, 'snapshot-id')
        snapshot = source_repository._snapshot(snapshot_id, _FINAL_TAG)
        capture_tags = [tag for tag in snapshot['tags']
                        if tag.startswith(_DRAFT_TAG + ':')]
        if len(capture_tags) != 1 or _HEX32_RE.fullmatch(
                capture_tags[0][len(_DRAFT_TAG) + 1:]) is None:
            raise RepositoryError('repository-point-invalid')
        capture_tag = capture_tags[0]
        manifest = source_repository._inspect_final(
            snapshot_id, capture_tag)
        source_digest = source_repository._snapshot_state_digest(
            snapshot_id, capture_tag)
        tag_filter = _FINAL_TAG + ',' + capture_tag
        result = self._run(
            ['snapshots', '--json', '--tag', tag_filter],
            max_bytes=_METADATA_MAX)
        matching = []
        for candidate_id in self._snapshot_ids(result.stdout):
            record = self._receipt(
                candidate_id,
                self._inspect_final(candidate_id, capture_tag))
            if record['manifest'] != manifest:
                raise RepositoryError('capture-conflict')
            # A shared manifest is not proof the stored trees match:
            # legacy v2 points carry no stateSetDigest, and state-root
            # metadata lives only in the parent tree blob.
            if self._snapshot_state_digest(
                    candidate_id, capture_tag) != source_digest:
                raise RepositoryError('capture-conflict')
            matching.append(record)
        if matching:
            self.check()
            matching.sort(key=lambda record: record['snapshotId'])
            return matching[0]
        source = source_repository
        self._run(
            ['copy', '--from-repo', source._transport['path'],
             '--from-password-file', source._config['passwordFile'],
             snapshot_id], timeout=_BULK_TIMEOUT)
        result = self._run(
            ['snapshots', '--json', '--tag', tag_filter],
            max_bytes=_METADATA_MAX)
        records = []
        for candidate_id in self._snapshot_ids(result.stdout):
            record = self._receipt(
                candidate_id,
                self._inspect_final(candidate_id, capture_tag))
            if record['manifest'] != manifest \
                    or self._snapshot_state_digest(
                        candidate_id, capture_tag) != source_digest:
                raise RepositoryError('repository-point-invalid')
            records.append(record)
        if not records:
            raise RepositoryError('repository-point-invalid')
        self.check()
        records.sort(key=lambda record: record['snapshotId'])
        return records[0]

    # -- restore --------------------------------------------------------

    def restore(self, snapshot_id, destination):
        """Extract a final point into a fresh private directory.

        The destination must not exist (including as a broken symlink)
        under an existing private euid-owned parent; a failed restore
        leaves the partial directory in place, never marked usable.
        This is isolated verified extraction only — no worker
        installation, ownership remap, readiness or fencing."""
        record = self.inspect(snapshot_id)
        try:
            worker._path(destination, 'destination')
        except worker.WorkerError:
            raise RepositoryError('invalid-destination') from None
        if os.path.lexists(destination):
            raise RepositoryError('destination-exists')
        parent = os.path.dirname(destination)
        _check_private_dir(parent, 'invalid-destination')
        try:
            os.mkdir(destination, 0o700)
            statefiles._sync_dir(parent)
        except OSError:
            raise RepositoryError('path-unavailable') from None
        self._run(['restore', snapshot_id, '--target', destination,
                   '--verify'], timeout=_BULK_TIMEOUT)
        try:
            names = set(os.listdir(destination))
        except OSError:
            raise RepositoryError('path-unavailable') from None
        if names != {_STATE_NAME, _MANIFEST_NAME}:
            raise RepositoryError('repository-point-invalid')
        manifest_st = _stage_lstat(
            os.path.join(destination, _MANIFEST_NAME))
        state_st = _stage_lstat(
            os.path.join(destination, _STATE_NAME))
        if manifest_st is None or not stat.S_ISREG(manifest_st.st_mode) \
                or stat.S_ISLNK(manifest_st.st_mode) \
                or state_st is None \
                or not stat.S_ISDIR(state_st.st_mode) \
                or stat.S_ISLNK(state_st.st_mode):
            raise RepositoryError('repository-point-invalid')
        try:
            children = os.listdir(
                os.path.join(destination, _STATE_NAME))
        except OSError:
            raise RepositoryError('path-unavailable') from None
        manifest = record['manifest']
        mounts = {mount['id']: mount for mount
                  in manifest['definition']['stateMounts']}
        if set(children) != set(mounts):
            raise RepositoryError('repository-point-invalid')
        uid_base = manifest['source']['uidBase']
        for mount_id, mount in mounts.items():
            st = _stage_lstat(os.path.join(
                destination, _STATE_NAME, mount_id))
            if st is None or not stat.S_ISDIR(st.st_mode) \
                    or stat.S_ISLNK(st.st_mode) \
                    or st.st_uid != uid_base + mount['ownerUid'] \
                    or st.st_gid != uid_base + mount['ownerGid']:
                raise RepositoryError('repository-point-invalid')
        raw = self._read_bounded(
            os.path.join(destination, _MANIFEST_NAME), _MANIFEST_MAX)
        try:
            restored = recovery.decode_manifest(raw or b'')
        except recovery.RecoveryError:
            raise RepositoryError('repository-point-invalid') from None
        if restored != record['manifest']:
            raise RepositoryError('repository-point-invalid')
        return record
