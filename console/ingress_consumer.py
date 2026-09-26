"""Expiry-enforced file-provider ingress consumer for non-NixOS edges.

Polls ``GET /v2/routes`` over mutual TLS with the exact same
nonce-bound, version-pinned, expiry-enforced snapshot contract as
``console/ingress.py`` — fetch, strict validation, highwater
persistence, locking and freshness checks are all delegated to
``ingress.Ingress``. The difference is delivery: instead of exposing
the rendered document through Traefik's HTTP provider, this daemon
writes it to ``renderFile`` atomically (``tmp`` + ``fsync`` +
``os.replace`` + directory ``fsync``) for Traefik's file provider
(``watch: true``), and only rewrites when the document differs.

The rendered file alone cannot expire a route Traefik has already
loaded, so expiry stays enforced per request: every generated router
still carries the forwardAuth guard served by this same daemon on
``127.0.0.1:listenPort`` (``ingress.make_server``). A dead guard, a
dead consumer or a stale registry all fail closed — Traefik denies
once the cached document's token no longer authorizes.

Stdlib only. The configuration is the ingress configuration plus one
field:

    renderFile — absolute path of the Traefik dynamic document to
    maintain. Emitted bytes are canonical JSON, which is also valid
    YAML 1.2 flow syntax; the file provider only reads YAML/TOML, so
    the deployment must give it a ``.yaml``/``.yml`` name.
"""
import argparse
import json
import os
import ssl
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path

import ingress
import worker

_MAX_CONFIG = 2 * 1024 * 1024
_POLL_INTERVAL = ingress._POLL_INTERVAL
_CONFIG_FIELDS = ingress._CONFIG_FIELDS | {'renderFile'}


def validate_config(config):
    """The ingress config plus ``renderFile``; returns a validated copy
    shaped like the ingress config with ``renderFile`` attached."""
    try:
        worker._fields(config, _CONFIG_FIELDS, 'config')
        worker._path(config['renderFile'], 'renderFile')
    except worker.WorkerError as error:
        raise ingress.IngressError(error.code) from None
    validated = ingress.validate_config(
        {key: config[key] for key in ingress._CONFIG_FIELDS})
    validated['renderFile'] = config['renderFile']
    return validated


def check_render_dir(path):
    """Like ``statefiles.check_private_dir`` but relaxed for a shared
    render directory: the leaf must be owned by the effective UID with
    no group/other WRITE bits (read/execute is fine — Traefik must
    traverse it), ancestors follow the root-or-euid/non-writable rule.
    Nothing may be a symlink."""
    euid = os.geteuid()
    current = ''
    for part in [p for p in path.split('/') if p]:
        current += '/' + part
        try:
            st = os.lstat(current)
        except OSError:
            raise ingress.IngressError('ingress-unavailable') from None
        if not stat.S_ISDIR(st.st_mode):
            raise ingress.IngressError('render-path-unsafe')
        mode = stat.S_IMODE(st.st_mode)
        if current == path:
            if st.st_uid != euid or mode & 0o022:
                raise ingress.IngressError('render-path-unsafe')
            return
        if st.st_uid not in (0, euid) \
                or (mode & 0o022
                    and not (st.st_uid == 0 and mode & stat.S_ISVTX)):
            raise ingress.IngressError('render-path-unsafe')
    raise ingress.IngressError('render-path-unsafe')


def _write_rendered(path, data):
    """Atomically and durably replace ``path`` with ``data``: same
    filesystem temp file, fsync before rename, directory fsync after.
    The file lands mode 0640 — it carries live guard tokens."""
    parent = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(dir=parent, prefix='.nexus-render-')
    try:
        os.fchmod(fd, 0o640)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.replace(tmp, path)
        dirfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


class Consumer:
    """Registry poll + file render cycle bound to a validated
    ``ingress.Ingress``. ``tick()`` always re-renders, so a snapshot
    that expires while the registry is unreachable still degrades the
    file to deny-all on the next tick — fail closed, never served
    stale-but-trusted."""

    def __init__(self, config, context=None, *, clock=time.time,
                 monotonic=time.monotonic, fetcher=None):
        self.config = validate_config(config)
        self.render_file = self.config['renderFile']
        check_render_dir(os.path.dirname(self.render_file))
        self.ingress = ingress.Ingress(
            {key: self.config[key] for key in ingress._CONFIG_FIELDS},
            context, clock=clock, monotonic=monotonic, fetcher=fetcher)
        self._rendered = None

    def render(self):
        """Deterministic document bytes: sorted keys, fixed indent —
        identical snapshots render byte-identical files."""
        return (json.dumps(self.ingress.dynamic_config(),
                           indent=2, sort_keys=True)
                + '\n').encode()

    def tick(self):
        """One poll + conditional rewrite. Poll failures are logged and
        swallowed so a missing snapshot still lets freshness flip the
        render to deny-all; write failures propagate to the caller."""
        try:
            self.ingress.poll()
        except ingress.IngressError as error:
            print(json.dumps({'event': 'poll-error',
                              'error': error.code}), flush=True)
        rendered = self.render()
        current = None
        try:
            with open(self.render_file, 'rb') as handle:
                current = handle.read(len(rendered) + 1)
        except OSError:
            pass
        if current != rendered:
            _write_rendered(self.render_file, rendered)
            print(json.dumps({'event': 'rendered',
                              'bytes': len(rendered)}), flush=True)
        self._rendered = rendered
        return rendered

    def run(self, stop, interval=_POLL_INTERVAL):
        while not stop.is_set():
            try:
                self.tick()
            except Exception as error:
                print(json.dumps({'event': 'tick-error',
                                  'type': type(error).__name__}),
                      flush=True)
            stop.wait(interval)

    def close(self):
        self.ingress.close()


def main(argv=None):
    parser = argparse.ArgumentParser(prog='nexus-ingress-consumer')
    parser.add_argument('--config', required=True)
    args = parser.parse_args(argv)
    try:
        with open(args.config, 'rb') as handle:
            raw = handle.read(_MAX_CONFIG + 1)
        if len(raw) > _MAX_CONFIG:
            raise ingress.IngressError('config-too-large')
        config = worker.load_json_bytes(raw)
        credentials = Path(os.environ['CREDENTIALS_DIRECTORY'])
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=credentials / 'ca')
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(credentials / 'cert', credentials / 'key')
    except (ingress.IngressError, worker.WorkerError, OSError, KeyError,
            ValueError) as error:
        code = getattr(error, 'code', 'invalid-config')
        sys.stdout.write(json.dumps(
            {'schemaVersion': 2, 'status': 'error', 'error': code},
            sort_keys=True, separators=(',', ':')) + '\n')
        return 1
    try:
        consumer = Consumer(config, context)
    except ingress.IngressError as error:
        sys.stdout.write(json.dumps(
            {'schemaVersion': 2, 'status': 'error',
             'error': error.code}, sort_keys=True,
            separators=(',', ':')) + '\n')
        return 1
    server = None
    stop = threading.Event()
    try:
        # The forwardAuth guard (and, as a side effect, the /traefik
        # HTTP provider document) stays on 127.0.0.1:listenPort; the
        # file provider render is additive, not a replacement.
        server = ingress.make_server(consumer.ingress)
        thread = threading.Thread(target=consumer.run, args=(stop,),
                                  daemon=True)
        thread.start()
        server.serve_forever()
    finally:
        stop.set()
        thread.join(timeout=ingress._FETCH_TIMEOUT + _POLL_INTERVAL + 1)
        if server is not None:
            server.server_close()
        consumer.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
