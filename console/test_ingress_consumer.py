"""Tests for console/ingress_consumer.py — the file-provider edge consumer."""
import contextlib
import http.client
import io
import json
import os
import stat
import tempfile
import threading
import time
import unittest

import ingress
import ingress_consumer
import test_ingress
import test_registry

BACKEND = test_ingress.BACKEND
UNAVAILABLE = 'http://127.0.0.1:9445/unavailable'


def consumer_config(tmp):
    os.makedirs(tmp, exist_ok=True)
    os.chmod(tmp, 0o700)
    config = test_ingress.ingress_config(os.path.join(tmp, 'state'))
    os.mkdir(config['stateDir'], 0o700)
    render_dir = os.path.join(tmp, 'dynamic')
    os.mkdir(render_dir)
    os.chmod(render_dir, 0o755)
    config['renderFile'] = os.path.join(render_dir, 'nexus.yaml')
    return config


def make_consumer(tmp, fake=None, fetcher=None, config=None):
    fake = fake or test_registry.FakeTime()
    fetcher = fetcher or (lambda nonce: test_ingress.snapshot(
        nonce, now=fake.now))
    consumer = ingress_consumer.Consumer(
        config or consumer_config(tmp), None,
        clock=lambda: fake.now, monotonic=lambda: fake.mono,
        fetcher=fetcher)
    return consumer, fake


def file_doc(consumer):
    with open(consumer.render_file, 'rb') as handle:
        return json.loads(handle.read())


def file_backend(consumer):
    return test_ingress.backend_url(file_doc(consumer))


def file_token(consumer):
    return test_ingress.auth_url(file_doc(consumer)).rsplit('/', 1)[1]


class ConfigTests(unittest.TestCase):
    def test_config_requires_render_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = consumer_config(tmp)
            validated = ingress_consumer.validate_config(good)
            self.assertEqual(validated['renderFile'], good['renderFile'])
            for mutated in (
                    {k: v for k, v in good.items() if k != 'renderFile'},
                    dict(good, extra=1),
                    dict(good, renderFile='relative/nexus.yaml'),
                    dict(good, renderFile='/a/../nexus.yaml'),
                    dict(good, renderFile='/tmp/nexus.yaml/'),
                    dict(good, renderFile=42),
                    dict(good, listenPort=0)):
                with self.assertRaises(ingress.IngressError,
                                       msg=mutated.get('renderFile',
                                                       mutated)):
                    ingress_consumer.validate_config(mutated)

    def test_render_dir_safety(self):
        with tempfile.TemporaryDirectory() as tmp:
            # A healthy render dir accepts and closes cleanly.
            consumer, _ = make_consumer(tmp)
            consumer.close()

            config = consumer_config(os.path.join(tmp, 'writable'))
            group_writable = os.path.dirname(config['renderFile'])
            os.chmod(group_writable, 0o775)
            with self.assertRaises(ingress.IngressError) as ctx:
                make_consumer(tmp, config=config)
            self.assertEqual(ctx.exception.code, 'render-path-unsafe')
            os.chmod(group_writable, 0o755)

            link = os.path.join(tmp, 'linked')
            os.symlink(group_writable, link)
            config['renderFile'] = os.path.join(link, 'nexus.yaml')
            with self.assertRaises(ingress.IngressError) as ctx:
                make_consumer(tmp, config=config)
            self.assertEqual(ctx.exception.code, 'render-path-unsafe')

            config['renderFile'] = os.path.join(tmp, 'missing',
                                                'nexus.yaml')
            with self.assertRaises(ingress.IngressError) as ctx:
                make_consumer(tmp, config=config)
            self.assertEqual(ctx.exception.code,
                             'ingress-unavailable')


class RenderTests(unittest.TestCase):
    def test_render_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            consumer, _ = make_consumer(tmp)
            first, second = consumer.render(), consumer.render()
            self.assertEqual(first, second)
            self.assertTrue(first.endswith(b'\n'))
            self.assertEqual(
                first.decode()[:-1],
                json.dumps(consumer.ingress.dynamic_config(),
                           indent=2, sort_keys=True))
            consumer.ingress.poll()
            self.assertEqual(consumer.render(), consumer.render())
            consumer.close()

    def test_render_same_across_instances(self):
        with tempfile.TemporaryDirectory() as tmp:
            one, _ = make_consumer(os.path.join(tmp, 'a'))
            two, _ = make_consumer(os.path.join(tmp, 'b'))
            self.assertEqual(one.render(), two.render())
            one.close()
            two.close()


class TickTests(unittest.TestCase):
    def test_initial_render_denies_and_writes_0640(self):
        with tempfile.TemporaryDirectory() as tmp:
            live = {'up': False}

            def fetcher(nonce):
                if not live['up']:
                    raise ingress.IngressError('registry-fetch-failed')
                return test_ingress.snapshot(nonce, now=fake.now)

            consumer, fake = make_consumer(tmp, fetcher=fetcher)
            # Even with the registry unreachable, the first tick writes
            # a deny-all document — never an absent or stale-trusted one.
            consumer.tick()
            self.assertEqual(file_backend(consumer), UNAVAILABLE)
            self.assertEqual(file_token(consumer), '0' * 64)
            mode = stat.S_IMODE(os.lstat(consumer.render_file).st_mode)
            self.assertEqual(mode, 0o640)
            live['up'] = True
            consumer.tick()
            self.assertEqual(file_backend(consumer),
                             'http://192.168.141.2:8080')
            consumer.close()

    def test_poll_installs_then_expiry_propagates_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            captured = {}

            def frozen(nonce):
                # Replays the first snapshot forever: once the clock
                # passes validUntil the registry answer is stale and
                # rejected, and the render flips to deny.
                if 'snap' not in captured:
                    captured['snap'] = test_ingress.snapshot(
                        nonce, now=fake.now)
                return dict(captured['snap'], nonce=nonce)

            consumer, fake = make_consumer(tmp, fetcher=frozen)
            consumer.tick()
            self.assertEqual(file_backend(consumer),
                             'http://192.168.141.2:8080')
            token = test_ingress.route_token()
            self.assertEqual(file_token(consumer), token)
            ino = os.lstat(consumer.render_file).st_ino

            # An unchanged document is not rewritten — Traefik's file
            # watch must not flap on every poll.
            consumer.tick()
            self.assertEqual(os.lstat(consumer.render_file).st_ino, ino)

            # Past validUntil the replayed snapshot is stale; the next
            # tick rewrites the file to deny.
            fake.now += 9
            consumer.tick()
            self.assertEqual(file_backend(consumer), UNAVAILABLE)
            self.assertEqual(file_token(consumer), '0' * 64)
            self.assertNotEqual(
                os.lstat(consumer.render_file).st_ino, ino)
            consumer.close()

    def test_deleted_render_file_is_restored(self):
        with tempfile.TemporaryDirectory() as tmp:
            consumer, _ = make_consumer(tmp)
            consumer.tick()
            os.unlink(consumer.render_file)
            consumer.tick()
            self.assertEqual(file_backend(consumer),
                             'http://192.168.141.2:8080')
            # Foreign edits are overwritten with the rendered document.
            with open(consumer.render_file, 'w') as handle:
                handle.write('garbage')
            consumer.tick()
            self.assertEqual(file_backend(consumer),
                             'http://192.168.141.2:8080')
            consumer.close()

    def test_write_failure_keeps_old_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            captured = {}

            def frozen(nonce):
                if 'snap' not in captured:
                    captured['snap'] = test_ingress.snapshot(
                        nonce, now=fake.now)
                return dict(captured['snap'], nonce=nonce)

            consumer, fake = make_consumer(tmp, fetcher=frozen)
            consumer.tick()
            with open(consumer.render_file, 'rb') as handle:
                before = handle.read()
            original = os.replace

            def boom(*args):
                raise OSError('replace failed')

            os.replace = boom
            try:
                with self.assertRaises(OSError):
                    fake.now += 9
                    consumer.tick()
            finally:
                os.replace = original
            with open(consumer.render_file, 'rb') as handle:
                self.assertEqual(handle.read(), before)
            leftovers = [name for name in
                         os.listdir(os.path.dirname(
                             consumer.render_file))
                         if name.startswith('.nexus-render-')]
            self.assertEqual(leftovers, [])
            consumer.tick()
            self.assertEqual(file_backend(consumer), UNAVAILABLE)
            consumer.close()

    def test_mtls_failure_keeps_then_expires(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = {'fail': False}

            def flaky(nonce):
                if calls['fail']:
                    raise ingress.IngressError('registry-fetch-failed')
                return test_ingress.snapshot(nonce, now=fake.now)

            consumer, fake = make_consumer(tmp, fetcher=flaky)
            consumer.tick()
            token = file_token(consumer)
            calls['fail'] = True
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                consumer.tick()
            self.assertIn('registry-fetch-failed', out.getvalue())
            # Still fresh: the last good document remains.
            self.assertEqual(file_token(consumer), token)
            fake.now += 9
            consumer.tick()
            self.assertEqual(file_backend(consumer), UNAVAILABLE)
            calls['fail'] = False
            consumer.tick()
            self.assertEqual(file_token(consumer), token)
            consumer.close()

    def test_malformed_snapshot_never_reaches_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = {'snapshot': None, 'echo': True}

            def bad_fetcher(nonce):
                snap = state['snapshot']
                # Echo the real nonce so rejection is caused by the
                # malformation under test, not by nonce-mismatch.
                if state['echo'] and type(snap) is dict \
                        and 'nonce' in snap:
                    return dict(snap, nonce=nonce)
                return snap

            consumer, fake = make_consumer(tmp, fetcher=bad_fetcher)
            state['echo'] = False
            state['snapshot'] = test_ingress.snapshot(
                'cd' * 16, now=fake.now)
            consumer.tick()
            self.assertEqual(file_backend(consumer), UNAVAILABLE)
            state['echo'] = True
            for malformed in (
                    {'bad': True},
                    dict(test_ingress.snapshot(
                        test_registry.NONCE, now=fake.now),
                        validUntil=fake.now + 999),
                    test_ingress.snapshot(
                        test_registry.NONCE, now=fake.now,
                        rows=[dict(test_registry.ROUTE,
                                   hostname='evil.example',
                                   backend=dict(BACKEND))])):
                state['snapshot'] = malformed
                consumer.tick()
                self.assertEqual(file_backend(consumer), UNAVAILABLE,
                                 malformed)
            # A good snapshot after the bad ones installs cleanly.
            state['snapshot'] = None

            def good(nonce):
                return test_ingress.snapshot(nonce, now=fake.now)

            consumer.ingress._fetcher = good
            consumer.tick()
            self.assertEqual(file_backend(consumer),
                             'http://192.168.141.2:8080')
            # A forged response afterwards must not displace it.
            consumer.ingress._fetcher = bad_fetcher
            state['snapshot'] = test_ingress.snapshot(
                test_registry.NONCE, now=fake.now,
                rows=[dict(test_registry.ROUTE, backend=dict(
                    BACKEND, address='192.168.140.2'))])
            consumer.tick()
            self.assertEqual(file_backend(consumer),
                             'http://192.168.141.2:8080')
            consumer.close()

    def test_second_consumer_rejected_and_close_denies(self):
        with tempfile.TemporaryDirectory() as tmp:
            consumer, _ = make_consumer(tmp)
            with self.assertRaises(ingress.IngressError) as ctx:
                # Same stateDir: the ingress lock must refuse a second
                # writer even with a different render target.
                make_consumer(tmp, config=dict(
                    consumer.config,
                    renderFile=consumer.render_file + '.two'))
            self.assertEqual(ctx.exception.code, 'ingress-in-use')
            consumer.tick()
            self.assertNotEqual(file_token(consumer), '0' * 64)
            consumer.close()
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rendered = consumer.tick()
            self.assertIn('ingress-closed', out.getvalue())
            self.assertEqual(
                test_ingress.backend_url(json.loads(rendered)),
                UNAVAILABLE)


class GuardTests(unittest.TestCase):
    def test_guard_server_serves_authorize_and_provider_doc(self):
        with tempfile.TemporaryDirectory() as tmp:
            consumer, _ = make_consumer(tmp)
            consumer.tick()
            server = ingress.make_server(consumer.ingress, port=0)
            thread = threading.Thread(target=server.serve_forever,
                                      daemon=True)
            thread.start()
            port = server.server_address[1]

            def get(path):
                conn = http.client.HTTPConnection('127.0.0.1', port,
                                                  timeout=5)
                try:
                    conn.request('GET', path)
                    response = conn.getresponse()
                    return response.status, response.read()
                finally:
                    conn.close()

            try:
                status, body = get('/traefik')
                self.assertEqual(status, 200)
                self.assertEqual(
                    json.loads(body)['http']['services']
                    ['nexus-route-web']['loadBalancer']['servers'][0]
                    ['url'], 'http://192.168.141.2:8080')
                token = test_ingress.route_token()
                status, _ = get('/authorize/route-web/' + token)
                self.assertEqual(status, 200)
                status, _ = get('/authorize/route-web/' + '0' * 64)
                self.assertEqual(status, 503)
                status, _ = get('/unavailable')
                self.assertEqual(status, 503)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
                consumer.close()

    def test_run_loop_converges_and_stops(self):
        with tempfile.TemporaryDirectory() as tmp:
            live = {'backend': dict(BACKEND), 'version': 1}

            def fetcher(nonce):
                return test_ingress.snapshot(
                    nonce, version=live['version'],
                    now=fake.now, backend=live['backend'])

            consumer, fake = make_consumer(tmp, fetcher=fetcher)
            stop = threading.Event()
            thread = threading.Thread(
                target=consumer.run,
                kwargs={'stop': stop, 'interval': 0.02}, daemon=True)
            thread.start()
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    try:
                        if file_backend(consumer) \
                                == 'http://192.168.141.2:8080':
                            break
                    except OSError:
                        pass
                    time.sleep(0.02)
                self.assertEqual(file_backend(consumer),
                                 'http://192.168.141.2:8080')
                live['backend'] = dict(BACKEND, address='192.168.140.2',
                                       hostId='host-a',
                                       instanceId=test_registry.I1,
                                       generation=3)
                live['version'] = 2
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if file_backend(consumer) \
                            == 'http://192.168.140.2:8080':
                        break
                    time.sleep(0.02)
                self.assertEqual(file_backend(consumer),
                                 'http://192.168.140.2:8080')
            finally:
                stop.set()
                thread.join(timeout=10)
                consumer.close()
            self.assertFalse(thread.is_alive())


if __name__ == '__main__':
    unittest.main()
