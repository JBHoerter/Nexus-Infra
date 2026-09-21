"""Authenticated cluster aggregation API. Hosts remain separate trust boundaries."""
import concurrent.futures
import copy
import hashlib
import hmac
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from common import Handler, HTTPError, Server

BASE = '/console'


def password_hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()


class Console:
    def __init__(self, config, state_dir):
        self.config, self.state_dir = config, Path(state_dir)
        self.lock = threading.Lock()
        self.sessions = {}
        self.failures = []
        self.last_actions = {}
        self.hosts = {host['inventory']['id']: {'id': host['inventory']['id'], 'online': False, 'lastSeen': None, 'inventory': host['inventory'], 'observation': None, 'error': 'Awaiting first observation'} for host in config['hosts']}
        self.targets = {host['inventory']['id']: host for host in config['hosts']}
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        auth_file = self.state_dir/'auth.json'
        if not auth_file.exists():
            password = secrets.token_urlsafe(24)
            salt = secrets.token_hex(16)
            auth_file.write_text(json.dumps({'salt': salt, 'hash': password_hash(password, salt)}))
            os.chmod(auth_file, 0o600)
            (self.state_dir/'initial-password').write_text(password+'\n')
            os.chmod(self.state_dir/'initial-password', 0o600)
        self.auth = json.loads(auth_file.read_text())
        with self.db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, time REAL, host TEXT, vm TEXT, action TEXT, result TEXT)')
        credentials = Path(os.environ['CREDENTIALS_DIRECTORY'])
        self.context = ssl.create_default_context(cafile=credentials/'ca')
        self.context.load_cert_chain(credentials/'cert', credentials/'key')

    def db(self):
        return sqlite3.connect(self.state_dir/'audit.sqlite', timeout=5)

    def request_host(self, host_id, path, body=None):
        target = self.targets.get(host_id)
        if target is None:
            raise HTTPError(404, 'Unknown host')
        request = urllib.request.Request(target['agentUrl']+path, data=json.dumps(body).encode() if body is not None else None, headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, context=self.context, timeout=4) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if error.code in (400, 403, 404, 429):
                raise HTTPError(error.code, 'Host rejected the request')
            raise HTTPError(503, 'Host agent unavailable')
        except (OSError, ValueError):
            raise HTTPError(503, 'Host agent unavailable')

    def poll(self, host_id):
        try:
            observation = self.request_host(host_id, '/v1/state')
            if observation.get('schemaVersion') != 1 or observation.get('id') != host_id:
                raise HTTPError(503, 'Host identity/schema mismatch')
            with self.lock:
                self.hosts[host_id].update(online=True, lastSeen=time.time(), observation=observation, error=None)
        except Exception:
            with self.lock:
                self.hosts[host_id].update(online=False, error='Host agent unreachable; showing last observation')

    def loop(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, max(1, len(self.hosts)))) as pool:
            while True:
                list(pool.map(self.poll, self.hosts))
                time.sleep(5)

    def state(self):
        with self.lock:
            hosts = copy.deepcopy(list(self.hosts.values()))
        for host in hosts:
            if host['lastSeen'] is None or time.time()-host['lastSeen'] > 20:
                host['online'] = False
            host['stale'] = not host['online']
        with self.db() as db:
            events = [dict(zip(('id','time','hostId','vmId','action','result'), row)) for row in db.execute('SELECT * FROM events ORDER BY id DESC LIMIT 50')]
        return {'schemaVersion': 1, 'generatedAt': time.time(), 'clusterName': self.config['clusterName'], 'hosts': hosts, 'events': events, 'pollSeconds': 5}

    def login(self, password):
        if not isinstance(password, str) or not 1 <= len(password) <= 256:
            raise HTTPError(400, 'Invalid password')
        now = time.time()
        with self.lock:
            self.failures = [stamp for stamp in self.failures if now-stamp < 60]
            if len(self.failures) >= 8:
                raise HTTPError(429, 'Too many attempts; try again in one minute')
            self.failures.append(now)
            if not hmac.compare_digest(password_hash(password, self.auth['salt']), self.auth['hash']):
                raise HTTPError(401, 'Incorrect password')
            self.failures.clear()
            self.sessions = {key: value for key, value in self.sessions.items() if now-value['last'] < 1800 and now-value['created'] < 28800}
            if len(self.sessions) >= 32:
                self.sessions.pop(next(iter(self.sessions)))
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            self.sessions[token] = {'created': now, 'last': now, 'csrf': csrf}
        return token, csrf

    def session(self, cookie):
        jar = SimpleCookie()
        try:
            jar.load(cookie or '')
            token = jar['nexus_session'].value
        except Exception:
            raise HTTPError(401, 'Sign in to Nexus')
        with self.lock:
            session = self.sessions.get(token)
            if not session or time.time()-session['last'] > 1800 or time.time()-session['created'] > 28800:
                self.sessions.pop(token, None)
                raise HTTPError(401, 'Session expired')
            session['last'] = time.time()
            return token, dict(session)

    def action(self, host_id, vm_id, payload):
        from agent import authorize_action
        target = self.targets.get(host_id)
        if target is None:
            raise HTTPError(404, 'Unknown host')
        authorize_action(target['inventory'], vm_id, payload)
        # No implicit retries for mutations: a timeout may mean a submitted job.
        result = 'accepted'
        try:
            response = self.request_host(host_id, '/v1/vms/'+vm_id+'/actions', payload)
        except HTTPError:
            result = 'rejected-or-unconfirmed'
            raise
        finally:
            with self.db() as db:
                db.execute('INSERT INTO events (time,host,vm,action,result) VALUES (?,?,?,?,?)', (time.time(),host_id,vm_id,payload['action'],result))
                db.execute('DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 500)')
        return response


def main():
    config = json.loads(Path(sys.argv[1]).read_text())
    console = Console(config, os.environ['STATE_DIRECTORY'])
    static = Path(__file__).parent/'static'
    class API(Handler):
        def origin(self):
            if self.headers.get('Origin') not in config['allowedOrigins']:
                raise HTTPError(403, 'Origin not allowed')

        def route(self, method):
            # Protect Host as well as Origin against DNS rebinding.
            allowed_hosts = {urlsplit(origin).netloc for origin in config['allowedOrigins']}
            if self.headers.get('Host') not in allowed_hosts:
                # Private liveness endpoint carries no data and no authority.
                if method == 'GET' and self.path == BASE+'/healthz':
                    return self.send(200, {'status': 'ok'})
                raise HTTPError(403, 'Host not allowed')
            if method == 'GET' and self.path in (BASE, BASE+'/'):
                if self.path == BASE:
                    return self.send(302, b'', 'text/plain', {'Location': BASE+'/'})
                return self.send(200, (static/'index.html').read_bytes(), 'text/html; charset=utf-8')
            assets = {BASE+'/app.js': ('app.js','text/javascript; charset=utf-8'), BASE+'/style.css': ('style.css','text/css; charset=utf-8')}
            if method == 'GET' and self.path in assets:
                file, mime = assets[self.path]
                return self.send(200, (static/file).read_bytes(), mime)
            if method == 'GET' and self.path == BASE+'/healthz':
                return self.send(200, {'status': 'ok'})
            if method == 'POST':
                self.origin()
            if method == 'POST' and self.path == BASE+'/api/v1/session':
                token, csrf = console.login(self.body(['password'])['password'])
                secure = '; Secure' if config.get('secureCookies') else ''
                return self.send(200, {'csrf': csrf}, headers={'Set-Cookie': f'nexus_session={token}; Path=/console; HttpOnly; SameSite=Strict; Max-Age=28800'+secure})
            token, session = console.session(self.headers.get('Cookie'))
            if method == 'GET' and self.path == BASE+'/api/v1/session':
                return self.send(200, {'csrf': session['csrf']})
            if method == 'GET' and self.path == BASE+'/api/v1/state':
                return self.send(200, console.state())
            if method == 'POST':
                if not hmac.compare_digest(self.headers.get('X-Nexus-CSRF', ''), session['csrf']):
                    raise HTTPError(403, 'Invalid CSRF token')
                if self.path == BASE+'/api/v1/logout':
                    with console.lock:
                        console.sessions.pop(token, None)
                    return self.send(200, {'ok': True}, headers={'Set-Cookie':'nexus_session=; Path=/console; HttpOnly; SameSite=Strict; Max-Age=0'})
                match = re.fullmatch(BASE+r'/api/v1/hosts/([a-zA-Z0-9_-]+)/vms/([a-zA-Z0-9_-]+)/actions', self.path)
                if match:
                    return self.send(202, console.action(match[1], match[2], self.body(['action'], 128)))
            raise HTTPError(404, 'Unknown endpoint')
    threading.Thread(target=console.loop, daemon=True).start()
    Server((config['listenAddress'], config['port']), API).serve_forever()

if __name__ == '__main__':
    main()
