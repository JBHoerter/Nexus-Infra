import argparse
import email.policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import formatdate
import hashlib
import imaplib
import json
import os
from pathlib import Path
import secrets
import shutil
import smtplib
import ssl
import subprocess
import time
import urllib.request
import uuid

WORK = Path('/work/mailcow')
STATE = Path('/work/mailcow-lab-state.json')
RESOLVED = WORK / 'nexus-lab-compose.json'
HOSTNAME = 'mail.nexus.test'
DOMAIN = 'nexus.test'
USERNAME = 'probe@nexus.test'


def guard():
    if Path('/etc/nexus-mailcow-lab-enabled').read_text().strip() != 'synthetic-only':
        raise RuntimeError('Not a Nexus synthetic mail lab')
    if Path('/proc/self/uid_map').read_text().split() != ['0', '65536', '65536']:
        raise RuntimeError('Unexpected user namespace; refusing to operate')


def state():
    return json.loads(STATE.read_text())


def redact(value):
    if STATE.exists():
        for secret in state().get('secrets', {}).values():
            if secret:
                value = value.replace(secret, '<redacted>')
    return value


def run(args, timeout=60):
    result = subprocess.run(args, cwd=WORK if WORK.exists() else '/work', capture_output=True, text=True, errors='replace', timeout=timeout)
    if result.returncode:
        raise RuntimeError(redact(f'{args[0]} failed ({result.returncode}): {result.stderr[-3000:]}'))
    return result.stdout


def compose(*args, timeout=60):
    return run(['docker-compose', '--file', str(RESOLVED), '--project-name', 'nexusmailcow', *args], timeout)


def assert_compose_roundtrip(expected, actual):
    if set(expected['services']) != set(actual['services']):
        raise RuntimeError('Rendered Compose changed its service set; refusing to start')
    for name, service in expected['services'].items():
        for field in ('image', 'environment', 'labels', 'command', 'entrypoint', 'volumes', 'privileged', 'cap_add', 'ulimits'):
            before = service.get(field)
            after = actual['services'][name].get(field)
            if field == 'privileged':
                before = False if before is None else before
                after = False if after is None else after
            elif field == 'volumes':
                before = [] if before is None else before
                after = [] if after is None else after
            if before != after:
                raise RuntimeError(f'Rendered Compose changed {name} field {field}; refusing to start')


def ensure_dhparams(source, tls):
    target = tls / 'dhparams.pem'
    expected = source.read_bytes()
    if target.is_symlink():
        raise RuntimeError('Unexpected DH parameter symlink; refusing to overwrite')
    if target.exists():
        if target.read_bytes() != expected:
            raise RuntimeError('Existing DH parameters differ from the pinned public asset')
    else:
        shutil.copyfile(source, target)
    target.chmod(0o644)
    run(['openssl', 'dhparam', '-in', str(target), '-check', '-noout'])


def ensure_app_info(work, revision):
    target = work / 'data/web/inc/app_info.inc.php'
    info = {'MAILCOW_GIT_VERSION': 'nexus-lab', 'MAILCOW_LAST_GIT_VERSION': '', 'MAILCOW_GIT_OWNER': 'mailcow', 'MAILCOW_GIT_REPO': 'mailcow-dockerized', 'MAILCOW_GIT_URL': 'https://github.com/mailcow/mailcow-dockerized', 'MAILCOW_GIT_COMMIT': revision, 'MAILCOW_GIT_COMMIT_DATE': '', 'MAILCOW_BRANCH': 'pinned-lab'}
    expected = '<?php\n' + ''.join(f'${key} = {json.dumps(value)};\n' for key, value in info.items()) + '$MAILCOW_UPDATEDAT = 0;\n'
    if target.is_symlink():
        raise RuntimeError('Unexpected public metadata symlink; refusing to change permissions')
    if target.exists():
        if target.read_text() != expected:
            raise RuntimeError('Public metadata differs from the expected lab revision')
    else:
        target.write_text(expected)
    target.chmod(0o644)


def bootstrap(artifacts, digest):
    os.umask(0o077)
    if STATE.exists():
        existing = state()
        if existing.get('artifactDigest') != digest or not existing.get('initialized'):
            raise RuntimeError('Existing lab state is incomplete or uses different artifacts; refusing to overwrite it')
        ensure_dhparams(Path(artifacts['source']) / 'data/assets/ssl-example/dhparams.pem', WORK / 'data/assets/ssl')
        ensure_app_info(WORK, artifacts['sourceRevision'])
        return
    if WORK.exists():
        raise RuntimeError('Existing work directory has no complete lab manifest; refusing to overwrite it')
    shutil.copytree(artifacts['source'], WORK, symlinks=True)
    for root, directories, files in os.walk(WORK):
        Path(root).chmod(Path(root).stat().st_mode | 0o700)
        for name in files:
            path = Path(root) / name
            if not path.is_symlink():
                path.chmod(path.stat().st_mode | 0o600)
    private = {key: secrets.token_hex(24) for key in ('DBPASS', 'DBROOT', 'REDISPASS', 'API_KEY')}
    private['SOGO_URL_ENCRYPTION_KEY'] = secrets.token_hex(8)
    private['MAILBOX_PASSWORD'] = secrets.token_urlsafe(24) + 'Aa1!'
    record = {'artifactDigest': digest, 'sourceRevision': artifacts['sourceRevision'], 'bootstrapVersion': artifacts['bootstrapVersion'], 'secrets': private, 'initialized': False, 'messageId': f'<{uuid.uuid4()}@nexus.test>', 'messageBody': f'Nexus isolated delivery probe {uuid.uuid4()}'}
    STATE.write_text(json.dumps(record))
    cfg = {
        'MAILCOW_HOSTNAME': HOSTNAME, 'MAILCOW_PASS_SCHEME': 'BLF-CRYPT',
        'DBNAME': 'mailcow', 'DBUSER': 'mailcow', 'TZ': 'Etc/UTC',
        'COMPOSE_PROJECT_NAME': 'nexusmailcow', 'DOCKER_COMPOSE_VERSION': 'standalone',
        'HTTP_BIND': '127.0.0.1', 'HTTP_PORT': '80', 'HTTPS_BIND': '127.0.0.1', 'HTTPS_PORT': '443', 'HTTP_REDIRECT': 'n',
        'IPV4_NETWORK': '172.22.1', 'IPV6_NETWORK': 'fd4d:6169:6c63:6f77::/64', 'ENABLE_IPV6': 'false',
        'SKIP_LETS_ENCRYPT': 'y', 'ADDITIONAL_SAN': '', 'SKIP_UNBOUND_HEALTHCHECK': 'n',
        'SKIP_CLAMD': 'n', 'SKIP_OLEFY': 'n', 'SKIP_SOGO': 'n', 'SKIP_FTS': 'n',
        'USE_WATCHDOG': 'y', 'WATCHDOG_NOTIFY_EMAIL': '', 'WATCHDOG_NOTIFY_WEBHOOK': '',
        'WATCHDOG_NOTIFY_START': 'n', 'WATCHDOG_NOTIFY_BAN': 'n', 'WATCHDOG_EXTERNAL_CHECKS': 'n',
        'API_ALLOW_FROM': '127.0.0.1,172.22.1.1', 'MAILCOW_REPLICA_IP': '',
        'DISABLE_NETFILTER_ISOLATION_RULE': 'n', 'MAILDIR_SUB': 'Maildir', 'FTS_HEAP': '128', 'FTS_PROCS': '1',
    }
    cfg.update({key: value for key, value in private.items() if key != 'MAILBOX_PASSWORD'})
    (WORK / 'mailcow.conf').write_text(''.join(f'{key}={value}\n' for key, value in sorted(cfg.items())))
    env_link = WORK / '.env'
    if not env_link.is_symlink():
        raise RuntimeError('Pinned source lacks expected .env symlink')
    if env_link.resolve() != WORK / 'mailcow.conf':
        raise RuntimeError('Unexpected .env target')
    ca = WORK / 'lab-ca'
    ca.mkdir()
    tls = WORK / 'data/assets/ssl'
    tls.mkdir(parents=True, exist_ok=True)
    ensure_dhparams(Path(artifacts['source']) / 'data/assets/ssl-example/dhparams.pem', tls)
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '2', '-subj', '/CN=Nexus isolated lab CA', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', str(ca / 'key.pem'), '-out', str(ca / 'cert.pem')])
    run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + HOSTNAME, '-keyout', str(tls / 'key.pem'), '-out', str(ca / 'server.csr')])
    extensions = ca / 'server.ext'
    extensions.write_text(f'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:{HOSTNAME}\n')
    run(['openssl', 'x509', '-req', '-in', str(ca / 'server.csr'), '-CA', str(ca / 'cert.pem'), '-CAkey', str(ca / 'key.pem'), '-CAcreateserial', '-days', '2', '-sha256', '-extfile', str(extensions), '-out', str(tls / 'cert.pem')])
    (tls / 'cert.pem').write_bytes((tls / 'cert.pem').read_bytes() + (ca / 'cert.pem').read_bytes())
    run(['openssl', 'verify', '-x509_strict', '-CAfile', str(ca / 'cert.pem'), str(tls / 'cert.pem')])
    with (WORK / 'data/conf/unbound/unbound.conf').open('a') as stream:
        stream.write('\nserver:\n  local-zone: "nexus.test." static\n  local-data: "nexus.test. 300 IN MX 10 mail.nexus.test."\n  local-data: "mail.nexus.test. 300 IN A 172.22.1.253"\n')
    ensure_app_info(WORK, artifacts['sourceRevision'])
    for image in artifacts['images'].values():
        run(['docker', 'load', '--input', image['archive']], timeout=600)
    rendered = json.loads(run(['docker-compose', '--env-file', 'mailcow.conf', '--file', 'docker-compose.yml', '--project-name', 'nexusmailcow', 'config', '--format', 'json']))
    if set(rendered['services']) != set(artifacts['images']):
        raise RuntimeError('Source service set differs from the frozen image set')
    for name, service in rendered['services'].items():
        service['image'] = artifacts['images'][name]['reference']
        service['pull_policy'] = 'never'
    netfilter = rendered['services']['netfilter-mailcow']
    netfilter['privileged'] = False
    netfilter['cap_add'] = ['NET_ADMIN', 'NET_RAW']
    netfilter['command'] = ['python', '-u', '/app/main.py', 'nftables']
    netfilter['volumes'] = [mount for mount in netfilter.get('volumes', []) if mount.get('target') != '/lib/modules']
    network = rendered['networks']['mailcow-network']
    network['enable_ipv6'] = False
    network['ipam']['config'] = [entry for entry in network['ipam']['config'] if ':' not in entry['subnet']]
    if any(service.get('privileged') for service in rendered['services'].values()):
        raise RuntimeError('Unexpected privileged inner service')
    RESOLVED.write_text(json.dumps(rendered))
    roundtrip = json.loads(compose('config', '--format', 'json'))
    assert_compose_roundtrip(rendered, roundtrip)
    record['certificateDigest'] = hashlib.sha256((tls / 'cert.pem').read_bytes()).hexdigest()
    record['initialized'] = True
    STATE.write_text(json.dumps(record))


def tls_context():
    return ssl.create_default_context(cafile=str(WORK / 'lab-ca/cert.pem'))


def api(path, payload=None):
    key = state()['secrets']['API_KEY']
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request('https://' + HOSTNAME + '/api/v1/' + path, data=data, headers={'X-API-Key': key, 'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, context=tls_context(), timeout=20) as response:
        result = json.load(response)
    entries = result if isinstance(result, list) else [result]
    if any(isinstance(item, dict) and item.get('type') in ('danger', 'error') for item in entries):
        raise RuntimeError('Lab API rejected ' + path)
    if payload is not None and not any(isinstance(item, dict) and item.get('type') == 'success' for item in entries):
        raise RuntimeError('Lab API did not confirm ' + path)
    return result


def service_states():
    ids = compose('ps', '--all', '--quiet').split()
    rows = []
    template = '{"service":{{json (index .Config.Labels "com.docker.compose.service")}},"id":{{json .Id}},"startedAt":{{json .State.StartedAt}},"restartCount":{{.RestartCount}},"state":{{json .State.Status}},"health":{{with (index .State "Health")}}{{json .Status}}{{else}}"none"{{end}},"privileged":{{.HostConfig.Privileged}},"runtime":{{json .HostConfig.Runtime}}}'
    for identifier in ids:
        rows.append(json.loads(run(['docker', 'inspect', '--format', template, identifier])))
    return rows


def services_ready(rows, expected_services):
    required_health = {'unbound-mailcow', 'clamd-mailcow'}
    return (
        len(rows) == len(expected_services)
        and {row['service'] for row in rows} == set(expected_services)
        and all(
            row['state'] == 'running'
            and row['privileged'] is False
            and row['runtime'] == 'crun'
            and (row['health'] == 'healthy' if row['service'] in required_health else row['health'] in ('none', 'healthy'))
            for row in rows
        )
    )


def domain_list_response_ready(value):
    return value == {} or (isinstance(value, list) and all(isinstance(item, dict) for item in value))


def ready(artifacts):
    deadline = time.monotonic() + 1800
    stable = None
    previous_generation = None
    latest = []
    api_error = None
    while time.monotonic() < deadline:
        latest = service_states()
        generation = tuple(sorted((row['service'], row['id'], row['startedAt'], row['restartCount']) for row in latest))
        good = services_ready(latest, artifacts['images'])
        if good:
            try:
                good = domain_list_response_ready(api('get/domain/all'))
                api_error = None if good else 'Unexpected domain-list response shape'
            except (OSError, ValueError, RuntimeError) as error:
                api_error = type(error).__name__ + ': ' + redact(str(error))[:400]
                good = False
        if good:
            if stable is None or generation != previous_generation:
                stable = time.monotonic()
            if time.monotonic() - stable >= 10:
                return
        else:
            stable = None
        previous_generation = generation
        time.sleep(2)
    raise RuntimeError('Lab readiness timed out: ' + json.dumps({'services': latest, 'apiError': api_error}))


def exercise():
    api('add/domain', {'domain': DOMAIN, 'description': 'Nexus isolated lab', 'aliases': 5, 'mailboxes': 5, 'defquota': 128, 'maxquota': 1024, 'quota': 2048, 'active': 1, 'backupmx': 0, 'relay_all_recipients': 0, 'relay_unknown_only': 0, 'restart_sogo': 0})
    password = state()['secrets']['MAILBOX_PASSWORD']
    api('add/mailbox', {'local_part': 'probe', 'domain': DOMAIN, 'name': 'Nexus lab probe', 'password': password, 'password2': password, 'quota': 128, 'active': 1, 'authsource': 'mailcow', 'force_pw_update': 0, 'imap_access': 1, 'smtp_access': 1, 'sogo_access': 1})
    record = state()
    message = EmailMessage()
    message['From'] = USERNAME
    message['To'] = USERNAME
    message['Subject'] = 'Nexus isolated delivery check'
    message['Message-ID'] = record['messageId']
    message['Date'] = formatdate(usegmt=True)
    message.set_content(record['messageBody'])
    with smtplib.SMTP_SSL(HOSTNAME, 465, context=tls_context(), timeout=30) as smtp:
        smtp.login(USERNAME, password)
        if smtp.send_message(message):
            raise RuntimeError('Lab recipient was refused')


def verify():
    record = state()
    if hashlib.sha256((WORK / 'data/assets/ssl/cert.pem').read_bytes()).hexdigest() != record['certificateDigest']:
        raise RuntimeError('Lab certificate changed unexpectedly')
    with urllib.request.urlopen('https://' + HOSTNAME + '/', context=tls_context(), timeout=20) as response:
        if response.status != 200:
            raise RuntimeError('Lab HTTPS frontend not ready')
    deadline = time.monotonic() + 180
    while True:
        try:
            with imaplib.IMAP4_SSL(HOSTNAME, 993, ssl_context=tls_context(), timeout=20) as imap:
                imap.login(USERNAME, record['secrets']['MAILBOX_PASSWORD'])
                if imap.select('INBOX', readonly=True)[0] != 'OK':
                    raise RuntimeError('Lab INBOX unavailable')
                status, found = imap.search(None, 'HEADER', 'Message-ID', record['messageId'])
                if status != 'OK' or not found[0].split():
                    raise RuntimeError('Lab message not delivered yet')
                status, content = imap.fetch(found[0].split()[-1], '(RFC822)')
                payload = next(item[1] for item in content if isinstance(item, tuple))
                message = BytesParser(policy=email.policy.default).parsebytes(payload)
                body = message.get_body(preferencelist=('plain',))
                if status != 'OK' or body is None or body.get_content().strip() != record['messageBody']:
                    raise RuntimeError('Lab message content differs')
                return
        except (OSError, imaplib.IMAP4.error, RuntimeError) as error:
            if time.monotonic() >= deadline:
                raise RuntimeError('Lab IMAP verification failed') from error
            time.sleep(2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('bootstrap', 'start', 'ready', 'exercise', 'verify'))
    parser.add_argument('artifacts')
    args = parser.parse_args()
    guard()
    artifact_path = Path(args.artifacts)
    artifacts = json.loads(artifact_path.read_text())
    if artifacts.get('bootstrapVersion') != 2:
        raise RuntimeError('Unsupported lab bootstrap version')
    digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    if args.action != 'bootstrap':
        current = state()
        if not current.get('initialized') or current.get('artifactDigest') != digest:
            raise RuntimeError('Lab state does not match the requested artifacts')
    if args.action == 'bootstrap':
        bootstrap(artifacts, digest)
    elif args.action == 'start':
        compose('up', '--detach', timeout=600)
    elif args.action == 'ready':
        ready(artifacts)
    elif args.action == 'exercise':
        exercise()
    else:
        verify()
    print(json.dumps({'action': args.action, 'status': 'passed'}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit(redact(str(error)))
