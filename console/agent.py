"""Per-host observations and allowlisted VM lifecycle actions. Never runs a shell."""
import concurrent.futures
import copy
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from common import Handler, HTTPError, Server

ACTIONS = frozenset(('start', 'stop', 'restart'))


def authorize_action(inventory, vm_id, payload):
    if set(payload) != {'action'} or not isinstance(payload['action'], str) or payload['action'] not in ACTIONS:
        raise HTTPError(400, 'Unsupported action')
    vm = next((vm for vm in inventory['vms'] if vm['id'] == vm_id), None)
    if vm is None:
        raise HTTPError(404, 'Unknown VM')
    if not vm.get('controllable', False):
        raise HTTPError(403, 'Infrastructure workload is protected')
    return payload['action'], 'microvm@' + vm_id + '.service'


def command(*args):
    return subprocess.check_output(args, text=True, timeout=5, stderr=subprocess.DEVNULL).strip()


def unit_properties(names):
    fields = 'Id,ActiveState,SubState,MainPID,MemoryCurrent,CPUUsageNSec,ActiveEnterTimestampMonotonic,Result'
    text = command('systemctl', 'show', '--property=' + fields, *names)
    return {row['Id']: row for block in text.split('\n\n')
            if (row := dict(line.split('=', 1) for line in block.splitlines() if '=' in line)) and 'Id' in row}


def integer(value):
    try:
        number = int(value)
        return number if 0 <= number < 2**63 else None
    except (ValueError, TypeError):
        return None


class Agent:
    def __init__(self, config):
        self.config = config
        self.lock = threading.Lock()
        self.snapshot = None
        self.previous_cpu = None
        self.previous_vm = {}
        self.last_action = {}
        self.action_lock = threading.Lock()

    def sample(self):
        inventory = self.config['inventory']
        now = time.time()
        ticks = list(map(int, Path('/proc/stat').read_text().splitlines()[0].split()[1:9]))
        total, idle = sum(ticks), ticks[3] + ticks[4]
        cpu = None
        if self.previous_cpu:
            dt, di = total-self.previous_cpu[0], idle-self.previous_cpu[1]
            cpu = round(100*(dt-di)/dt, 1) if dt > 0 else None
        self.previous_cpu = total, idle
        mem = {line.split(':')[0]: int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines()}
        model = next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), os.uname().machine)
        vm_records = copy.deepcopy(inventory['vms'])
        known = {vm['id'] for vm in vm_records}
        # Surface running/unloaded declarations independently; no actions on discoveries.
        for line in command('systemctl', 'list-units', 'microvm@*.service', '--all', '--plain', '--no-legend', '--no-pager').splitlines():
            match = re.match(r'microvm@([a-zA-Z0-9_-]+)\.service\s', line)
            if match and match[1] not in known:
                vm_records.append({'id': match[1], 'declared': False, 'controllable': False, 'role': 'unmanaged', 'ip': None, 'vcpu': None, 'memoryMiB': None, 'volumes': []})
        names = ['microvm@'+vm['id']+'.service' for vm in vm_records] + inventory['services']
        props = unit_properties(names)
        for vm in vm_records:
            unit = props.get('microvm@'+vm['id']+'.service', {})
            state = unit.get('ActiveState', 'unknown')
            vm.update({'hostId': inventory['id'], 'state': {'active':'running', 'inactive':'stopped'}.get(state, state), 'subState': unit.get('SubState'), 'memoryBytes': integer(unit.get('MemoryCurrent')), 'activation': unit.get('ActiveEnterTimestampMonotonic'), 'pid': integer(unit.get('MainPID')), 'cpuPercent': None})
            usage = integer(unit.get('CPUUsageNSec'))
            previous = self.previous_vm.get(vm['id'])
            if usage is not None and previous and previous[2] == vm['activation'] and now > previous[0]:
                vm['cpuPercent'] = round(max(0, (usage-previous[1])/(now-previous[0])/1e7), 1)
            if usage is not None:
                self.previous_vm[vm['id']] = now, usage, vm['activation']
            state_dir = Path('/var/lib/microvms')/vm['id']
            vm['runnerMatches'] = (os.path.realpath(state_dir/'booted') == os.path.realpath(state_dir/'current')) if state == 'active' else None
            vm['drift'] = not vm.get('declared', True) or (vm.get('autostart', True) and vm['state'] != 'running') or vm['runnerMatches'] is False
        backends = []
        for backend in inventory['backends']:
            item = dict(backend)
            try:
                stat = os.statvfs(backend['mountPoint'])
                item.update(capacityBytes=stat.f_blocks*stat.f_frsize, usedBytes=(stat.f_blocks-stat.f_bfree)*stat.f_frsize, availableBytes=stat.f_bavail*stat.f_frsize, mounted=os.path.ismount(backend['mountPoint']))
            except OSError:
                item.update(capacityBytes=None, usedBytes=None, availableBytes=None, mounted=False)
            backends.append(item)
        def check(vm):
            if not vm.get('healthUrl'):
                return None
            try:
                with urllib.request.urlopen(vm['healthUrl'], timeout=1.5) as response:
                    return {'state': 'healthy' if 200 <= response.status < 400 else 'unhealthy', 'status': response.status}
            except Exception:
                return {'state': 'unreachable'}
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for vm, health in zip(vm_records, pool.map(check, vm_records)):
                vm['health'] = health
        interfaces = json.loads(command('ip', '-j', 'address', 'show'))
        snapshot = {
            'schemaVersion': 1, 'sampledAt': now, 'id': inventory['id'], 'hostname': os.uname().nodename,
            'machine': {'cpuModel': model, 'logicalCPUs': os.cpu_count(), 'architecture': os.uname().machine, 'kernel': os.uname().release, 'system': os.path.realpath('/run/current-system')},
            'metrics': {'cpuPercent': cpu, 'memoryTotalBytes': mem['MemTotal'], 'memoryUsedBytes': mem['MemTotal']-mem['MemAvailable'], 'uptimeSeconds': float(Path('/proc/uptime').read_text().split()[0]), 'load': list(os.getloadavg())},
            'vms': vm_records, 'backends': backends, 'network': inventory['network'],
            'interfaces': [{'name': nic['ifname'], 'state': nic['operstate'], 'addresses': [a['local']+'/'+str(a['prefixlen']) for a in nic.get('addr_info', [])]} for nic in interfaces],
            'services': [{'id': name, 'state': props.get(name, {}).get('ActiveState', 'unknown')} for name in inventory['services']],
        }
        with self.lock:
            self.snapshot = snapshot

    def loop(self):
        while True:
            try:
                self.sample()
            except Exception as error:
                print(json.dumps({'event': 'sample-failed', 'type': type(error).__name__}), flush=True)
            time.sleep(5)

    def action(self, vm_id, payload):
        action, unit = authorize_action(self.config['inventory'], vm_id, payload)
        with self.action_lock:
            now = time.monotonic()
            if now-self.last_action.get(vm_id, -100) < 5:
                raise HTTPError(429, 'Wait for the previous action to settle')
            self.last_action[vm_id] = now
            subprocess.run(['systemctl', '--no-ask-password', '--no-block', action, unit], check=True, timeout=5, capture_output=True)
        print(json.dumps({'event': 'vm-action', 'vm': vm_id, 'action': action, 'result': 'accepted'}), flush=True)
        return {'accepted': True, 'vmId': vm_id, 'action': action}


def main():
    config = json.loads(Path(sys.argv[1]).read_text())
    agent = Agent(config)
    class API(Handler):
        def route(self, method):
            if method == 'GET' and self.path == '/v1/state':
                with agent.lock:
                    state = copy.deepcopy(agent.snapshot)
                if not state or time.time()-state['sampledAt'] > 20:
                    raise HTTPError(503, 'No fresh host observation available')
                return self.send(200, state)
            match = re.fullmatch(r'/v1/vms/([a-zA-Z0-9_-]+)/actions', self.path)
            if method == 'POST' and match:
                return self.send(202, agent.action(match[1], self.body(['action'], 128)))
            raise HTTPError(404, 'Unknown endpoint')
    credentials = Path(os.environ['CREDENTIALS_DIRECTORY'])
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=credentials/'ca')
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(credentials/'cert', credentials/'key')
    server = Server((config['listenAddress'], config['port']), API)
    # Wrap each accepted socket with a handshake timeout, not the listener.
    original = server.get_request
    def accept():
        sock, address = original()
        try:
            return context.wrap_socket(sock, server_side=True), address
        except Exception:
            sock.close()
            raise
    server.get_request = accept
    threading.Thread(target=agent.loop, daemon=True).start()
    server.serve_forever()

if __name__ == '__main__':
    main()
