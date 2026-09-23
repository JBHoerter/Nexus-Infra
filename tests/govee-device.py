import json
import selectors
import socket
import uuid
from pathlib import Path

GROUP = '239.255.255.250'
ADDRESS = '192.168.100.1'
DEVICE = '00:00:00:00:00:00:00:42'
state = {'on': True, 'sawMulticast': False, 'lastCommandSource': None, 'generation': uuid.uuid4().hex}
status_path = Path('/run/govee-fixture.json')
selector = selectors.DefaultSelector()
scan = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
scan.bind(('0.0.0.0', 4001))
scan.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(GROUP) + socket.inet_aton(ADDRESS))
scan.setsockopt(socket.IPPROTO_IP, 8, 1)
command = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
command.bind((ADDRESS, 4003))
selector.register(scan, selectors.EVENT_READ)
selector.register(command, selectors.EVENT_READ)


def persist():
    temporary = status_path.with_suffix('.tmp')
    temporary.write_text(json.dumps(state))
    temporary.replace(status_path)


def reply(peer, cmd, data):
    command.sendto(json.dumps({'msg': {'cmd': cmd, 'data': data}}).encode(), (peer[0], 4002))


def status():
    return {'onOff': int(state['on']), 'brightness': 42, 'color': {'r': 1, 'g': 2, 'b': 3}, 'colorTemInKelvin': 4000}


persist()
while True:
    for key, _ in selector.select():
        raw, ancillary, flags, peer = key.fileobj.recvmsg(4096, 128)
        if peer[0] != '192.168.100.2':
            continue
        message = json.loads(raw)['msg']
        cmd = message['cmd']
        if key.fileobj is scan and cmd == 'scan':
            state['sawMulticast'] |= any(level == socket.IPPROTO_IP and kind == 8 and len(data) >= 12 and socket.inet_ntoa(data[8:12]) == GROUP for level, kind, data in ancillary)
            reply(peer, 'scan', {'ip': ADDRESS, 'device': DEVICE, 'sku': 'H610A', 'bleVersionHard': '1.0', 'bleVersionSoft': '1.0', 'wifiVersionHard': '1.0', 'wifiVersionSoft': '1.0'})
        elif key.fileobj is command and cmd == 'devStatus':
            reply(peer, 'devStatus', status())
        elif key.fileobj is command and cmd == 'turn':
            assert message['data']['value'] in (0, 1)
            state['on'] = bool(message['data']['value'])
            state['lastCommandSource'] = peer[0]
            reply(peer, 'devStatus', status())
        persist()
