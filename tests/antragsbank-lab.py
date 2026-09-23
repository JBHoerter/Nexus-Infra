import json
import os
import shutil
import sqlite3
import sys
from http.cookiejar import CookieJar
from pathlib import Path
from urllib import error, parse, request

BASE = 'http://192.168.100.2:8000'
DATA = Path('/app/data')
CONTROLS = Path('/lab/event_state_controls.json')
EVENT_ID = 'nexus-lab-event'
CREATED_ID = 'nexus-lab-event-01'
ARCHIVE_ID = 'nexus-lab-archive'
EXPECTED_CREATED = {
    'id': CREATED_ID,
    'seq': 1,
    'title': 'Synthetic API proposal',
    'lines': [{'type': 'paragraph', 'content': 'Acknowledged synthetic content'}],
    'footnotes': ['Synthetic footnote'],
    'keywords': ['synthetic'],
}
EXPECTED_ARCHIVE = {
    'proposal_id': ARCHIVE_ID,
    'year': 2026,
    'seq': 1,
    'title': 'Synthetic archive',
    'lines': [{'type': 'paragraph', 'content': 'Persisted archive content'}],
    'footnotes': [],
    'keywords': ['synthetic'],
}
ORGANISATION_BYTES = b'{"name":"Nexus Lab","groups":[],"roles":[]}\n'


def _expect_exact(record, expected):
    if not isinstance(record, dict):
        raise AssertionError('record is not a JSON object')
    for key, value in expected.items():
        actual = record.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            assert type(actual) is int and actual == value, (key, actual)
        else:
            assert actual == value, (key, actual)
    return record


def expect_event_list(payload):
    events = json.loads(payload)
    if not isinstance(events, list):
        raise AssertionError('event list is not a JSON array')
    matches = [entry for entry in events if isinstance(entry, dict) and entry.get('id') == EVENT_ID]
    if not matches:
        raise AssertionError(f'{EVENT_ID} missing from event list')
    return matches[0]


def expect_created(payload):
    return _expect_exact(json.loads(payload), EXPECTED_CREATED)


def expect_proposal_list(payload):
    records = json.loads(payload)
    if not isinstance(records, list):
        raise AssertionError('proposal list is not a JSON array')
    matches = [entry for entry in records if isinstance(entry, dict) and entry.get('id') == CREATED_ID]
    if len(matches) != 1:
        raise AssertionError(f'{CREATED_ID} matched {len(matches)} entries')
    return _expect_exact(matches[0], EXPECTED_CREATED)


def expect_archive(payload):
    return _expect_exact(json.loads(payload), EXPECTED_ARCHIVE)


def _app_imports():
    if '/app' not in sys.path:
        sys.path.insert(0, '/app')


def _open(opener, method, path, body=None, form=None):
    data = None
    headers = {}
    if form is not None:
        data = parse.urlencode(form).encode()
    elif body is not None:
        data = json.dumps(body).encode()
        headers['Content-Type'] = 'application/json'
    req = request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        response = opener.open(req, timeout=20)
        return response.status, response.geturl(), response.read()
    except error.HTTPError as exc:
        return exc.code, exc.geturl(), exc.read()


def _login(opener):
    status, url, _ = _open(opener, 'POST', '/login/account', form={
        'email': 'admin@example.test',
        'password': os.environ['LAB_PASSWORD'],
        'next': '/',
    })
    assert status == 200, status
    assert '/login' not in url and 'error=' not in url, url


def seed():
    _app_imports()
    from datetime import date
    from sqlmodel import Session
    from backend.modules.analytics.db import init_analytics, record_hit
    from backend.modules.shared.auth import hash_password
    from backend.modules.shared.chroma_client import get_client
    from backend.modules.shared.db.engine import get_general_engine, get_proposals_engine, init_db
    from backend.modules.shared.db.fts import populate_fts
    from backend.modules.shared.db.models import Event, Proposal, User

    DATA.joinpath('proposals').mkdir(parents=True, exist_ok=True)
    init_db()
    init_analytics()
    with Session(get_general_engine()) as session:
        session.add(User(id='nexus-lab-admin', email='admin@example.test', full_name='Nexus Lab', system_role='admin', account_type='personal', password_hash=hash_password(os.environ['LAB_PASSWORD']), email_verified=True, is_active=True, force_password_change=False))
        session.add(Event(id=EVENT_ID, title='Synthetic Event', type='assembly', status='active', location='Lab', start_date=date(2026, 1, 1)))
        session.commit()
    with Session(get_proposals_engine()) as session:
        session.add(Proposal(id=ARCHIVE_ID, year=2026, seq=1, title='Synthetic archive', lines=EXPECTED_ARCHIVE['lines'], footnotes=[], keywords=['synthetic']))
        session.commit()
        populate_fts(ARCHIVE_ID, session)
    record_hit('/nexus-lab-before-restore', 201, '192.0.2.3', True, 'synthetic-observer')
    collection = get_client().get_or_create_collection('nexus-lab', embedding_function=None)
    collection.add(ids=['vector-one'], embeddings=[[1.0, 2.0, 3.0]], documents=['Synthetic vector payload'])
    shutil.copyfile(CONTROLS, DATA / 'event_state_controls.json')
    (DATA / 'organisation.json').write_bytes(ORGANISATION_BYTES)


def verify_state():
    _app_imports()
    from sqlmodel import Session
    from backend.modules.shared.chroma_client import get_client
    from backend.modules.shared.db.engine import get_general_engine, get_proposals_engine
    from backend.modules.shared.db.models import Event, EventProposal, Proposal, User

    databases = {name: DATA / name for name in ('general.db', 'proposals/proposals.db', 'analytics.db')}
    for name, path in databases.items():
        assert path.is_file(), f'{name} missing'

    with Session(get_general_engine()) as session:
        user = session.get(User, 'nexus-lab-admin')
        assert user is not None and user.system_role == 'admin' and user.email == 'admin@example.test' and user.is_active is True and user.email_verified is True and user.force_password_change is False
        event = session.get(Event, EVENT_ID)
        assert event is not None and event.title == 'Synthetic Event' and event.status == 'active' and event.start_date.isoformat() == '2026-01-01'
        assert event.proposal_ids.count(CREATED_ID) == 1, event.proposal_ids
        created = session.get(EventProposal, CREATED_ID)
        assert created is not None
        assert created.title == EXPECTED_CREATED['title'] and type(created.seq) is int and created.seq == 1
        assert created.lines == EXPECTED_CREATED['lines'] and created.footnotes == EXPECTED_CREATED['footnotes'] and created.keywords == EXPECTED_CREATED['keywords']
    with Session(get_proposals_engine()) as session:
        archived = session.get(Proposal, ARCHIVE_ID)
        assert archived is not None
        assert archived.title == EXPECTED_ARCHIVE['title'] and type(archived.year) is int and archived.year == 2026 and type(archived.seq) is int and archived.seq == 1
        assert archived.lines == EXPECTED_ARCHIVE['lines'] and archived.footnotes == [] and archived.keywords == ['synthetic']

    for name, path in databases.items():
        with sqlite3.connect(path.as_uri() + '?mode=ro', uri=True) as conn:
            assert conn.execute('PRAGMA integrity_check').fetchone()[0] == 'ok', name
    with sqlite3.connect(databases['analytics.db'].as_uri() + '?mode=ro', uri=True) as conn:
        assert conn.execute("SELECT 1 FROM hits WHERE path='/nexus-lab-before-restore' AND status=201 LIMIT 1").fetchone() is not None
    with sqlite3.connect(databases['proposals/proposals.db'].as_uri() + '?mode=ro', uri=True) as conn:
        rows = conn.execute("SELECT proposal_id FROM proposal_fts WHERE proposal_fts MATCH 'Persisted'").fetchall()
        assert any(row[0] == ARCHIVE_ID for row in rows), rows

    got = get_client().get_collection('nexus-lab', embedding_function=None).get(ids=['vector-one'], include=['documents', 'embeddings'])
    assert got['ids'] == ['vector-one'], got['ids']
    assert got['documents'] == ['Synthetic vector payload'], got['documents']
    assert got['embeddings'].tolist() == [[1.0, 2.0, 3.0]]
    assert (DATA / 'event_state_controls.json').read_bytes() == CONTROLS.read_bytes()
    assert (DATA / 'organisation.json').read_bytes() == ORGANISATION_BYTES


def http_create():
    opener = request.build_opener(request.HTTPCookieProcessor(CookieJar()))
    _login(opener)
    status, _, payload = _open(opener, 'GET', '/api/events')
    assert status == 200, status
    expect_event_list(payload)
    status, _, payload = _open(opener, 'POST', f'/api/events/{EVENT_ID}/proposals', body={
        'title': 'Synthetic API proposal',
        'lines': [{'type': 'paragraph', 'content': 'Acknowledged synthetic content'}],
        'footnotes': ['Synthetic footnote'],
        'keywords': ['synthetic'],
    })
    assert status == 201, status
    record = expect_created(payload)
    print(json.dumps({'created': record}))


def http_verify():
    opener = request.build_opener(request.HTTPCookieProcessor(CookieJar()))
    _login(opener)
    status, _, payload = _open(opener, 'GET', '/api/events')
    assert status == 200, status
    expect_event_list(payload)
    status, _, payload = _open(opener, 'GET', f'/api/events/{EVENT_ID}/proposals')
    assert status == 200, status
    created = expect_proposal_list(payload)
    status, _, payload = _open(opener, 'GET', f'/api/proposals/{ARCHIVE_ID}')
    assert status == 200, status
    archive = expect_archive(payload)
    print(json.dumps({'created': created, 'archive': archive}))


ACTIONS = {
    'seed': seed,
    'verify-state': verify_state,
    'http-create': http_create,
    'http-verify': http_verify,
}

if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] not in ACTIONS:
        raise SystemExit(f'usage: antragsbank-lab.py {"|".join(ACTIONS)}')
    ACTIONS[sys.argv[1]]()
