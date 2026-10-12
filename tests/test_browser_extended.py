"""Browser records, provenance, timeline semantics and evidence preservation."""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3

import pytest
import dftk
from dftk.core.case import CaseSession
from dftk.primitives.browser_extended import (
    chromium_bookmarks, chromium_search_terms, firefox_bookmarks, firefox_cookies,
)

CHROME_TIME = 13348540800000001  # 2024-01-01T00:00:00.000001Z
UNIX_MICRO = 1704067200000001


def _database(path, schema, rows):
    with closing(sqlite3.connect(path)) as con:
        con.executescript(schema)
        for sql, params in rows:
            con.execute(sql, params)
        con.commit()
    return path


def _cookies(tmp_path):
    return _database(tmp_path / 'cookies.sqlite', '''
        CREATE TABLE moz_cookies(id INTEGER PRIMARY KEY,host TEXT,name TEXT,path TEXT,
          value TEXT,creationTime INTEGER,lastAccessed INTEGER,expiry INTEGER,
          isSecure INTEGER,isHttpOnly INTEGER,originAttributes TEXT,sameSite INTEGER);
    ''', [('INSERT INTO moz_cookies VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
           (1, '.example.test', 'sid', '/', 'secret-session-token', UNIX_MICRO,
            UNIX_MICRO + 1000000, 1704153600, 1, 1, '^userContextId=3', 2)),
          ('INSERT INTO moz_cookies VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
           (2, 'example.test', 'empty', '/', '', 0, 0, 0, 0, 0, '', 0))])


def _places(tmp_path):
    return _database(tmp_path / 'places.sqlite', '''
        CREATE TABLE moz_places(id INTEGER PRIMARY KEY,url TEXT);
        CREATE TABLE moz_bookmarks(id INTEGER PRIMARY KEY,type INTEGER,fk INTEGER,
          parent INTEGER,position INTEGER,title TEXT,dateAdded INTEGER,lastModified INTEGER,guid TEXT);
    ''', [('INSERT INTO moz_places VALUES(?,?)', (4, 'https://example.test/bookmark')),
          ('INSERT INTO moz_bookmarks VALUES(?,?,?,?,?,?,?,?,?)', (1, 2, None, 0, 0, 'root', 0, 0, 'root_guid')),
          ('INSERT INTO moz_bookmarks VALUES(?,?,?,?,?,?,?,?,?)', (2, 2, None, 1, 0, 'Research', 0, 0, 'folder_guid')),
          ('INSERT INTO moz_bookmarks VALUES(?,?,?,?,?,?,?,?,?)', (3, 1, 4, 2, 0, 'Example', UNIX_MICRO, UNIX_MICRO + 1, 'item_guid')),
          ('INSERT INTO moz_bookmarks VALUES(?,?,?,?,?,?,?,?,?)', (5, 3, None, 2, 1, None, 0, 0, 'separator_guid'))])


def _bookmarks(tmp_path):
    source = tmp_path / 'Bookmarks'
    source.write_text(json.dumps({'version': 1, 'checksum': 'unverified', 'roots': {
        'bookmark_bar': {'id': '1', 'name': 'Bookmarks bar', 'type': 'folder',
            'children': [{'id': '2', 'name': 'Research', 'type': 'folder', 'children': [
                {'id': '3', 'guid': 'guid-3', 'name': 'Example', 'type': 'url',
                 'url': 'https://example.test/bookmark', 'date_added': str(CHROME_TIME),
                 'date_last_used': str(CHROME_TIME + 1)}]}]}}}), encoding='utf-8')
    return source


def test_firefox_cookie_redaction_and_timestamp_units(tmp_path):
    p = _cookies(tmp_path)
    before = p.read_bytes()
    obs = firefox_cookies(str(p))
    assert obs.status.value == 'ok'
    cookie = obs.facts['cookies'][0]
    assert cookie['creationTime_iso'] == '2024-01-01T00:00:00.000001+00:00'
    assert cookie['expiry_iso'] == '2024-01-02T00:00:00+00:00'
    assert cookie['originAttributes'] == '^userContextId=3'
    assert cookie['value_present'] and cookie['value_length'] == 20
    assert 'secret-session-token' not in json.dumps(obs.to_dict())
    assert not obs.facts['cookies'][1]['value_present']
    assert all('expiry' not in event['kind'] for event in obs.facts['events'])
    explicit = firefox_cookies(str(p), include_values=True)
    assert explicit.facts['cookies'][0]['value'] == 'secret-session-token'
    assert p.read_bytes() == before
    assert not Path(str(p) + '-wal').exists()
    assert obs.evidence[0].source_sha256 == hashlib.sha256(before).hexdigest()
    assert obs.evidence[0].locator == 'table:moz_cookies/id:1'


def test_firefox_cookie_old_schema_and_empty_value(tmp_path):
    p = _database(tmp_path / 'old.sqlite',
                  'CREATE TABLE moz_cookies(id INTEGER PRIMARY KEY,host TEXT,name TEXT,path TEXT);',
                  [('INSERT INTO moz_cookies VALUES(?,?,?,?)', (1, 'example.test', 'x', '/'))])
    obs = firefox_cookies(str(p))
    assert obs.status.value == 'ok'
    assert 'value_present' not in obs.facts['cookies'][0]
    assert not obs.facts['value_column_present']
    assert obs.facts['events'] == []


def test_firefox_bookmark_hierarchy_timestamps_and_locator(tmp_path):
    p = _places(tmp_path)
    before = p.read_bytes()
    obs = firefox_bookmarks(str(p))
    assert obs.status.value == 'ok'
    bookmark = obs.facts['bookmarks'][2]
    assert bookmark['folder_path'] == ['root', 'Research']
    assert bookmark['guid'] == 'item_guid'
    assert bookmark['dateAdded_iso'] == '2024-01-01T00:00:00.000001+00:00'
    assert bookmark['lastModified_iso'] == '2024-01-01T00:00:00.000002+00:00'
    assert bookmark['url'] == 'https://example.test/bookmark'
    assert bookmark['locator'] == 'table:moz_bookmarks/id:3'
    assert obs.facts['bookmarks'][3]['node_type'] == 'separator'
    assert len(obs.facts['events']) == 2
    assert p.read_bytes() == before


def test_bookmark_ancestry_cycle_and_missing_parent(tmp_path):
    p = _places(tmp_path)
    with closing(sqlite3.connect(p)) as con:
        con.execute('UPDATE moz_bookmarks SET parent=2 WHERE id=1')
        con.execute('UPDATE moz_bookmarks SET parent=999 WHERE id=5')
        con.commit()
    obs = firefox_bookmarks(str(p))
    assert obs.status.value == 'partial'
    assert any('cycle' in warning for warning in obs.warnings)
    assert any('absent' in warning for warning in obs.warnings)
    assert len(obs.facts['bookmarks']) == 4


def test_chromium_bookmarks_json_pointers_folder_paths_and_readonly(tmp_path):
    p = _bookmarks(tmp_path)
    before = p.read_bytes()
    obs = chromium_bookmarks(str(p))
    assert obs.status.value == 'ok'
    row = obs.facts['bookmarks'][2]
    assert row['folder_path'] == ['Bookmarks bar', 'Research']
    assert row['date_added'] == '2024-01-01T00:00:00.000001+00:00'
    assert row['date_last_used'] == '2024-01-01T00:00:00.000002+00:00'
    assert row['locator'] == 'json:/roots/bookmark_bar/children/0/children/0'
    assert obs.facts['checksum_verified'] is False
    assert obs.evidence[2].source_sha256 == hashlib.sha256(before).hexdigest()
    assert p.read_bytes() == before


def test_bookmark_depth_size_and_exact_record_limit(tmp_path):
    p = _bookmarks(tmp_path)
    assert chromium_bookmarks(str(p), limit=3).status.value == 'ok'
    limited = chromium_bookmarks(str(p), limit=2)
    assert limited.status.value == 'partial' and len(limited.facts['bookmarks']) == 2
    assert chromium_bookmarks(str(p), max_depth=1).status.value == 'partial'
    assert chromium_bookmarks(str(p), max_bytes=2).status.value == 'unsupported'


def test_malformed_nodes_do_not_hide_valid_records(tmp_path):
    p = tmp_path / 'Bookmarks'
    obj = {'roots': {'x/y~z': {'type': 'folder', 'name': 'root', 'children': [
        None, {'type': 'unsupported'}, {'type': 'url', 'name': 'Valid', 'url': 'https://example.test', 'date_added': 'bad'},
        {'type': 'folder', 'name': 'Bad children', 'children': {}}]}}}
    p.write_text(json.dumps(obj))
    obs = chromium_bookmarks(str(p))
    assert obs.status.value == 'partial'
    assert len(obs.facts['bookmarks']) == 3
    assert obs.facts['bookmarks'][1]['locator'].startswith('json:/roots/x~1y~0z/')
    assert obs.facts['bookmarks'][1]['date_added'] is None
    bounded = chromium_bookmarks(str(p), limit=2)
    assert bounded.facts['scanned_count'] == 2


@pytest.mark.parametrize('normalized', ['normalized_term', 'lower_term'])
def test_chromium_search_term_version_variants_and_time_semantics(tmp_path, normalized):
    p = _database(tmp_path / 'History', f'''
        CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,visit_count INTEGER,last_visit_time INTEGER);
        CREATE TABLE keyword_search_terms(keyword_id INTEGER,url_id INTEGER,term TEXT,{normalized} TEXT);
    ''', [('INSERT INTO urls VALUES(?,?,?,?,?)', (1, 'https://example.test/?q=forensics', 'Search', 7, CHROME_TIME)),
          ('INSERT INTO keyword_search_terms VALUES(?,?,?,?)', (8, 1, 'Digital Forensics', 'digital forensics')),
          ('INSERT INTO keyword_search_terms VALUES(?,?,?,?)', (9, 999, 'Orphan term', 'orphan term'))])
    before = p.read_bytes()
    obs = chromium_search_terms(str(p))
    assert obs.status.value == 'ok'
    first = obs.facts['search_terms'][0]
    assert first['term'] == 'Digital Forensics' and first[normalized] == 'digital forensics'
    assert first['url_last_visit_time'] == '2024-01-01T00:00:00.000001+00:00'
    assert first['search_time'] is None and obs.facts['events'] == []
    assert obs.evidence[0].value == 'Digital Forensics'
    assert obs.facts['search_terms'][1]['url'] is None
    assert p.read_bytes() == before


def test_search_terms_without_url_context(tmp_path):
    p = _database(tmp_path / 'History',
                  'CREATE TABLE keyword_search_terms(keyword_id INTEGER,url_id INTEGER,term TEXT);',
                  [('INSERT INTO keyword_search_terms VALUES(?,?,?)', (1, 2, 'Standalone'))])
    obs = chromium_search_terms(str(p))
    assert obs.status.value == 'partial'
    assert obs.facts['search_terms'][0]['term'] == 'Standalone'


@pytest.mark.parametrize('function', [firefox_cookies, firefox_bookmarks, chromium_search_terms])
def test_missing_corrupt_and_wrong_schema_are_distinct(tmp_path, function):
    assert function(str(tmp_path / 'missing')).status.value == 'error'
    p = tmp_path / 'corrupt'
    p.write_bytes(b'not-a-database')
    assert function(str(p)).status.value == 'error'
    db = _database(tmp_path / 'other.sqlite', 'CREATE TABLE unrelated(id INTEGER);', [])
    assert function(str(db)).status.value == 'unsupported'


@pytest.mark.parametrize('value', [0, -1, True, 100001, '5'])
@pytest.mark.parametrize('function', [firefox_cookies, firefox_bookmarks, chromium_search_terms, chromium_bookmarks])
def test_invalid_limits_rejected_before_opening(tmp_path, value, function):
    assert function(str(tmp_path / 'missing'), limit=value).status.value == 'error'


def test_sqlite_bounds_and_sidecar_warning(tmp_path):
    p = _cookies(tmp_path)
    Path(str(p) + '-wal').write_bytes(b'uncheckpointed-evidence')
    obs = firefox_cookies(str(p), limit=1)
    assert obs.status.value == 'partial'
    assert len(obs.facts['cookies']) == 1
    assert any('sidecar' in warning for warning in obs.warnings)
    assert Path(str(p) + '-wal').read_bytes() == b'uncheckpointed-evidence'
    Path(str(p) + '-wal').unlink()
    assert firefox_cookies(str(p), limit=2).status.value == 'ok'


def test_sqlite_uri_preserves_question_hash_percent_and_space(tmp_path):
    p = _cookies(tmp_path)
    tricky = tmp_path / 'cookies ?#% space.sqlite'
    p.rename(tricky)
    assert firefox_cookies(str(tricky)).status.value == 'ok'


def test_cookie_value_bound_and_invalid_timestamp(tmp_path):
    p = _cookies(tmp_path)
    with closing(sqlite3.connect(p)) as con:
        con.execute('UPDATE moz_cookies SET value=?, creationTime=-1 WHERE id=1', ('x' * 20000,))
        con.commit()
    obs = firefox_cookies(str(p), include_values=True)
    assert obs.status.value == 'partial'
    assert len(obs.facts['cookies'][0]['value']) == 16384
    assert obs.facts['cookies'][0]['value_length'] == 20000
    assert obs.facts['cookies'][0]['creationTime_iso'] is None


def test_case_timeline_and_mcp_root_policy(tmp_path):
    from dftk.mcp_server import DFTKMCPGateway
    p = _bookmarks(tmp_path)
    session = CaseSession(tmp_path / 'workspace')
    case = session.new('browser-test')
    obs = session.run(case['case_id'], 'browser.chromium_bookmarks', {'path': str(p)})
    assert obs.status.value == 'ok'
    timeline = session.timeline(case['case_id'])
    assert len(timeline.facts['events']) == 2
    gateway = DFTKMCPGateway(root=tmp_path)
    reply = gateway.run('browser.chromium_bookmarks', {'path': str(p)})
    assert reply['ok'] and reply['observation']['evidence'][2]['source_sha256']
    assert not gateway.run('browser.chromium_bookmarks', {'path': '/outside/Bookmarks'})['ok']


def test_all_tools_discoverable_and_suggestion_specialists():
    from dftk.suggest import suggest
    specs = dftk.get_registry().find(produces='browser_bookmarks')
    assert {spec.name for spec in specs} == {'browser.chromium_bookmarks', 'browser.firefox_bookmarks'}
    names = [item['name'] for item in suggest('cookies.sqlite', limit=50)['results']]
    assert 'browser.firefox_cookies' in names
    assert all(dftk.get_registry().get(name).path_roles for name in (
        'browser.chromium_bookmarks', 'browser.firefox_bookmarks', 'browser.firefox_cookies', 'browser.chromium_search_terms'))


@pytest.mark.parametrize('data,status', [('not-json', 'error'), ('{}', 'unsupported'),
                                         ('{"roots": {}, "version": NaN}', 'error'),
                                         ('{"version": 99, "roots": {}}', 'unsupported'),
                                         ('{"roots": {}}', 'ok')])
def test_bookmark_parse_outcomes(tmp_path, data, status):
    p = tmp_path / 'Bookmarks'
    p.write_text(data)
    assert chromium_bookmarks(str(p)).status.value == status


def test_real_uncheckpointed_wal_is_preserved_and_reported(tmp_path):
    import shutil
    original = _cookies(tmp_path)
    live = sqlite3.connect(original)
    try:
        live.execute('PRAGMA journal_mode=WAL')
        live.execute('PRAGMA wal_autocheckpoint=0')
        live.execute("INSERT INTO moz_cookies(id,host,name,path) VALUES(3,'new.test','pending','/')")
        live.commit()
        evidence_dir = tmp_path / 'copied'
        evidence_dir.mkdir()
        for suffix in ('', '-wal', '-shm'):
            source = Path(str(original) + suffix)
            if source.exists():
                shutil.copyfile(source, evidence_dir / ('cookies.sqlite' + suffix))
        evidence = evidence_dir / 'cookies.sqlite'
        before = {path.name: path.read_bytes() for path in evidence_dir.iterdir()}
        obs = firefox_cookies(str(evidence))
        assert obs.status.value == 'partial'
        assert len(obs.facts['cookies']) == 2
        assert any('sidecar' in warning for warning in obs.warnings)
        assert {path.name: path.read_bytes() for path in evidence_dir.iterdir()} == before
    finally:
        live.close()


@pytest.mark.parametrize('kwargs', [{'max_depth': 0}, {'max_depth': True}, {'max_bytes': 0}, {'max_bytes': True}])
def test_json_resource_bounds_validate_parameters(tmp_path, kwargs):
    assert chromium_bookmarks(str(tmp_path / 'missing'), **kwargs).status.value == 'error'
