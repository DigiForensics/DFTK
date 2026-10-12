# Copyright 2026 DyNooob @ DigiForensics
# Licensed under the Apache License, Version 2.0.
"""Bounded browser records from immutable SQLite and Chromium bookmark JSON."""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

from dftk.core.helpers import sha256_file
from dftk.core.models import Evidence, Observation, SafetyLevel, Status
from dftk.core.registry import registry
from .browser import _chrome_time, _open_ro, _tables

_LIMIT = {"type": "integer", "default": 5000, "minimum": 1, "maximum": 100000}
_MAX_TEXT = 16384


class _Unsupported(ValueError):
    pass


def _columns(con, table, required):
    if table not in _tables(con):
        raise _Unsupported(f"Required table not found: {table}")
    columns = {row[1] for row in con.execute(f'PRAGMA table_info("{table}")')}
    missing = set(required) - columns
    if missing:
        raise _Unsupported(f"{table} lacks required columns: {', '.join(sorted(missing))}")
    return columns


def _limit(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 100000:
        raise ValueError("limit must be an integer between 1 and 100000")
    return value


def _unix_time(value, microseconds=False):
    try:
        if value is None or isinstance(value, bool):
            return None
        n = int(value)
        if n <= 0:
            return None
        delta = timedelta(microseconds=n) if microseconds else timedelta(seconds=n)
        return (datetime(1970, 1, 1, tzinfo=timezone.utc) + delta).isoformat()
    except (ValueError, TypeError, OverflowError):
        return None


def _event(events, path, row, field, kind, detail):
    value = row.get(field)
    if value:
        event_path = row.get("url") or row.get("host") or ""
        events.append({"time": value, "source": str(path), "kind": kind,
                       "path": event_path if isinstance(event_path, str) else "",
                       "detail": detail, "locator": row["locator"]})


def _finish(tool, path, key, rows, events, warnings, digest, **facts):
    evidence = [Evidence(str(path), key.rstrip('s'), row.get('term') or row.get('url') or row.get('host') or row.get('title'),
                         locator=row['locator'], source_sha256=digest,
                         method=tool) for row in rows]
    return Observation(tool, Status.PARTIAL if warnings else Status.OK,
                       f"Read {len(rows)} {key} record(s)",
                       facts={key: rows, "events": events, "returned_count": len(rows), **facts},
                       evidence=evidence, warnings=list(dict.fromkeys(warnings)),
                       meta={"source_sha256": digest})


def _read_sqlite(tool, path, limit, reader):
    digest = ""
    try:
        _limit(limit)
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"Database not found: {p}")
        digest = sha256_file(p)
        warnings = []
        # Immutable mode intentionally ignores uncheckpointed WAL and rollback state.
        if any(Path(str(p) + suffix).exists() for suffix in ('-wal', '-journal')):
            warnings.append("SQLite sidecar present: immutable view excludes uncheckpointed WAL/rollback changes; analyze a derived snapshot or database.sqlite_wal separately.")
        with closing(_open_ro(p)) as con:
            ticks = 0
            def budget():
                nonlocal ticks
                ticks += 1
                return int(ticks > 50000)
            con.set_progress_handler(budget, 1000)
            return reader(con, p, limit, warnings, digest)
    except _Unsupported as exc:
        return Observation(tool, Status.UNSUPPORTED, "Unsupported browser schema",
                           errors=[str(exc)], meta={"source_sha256": digest})
    except (OSError, sqlite3.DatabaseError, ValueError, TypeError) as exc:
        return Observation(tool, Status.ERROR, "Browser record parsing failed",
                           errors=[str(exc)], meta={"source_sha256": digest})


def _select(con, sql, limit, warnings):
    cursor = con.execute(sql, (limit + 1,))
    names = [column[0] for column in cursor.description]
    rows = [dict(zip(names, values)) for values in cursor]
    if len(rows) > limit:
        warnings.append(f"Record limit {limit} reached; additional records omitted.")
    return rows[:limit]


def _text_sql(alias, name):
    # Limit text in SQLite before it is materialized in Python.
    return f'substr({alias}."{name}", 1, {_MAX_TEXT + 1}) AS "{name}"'


def _trim(row, warnings):
    for name, value in row.items():
        if isinstance(value, (str, bytes)) and len(value) > _MAX_TEXT:
            warnings.append(f"Text/blob fields limited to {_MAX_TEXT} characters/bytes.")
            row[name] = value[:_MAX_TEXT]
        if isinstance(row[name], bytes):
            warnings.append("Unexpected binary field rendered as hexadecimal.")
            row[name] = {"hex": row[name].hex()}


@registry.tool(
    name='browser.firefox_cookies',
    description='Read Firefox moz_cookies metadata in immutable read-only mode; redact plaintext values by default and normalize Unix second/microsecond timestamps.',
    safety=SafetyLevel.READ_ONLY, tags=('browser', 'firefox', 'cookies', 'timeline'),
    produces=('browser_cookies', 'timeline'), cost_hint='medium',
    path_roles={'path': 'EVIDENCE_INPUT'},
    parameters={'type': 'object', 'properties': {'path': {'type': 'string'},
                'limit': _LIMIT, 'include_values': {'type': 'boolean', 'default': False}}, 'required': ['path']})
def firefox_cookies(path: str, limit: int = 5000, include_values: bool = False) -> Observation:
    tool = 'browser.firefox_cookies'
    if not isinstance(include_values, bool):
        return Observation(tool, Status.ERROR, 'Invalid include_values', errors=['include_values must be a boolean'])
    def read(con, p, limit, warnings, digest):
        cols = _columns(con, 'moz_cookies', {'id', 'host', 'name', 'path'})
        wanted = ['id', 'host', 'name', 'path', 'originAttributes', 'baseDomain', 'expiry',
                  'lastAccessed', 'creationTime', 'isSecure', 'isHttpOnly', 'sameSite',
                  'rawSameSite', 'schemeMap', 'isPartitionedAttributeSet']
        text = {'host', 'name', 'path', 'originAttributes', 'baseDomain'}
        selected = [_text_sql('c', key) if key in text else f'c."{key}"' for key in wanted if key in cols]
        if 'value' in cols:
            selected += ['length(c.value) AS value_length', 'CASE WHEN length(c.value)>0 THEN 1 ELSE 0 END AS value_present']
            if include_values:
                selected.append(_text_sql('c', 'value'))
        rows = _select(con, 'SELECT ' + ','.join(selected) + ' FROM moz_cookies c ORDER BY c.id LIMIT ?', limit, warnings)
        events = []
        for row in rows:
            _trim(row, warnings)
            row['locator'] = f"table:moz_cookies/id:{row['id']}"
            for field in ('creationTime', 'lastAccessed', 'expiry'):
                if field in row:
                    row[field + '_iso'] = _unix_time(row[field], field != 'expiry')
                    if row[field] not in (None, 0) and not row[field + '_iso']:
                        warnings.append(f"Invalid {field} timestamp retained as raw value.")
            if 'value_present' in row:
                row['value_present'] = bool(row['value_present'])
            # Expiry is a stored deadline, not an observed browser action.
            _event(events, p, row, 'creationTime_iso', 'browser_cookie_created', f"cookie id={row['id']}")
            _event(events, p, row, 'lastAccessed_iso', 'browser_cookie_last_accessed', f"cookie id={row['id']}")
        return _finish(tool, p, 'cookies', rows, events, warnings, digest,
                       include_values=include_values, value_column_present='value' in cols)
    return _read_sqlite(tool, path, limit, read)


@registry.tool(
    name='browser.chromium_search_terms',
    description='Read recorded Chromium keyword_search_terms with URL context. URL last_visit_time is context, not an exact search timestamp; never inferred as a search event.',
    safety=SafetyLevel.READ_ONLY, tags=('browser', 'chromium', 'history', 'search'),
    produces=('browser_search_terms',), cost_hint='medium', path_roles={'path': 'EVIDENCE_INPUT'},
    parameters={'type': 'object', 'properties': {'path': {'type': 'string'}, 'limit': _LIMIT}, 'required': ['path']})
def chromium_search_terms(path: str, limit: int = 5000) -> Observation:
    tool = 'browser.chromium_search_terms'
    def read(con, p, limit, warnings, digest):
        cols = _columns(con, 'keyword_search_terms', {'keyword_id', 'url_id', 'term'})
        selected = ['k.rowid AS record_id', 'k.keyword_id', 'k.url_id', _text_sql('k', 'term')]
        for key in ('normalized_term', 'lower_term'):
            if key in cols:
                selected.append(_text_sql('k', key))
        join = ''
        if 'urls' in _tables(con):
            ucols = _columns(con, 'urls', {'id', 'url'})
            selected.append(_text_sql('u', 'url'))
            for key in ('title', 'visit_count', 'last_visit_time'):
                if key in ucols:
                    selected.append(_text_sql('u', key) if key == 'title' else f'u."{key}"')
            join = ' LEFT JOIN urls u ON u.id=k.url_id'
        else:
            warnings.append('URLs table absent; search term URL context unavailable.')
        rows = _select(con, 'SELECT ' + ','.join(selected) + ' FROM keyword_search_terms k' + join + ' ORDER BY k.rowid LIMIT ?', limit, warnings)
        for row in rows:
            _trim(row, warnings)
            row['locator'] = f"table:keyword_search_terms/rowid:{row['record_id']}"
            if 'last_visit_time' in row:
                row['url_last_visit_time_raw'] = row.pop('last_visit_time')
                row['url_last_visit_time'] = _chrome_time(row['url_last_visit_time_raw'])
            row['search_time'] = None
        return _finish(tool, p, 'search_terms', rows, [], warnings, digest,
                       timestamp_semantics='URL last visit is context only; no exact search time is stored in keyword_search_terms.')
    return _read_sqlite(tool, path, limit, read)


@registry.tool(
    name='browser.firefox_bookmarks',
    description='Read Firefox moz_bookmarks joined to moz_places in immutable mode, preserving folder relationships, GUIDs and creation/modification timestamps.',
    safety=SafetyLevel.READ_ONLY, tags=('browser', 'firefox', 'bookmarks', 'timeline'),
    produces=('browser_bookmarks', 'timeline'), cost_hint='medium', path_roles={'path': 'EVIDENCE_INPUT'},
    parameters={'type': 'object', 'properties': {'path': {'type': 'string'}, 'limit': _LIMIT}, 'required': ['path']})
def firefox_bookmarks(path: str, limit: int = 5000) -> Observation:
    tool = 'browser.firefox_bookmarks'
    def read(con, p, limit, warnings, digest):
        cols = _columns(con, 'moz_bookmarks', {'id', 'type', 'parent', 'fk'})
        _columns(con, 'moz_places', {'id', 'url'})
        selected = [f'b."{key}"' for key in ('id', 'type', 'parent', 'fk', 'position', 'dateAdded', 'lastModified') if key in cols]
        selected += [_text_sql('b', key) for key in ('title', 'guid') if key in cols]
        selected.append(_text_sql('p', 'url'))
        rows = _select(con, 'SELECT ' + ','.join(selected) + ' FROM moz_bookmarks b LEFT JOIN moz_places p ON p.id=b.fk ORDER BY b.id LIMIT ?', limit, warnings)
        by_id = {row['id']: row for row in rows}
        events = []
        for row in rows:
            _trim(row, warnings)
            row['locator'] = f"table:moz_bookmarks/id:{row['id']}"
            row['node_type'] = {1: 'url', 2: 'folder', 3: 'separator'}.get(row['type'], 'unknown')
            folders, seen, parent = [], {row['id']}, row['parent']
            while parent not in (None, 0):
                if parent in seen or len(seen) >= 128:
                    warnings.append('Bookmark ancestry cycle/depth limit; folder path is incomplete.')
                    break
                seen.add(parent)
                ancestor = by_id.get(parent)
                if ancestor is None:
                    warnings.append('Bookmark parent absent from bounded result; folder path is incomplete.')
                    break
                folders.append(ancestor.get('title') or str(parent))
                parent = ancestor['parent']
            row['folder_path'] = list(reversed(folders))
            for field in ('dateAdded', 'lastModified'):
                if field in row:
                    row[field + '_iso'] = _unix_time(row[field], True)
                    if row[field] not in (None, 0) and not row[field + '_iso']:
                        warnings.append(f'Invalid {field} timestamp retained as raw value.')
            _event(events, p, row, 'dateAdded_iso', 'browser_bookmark_added', f"bookmark id={row['id']}")
            _event(events, p, row, 'lastModified_iso', 'browser_bookmark_modified', f"bookmark id={row['id']}")
        return _finish(tool, p, 'bookmarks', rows, events, warnings, digest)
    return _read_sqlite(tool, path, limit, read)


@registry.tool(
    name='browser.chromium_bookmarks',
    description='Read bounded Chromium Bookmarks JSON trees with folder paths, JSON-pointer locators and Windows-epoch microsecond timestamps; no browser launch or URL access.',
    safety=SafetyLevel.READ_ONLY, tags=('browser', 'chromium', 'bookmarks', 'json', 'timeline'),
    produces=('browser_bookmarks', 'timeline'), cost_hint='medium', path_roles={'path': 'EVIDENCE_INPUT'},
    parameters={'type': 'object', 'properties': {'path': {'type': 'string'}, 'limit': _LIMIT,
                'max_bytes': {'type': 'integer', 'default': 33554432, 'minimum': 1, 'maximum': 134217728},
                'max_depth': {'type': 'integer', 'default': 64, 'minimum': 1, 'maximum': 128}}, 'required': ['path']})
def chromium_bookmarks(path: str, limit: int = 5000, max_bytes: int = 33554432, max_depth: int = 64) -> Observation:
    tool = 'browser.chromium_bookmarks'
    digest = ''
    try:
        _limit(limit)
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= 134217728:
            raise ValueError('max_bytes must be an integer between 1 and 134217728')
        if isinstance(max_depth, bool) or not isinstance(max_depth, int) or not 1 <= max_depth <= 128:
            raise ValueError('max_depth must be an integer between 1 and 128')
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f'Bookmarks file not found: {p}')
        with p.open('rb') as stream:
            data = stream.read(max_bytes + 1)
        if len(data) > max_bytes:
            return Observation(tool, Status.UNSUPPORTED, 'Bookmarks file exceeds read limit',
                               errors=[f'max_bytes={max_bytes}'], meta={'read_limit': max_bytes})
        digest = hashlib.sha256(data).hexdigest()
        def invalid_constant(value):
            raise ValueError(f'Non-standard JSON numeric constant: {value}')
        obj = json.loads(data.decode('utf-8-sig'), parse_constant=invalid_constant)
        if not isinstance(obj, dict) or not isinstance(obj.get('roots'), dict):
            raise _Unsupported('Expected Chromium Bookmarks JSON object with roots dictionary')
        if obj.get('version') not in (None, 1):
            raise _Unsupported(f"Unsupported bookmark version: {obj.get('version')!r}")
        warnings, rows, events = [], [], []
        scanned = 0
        def pointer(text):
            return text.replace('~', '~0').replace('/', '~1')
        # Iterator frames keep the traversal bounded even for very wide/deep trees.
        stack = [(iter(obj['roots'].items()), '/roots', [], 0)]
        while stack:
            iterator, base, folders, depth = stack[-1]
            try:
                index, node = next(iterator)
            except StopIteration:
                stack.pop()
                continue
            if scanned >= limit:
                warnings.append(f'Record limit {limit} reached; additional nodes omitted.')
                break
            scanned += 1
            locator = base + '/' + pointer(str(index))
            if not isinstance(node, dict) or node.get('type') not in ('url', 'folder'):
                warnings.append('Malformed/unknown bookmark node omitted.')
                continue
            row = {key: node[key] for key in ('id', 'guid', 'name', 'type', 'url') if key in node}
            if not isinstance(row.get('name', ''), str) or (row['type'] == 'url' and not isinstance(row.get('url'), str)):
                warnings.append('Bookmark node with invalid name/URL omitted.')
                continue
            row['title'] = row.pop('name', '')
            row['locator'], row['folder_path'] = 'json:' + locator, folders
            for field in ('date_added', 'date_modified', 'date_last_used'):
                if field in node:
                    row[field + '_raw'] = node[field]
                    row[field] = _chrome_time(node[field])
                    if node[field] not in (None, 0, '0') and not row[field]:
                        warnings.append(f'Invalid {field} timestamp retained as raw value.')
            _trim(row, warnings)
            rows.append(row)
            for field, kind in (('date_added', 'browser_bookmark_added'),
                                ('date_modified', 'browser_bookmark_modified'),
                                ('date_last_used', 'browser_bookmark_last_used')):
                _event(events, p, row, field, kind, f"bookmark locator={row['locator']}")
            if node['type'] == 'folder':
                children = node.get('children', [])
                if not isinstance(children, list):
                    warnings.append('Folder children is not an array; descendants omitted.')
                elif children and depth >= max_depth:
                    warnings.append(f'Bookmark depth limit {max_depth} reached; descendants omitted.')
                elif children:
                    stack.append((iter(enumerate(children)), locator + '/children', folders + [row['title']], depth + 1))
        return _finish(tool, p, 'bookmarks', rows, events, warnings, digest,
                       version=obj.get('version'), scanned_count=scanned, checksum_verified=False)
    except _Unsupported as exc:
        return Observation(tool, Status.UNSUPPORTED, 'Unsupported bookmark format', errors=[str(exc)], meta={'source_sha256': digest})
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        return Observation(tool, Status.ERROR, 'Bookmark parsing failed', errors=[str(exc)], meta={'source_sha256': digest})
