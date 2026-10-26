"""Small composable eyes/hands: browse sources and read bounded text windows."""
from __future__ import annotations

import hashlib
import stat
from itertools import islice
from pathlib import Path

from dftk.core.helpers import sha256_file
from dftk.core.media_types import media_type, media_signature
from dftk.core.models import Evidence, Observation, Status
from dftk.core.registry import registry


@registry.tool(name='evidence.browse', description='Page a directory without a fixed investigation workflow. Lists media hints and unreadable/symlink entries explicitly; does not decode images or send pixels. Evidence/workspace directory metadata only; content-reading tools independently validate registered derived files.',
    tags=('evidence', 'browse', 'directory', 'media'), produces=('directory_entries',), path_roles={'path': 'ANALYSIS_INPUT'},
    parameters={'type': 'object', 'properties': {
        'path': {'type': 'string'}, 'offset': {'type': 'integer', 'minimum': 0, 'maximum': 50000, 'default': 0},
        'limit': {'type': 'integer', 'minimum': 1, 'maximum': 500, 'default': 100}}, 'required': ['path']})
def browse(path: str, offset: int = 0, limit: int = 100) -> Observation:
    p = Path(path)
    if not p.is_dir():
        return Observation('evidence.browse', Status.ERROR, 'Not a directory', errors=[path])
    # Bounded directory enumeration; never follow a symlink to discover content.
    entries = list(islice(p.iterdir(), 50001))
    scan_limited = len(entries) > 50000
    entries = sorted(entries[:50000], key=lambda item: item.name)
    rows, warnings = [], []
    for entry in entries[offset:offset + limit]:
        row = {'path': str(entry), 'name': entry.name, 'media_hint': media_type('unknown', entry.name)}
        try:
            st = entry.lstat()
            row.update(size=st.st_size, mtime_ns=st.st_mtime_ns,
                type='symlink' if entry.is_symlink() else 'directory' if stat.S_ISDIR(st.st_mode) else 'file' if stat.S_ISREG(st.st_mode) else 'special',
                content_examined=False)
            if entry.is_symlink():
                row['status'] = 'excluded_symlink'
        except OSError as exc:
            row.update(status='unreadable', error=str(exc)); warnings.append(f'{entry.name}: {exc}')
        rows.append(row)
    if scan_limited:
        warnings.append('Directory scan capped at 50000 entries; this is not a complete directory inventory')
    next_offset = offset + len(rows) if offset + len(rows) < len(entries) else None
    return Observation('evidence.browse', Status.PARTIAL if warnings else Status.OK,
        f'Listed {len(rows)} directory entries; content remains unexamined',
        facts={'path': path, 'entries': rows, 'offset': offset, 'next_offset': next_offset,
               'enumerated_count': len(entries), 'scan_limited': scan_limited}, warnings=warnings)


@registry.tool(name='file.read_text', description='Read a bounded byte window as text, with byte locators and explicit continuation. Use for configs/logs/plain documents. Images/videos require authorised media.preview; this tool does not decode them.',
    tags=('file', 'text', 'read', 'log', 'config'), produces=('text_window',),
    parameters={'type': 'object', 'properties': {
        'path': {'type': 'string'}, 'offset': {'type': 'integer', 'minimum': 0, 'default': 0},
        'length': {'type': 'integer', 'minimum': 1, 'maximum': 65536, 'default': 16384},
        'encoding': {'type': 'string', 'enum': ['utf-8', 'utf-16-le', 'utf-16-be', 'gb18030', 'latin-1'], 'default': 'utf-8'}}, 'required': ['path']})
def read_text(path: str, offset: int = 0, length: int = 16384, encoding: str = 'utf-8') -> Observation:
    p = Path(path)
    if not p.is_file():
        return Observation('file.read_text', Status.ERROR, 'Text input must be a regular file', errors=[path])
    with p.open('rb') as stream:
        head = stream.read(64)
        if media_type(media_signature(head) or 'unknown', p.name):
            return Observation('file.read_text', Status.BLOCKED, 'Media found; use authorised visual preview or local OCR',
                facts={'path': path, 'content_examined': False, 'reason_code': 'media_requires_specialist_access'})
        stream.seek(offset)
        raw = stream.read(length)
    text = raw.decode(encoding, errors='replace')
    warnings = ['Decode replacement characters present; choose the correct encoding/window alignment'] if '\ufffd' in text else []
    size = p.stat().st_size
    source_sha = sha256_file(p) if size <= 64 * 1024 * 1024 else ''
    if not source_sha:
        warnings.append('Full source hash omitted for large file; window hash identifies only the returned bytes')
    return Observation('file.read_text', Status.PARTIAL if warnings else Status.OK, f'Read {len(raw)} byte(s) of text',
        facts={'path': path, 'offset': offset, 'bytes_read': len(raw), 'source_size': size,
               'content_examined': True, 'scope': 'returned byte window only',
               'next_offset': offset + len(raw) if offset + len(raw) < size else None,
               'encoding': encoding, 'text': text, 'window_sha256': hashlib.sha256(raw).hexdigest()},
        evidence=[Evidence(path, 'text_window', text, locator=f'bytes:{offset}-{offset + len(raw)}',
                           source_sha256=source_sha, method=f'bounded decode:{encoding}')], warnings=warnings)
