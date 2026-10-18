# Copyright 2026 DyNooob @ DigiForensics
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Pure-Python SQLite forensic parser — DFTK 3.5.0.

This module deliberately does *not* use the ``sqlite3`` standard-library module
for recovery. The whole point of forensic SQLite analysis is to recover data
the engine itself considers gone: deleted rows still present in unallocated
page space, freeblocks, freelist pages, and un-checkpointed WAL frames. The
standard library only exposes the *consistent* view and silently hides all of
that. So we parse the file format directly from bytes with a bounded reader.

Covered:
  * 100-byte database header (page size, change counter, freelist, schema
    cookie, autovacuum, encoding, page count, ...).
  * B-tree pages (table/interior/leaf) with varint + serial-type record decode
    and overflow-page reassembly.
  * WAL header/frames with native-order checksum verification and logical-page
    reconstruction (DB page + latest valid WAL frame => current page).
  * Freelist trunk/leaf enumeration.
  * Deleted-record recovery by carving record-shaped byte sequences from
    unallocated space, freeblocks and freelist pages, classified as
    LIVE / DELETED_CANDIDATE / CARVED / PARTIAL.

All readers are bounded; nothing here modifies evidence.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any


# --------------------------------------------------------------------------- #
# Low-level primitives
# --------------------------------------------------------------------------- #

def read_varint(data: bytes, off: int) -> tuple[int, int]:
    """Decode a SQLite varint. Returns (value, next_offset)."""
    result = 0
    for i in range(9):
        if off + i >= len(data):
            raise ValueError("varint runs past end of buffer")
        byte = data[off + i]
        if i == 8:
            result = (result << 8) | byte
            return result & 0xFFFFFFFFFFFFFFFF, off + 9
        result = (result << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            return result, off + i + 1
    return result & 0xFFFFFFFFFFFFFFFF, off + 9


def serial_content_size(st: int) -> int:
    """Number of payload bytes a serial type occupies, or -1 if reserved."""
    if st == 0 or st == 8 or st == 9:
        return 0
    if 1 <= st <= 4:
        return st
    if st == 5:
        return 6      # SQLite serial type 5 is a 48-bit (6-byte) integer
    if st == 6:
        return 8      # serial type 6 is a 64-bit (8-byte) integer
    if st == 7:
        return 8
    if st >= 12:
        return (st - 12) // 2 if st % 2 == 0 else (st - 13) // 2
    return -1  # 10, 11 reserved


def serial_type_value(st: int, data: bytes, off: int, encoding: int) -> Any:
    """Decode a single column value for serial type ``st`` starting at ``off``."""
    if st == 0:
        return None
    if st == 8:
        return 0
    if st == 9:
        return 1
    if 1 <= st <= 6:
        # Serial types 5 and 6 are 6- and 8-byte integers, NOT 5 and 6 bytes.
        n = st if st <= 4 else (6 if st == 5 else 8)
        raw = data[off:off + n]
        if len(raw) < n:
            raise ValueError("truncated integer column")
        return int.from_bytes(raw, "big", signed=True)
    if st == 7:
        return struct.unpack(">d", data[off:off + 8])[0]
    if st >= 12:
        n = (st - 12) // 2 if st % 2 == 0 else (st - 13) // 2
        raw = data[off:off + n]
        if st % 2 == 0:
            return raw  # BLOB
        return raw.decode(_encoding_name(encoding) or "utf-8", "replace")
    raise ValueError("reserved serial type %d" % st)


def _encoding_name(encoding: int) -> str:
    return {1: "utf-8", 2: "utf-16-le", 3: "utf-16-be"}.get(encoding, "utf-8")


def parse_record(payload: bytes, encoding: int) -> list[Any]:
    """Parse a record payload (header + body) into a list of column values."""
    hdr_len, p = read_varint(payload, 0)
    serials: list[int] = []
    q = p
    while q < hdr_len:
        st, q = read_varint(payload, q)
        serials.append(st)
    body = hdr_len
    cols: list[Any] = []
    for st in serials:
        size = serial_content_size(st)
        if size < 0:
            cols.append(None)
            continue
        if body + size > len(payload):
            # Partial / truncated record — still surface what we have.
            cols.append(serial_type_value(st, payload, body, encoding) if size <= len(payload) - body else None)
            body += size
            continue
        cols.append(serial_type_value(st, payload, body, encoding))
        body += size
    return cols


# --------------------------------------------------------------------------- #
# Database header
# --------------------------------------------------------------------------- #

def parse_sqlite_header(data: bytes) -> dict[str, Any]:
    if len(data) < 100:
        raise ValueError("file too small for SQLite header")
    if data[0:16] != b"SQLite format 3\x00":
        raise ValueError("not a SQLite database (magic mismatch)")
    page_size = int.from_bytes(data[16:18], "big")
    if page_size == 1:
        page_size = 65536
    if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
        raise ValueError("invalid SQLite page size")
    enc = int.from_bytes(data[56:60], "big")
    return {
        "magic": "SQLite format 3",
        "page_size": page_size,
        "write_version": data[18],
        "read_version": data[19],
        "reserved_bytes_per_page": data[20],
        "max_embed_payload_frac": data[21],
        "min_embed_payload_frac": data[22],
        "leaf_payload_frac": data[23],
        "file_change_counter": int.from_bytes(data[24:28], "big"),
        "in_header_db_size_pages": int.from_bytes(data[28:32], "big"),
        "first_freelist_trunk": int.from_bytes(data[32:36], "big"),
        "total_freelist_pages": int.from_bytes(data[36:40], "big"),
        "schema_cookie": int.from_bytes(data[40:44], "big"),
        "schema_format": int.from_bytes(data[44:48], "big"),
        "default_page_cache_size": int.from_bytes(data[48:52], "big"),
        "largest_root_btree_page": int.from_bytes(data[52:56], "big"),
        "text_encoding": enc,
        "text_encoding_name": _encoding_name(enc),
        "user_version": int.from_bytes(data[60:64], "big"),
        "incremental_vacuum": int.from_bytes(data[64:68], "big"),
        "application_id": int.from_bytes(data[68:72], "big"),
        "version_valid_for": int.from_bytes(data[92:96], "big"),
        "sqlite_version_number": int.from_bytes(data[96:100], "big"),
    }


# --------------------------------------------------------------------------- #
# WAL
# --------------------------------------------------------------------------- #

def wal_checksum(data: bytes, c0: int, c1: int, little_endian: bool) -> tuple[int, int]:
    """Native-order WAL checksum accumulator over ``data`` (length multiple of 8).

    Mirrors SQLite's ``walChecksumBytes``: read 32-bit words in the checksum's
    native byte order, accumulate ``s1 += w0 + s2; s2 += w1 + s1`` in pairs.
    The ``little_endian`` flag selects the word-read byte order (see
    ``parse_wal`` for how the magic's LSB drives it).
    """
    fmt = "<" if little_endian else ">"
    n = len(data) // 4
    words = struct.unpack(f"{fmt}{n}I", data)
    for i in range(0, n, 2):
        c0 = (c0 + words[i] + c1) & 0xFFFFFFFF
        c1 = (c1 + words[i + 1] + c0) & 0xFFFFFFFF
    return c0, c1


def parse_wal(wal_bytes: bytes) -> dict[str, Any]:
    """Parse a WAL file. Returns header + per-frame validity/commit info.

    The 32-byte WAL header layout (per SQLite's ``wal.c``):

      =====  =========================
      off    field (all big-endian)
      =====  =========================
      0      magic  0x377f0682/0x377f0683
      4      file format version (3007000)
      8      page size
      12     checkpoint sequence number
      16     salt-1
      20     salt-2
      24     checksum-1 (over first 24 bytes)
      28     checksum-2
      =====  =========================

    The magic's least-significant bit selects the checksum word byte order:
    bit 0 -> the writer used little-endian checksum words, bit 1 -> big-endian.
    The checksum checksum itself is stored big-endian (sqlite3Get4byte), so we
    always compare against a big-endian read of the stored value.

    Frame validation follows ``walDecodeFrame`` exactly: the checksum chains
    over (a) the first 8 bytes of the frame header, then (b) the page data,
    seeded by the running checksum (header checksum for frame 0). The frame's
    salt must match the header salt and the result must equal the stored
    checksum at frame-header bytes 16/20.
    """
    if len(wal_bytes) < 32:
        raise ValueError("WAL too small")
    magic = int.from_bytes(wal_bytes[0:4], "big")
    if magic not in (0x377F0682, 0x377F0683):
        raise ValueError("WAL magic mismatch")
    # magic LSB bit 0 -> little-endian checksum words, bit 1 -> big-endian.
    le = (magic & 0x01) == 0
    # All header/data integers are big-endian (written via sqlite3Put4byte).
    format_version = struct.unpack(">I", wal_bytes[4:8])[0]
    page_size = struct.unpack(">I", wal_bytes[8:12])[0]
    if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
        raise ValueError("invalid WAL page size")
    if format_version != 3007000:
        raise ValueError("unsupported WAL format version")
    header = {
        "magic": hex(magic),
        "little_endian_checksum": le,
        "format_version": format_version,
        "page_size": page_size,
        "checkpoint_sequence": struct.unpack(">I", wal_bytes[12:16])[0],
        "salt_1": struct.unpack(">I", wal_bytes[16:20])[0],
        "salt_2": struct.unpack(">I", wal_bytes[20:24])[0],
        "checksum_1": struct.unpack(">I", wal_bytes[24:28])[0],
        "checksum_2": struct.unpack(">I", wal_bytes[28:32])[0],
    }
    # Header checksum over the first 24 bytes, seeded 0,0.
    hc0, hc1 = wal_checksum(wal_bytes[0:24], 0, 0, le)
    header["header_checksum_valid"] = (hc0 == header["checksum_1"] and hc1 == header["checksum_2"])

    frame_size = 24 + page_size
    frames: list[dict[str, Any]] = []
    salt = (header["salt_1"], header["salt_2"])
    seed0, seed1 = hc0, hc1
    offset = 32
    idx = 0
    chain_valid = header["header_checksum_valid"]
    last_commit = None
    while offset + frame_size <= len(wal_bytes):
        fh = wal_bytes[offset:offset + 24]
        page_no = struct.unpack(">I", fh[0:4])[0]
        # A nonzero DB-size field marks a commit (not a high-bit flag).
        n_subj = struct.unpack(">I", fh[4:8])[0]
        f_salt_1 = struct.unpack(">I", fh[8:12])[0]
        f_salt_2 = struct.unpack(">I", fh[12:16])[0]
        fc0 = struct.unpack(">I", fh[16:20])[0]
        fc1 = struct.unpack(">I", fh[20:24])[0]
        # walDecodeFrame: checksum first 8 header bytes, then the page data.
        c0, c1 = wal_checksum(wal_bytes[offset:offset + 8], seed0, seed1, le)
        c0, c1 = wal_checksum(wal_bytes[offset + 24:offset + 24 + page_size], c0, c1, le)
        salt_ok = (f_salt_1, f_salt_2) == salt
        checksum_ok = (c0 == fc0 and c1 == fc1)
        commit = n_subj != 0
        chain_valid = chain_valid and salt_ok and checksum_ok and 0 < page_no <= 0xFFFFFFFE
        if commit and chain_valid:
            last_commit = idx
        frames.append({
            "index": idx,
            "page_number": page_no,
            "db_size": n_subj,
            "commit": commit,
            "salt_ok": salt_ok,
            "checksum_ok": checksum_ok,
            "valid": chain_valid,
        })
        if salt_ok and checksum_ok:
            seed0, seed1 = c0, c1
        offset += frame_size
        idx += 1
    return {
        "header": header,
        "frames": frames,
        "frame_count": len(frames),
        "valid_frames": sum(1 for f in frames if f["valid"]),
        "last_commit_index": last_commit,
        "committed_frame_count": last_commit + 1 if last_commit is not None else 0,
        "trailing_bytes": len(wal_bytes) - offset,
    }


def reconstruct_logical_pages(db_bytes: bytes, wal_bytes: bytes | None,
                               page_size: int, *, diagnostics: dict | None = None) -> dict[int, bytes]:
    """Rebuild the last committed snapshot, never overlaying uncommitted tails.

    Follows SQLite's file format §§4.1/4.5. Diagnostics make skipped WAL data
    visible to the public tool instead of silently claiming an applied WAL.
    """
    if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
        raise ValueError("invalid SQLite page size")
    detail = diagnostics if diagnostics is not None else {}
    detail.update(applied_frames=0, page_sources={}, warnings=[])
    pages = {pn: db_bytes[(pn-1)*page_size:pn*page_size]
             for pn in range(1, len(db_bytes)//page_size + 1)}
    if len(db_bytes) % page_size:
        detail["warnings"].append("database ends in a truncated page; incomplete page excluded")
    if wal_bytes is None:
        return pages
    try:
        wal = parse_wal(wal_bytes)
    except ValueError as exc:
        detail["warnings"].append(f"WAL was not applied: {exc}")
        return pages
    detail["wal"] = {key: value for key, value in wal.items() if key != "frames"}
    if wal["header"]["page_size"] != page_size:
        detail["warnings"].append("WAL page size differs from database; WAL was not applied")
        return pages
    committed = wal["committed_frame_count"]
    if not wal["header"]["header_checksum_valid"]:
        detail["warnings"].append("WAL header checksum is invalid; WAL was not applied")
    if wal["valid_frames"] < wal["frame_count"]:
        detail["warnings"].append("invalid WAL checksum/salt/page chain; frames after its first failure were excluded")
    if wal["trailing_bytes"]:
        detail["warnings"].append("truncated WAL tail excluded from reconstruction")
    if wal["valid_frames"] > committed:
        detail["warnings"].append("uncommitted WAL frames excluded from the current snapshot")
    if not committed:
        return pages
    frame_size = 24 + page_size
    for fr in wal["frames"][:committed]:
        offset = 32 + fr["index"] * frame_size
        pages[fr["page_number"]] = wal_bytes[offset+24:offset+24+page_size]
        detail["page_sources"][fr["page_number"]] = {"frame_index": fr["index"], "offset": offset+24}
    db_size = wal["frames"][committed-1]["db_size"]
    pages = {number: data for number, data in pages.items() if number <= db_size}
    detail["page_sources"] = {number: ref for number, ref in detail["page_sources"].items() if number <= db_size}
    detail["applied_frames"] = committed
    detail["committed_db_size"] = db_size
    return pages


# --------------------------------------------------------------------------- #
# B-tree page walking
# --------------------------------------------------------------------------- #

PAGE_TYPE_NAMES = {
    0: "freelist",
    2: "interior_index",
    5: "interior_table",
    10: "leaf_index",
    13: "leaf_table",
}

_PAGE_HEADER_LEN = {2: 12, 5: 12, 10: 8, 13: 8}


def _page_header_offset(pn: int) -> int:
    """Page 1 carries the 100-byte database header before its b-tree header."""
    return 100 if pn == 1 else 0


def _cell_pointers(page: bytes, ptype: int, hdr_off: int = 0) -> list[int]:
    hdr_len = _PAGE_HEADER_LEN.get(ptype, 8)
    num = int.from_bytes(page[hdr_off + 3:hdr_off + 5], "big")
    return [int.from_bytes(page[hdr_off + hdr_len + i * 2:hdr_off + hdr_len + i * 2 + 2], "big")
            for i in range(num)]


def _reassemble_payload(db_get_page, page_data: bytes, cell_off: int, ptype: int,
                         page_size: int, reserved: int) -> bytes:
    """Read [payload_len][rowid] then the full payload, following overflow chain."""
    p_start = cell_off
    payload_len, p = read_varint(page_data, p_start)
    _rowid, p = read_varint(page_data, p)
    usable = page_size - reserved
    if ptype in (13, 5):
        max_local = usable - 35
    else:
        max_local = ((usable - 12) * 64) // 255 - 23
    if payload_len <= max_local:
        return page_data[p:p + payload_len]
    min_local = ((usable - 12) * 32) // 255 - 23
    K = min_local + (payload_len - min_local) % (usable - 4)
    if K > max_local:
        K = max_local
    out = bytearray(page_data[p:p + K])
    # First overflow page pointer lives right after the on-page portion.
    ovf_off = p + K
    if ovf_off + 4 > len(page_data):
        return bytes(out)
    next_page = int.from_bytes(page_data[ovf_off:ovf_off + 4], "big")
    remaining = payload_len - K
    guard = 0
    while next_page and remaining > 0 and guard < 100000:
        pg = db_get_page(next_page)
        if pg is None or len(pg) < 4:
            break
        chunk = pg[4:4 + min(remaining, page_size - 4)]
        out += chunk
        remaining -= len(chunk)
        next_page = int.from_bytes(pg[0:4], "big")
        guard += 1
    return bytes(out)


def _table_leaf_cells(page: bytes, ptype: int, encoding: int,
                      page_size: int, reserved: int,
                      db_get_page, hdr_off: int = 0) -> list[tuple[int, list[Any]]]:
    if ptype != 13:
        return []
    cells = []
    for cp in _cell_pointers(page, ptype, hdr_off):
        try:
            payload = _reassemble_payload(db_get_page, page, cp, ptype, page_size, reserved)
            _plen, p = read_varint(page, cp)
            rowid, _ = read_varint(page, p)
            cols = parse_record(payload, encoding)
            cells.append((rowid, cols))
        except (ValueError, IndexError):
            continue
    return cells


def walk_table_leaves(pages: dict[int, bytes], root: int, page_size: int,
                      reserved: int, encoding: int) -> list[tuple[int, int, list[Any]]]:
    """Collect (page_num, rowid, cols) from all leaf pages of a table b-tree."""
    out: list[tuple[int, int, list[Any]]] = []
    seen: set[int] = set()

    def db_get_page(n: int) -> bytes | None:
        return pages.get(n)

    def recurse(pn: int) -> None:
        if pn in seen or pn not in pages:
            return
        seen.add(pn)
        page = pages[pn]
        h = _page_header_offset(pn)
        ptype = page[h]
        if ptype == 13:
            for rowid, cols in _table_leaf_cells(page, ptype, encoding, page_size, reserved, db_get_page, h):
                out.append((pn, rowid, cols))
        elif ptype == 5:
            for cp in _cell_pointers(page, ptype, h):
                child = int.from_bytes(page[cp:cp + 4], "big")
                recurse(child)
            right = int.from_bytes(page[h + 8:h + 12], "big")
            recurse(right)
    recurse(root)
    return out


def collect_leaf_pages(pages: dict[int, bytes], root: int) -> set[int]:
    """Return the set of leaf page numbers belonging to a table b-tree."""
    leaves: set[int] = set()
    seen: set[int] = set()

    def recurse(pn: int) -> None:
        if pn in seen or pn not in pages:
            return
        seen.add(pn)
        page = pages[pn]
        h = _page_header_offset(pn)
        ptype = page[h]
        if ptype == 13:
            leaves.add(pn)
        elif ptype == 5:
            for cp in _cell_pointers(page, ptype, h):
                recurse(int.from_bytes(page[cp:cp + 4], "big"))
            recurse(int.from_bytes(page[h + 8:h + 12], "big"))
    recurse(root)
    return leaves


def parse_schema(pages: dict[int, bytes], page_size: int, reserved: int,
                 encoding: int) -> list[dict[str, Any]]:
    """Parse sqlite_master (root page 1) into table definitions."""
    tables: list[dict[str, Any]] = []
    for _pn, _rowid, cols in walk_table_leaves(pages, 1, page_size, reserved, encoding):
        if len(cols) < 5:
            continue
        typ, name, tbl_name, rootpage, sql = cols[0], cols[1], cols[2], cols[3], cols[4]
        if typ != "table":
            continue
        if isinstance(name, str) and name.startswith("sqlite_"):
            continue
        tables.append({"type": typ, "name": name, "tbl_name": tbl_name,
                       "rootpage": int(rootpage) if isinstance(rootpage, int) else 0,
                       "sql": sql if isinstance(sql, str) else ""})
    return tables


# --------------------------------------------------------------------------- #
# Deleted-record carving
# --------------------------------------------------------------------------- #

def _record_len(payload: bytes) -> int | None:
    """Return the exact byte length of a *well-formed* record, else ``None``.

    A well-formed record fully consumes its declared ``hdr_len`` plus the exact
    content size implied by its serial types. This lets us reject byte runs that
    merely *look* record-shaped (e.g. the serial-type tail of a clobbered cell
    misread as a payload length) — forensic carving must not report those.
    """
    try:
        hdr_len, p = read_varint(payload, 0)
    except ValueError:
        return None
    q = p
    content = 0
    while q < hdr_len:
        try:
            st, q = read_varint(payload, q)
        except ValueError:
            return None
        sz = serial_content_size(st)
        if sz < 0:
            return None
        content += sz
    if q != hdr_len:
        return None
    return hdr_len + content


def _carve_cell_at(page: bytes, i: int, encoding: int) -> tuple[list[Any], int, int] | None:
    """Try to parse a table-leaf *cell* at absolute page offset ``i``.

    A cell is ``[payload_len_varint][rowid_varint][record]``. Returns
    ``(columns, rowid, cell_len)`` on success, else ``None``. This is what
    deleted rows retain after a ``DELETE`` (without ``VACUUM``): the cell bytes
    stay in the page's cell-content area, just no longer referenced by a live
    cell pointer.
    """
    try:
        plen, p1 = read_varint(page, i)
    except ValueError:
        return None
    if plen <= 0 or plen > 5_000_000:
        return None
    if p1 <= i:  # payload-length varint made no progress
        return None
    try:
        rowid, p2 = read_varint(page, p1)
    except ValueError:
        return None
    if p2 <= p1:  # rowid varint made no progress
        return None
    # The record payload starts immediately after the rowid varint (at p2).
    rec_start = p2
    if rec_start + plen > len(page):
        return None
    payload = page[rec_start:rec_start + plen]
    # Reject byte runs that only *look* record-shaped: the parsed record must
    # consume exactly ``plen`` bytes. Without this, a clobbered cell's serial
    # types misread as a payload length would produce garbage candidates.
    if _record_len(payload) != plen:
        return None
    try:
        cols = parse_record(payload, encoding)
    except (ValueError, struct.error):
        return None
    if not cols:
        return None
    # cell length = bytes consumed by [payload_len][rowid] plus the payload.
    return cols, rowid, (p2 - i) + plen


def _freeblock_regions(page: bytes, h: int) -> list[tuple[int, int]]:
    """Walk the page's freeblock chain; return ``[(start, size), ...]``."""
    regions: list[tuple[int, int]] = []
    fb = int.from_bytes(page[h + 1:h + 3], "big")
    seen: set[int] = set()
    guard = 0
    while fb and fb not in seen and guard < 100000:
        seen.add(fb)
        nxt = int.from_bytes(page[fb:fb + 2], "big")
        size = int.from_bytes(page[fb + 2:fb + 4], "big")
        if size <= 0 or fb + size > len(page) + 4:
            break
        regions.append((fb, size))
        fb = nxt
        guard += 1
    return regions


def _next_zero_triple(page: bytes, start: int) -> int | None:
    """Return the first offset ``>= start`` where three consecutive 0x00 bytes begin."""
    j = start
    L = len(page) - 2
    while j < L:
        if page[j] == 0 and page[j + 1] == 0 and page[j + 2] == 0:
            return j
        j += 1
    return None


def _enc_varint(v: int) -> bytes:
    """Encode a single non-negative integer as a SQLite varint."""
    if v < 0x80:
        return bytes([v])
    out = bytearray()
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def _reconstruct_clobbered_record(window: bytes, encoding: int) -> tuple[list[Any], int] | None:
    """Reconstruct a record whose leading ``[hdr_len][leading_serial_type]`` bytes
    were overwritten by a freeblock header.

    After ``DELETE``, SQLite writes a 4-byte freeblock header over the start of
    each dropped cell, destroying ``[payload_len][rowid][hdr_len][st0]``. What
    survives is the *tail* of the original record: ``[st1..stk][body]``. We treat
    those surviving serial types as a record header (synthesizing the correct
    ``hdr_len`` = 1 byte for the varint plus the ``q`` serial-type bytes) and
    require the serial types + content to consume the window exactly — a clean
    record boundary — so we don't report mid-record junk.
    """
    L = len(window)
    serials: list[int] = []
    q = 0
    while q < L:
        try:
            st, q = read_varint(window, q)
        except ValueError:
            return None
        if st < 0:
            return None
        serials.append(st)
        content = 0
        ok = True
        for s in serials:
            sz = serial_content_size(s)
            if sz < 0:
                ok = False
                break
            content += sz
        if not ok:
            return None
        if q + content > L:
            # Too many serial types for the available bytes — not a clean record.
            return None
        if q + content == L:
            # Exact fit: synthesize a record header = [hdr_len_varint][serial types].
            # hdr_len = 1 (varint byte) + q (serial-type bytes).
            header = _enc_varint(1 + q) + window[:q]
            payload = header + window[q:]
            try:
                cols = parse_record(payload, encoding)
            except (ValueError, struct.error):
                return None
            if 1 <= len(cols) <= 12:
                return cols, q + content
            return None
    return None


def _classify_deleted(ncols: int, expected: int | None) -> str:
    """Classify a carved record.

    ``DELETED_CANDIDATE`` when the column count matches the live schema, or is
    exactly one short (the leading column was clobbered by a freeblock header).
    Otherwise ``CARVED`` (record-shaped but schema-unmatched — heuristic only).
    """
    if expected is None:
        return "CARVED"
    if ncols == expected or ncols == expected - 1:
        return "DELETED_CANDIDATE"
    return "CARVED"


def recover_deleted(pages: dict[int, bytes], schema: list[dict[str, Any]],
                    page_size: int, reserved: int, encoding: int,
                    limit_per_table: int = 200) -> list[dict[str, Any]]:
    """Recover deleted/carved records across all table leaf pages + freelist pages.

    A ``DELETE`` (without ``VACUUM``) leaves the deleted cell's bytes in the
    page's cell-content area; the cell pointer is simply dropped. Two cases:

    * **Intact dropped cells** — still parse as ``[payload_len][rowid][record]``.
      Carved directly via :func:`_carve_cell_at`, excluding live-cell byte spans.
    * **Freeblock-clobbered cells** — SQLite wrote a 4-byte freeblock header over
      the cell start, destroying ``[payload_len][rowid][hdr_len][st0]``. The
      surviving serial-type tail is reconstructed via
      :func:`_reconstruct_clobbered_record`, bounded by the next freeblock header
      (three consecutive 0x00 bytes) so we only report clean record boundaries.
    """
    results: list[dict[str, Any]] = []
    freelist_leaves = _freelist_leaves(pages, page_size)
    for table in schema:
        root = table.get("rootpage", 0)
        if not root or root not in pages:
            continue
        leaf_set = collect_leaf_pages(pages, root)
        # Determine expected column count from live records.
        live = walk_table_leaves(pages, root, page_size, reserved, encoding)
        col_counts: dict[int, int] = {}
        for _pn, _rid, cols in live:
            col_counts[len(cols)] = col_counts.get(len(cols), 0) + 1
        expected = max(col_counts, key=col_counts.get) if col_counts else None
        candidates: list[dict[str, Any]] = []
        seen_offsets: set[int] = set()
        for pn in (leaf_set | freelist_leaves):
            page = pages[pn]
            h = _page_header_offset(pn)
            if page[h] != 13:
                continue
            content_start = int.from_bytes(page[h + 5:h + 7], "big")
            # Byte spans occupied by live cells — skip these as carve starts.
            live_spans: set[int] = set()
            if pn in leaf_set:
                for cp in _cell_pointers(page, 13, h):
                    c = _carve_cell_at(page, cp, encoding)
                    if c is not None:
                        for o in range(cp, min(cp + c[2], len(page))):
                            live_spans.add(o)
            regions = _freeblock_regions(page, h)
            region_end = lambda i: next((r0 + r1 for r0, r1 in regions if r0 <= i < r0 + r1), None)
            i = content_start
            L = len(page)
            while i < L and len(candidates) < limit_per_table:
                if i in live_spans or i in seen_offsets:
                    i += 1
                    continue
                # 1) Intact dropped cell?
                c = _carve_cell_at(page, i, encoding)
                if c is not None:
                    cols, rowid, clen = c
                    state = _classify_deleted(len(cols), expected)
                    candidates.append({
                        "state": state, "columns": cols, "col_count": len(cols),
                        "rowid": rowid, "offset": i, "length": clen,
                        "table": table["name"] + ("" if pn in leaf_set else "?"),
                        "page": pn,
                    })
                    seen_offsets.update(range(i, i + clen))
                    i += clen
                    continue
                # 2) Freeblock-clobbered cell? Only meaningful inside a freeblock
                #    region; the surviving serial-type tail is reconstructed and
                #    bounded by the next freeblock header (three 0x00 bytes) or
                #    the region end, so windows never span multiple cells.
                rend = region_end(i)
                if rend is not None:
                    b = _next_zero_triple(page, i + 4)
                    if b is None or b > rend:
                        b = rend
                    # SQLite wrote a 4-byte freeblock header over the cell start,
                    # destroying [payload_len][rowid][hdr_len][st0]. Skip it: only
                    # the surviving record tail [st1..stk][body] is record-shaped.
                    # (Leaving those 4 bytes in made the reconstruct below parse
                    # the freeblock header itself as serial types, so no
                    # freeblock-clobbered record could ever be recovered.)
                    window = page[i + 4:b]
                    if len(window) >= 4:
                        rec = _reconstruct_clobbered_record(window, encoding)
                        if rec is not None:
                            cols, rlen = rec
                            state = _classify_deleted(len(cols), expected)
                            candidates.append({
                                "state": state, "columns": cols, "col_count": len(cols),
                                "rowid": None, "offset": i, "length": rlen,
                                "table": table["name"] + ("" if pn in leaf_set else "?"),
                                "page": pn,
                            })
                            seen_offsets.update(range(i, i + rlen))
                            i += rlen
                            continue
                i += 1
        results.append({"table": table["name"], "live_rows": len(live),
                        "live_records": [{"page": pn, "rowid": rowid, "columns": cols, "state": "LIVE"}
                                         for pn, rowid, cols in live[:limit_per_table]],
                        "recovered": candidates})
    return results


def _freelist_leaves(pages: dict[int, bytes], page_size: int) -> set[int]:
    leaves: set[int] = set()
    start = int.from_bytes(pages.get(1, b"\x00" * 100)[32:36], "big")
    seen: set[int] = set()
    guard = 0
    while start and start in pages and start not in seen and guard < 100000:
        seen.add(start)
        trunk = pages[start]
        nxt = int.from_bytes(trunk[0:4], "big")
        n_leaf = int.from_bytes(trunk[4:8], "big")
        base = 8
        for i in range(n_leaf):
            off = base + i * 4
            if off + 4 > len(trunk):
                break
            leaves.add(int.from_bytes(trunk[off:off + 4], "big"))
        start = nxt
        guard += 1
    return leaves


def parse_sqlite_header_leaf(pages: dict[int, bytes], off: int) -> bytes:
    page = pages.get(1, b"")
    return page[off:off + 4]
