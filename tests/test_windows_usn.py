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

"""End-to-end tests for windows.usnjrnl and the MFT path index it correlates with."""

from __future__ import annotations

import os
import struct
import tempfile
from datetime import datetime, timezone, timedelta

from dftk.primitives.windows_host import build_mft_path_index, mft
from dftk.primitives import windows_usn as usn_mod
from dftk.primitives.windows_usn import usnjrnl, _parse_usn_records


def _filetime(dt: datetime) -> int:
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int((dt - epoch).total_seconds() * 10_000_000)


# Reason codes reused from windows_usn._REASONS values.
_R_FILE_CREATE = 0x00000080
_R_CLOSE = 0x00800000
_R_RENAME_NEW = 0x00001000


def _usn_record(entry: int, parent: int, usn: int, ft: int, reason: int,
                name: str, attrs: int = 0x20, sequence: int = 1,
                major: int = 2) -> bytes:
    """Build a single USN_RECORD (V2 when major==2, V3 when major==3).

    Offsets follow the canonical winioctl.h layouts:
      V2: FRN@8(8B) PFRN@16(8B) Usn@24 TS@32 Reason@40 Src@44 Sec@48 Attr@52
          FileNameLength@56(DWORD) FileNameOffset@60(DWORD).
      V3: FRN@8(16B FILE_ID_128) PFRN@24(16B) Usn@40 TS@48 Reason@56 Src@60
          Sec@64 Attr@68 FileNameLength@72(WORD) FileNameOffset@74(WORD).
    """
    name_utf16 = name.encode("utf-16-le")
    nlen = len(name_utf16) // 2
    frn64 = (entry & 0x0000FFFFFFFFFFFF) | (sequence << 48)
    pfrn64 = (parent & 0x0000FFFFFFFFFFFF) | (sequence << 48)
    if major == 3:
        fn_off = 76                       # after FileNameOffset WORD at 74
        base = fn_off + len(name_utf16)
        padded = (base + 7) & ~7
        rec = bytearray(padded)
        struct.pack_into("<I", rec, 0, padded)          # RecordLength
        struct.pack_into("<H", rec, 4, major)           # MajorVersion
        struct.pack_into("<H", rec, 6, 0)               # MinorVersion
        struct.pack_into("<Q", rec, 8, frn64)           # FileReferenceNumber low 64
        struct.pack_into("<Q", rec, 16, 0)              # FILE_ID_128 high 64
        struct.pack_into("<Q", rec, 24, pfrn64)         # ParentFileReferenceNumber low
        struct.pack_into("<Q", rec, 32, 0)              # FILE_ID_128 high 64
        struct.pack_into("<Q", rec, 40, usn)            # Usn
        struct.pack_into("<Q", rec, 48, ft)             # TimeStamp
        struct.pack_into("<I", rec, 56, reason)         # Reason
        struct.pack_into("<I", rec, 60, 0)              # SourceInfo
        struct.pack_into("<I", rec, 64, 0)              # SecurityId
        struct.pack_into("<I", rec, 68, attrs)          # FileAttributes
        struct.pack_into("<H", rec, 72, nlen)           # FileNameLength
        struct.pack_into("<H", rec, 74, fn_off)         # FileNameOffset
    else:
        fn_off = 64
        base = fn_off + len(name_utf16)
        padded = (base + 7) & ~7
        rec = bytearray(padded)
        struct.pack_into("<I", rec, 0, padded)          # RecordLength
        struct.pack_into("<H", rec, 4, major)           # MajorVersion
        struct.pack_into("<H", rec, 6, 0)               # MinorVersion
        struct.pack_into("<Q", rec, 8, frn64)           # FileReferenceNumber
        struct.pack_into("<Q", rec, 16, pfrn64)         # ParentFileReferenceNumber
        struct.pack_into("<Q", rec, 24, usn)            # Usn
        struct.pack_into("<Q", rec, 32, ft)             # TimeStamp
        struct.pack_into("<I", rec, 40, reason)         # Reason
        struct.pack_into("<I", rec, 44, 0)              # SourceInfo
        struct.pack_into("<I", rec, 48, 0)              # SecurityId
        struct.pack_into("<I", rec, 52, attrs)          # FileAttributes
        struct.pack_into("<I", rec, 56, nlen)           # FileNameLength
        struct.pack_into("<I", rec, 60, fn_off)         # FileNameOffset
    rec[fn_off:fn_off + len(name_utf16)] = name_utf16
    return bytes(rec)


def _mft_record(entry: int, name: str, parent: int, is_dir: bool = False,
                seq: int = 1) -> bytearray:
    """Build a minimal 1024-byte $MFT FILE record that dftk's parser understands.

    Layout is aligned to ``windows_host._parse_mft_record``: the $FILE_NAME
    content places name_len at cstart+0x40 and the UTF-16 name at cstart+0x42.
    """
    rec = bytearray(1024)
    rec[0:4] = b"FILE"
    struct.pack_into("<H", rec, 4, 0)               # usa_off (0 => no fixup)
    struct.pack_into("<H", rec, 6, 0)               # usa_count
    struct.pack_into("<H", rec, 0x10, seq)          # sequence
    struct.pack_into("<H", rec, 0x14, 0x38)         # attr_off
    flags = 0x01 | (0x02 if is_dir else 0)
    struct.pack_into("<H", rec, 0x16, flags)
    attroff = 0x38
    coff = 0x18
    name_utf16 = name.encode("utf-16-le")
    nlen = len(name_utf16) // 2
    cstart = attroff + coff                         # 0x50
    struct.pack_into("<Q", rec, cstart + 0, parent)
    for k in range(8, 0x30, 8):
        struct.pack_into("<Q", rec, cstart + k, 1)
    struct.pack_into("<Q", rec, cstart + 0x30, 100)  # size (parser reads here)
    struct.pack_into("<I", rec, cstart + 0x38, 0)   # fn flags
    rec[cstart + 0x40] = nlen                       # name_len (parser reads here)
    rec[cstart + 0x42:cstart + 0x42 + len(name_utf16)] = name_utf16
    clen = 0x42 + len(name_utf16)
    alen = coff + clen
    struct.pack_into("<I", rec, attroff + 0, 0x30)  # attribute type $FILE_NAME
    struct.pack_into("<I", rec, attroff + 4, alen)  # attribute length
    rec[attroff + 8] = 0                            # resident
    struct.pack_into("<H", rec, attroff + 0x0C, 0)  # instance
    struct.pack_into("<I", rec, attroff + 0x10, clen)
    struct.pack_into("<H", rec, attroff + 0x14, coff)
    struct.pack_into("<I", rec, attroff + alen, 0xFFFFFFFF)  # attribute terminator
    return rec


def _build_mft(entries: list[tuple[int, str, int, bool]]) -> str:
    max_entry = max(e[0] for e in entries)
    blob = bytearray((max_entry + 1) * 1024)
    for entry, name, parent, is_dir in entries:
        rec = _mft_record(entry, name, parent, is_dir)
        blob[entry * 1024:entry * 1024 + 1024] = rec
    fd, path = tempfile.mkstemp(suffix=".mft")
    with os.fdopen(fd, "wb") as f:
        f.write(blob)
    return path


def _build_j(records: list[bytes]) -> str:
    fd, path = tempfile.mkstemp(suffix=".usn")
    with os.fdopen(fd, "wb") as f:
        for r in records:
            f.write(r)
    return path


def test_parse_usn_v2_basic():
    t1 = _filetime(datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc))
    t2 = _filetime(datetime(2024, 1, 2, 3, 4, 6, tzinfo=timezone.utc))
    recs = [
        _usn_record(30, 5, 100, t1, _R_FILE_CREATE, "Users", attrs=0x10),
        _usn_record(45, 30, 200, t2, _R_CLOSE, "note.txt", attrs=0x20),
    ]
    data = b"".join(recs)
    parsed, malformed, versions = _parse_usn_records(data, 1000)
    assert malformed == 0
    assert versions == {2}
    assert len(parsed) == 2
    assert parsed[0]["mft_entry"] == 30
    assert parsed[0]["parent_entry"] == 5
    assert parsed[0]["reason"] == ["FILE_CREATE"]
    assert parsed[0]["is_dir"] is True
    assert parsed[1]["mft_entry"] == 45
    assert parsed[1]["reason"] == ["CLOSE"]
    assert parsed[1]["filename"] == "note.txt"
    assert parsed[0]["timestamp"].startswith("2024-01-02T03:04:05")


def test_parse_usn_v3_filename_offset():
    t = _filetime(datetime(2024, 6, 1, 0, 0, 0, tzinfo=timezone.utc))
    data = _usn_record(45, 30, 300, t, _R_RENAME_NEW, "renamed.txt", major=3)
    parsed, malformed, versions = _parse_usn_records(data, 1000)
    assert malformed == 0
    assert versions == {3}
    assert parsed[0]["filename"] == "renamed.txt"
    assert parsed[0]["reason"] == ["RENAME_NEW_NAME"]


def test_usnjrnl_no_mft():
    t1 = _filetime(datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc))
    t2 = _filetime(datetime(2024, 1, 2, 3, 4, 6, tzinfo=timezone.utc))
    t3 = _filetime(datetime(2024, 1, 2, 3, 4, 7, tzinfo=timezone.utc))
    recs = [
        _usn_record(30, 5, 100, t1, _R_FILE_CREATE, "Users", attrs=0x10),
        _usn_record(45, 30, 200, t2, _R_FILE_CREATE, "note.txt", attrs=0x20),
        _usn_record(45, 30, 250, t3, _R_CLOSE, "note.txt", attrs=0x20),
    ]
    jpath = _build_j(recs)
    try:
        obs = usnjrnl(jpath)
        assert obs.status.name in ("OK", "PARTIAL")
        facts = obs.facts
        assert facts["record_count"] == 3
        assert facts["mft_resolved"] is False
        assert facts["reason_summary"]["FILE_CREATE"] == 2
        assert facts["reason_summary"]["CLOSE"] == 1
        # Timeline sorted ascending by timestamp.
        times = [t["timestamp"] for t in facts["timeline"]]
        assert times == sorted(times)
        assert facts["timeline"][0]["path"] == "Users"
    finally:
        os.remove(jpath)


def test_usnjrnl_with_mft_resolution():
    mft_path = _build_mft([
        (5, "C", 5, True),
        (30, "Users", 5, True),
        (45, "note.txt", 30, False),
    ])
    t2 = _filetime(datetime(2024, 1, 2, 3, 4, 6, tzinfo=timezone.utc))
    t3 = _filetime(datetime(2024, 1, 2, 3, 4, 7, tzinfo=timezone.utc))
    recs = [
        _usn_record(45, 30, 200, t2, _R_FILE_CREATE, "note.txt", attrs=0x20),
        _usn_record(45, 30, 250, t3, _R_CLOSE, "note.txt", attrs=0x20),
    ]
    jpath = _build_j(recs)
    try:
        # Sanity: the MFT builder is parser-compatible.
        mft_obs = mft(mft_path)
        assert mft_obs.facts["record_count"] == 3
        resolved_paths = {r["path"] for r in mft_obs.facts["records"]}
        assert "C\\Users" in resolved_paths
        assert "C\\Users\\note.txt" in resolved_paths

        obs = usnjrnl(jpath, mft_path=mft_path)
        facts = obs.facts
        assert facts["mft_resolved"] is True
        assert facts["resolved_path_count"] == 2
        for r in facts["records"]:
            assert r["path"] == "C\\Users\\note.txt"
    finally:
        os.remove(jpath)
        os.remove(mft_path)


def test_usnjrnl_reason_filter():
    t1 = _filetime(datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc))
    t2 = _filetime(datetime(2024, 1, 2, 3, 4, 6, tzinfo=timezone.utc))
    recs = [
        _usn_record(45, 30, 200, t1, _R_FILE_CREATE, "note.txt", attrs=0x20),
        _usn_record(45, 30, 250, t2, _R_CLOSE, "note.txt", attrs=0x20),
    ]
    jpath = _build_j(recs)
    try:
        obs = usnjrnl(jpath, reason_filter=["CLOSE"])
        assert obs.facts["record_count"] == 1
        assert obs.facts["records"][0]["reason"] == ["CLOSE"]
    finally:
        os.remove(jpath)


def test_build_mft_path_index_direct():
    mft_path = _build_mft([
        (5, "C", 5, True),
        (30, "Users", 5, True),
        (45, "note.txt", 30, False),
    ])
    try:
        idx = build_mft_path_index(mft_path)
        assert idx[45] == "C\\Users\\note.txt"
        assert idx[30] == "C\\Users"
        assert idx[5] == "C"
    finally:
        os.remove(mft_path)
