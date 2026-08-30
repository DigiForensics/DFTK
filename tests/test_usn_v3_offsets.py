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

"""Independent regression test for USN_RECORD_V3 parsing offsets.

The builder here hardcodes the canonical winioctl.h USN_RECORD_V3 layout and
does NOT call the test's ``_usn_record`` helper, so it stays anchored to the
real spec. This catches the bug where the V3 branch reused the V2 field offsets
(FILE_ID_128 is 16 bytes, not 8), which silently misparsed every real V3 record.
"""

import struct

from dftk.primitives.windows_usn import _parse_usn_records


def _build_v3_canonical(entry: int, parent: int, usn: int,
                        ft: int, reason: int, name: str,
                        sequence: int = 1) -> bytes:
    name_utf16 = name.encode("utf-16-le")
    nlen = len(name_utf16) // 2
    frn64 = (entry & 0x0000FFFFFFFFFFFF) | (sequence << 48)
    pfrn64 = (parent & 0x0000FFFFFFFFFFFF) | (sequence << 48)
    fn_off = 76
    base = fn_off + len(name_utf16)
    padded = (base + 7) & ~7
    rec = bytearray(padded)
    # --- canonical V3 field offsets (winioctl.h) ---
    struct.pack_into("<I", rec, 0, padded)        # RecordLength
    struct.pack_into("<H", rec, 4, 3)             # MajorVersion = 3
    struct.pack_into("<H", rec, 6, 0)             # MinorVersion
    struct.pack_into("<Q", rec, 8, frn64)         # FileReferenceNumber low 64
    struct.pack_into("<Q", rec, 16, 0)            # FileReferenceNumber high 64 (FILE_ID_128)
    struct.pack_into("<Q", rec, 24, pfrn64)       # ParentFileReferenceNumber low 64
    struct.pack_into("<Q", rec, 32, 0)            # ParentFileReferenceNumber high 64
    struct.pack_into("<Q", rec, 40, usn)          # Usn
    struct.pack_into("<Q", rec, 48, ft)           # TimeStamp
    struct.pack_into("<I", rec, 56, reason)       # Reason
    struct.pack_into("<I", rec, 60, 0)            # SourceInfo
    struct.pack_into("<I", rec, 64, 0)            # SecurityId
    struct.pack_into("<I", rec, 68, 0x20)         # FileAttributes (ARCHIVE)
    struct.pack_into("<H", rec, 72, nlen)         # FileNameLength (WORD)
    struct.pack_into("<H", rec, 74, fn_off)       # FileNameOffset (WORD)
    rec[fn_off:fn_off + len(name_utf16)] = name_utf16
    return bytes(rec)


def _ft_2024():
    from datetime import datetime, timezone
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int((datetime(2024, 6, 1, 0, 0, 0, tzinfo=timezone.utc) - epoch).total_seconds() * 10_000_000)


def test_v3_canonical_record_parsed_correctly():
    t = _ft_2024()
    data = _build_v3_canonical(45, 30, 300, t, 0x00001000, "renamed.txt")
    parsed, malformed, versions = _parse_usn_records(data, 1000)
    assert malformed == 0
    assert versions == {3}
    r = parsed[0]
    # MFT entry is the low 48 bits of the FILE_ID_128.
    assert r["mft_entry"] == 45, r
    assert r["parent_entry"] == 30, r
    assert r["usn"] == 300, r
    assert r["raw_timestamp"] == t, r
    assert r["reason"] == ["RENAME_NEW_NAME"], r
    assert r["filename"] == "renamed.txt", r
    assert r["is_dir"] is False, r


def test_v3_roundtrip_against_helper():
    """The shared helper must agree with the spec-anchored builder (regression
    guard so the two cannot silently drift apart)."""
    from test_windows_usn import _usn_record
    t = _ft_2024()
    a = _build_v3_canonical(45, 30, 300, t, 0x00001000, "renamed.txt")
    b = _usn_record(45, 30, 300, t, 0x00001000, "renamed.txt", major=3)
    pa, _, _ = _parse_usn_records(a, 10)
    pb, _, _ = _parse_usn_records(b, 10)
    assert pa[0]["mft_entry"] == pb[0]["mft_entry"] == 45
    assert pa[0]["filename"] == pb[0]["filename"] == "renamed.txt"
    assert pa[0]["usn"] == pb[0]["usn"] == 300
