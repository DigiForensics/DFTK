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

"""Pure-Python NTFS $UsnJrnl ($J) parser.

The USN change journal records file-system operations on an NTFS volume. Each
record carries a File Reference Number (FRN) whose low 48 bits are the MFT entry
and high 16 bits the sequence number, a parent FRN, a USN sequence value, a
FILETIME timestamp, a ``Reason`` bitmask, ``SourceInfo`` and ``FileAttributes``,
and the (then-current) file name.

This tool does NOT interpret USN records as execution evidence. It reports
file-system activity factually; consumers correlate USN with Prefetch / Amcache /
MFT for execution inference. That separation matches DFTK's confidence model.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from dftk.core.registry import registry
from dftk.core.models import Observation, Evidence, Status, SafetyLevel
from dftk.core.helpers import sha256_file, read_file_bounded_observation
from dftk.primitives.windows_host import build_mft_path_index

# USN_REASON_* bitmask values (winnt.h).
_REASONS = {
    0x00000001: "DATA_OVERWRITE",
    0x00000002: "DATA_EXTEND",
    0x00000004: "DATA_TRUNCATION",
    0x00000010: "NAMED_DATA_OVERWRITE",
    0x00000020: "NAMED_DATA_EXTEND",
    0x00000040: "NAMED_DATA_TRUNCATION",
    0x00000080: "FILE_CREATE",
    0x00000100: "FILE_DELETE",
    0x00000200: "EA_CHANGE",
    0x00000400: "SECURITY_CHANGE",
    0x00000800: "RENAME_OLD_NAME",
    0x00001000: "RENAME_NEW_NAME",
    0x00002000: "INDEXABLE_CHANGE",
    0x00004000: "BASIC_INFO_CHANGE",
    0x00008000: "HARD_LINK_CHANGE",
    0x00010000: "COMPRESSION_CHANGE",
    0x00020000: "ENCRYPTION_CHANGE",
    0x00040000: "OBJECT_ID_CHANGE",
    0x00080000: "REPARSE_POINT_CHANGE",
    0x00100000: "STREAM_CHANGE",
    0x00200000: "TRANSACTED_CHANGE",
    0x00400000: "INTEGRITY_CHANGE",
    0x00800000: "CLOSE",
}

# USN_SOURCE_* flags.
_SOURCES = {
    0x0001: "DATA_MANAGEMENT",   # e.g. defrag / tiering
    0x0002: "AUXILIARY_DATA",
    0x0004: "REPLICATION_MANAGEMENT",
    0x0008: "PASS_THROUGH",
    0x0010: "RENAME_REVERT",
    0x0020: "RENAME_FORCED",
    0x0040: "CHKDSK",
    0x0100: "DIRTY",             # transaction commit / abort
}

# FILE_ATTRIBUTE_* flags (a subset of the common ones).
_ATTRS = {
    0x0001: "READONLY",
    0x0002: "HIDDEN",
    0x0004: "SYSTEM",
    0x0010: "DIRECTORY",
    0x0020: "ARCHIVE",
    0x0040: "DEVICE",
    0x0080: "NORMAL",
    0x0100: "TEMPORARY",
    0x0200: "SPARSE_FILE",
    0x0400: "REPARSE_POINT",
    0x0800: "COMPRESSED",
    0x1000: "OFFLINE",
    0x2000: "NOT_CONTENT_INDEXED",
    0x4000: "ENCRYPTED",
    0x8000: "INTEGRITY_STREAM",
}


def _decode(mask: int, table: dict) -> list[str]:
    if not mask:
        return []
    return [name for bit, name in table.items() if mask & bit]


def _u16(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 2], "little")


def _u32(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 4], "little")


def _u64(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 8], "little")


def _u128(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 16], "little")


def _utf16(b: bytes) -> str:
    return b.decode("utf-16-le", "replace").split("\x00", 1)[0]


def _filetime_to_iso(ft: int) -> str | None:
    if not ft:
        return None
    try:
        from datetime import datetime, timezone, timedelta
        _EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
        seconds, rest = divmod(ft, 10_000_000)
        dt = _EPOCH + timedelta(seconds=seconds, microseconds=rest // 10)
        return dt.isoformat()
    except (OverflowError, ValueError, OSError):
        return None


def _parse_usn_records(data: bytes, record_limit: int) -> tuple[list[dict], int, set[int]]:
    """Parse a ``$J`` stream into a list of record dicts.

    Returns ``(records, malformed, versions_seen)``. Each record dict has raw
    and decoded fields but NOT resolved paths (caller supplies the MFT index).
    """
    records: list[dict] = []
    malformed = 0
    versions: set[int] = set()
    off = 0
    n = 0
    total = len(data)
    while off + 60 <= total and n < record_limit:
        rec_len = _u32(data, off)
        if rec_len < 60 or off + rec_len > total:
            # A record shorter than the fixed header, or one that overruns the
            # buffer, ends the journal stream (records are back-to-back). Stop
            # rather than misalign on arbitrary bytes.
            if rec_len == 0:
                break
            malformed += 1
            break
        major = _u16(data, off + 4)
        minor = _u16(data, off + 6)
        versions.add(major)
        if major == 3:
            # USN_RECORD_V3: FileReferenceNumber / Parent are FILE_ID_128 (16 bytes
            # each), shifting every later field +16 bytes vs. V2. Canonical layout
            # (winioctl.h): FRN@8(16B) PFRN@24(16B) Usn@40 TS@48 Reason@56
            # SourceInfo@60 SecurityId@64 FileAttributes@68
            # FileNameLength@72(WORD) FileNameOffset@74(WORD).
            frn = _u128(data, off + 8)
            parent_frn = _u128(data, off + 24)
            usn = _u64(data, off + 40)
            ts = _u64(data, off + 48)
            reason = _u32(data, off + 56)
            source = _u32(data, off + 60)
            security = _u32(data, off + 64)
            attrs = _u32(data, off + 68)
            fn_len = _u16(data, off + 72)
            fn_off = _u16(data, off + 74)
        elif major == 2:
            # USN_RECORD_V2 (USN_RECORD): FRN/PFRN are DWORDLONG (8 bytes).
            frn = _u64(data, off + 8)
            parent_frn = _u64(data, off + 16)
            usn = _u64(data, off + 24)
            ts = _u64(data, off + 32)
            reason = _u32(data, off + 40)
            source = _u32(data, off + 44)
            security = _u32(data, off + 48)
            attrs = _u32(data, off + 52)
            fn_len = _u32(data, off + 56)
            fn_off = _u32(data, off + 60)
        else:
            # V4+ uses a different (hashed) layout we do not parse; stop safely.
            malformed += 1
            break
        name = ""
        if fn_len and off + fn_off + fn_len * 2 <= total:
            name = _utf16(data[off + fn_off:off + fn_off + fn_len * 2])
        entry = frn & 0x0000FFFFFFFFFFFF
        parent_entry = parent_frn & 0x0000FFFFFFFFFFFF
        records.append({
            "usn": usn,
            "frn": frn,
            "parent_frn": parent_frn,
            "mft_entry": entry,
            "parent_entry": parent_entry,
            "timestamp": _filetime_to_iso(ts),
            "raw_timestamp": ts,
            "reason": _decode(reason, _REASONS),
            "reason_raw": reason,
            "source_info": _decode(source, _SOURCES),
            "security_id": security,
            "file_attributes": _decode(attrs, _ATTRS),
            "is_dir": bool(attrs & 0x0010),
            "filename": name,
            "major_version": major,
            "minor_version": minor,
        })
        off += rec_len
        n += 1
    return records, malformed, versions


@registry.tool(
    name="windows.usnjrnl",
    description="Parse an NTFS $UsnJrnl $J change-journal stream (pure-Python): recover USN records with File "
                "Reference Numbers, timestamps, reason codes, source info and file attributes. Optionally resolves "
                "FRNs to full NTFS paths via a provided $MFT. Reports file-system activity factually; it does NOT "
                "infer program execution (correlate with Prefetch/Amcache/MFT instead).",
    safety=SafetyLevel.READ_ONLY,
    tags=("windows", "usnjrnl", "timeline", "filesystem"),
    produces=("usn_records", "timeline"),
    cost_hint="medium",
    parameters={"type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to the extracted $J stream file"},
                    "mft_path": {"type": "string", "description": "Optional $MFT file to resolve FRNs to full paths", "default": None},
                    "record_limit": {"type": "integer", "default": 200000},
                    "reason_filter": {"type": "array", "items": {"type": "string"},
                                      "description": "Only include records whose reason set intersects these names (e.g. FILE_CREATE, RENAME_NEW_NAME, CLOSE)", "default": None},
                },
                "required": ["path"]},
)
def usnjrnl(path: str, mft_path: str | None = None, record_limit: int = 200000,
            reason_filter: list[str] | None = None) -> Observation:
    p = Path(path)
    if not p.is_file():
        return Observation("windows.usnjrnl", Status.ERROR, "USN $J file not found", errors=[str(p)])
    data, err = read_file_bounded_observation("windows.usnjrnl", p, 8 * 1024 * 1024 * 1024)
    if err:
        return err
    h = sha256_file(p)

    records, malformed, versions = _parse_usn_records(data, record_limit)

    path_index: dict = {}
    if mft_path:
        try:
            path_index = build_mft_path_index(mft_path, record_limit=record_limit)
        except Exception:  # path resolution is best-effort
            malformed += 1
            path_index = {}

    resolved = 0
    reason_set = {r.upper() for r in (reason_filter or [])}
    out: list[dict] = []
    for r in records:
        if reason_set:
            if not (reason_set & set(r["reason"])):
                continue
        full = path_index.get(r["mft_entry"]) if path_index else None
        if full:
            resolved += 1
        row = {k: r[k] for k in ("usn", "timestamp", "reason", "reason_raw",
                                 "source_info", "file_attributes", "is_dir",
                                 "filename", "mft_entry", "parent_entry",
                                 "major_version")}
        row["path"] = full if full else None
        out.append(row)

    reason_summary: Counter = Counter()
    for r in out:
        for rs in r["reason"]:
            reason_summary[rs] += 1
    timeline = [
        {"timestamp": r["timestamp"], "path": r["path"] or r["filename"],
         "reason": r["reason"], "frn": r["mft_entry"]}
        for r in out if r["timestamp"]
    ]
    timeline.sort(key=lambda t: t["timestamp"] or "")

    ev = [
        Evidence(str(p), "usn_record",
                 (r["path"] or r["filename"] or f"<frn:{r['mft_entry']}>"),
                 locator=f"usn:{r['usn']}", note=",".join(r["reason"]) or None,
                 source_sha256=h, method="NTFS $UsnJrnl parser")
        for r in out[:300]
    ]

    warnings = []
    if malformed:
        warnings.append(f"{malformed} record(s) skipped as malformed or truncated")
    if len(out) >= record_limit:
        warnings.append(f"record parsing limited to {record_limit}")
    if mft_path and not path_index:
        warnings.append("MFT path index could not be built; FRNs left unresolved")
    if mft_path and path_index and out and resolved == 0:
        warnings.append("MFT supplied but no FRN matched an indexed entry (entry numbering mismatch?)")

    return Observation(
        "windows.usnjrnl",
        Status.PARTIAL if warnings else Status.OK,
        f"Parsed {len(out)} USN record(s) from $J (v{','.join(map(str, sorted(versions))) or '?'})"
        + (f", {resolved} resolved to MFT path" if path_index else ""),
        facts={
            "record_count": len(out),
            "versions": sorted(versions),
            "resolved_path_count": resolved if path_index else 0,
            "mft_resolved": bool(path_index),
            "reason_summary": dict(reason_summary.most_common()),
            "records": out,
            "timeline": timeline,
        },
        evidence=ev,
        warnings=warnings,
        meta={"source_sha256": h},
    )
