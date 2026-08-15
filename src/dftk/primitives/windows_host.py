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

"""Pure-Python Windows host-forensics artifacts.

These tools parse the most common endpoint-forensic artifacts without any
external binary or third-party library (stdlib only), so they work out of the
box on student machines:

* ``windows.mft``        -- NTFS $MFT records (file paths + SI/FN timestamps)
* ``windows.prefetch``   -- Windows Prefetch (.pf) execution traces
* ``windows.lnk``        -- Shell Link (.lnk) target + timestamps + tracker
* ``windows.recyclebin`` -- Recycle Bin $I metadata (deleted name + time)
"""

from __future__ import annotations

import datetime
import struct
from pathlib import Path

from dftk.core.registry import registry
from dftk.core.models import Observation, Evidence, Status, SafetyLevel
from dftk.core.helpers import sha256_file, read_file_bounded_observation

# Windows epoch: 100ns intervals since 1601-01-01 UTC.
_WIN_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
_FT_2000 = 0
_FT_2050 = 0


def _init_bounds() -> None:
    global _FT_2000, _FT_2050
    if _FT_2000:
        return
    _FT_2000 = int((datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc) - _WIN_EPOCH).total_seconds() * 10_000_000)
    _FT_2050 = int((datetime.datetime(2050, 1, 1, tzinfo=datetime.timezone.utc) - _WIN_EPOCH).total_seconds() * 10_000_000)


def _filetime_to_iso(ft: int) -> str | None:
    if not ft:
        return None
    try:
        # FILETIME counts 100-nanosecond intervals. Convert with integer
        # arithmetic: a float division would lose precision for large values
        # (double has ~53 bits of mantissa) and skew the microsecond result.
        seconds, rest = divmod(ft, 10_000_000)
        dt = _WIN_EPOCH + datetime.timedelta(seconds=seconds, microseconds=rest // 10)
        return dt.isoformat()
    except (OverflowError, ValueError, OSError):
        return None


def _plausible_ft(ft: int) -> bool:
    _init_bounds()
    return bool(ft) and _FT_2000 <= ft <= _FT_2050


def _u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def _u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def _u64(b: bytes, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]


def _utf16(b: bytes) -> str:
    return b.decode("utf-16-le", "replace").split("\x00", 1)[0]


# --------------------------------------------------------------------------- #
# NTFS $MFT
# --------------------------------------------------------------------------- #

def _apply_usa(rec: bytearray, base: int) -> None:
    """Apply the Update Sequence Array fixup to a FILE record (512-byte sectors)."""
    if base + 8 > len(rec):
        return
    usa_off = _u16(rec, base + 4)
    usa_count = _u16(rec, base + 6)
    if usa_off < 8 or usa_off + 2 * usa_count > len(rec) or usa_count < 2:
        return
    usa_num = _u16(rec, base + usa_off)
    for s in range(1, usa_count):
        sector_end = base + s * 512
        if sector_end + 2 > len(rec):
            break
        if _u16(rec, sector_end - 2) == usa_num:
            rec[sector_end - 2] = rec[base + usa_off + 2 * s]
            rec[sector_end - 1] = rec[base + usa_off + 2 * s + 1]


def _parse_mft_record(rec: bytearray, base: int, entry_no: int) -> dict | None:
    sig = bytes(rec[base:base + 4])
    if sig not in (b"FILE", b"BAAD"):
        return None
    _apply_usa(rec, base)
    attr_off = _u16(rec, base + 0x14)
    flags = _u16(rec, base + 0x16)
    is_dir = bool(flags & 0x02)
    in_use = bool(flags & 0x01)

    si = {}
    fn_list = []
    off = base + attr_off
    end = len(rec)
    while off + 4 <= end:
        atype = _u32(rec, off)
        if atype == 0xFFFFFFFF:
            break
        alen = _u32(rec, off + 4)
        if alen <= 0 or off + alen > end:
            break
        non_res = rec[off + 8]
        if atype in (0x10, 0x30) and not non_res:
            clen = _u32(rec, off + 0x10)
            coff = _u16(rec, off + 0x14)
            cstart = off + coff
            if cstart + clen > end or clen < 8:
                off += alen
                continue
            if atype == 0x10 and clen >= 32:  # Standard Information
                si = {
                    "creation": _filetime_to_iso(_u64(rec, cstart + 0)),
                    "modified": _filetime_to_iso(_u64(rec, cstart + 8)),
                    "mft_modified": _filetime_to_iso(_u64(rec, cstart + 16)),
                    "accessed": _filetime_to_iso(_u64(rec, cstart + 24)),
                }
            elif atype == 0x30 and clen >= 0x42:  # $FILE_NAME
                parent_ref = _u64(rec, cstart + 0)
                parent = parent_ref & 0x0000FFFFFFFFFFFF
                fn = {
                    "parent": parent,
                    "creation": _filetime_to_iso(_u64(rec, cstart + 8)),
                    "modified": _filetime_to_iso(_u64(rec, cstart + 16)),
                    "mft_modified": _filetime_to_iso(_u64(rec, cstart + 24)),
                    "accessed": _filetime_to_iso(_u64(rec, cstart + 32)),
                    "flags": _u32(rec, cstart + 0x38),
                    "size": _u64(rec, cstart + 0x30),
                    "allocated": _u64(rec, cstart + 0x40),
                }
                name_len = rec[cstart + 0x40]
                raw = bytes(rec[cstart + 0x42:cstart + 0x42 + name_len * 2])
                fn["name"] = _utf16(raw)
                fn_list.append(fn)
        off += alen

    name = fn_list[0]["name"] if fn_list else ""
    fn_times = fn_list[0] if fn_list else {}
    parent = fn_list[0]["parent"] if fn_list else 0
    return {
        "entry": entry_no,
        "sequence": _u16(rec, base + 0x10),
        "in_use": in_use,
        "is_dir": is_dir,
        "name": name,
        "parent": parent,
        "si": si,
        "fn": fn_times,
    }


def _build_path(parents: dict[int, tuple[str, int]], entry_no: int) -> str:
    parts: list[str] = []
    seen: set[int] = set()
    cur = entry_no
    while cur in parents and cur not in seen and len(parts) < 64:
        seen.add(cur)
        name, parent = parents[cur]
        parts.append(name)
        if cur == parent:
            break
        cur = parent
    if not parts:
        return f"<MFT#{entry_no}>"
    return "\\".join(reversed(parts))


@registry.tool(
    name="windows.mft",
    description="Parse an NTFS $MFT file with pure-Python parsing: recover file/directory paths, "
                "Standard Information and $FILE_NAME timestamps, record flags and sizes. Best-effort "
                "full-path reconstruction via parent references.",
    safety=SafetyLevel.READ_ONLY,
    tags=("windows", "mft", "timeline", "filesystem"),
    produces=("mft_records", "timeline"),
    cost_hint="medium",
    parameters={"type": "object",
                "properties": {"path": {"type": "string"},
                               "record_limit": {"type": "integer", "default": 200000},
                               "deleted_only": {"type": "boolean", "default": False}},
                "required": ["path"]},
)
def mft(path: str, record_limit: int = 200000, deleted_only: bool = False) -> Observation:
    p = Path(path)
    if not p.is_file():
        return Observation("windows.mft", Status.ERROR, "MFT file not found", errors=[str(p)])
    data, err = read_file_bounded_observation("windows.mft", p, 8 * 1024 * 1024 * 1024)
    if err:
        return err
    h = sha256_file(p)
    records: list[dict] = []
    parents: dict[int, tuple[str, int]] = {}
    stride = 1024
    off = 0
    malformed = 0
    n = 0
    while off + 48 <= len(data) and n < record_limit:
        sig = bytes(data[off:off + 4])
        if sig in (b"FILE", b"BAAD"):
            rec = bytearray(data[off:off + stride])
            entry = _parse_mft_record(rec, 0, off // stride)
            if entry is None:
                malformed += 1
                off += stride
                continue
            if entry["name"]:
                parents[entry["entry"]] = (entry["name"], entry["parent"])
            records.append(entry)
            alloc = _u32(data, off + 0x1C)
            step = alloc if 0 < alloc <= 0x10000 else stride
        else:
            step = stride
        off += step
        n += 1

    for r in records:
        r["path"] = _build_path(parents, r["entry"])
    if deleted_only:
        records = [r for r in records if not r["in_use"]]
    for r in records:
        r.pop("in_use", None)
        r.pop("parent", None)

    ev = []
    for r in records[:300]:
        ev.append(Evidence(str(p), "mft_record", f"{r['path']}", locator=f"entry:{r['entry']}",
                            note=f"{'dir' if r['is_dir'] else 'file'}", source_sha256=h, method="NTFS $MFT parser"))
    warnings = []
    if malformed:
        warnings.append(f"{malformed} non-FILE/BAAD region(s) skipped")
    if n >= record_limit:
        warnings.append(f"record parsing limited to {record_limit}")
    return Observation(
        "windows.mft",
        Status.PARTIAL if warnings else Status.OK,
        f"Parsed {len(records)} $MFT record(s)",
        facts={"record_count": len(records), "records": records},
        evidence=ev,
        warnings=warnings,
        meta={"source_sha256": h},
    )


# --------------------------------------------------------------------------- #
# Windows Prefetch (.pf)
# --------------------------------------------------------------------------- #

def _read_prefetch_trace(data: bytes, trace_off: int, trace_count: int, entry_size: int) -> list[str]:
    out: list[str] = []
    for k in range(trace_count):
        eo = trace_off + k * entry_size
        if eo + entry_size > len(data):
            break
        fn_off = _u32(data, eo + 4)
        if fn_off + 2 > len(data):
            continue
        # trace filenames are UTF-16LE, null terminated
        end = data.find(b"\x00\x00", fn_off)
        if end == -1:
            end = len(data)
        s = _utf16(data[fn_off:end])
        if s:
            out.append(s)
    return out


@registry.tool(
    name="windows.prefetch",
    description="Parse a Windows Prefetch file (.pf, versions 17/23/26/30) with pure-Python parsing: recover the "
                "executable path, prefetch hash, run count and last-run time(s), and the set of referenced files.",
    safety=SafetyLevel.READ_ONLY,
    tags=("windows", "prefetch", "execution", "timeline"),
    produces=("prefetch_execution", "timeline"),
    cost_hint="low",
    parameters={"type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"]},
)
def prefetch(path: str) -> Observation:
    p = Path(path)
    if not p.is_file():
        return Observation("windows.prefetch", Status.ERROR, "Prefetch file not found", errors=[str(p)])
    data, err = read_file_bounded_observation("windows.prefetch", p, 64 * 1024 * 1024)
    if err:
        return err
    h = sha256_file(p)
    if len(data) < 0x54 or data[4:8] != b"SCCA":
        return Observation("windows.prefetch", Status.UNSUPPORTED, "Not a Prefetch (SCCA) file",
                           errors=["missing SCCA signature"], meta={"source_sha256": h})
    version = _u32(data, 0)
    name_off = _u32(data, 0x0C)
    name_len = _u32(data, 0x10)
    pf_hash = _u32(data, 0x14)
    exe_name = ""
    if name_off + name_len * 2 <= len(data) and name_len:
        exe_name = _utf16(data[name_off:name_off + name_len * 2])
    metrics_off = _u32(data, 0x1C)
    metrics_count = _u32(data, 0x20)
    trace_off = _u32(data, 0x24)
    trace_count = _u32(data, 0x28)
    entry_size = {17: 0x14, 23: 0x20, 26: 0x20, 30: 0x20}.get(version, 0x20)
    refs = _read_prefetch_trace(data, trace_off, trace_count, entry_size)

    run_count = None
    last_runs: list[str] = []
    best_effort = False
    if version == 17:
        if 0x98 + 12 <= len(data):
            run_count = _u32(data, 0x98)
            for t in range(0x9C, 0x9C + 8 * 8, 8):
                iso = _filetime_to_iso(_u64(data, t)) if t + 8 <= len(data) else None
                if iso:
                    last_runs.append(iso)
    else:
        # v23/26/30: run count and last-run are stored in the file-information section.
        # Best-effort: last-run is the leading FILETIME of the metrics array header on these
        # versions; run count is read from the historical 0x98 offset when it looks valid.
        if metrics_off + 8 <= len(data):
            ft = _u64(data, metrics_off)
            iso = _filetime_to_iso(ft)
            if iso:
                last_runs.append(iso)
                best_effort = True
        if 0x98 + 4 <= len(data):
            rc = _u32(data, 0x98)
            if 1 <= rc <= 1_000_000:
                run_count = rc
                best_effort = True

    notes = []
    if best_effort:
        notes.append("run count / last-run parsed best-effort for Prefetch v23+; confirm with a specialist parser")
    return Observation(
        "windows.prefetch",
        Status.OK,
        f"Parsed Prefetch v{version} for {exe_name or '<unknown>'}",
        facts={
            "version": version,
            "executable": exe_name,
            "prefetch_hash": f"0x{pf_hash:08X}",
            "run_count": run_count,
            "last_run_times": last_runs,
            "referenced_file_count": len(refs),
            "referenced_files": refs[:2000],
        },
        evidence=[Evidence(str(p), "prefetch_executable", exe_name, locator="executable",
                           source_sha256=h, method="Prefetch parser")],
        warnings=notes,
        meta={"source_sha256": h},
    )


# --------------------------------------------------------------------------- #
# Shell Link (.lnk)
# --------------------------------------------------------------------------- #

def _read_lnk_strings(data: bytes, pos: int) -> tuple[list[str], int]:
    """Read the StringData section (NAME, RELATIVE_PATH, WORKING_DIR, ARGS, ICON)."""
    flags = _u32(data, 0x14)
    strings: list[str] = []
    p = pos
    for bit, _ in ((0x00000004, "name"), (0x00000008, "rel"), (0x00000010, "cwd"),
                   (0x00000020, "args"), (0x00004000, "icon")):
        if not (flags & bit):
            continue
        if p + 2 > len(data):
            break
        slen = _u16(data, p)
        p += 2
        raw = data[p:p + slen * 2]
        p += slen * 2
        strings.append(_utf16(raw))
    return strings, p


@registry.tool(
    name="windows.lnk",
    description="Parse a Windows Shell Link (.lnk) shortcut with pure-Python parsing: recover the target path, "
                "file attributes, creation/access/write timestamps, and TrackerDataBlock (machine id / MAC).",
    safety=SafetyLevel.READ_ONLY,
    tags=("windows", "lnk", "shortcut", "timeline"),
    produces=("lnk_target", "timeline"),
    cost_hint="low",
    parameters={"type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"]},
)
def lnk(path: str) -> Observation:
    p = Path(path)
    if not p.is_file():
        return Observation("windows.lnk", Status.ERROR, "LNK file not found", errors=[str(p)])
    data, err = read_file_bounded_observation("windows.lnk", p, 16 * 1024 * 1024)
    if err:
        return err
    h = sha256_file(p)
    if len(data) < 0x4C or _u32(data, 0) != 0x4C:
        return Observation("windows.lnk", Status.UNSUPPORTED, "Not a Shell Link (.lnk) file",
                           errors=["header size != 0x4C"], meta={"source_sha256": h})
    flags = _u32(data, 0x14)
    times = {
        "creation": _filetime_to_iso(_u64(data, 0x1C)),
        "accessed": _filetime_to_iso(_u64(data, 0x24)),
        "write": _filetime_to_iso(_u64(data, 0x2C)),
    }
    file_size = _u32(data, 0x34)
    file_attrs = _u32(data, 0x18)

    target_path = ""
    pos = 0x4C
    if flags & 0x01:  # HasLinkTargetIDList
        idlist_size = _u16(data, pos)
        pos += 2 + idlist_size
    if flags & 0x02:  # HasLinkInfo
        if pos + 4 <= len(data):
            li_size = _u32(data, pos)
            li_hdr = _u32(data, pos + 4)
            if li_hdr >= 0x1C and pos + li_hdr <= len(data):
                local_base_off = _u32(data, pos + 0x10)
                common_suffix_off = _u32(data, pos + 0x18)
                uni_base_off = _u32(data, pos + 0x1C) if li_hdr >= 0x24 else 0
                base = ""
                if uni_base_off and pos + uni_base_off + 2 <= len(data):
                    blen = _u16(data, pos + uni_base_off)
                    base = _utf16(data[pos + uni_base_off + 2:pos + uni_base_off + 2 + blen * 2])
                elif local_base_off and pos + local_base_off + 2 <= len(data):
                    blen = _u16(data, pos + local_base_off)
                    base = _utf16(data[pos + local_base_off + 2:pos + local_base_off + 2 + blen * 2])
                suffix = ""
                if common_suffix_off and pos + common_suffix_off + 2 <= len(data):
                    slen = _u16(data, pos + common_suffix_off)
                    suffix = _utf16(data[pos + common_suffix_off + 2:pos + common_suffix_off + 2 + slen * 2])
                target_path = (base + suffix).rstrip("\x00")
            pos += li_size
    # StringData
    strings, pos = _read_lnk_strings(data, pos)

    # ExtraData: scan for TrackerDataBlock (0xA0000003)
    machine_id = ""
    mac = ""
    while pos + 4 <= len(data):
        block_size = _u32(data, pos)
        block_sig = _u32(data, pos + 4)
        if block_size < 8 or pos + block_size > len(data):
            break
        if block_sig == 0xA0000003 and block_size >= 0x58:  # TrackerDataBlock
            mac = data[pos + 0x18:pos + 0x1E].hex()
            machine_id = data[pos + 0x30:pos + 0x40].hex()
            break
        pos += block_size

    return Observation(
        "windows.lnk",
        Status.OK,
        f"Parsed shortcut -> {target_path or '<no target path>'}",
        facts={
            "target_path": target_path,
            "string_data": strings,
            "file_size": file_size,
            "file_attributes": file_attrs,
            "timestamps": times,
            "machine_id": machine_id,
            "mac_address": mac,
        },
        evidence=[Evidence(str(p), "lnk_target", target_path, locator="link_info",
                           source_sha256=h, method="Shell Link parser")],
        meta={"source_sha256": h},
    )


# --------------------------------------------------------------------------- #
# Recycle Bin $I metadata (Windows 10+)
# --------------------------------------------------------------------------- #

@registry.tool(
    name="windows.recyclebin",
    description="Parse Windows Recycle Bin $I metadata files (Windows 10+): recover the original deleted file name, "
                "size and deletion time, and detect the paired $R data file when present.",
    safety=SafetyLevel.READ_ONLY,
    tags=("windows", "recyclebin", "timeline"),
    produces=("recyclebin_deleted", "timeline"),
    cost_hint="low",
    parameters={"type": "object",
                "properties": {"path": {"type": "string"},
                               "find_data": {"type": "boolean", "default": True}},
                "required": ["path"]},
)
def recyclebin(path: str, find_data: bool = True) -> Observation:
    p = Path(path)
    if not p.is_file():
        return Observation("windows.recyclebin", Status.ERROR, "Recycle Bin $I file not found", errors=[str(p)])
    name = p.name
    if not name.startswith("$I"):
        return Observation("windows.recyclebin", Status.UNSUPPORTED, "File is not a $I Recycle Bin metadata file",
                           errors=[f"name={name}"], meta={"source_sha256": sha256_file(p)})
    data, err = read_file_bounded_observation("windows.recyclebin", p, 1 * 1024 * 1024)
    if err:
        return err
    h = sha256_file(p)
    if len(data) < 0x18:
        return Observation("windows.recyclebin", Status.UNSUPPORTED, "$I file too small", meta={"source_sha256": h})
    version = _u32(data, 0)
    orig_size = _u64(data, 0x04)
    deletion_ft = _u64(data, 0x0C)
    deletion = _filetime_to_iso(deletion_ft)
    name_len = _u32(data, 0x14)
    orig_name = ""
    if name_len and 0x18 + name_len * 2 <= len(data):
        orig_name = _utf16(data[0x18:0x18 + name_len * 2])

    paired_r = ""
    if find_data:
        r_path = p.with_name("$R" + name[2:])
        if r_path.is_file():
            paired_r = str(r_path)

    return Observation(
        "windows.recyclebin",
        Status.OK,
        f"Deleted: {orig_name or '<unknown>'}",
        facts={
            "version": version,
            "original_name": orig_name,
            "original_size": orig_size,
            "deletion_time": deletion,
            "paired_data_file": paired_r,
        },
        evidence=[Evidence(str(p), "deleted_file", orig_name, locator="original_name",
                           source_sha256=h, method="Recycle Bin $I parser")],
        meta={"source_sha256": h},
    )
