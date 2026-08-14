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

"""Pure-Python Windows host-forensics tools: synthetic-evidence round-trip tests."""

from __future__ import annotations

import struct
import datetime
from pathlib import Path
import tempfile

from dftk.catalog import load_builtin_tools
from dftk.core.registry import registry

load_builtin_tools()


def _ft(dt: datetime.datetime) -> int:
    epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    return int((dt - epoch).total_seconds() * 10_000_000)


def _si_content(times: dict) -> bytes:
    out = b""
    for k in ("creation", "modified", "mft_modified", "accessed"):
        out += struct.pack("<Q", _ft(times[k]))
    out += struct.pack("<I", 0)  # DOS attributes
    out += struct.pack("<I", 0)  # owner id
    return out


def _fn_attribute(parent: int, name: str, times: dict, size: int) -> bytes:
    content = struct.pack("<Q", parent & 0x0000FFFFFFFFFFFF)  # parent reference (48-bit)
    for k in ("creation", "modified", "mft_modified", "accessed"):
        content += struct.pack("<Q", _ft(times[k]))
    content += struct.pack("<Q", size)  # allocated
    content += struct.pack("<Q", size)  # real size
    content += struct.pack("<I", 0x20)  # flags (file)
    content += struct.pack("<I", 0)  # reparse
    raw = name.encode("utf-16-le")
    content += struct.pack("<B", len(name))  # name length (chars)
    content += struct.pack("<B", 1)  # namespace (1=Win32)
    content += raw
    hdr = struct.pack("<I", 0x30)  # type
    hdr += struct.pack("<I", 0x18 + len(content))  # length
    hdr += struct.pack("<B", 0)  # non-resident
    hdr += struct.pack("<B", 0)  # name length
    hdr += struct.pack("<B", 0)  # name offset
    hdr += struct.pack("<B", 0)  # flags
    hdr += struct.pack("<H", 0)  # instance
    hdr += struct.pack("<H", 0)  # reserved
    hdr += struct.pack("<I", len(content))  # content length
    hdr += struct.pack("<H", 0x18)  # content offset
    hdr += struct.pack("<H", 0)  # reserved
    return hdr + content


def _si_attribute(times: dict) -> bytes:
    content = _si_content(times)
    hdr = struct.pack("<I", 0x10)
    hdr += struct.pack("<I", 0x18 + len(content))
    hdr += struct.pack("<B", 0)
    hdr += struct.pack("<B", 0)
    hdr += struct.pack("<B", 0)
    hdr += struct.pack("<B", 0)
    hdr += struct.pack("<H", 0)
    hdr += struct.pack("<H", 0)
    hdr += struct.pack("<I", len(content))
    hdr += struct.pack("<H", 0x18)
    hdr += struct.pack("<H", 0)
    return hdr + content


def _mft_record(entry_no: int, name: str, is_dir: bool, times: dict, size: int) -> bytes:
    rec = bytearray(1024)
    # header
    rec[0:4] = b"FILE"
    struct.pack_into("<H", rec, 4, 0x30)   # usa offset (unused, count=0 -> skip)
    struct.pack_into("<H", rec, 6, 0)      # usa count = 0 -> no fixup applied
    struct.pack_into("<Q", rec, 8, 0)      # LSN
    struct.pack_into("<H", rec, 0x10, 1)   # sequence
    struct.pack_into("<H", rec, 0x12, 1)   # hard links
    struct.pack_into("<H", rec, 0x14, 0x38)  # attr offset
    flags = (0x02 if is_dir else 0x00) | 0x01
    struct.pack_into("<H", rec, 0x16, flags)
    struct.pack_into("<I", rec, 0x1C, 1024)  # used size
    struct.pack_into("<I", rec, 0x20, 1024)  # alloc size
    off = 0x38
    for attr in (_si_attribute(times), _fn_attribute(entry_no, name, times, size)):
        rec[off:off + len(attr)] = attr
        off += len(attr)
    rec[off:off + 4] = b"\xff\xff\xff\xff"  # end marker
    return bytes(rec)


def _write_tmp(data: bytes, suffix: str) -> Path:
    d = Path(tempfile.mkdtemp(prefix="dftk-wh-"))
    f = d / suffix
    f.write_bytes(data)
    return f


def test_mft_records_and_paths():
    t = datetime.datetime(2024, 3, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
    times = {"creation": t, "modified": t, "mft_modified": t, "accessed": t}
    root = _mft_record(5, "$", True, times, 0)
    secret = _mft_record(100, "secret.txt", False, times, 1234)
    data = bytearray(1024 * 101)
    data[0:1024] = root
    data[100 * 1024:100 * 1024 + 1024] = secret
    f = _write_tmp(bytes(data), "MFT")
    obs = registry.run("windows.mft", {"path": str(f)})
    assert obs.status.value == "ok", obs.errors
    recs = {r["name"]: r for r in obs.facts["records"]}
    assert "secret.txt" in recs
    assert recs["secret.txt"]["path"].endswith("secret.txt")
    assert recs["secret.txt"]["si"]["creation"] is not None
    assert recs["secret.txt"]["fn"]["size"] == 1234


def _prefetch_file(version: int, exe: str, refs: list[str], run_count: int, last_run: int) -> bytes:
    exe_u = exe.encode("utf-16-le")
    name_off = 0x54
    trace_off = 0x100  # after the v17 header region incl. 8 last-run slots (0x9C..0xDC)
    buf = bytearray(trace_off)
    buf[name_off:name_off + len(exe_u)] = exe_u
    entry_size = {17: 0x14, 23: 0x20, 26: 0x20, 30: 0x20}[version]
    entries = bytearray()
    names_blob = bytearray()
    names_base = trace_off + len(refs) * entry_size  # names sit after all entries
    for r in refs:
        ru = r.encode("utf-16-le") + b"\x00\x00"
        fname_off = names_base + len(names_blob)  # absolute offset
        entry = struct.pack("<I", 0)          # duration/unknown
        entry += struct.pack("<I", fname_off)  # filename offset (absolute)
        entry += struct.pack("<I", 0)          # ... (rest ignored)
        if len(entry) < entry_size:
            entry += b"\x00" * (entry_size - len(entry))
        entries += entry
        names_blob += ru
    trace_entries = entries + names_blob
    # header
    struct.pack_into("<I", buf, 0, version)
    buf[4:8] = b"SCCA"
    struct.pack_into("<I", buf, 0x0C, name_off)
    struct.pack_into("<I", buf, 0x10, len(exe))
    struct.pack_into("<I", buf, 0x14, 0xDEADBEEF)  # hash
    struct.pack_into("<I", buf, 0x1C, 0)  # metrics offset (unused, count 0)
    struct.pack_into("<I", buf, 0x20, 0)
    struct.pack_into("<I", buf, 0x24, trace_off)  # trace offset
    struct.pack_into("<I", buf, 0x28, len(refs))
    if version == 17:
        struct.pack_into("<I", buf, 0x98, run_count)
        struct.pack_into("<Q", buf, 0x9C, last_run)
    buf += trace_entries
    struct.pack_into("<I", buf, 8, len(buf))
    return bytes(buf)


def test_prefetch_v17():
    lr = _ft(datetime.datetime(2024, 5, 2, 9, 30, 0, tzinfo=datetime.timezone.utc))
    data = _prefetch_file(17, "C:\\WINDOWS\\system32\\evil.exe",
                          ["\\VOLUME{abc}\\dir\\dep.dll", "\\WINDOWS\\x.dat"], 7, lr)
    f = _write_tmp(data, "evil.EXE-DEADBEEF.pf")
    obs = registry.run("windows.prefetch", {"path": str(f)})
    assert obs.status.value == "ok", obs.errors
    assert obs.facts["executable"] == "C:\\WINDOWS\\system32\\evil.exe"
    assert obs.facts["run_count"] == 7
    assert obs.facts["last_run_times"] == [datetime.datetime(2024, 5, 2, 9, 30, 0, tzinfo=datetime.timezone.utc).isoformat()]
    assert len(obs.facts["referenced_files"]) == 2


def _lnk_file(target: str, t: datetime.datetime) -> bytes:
    base = target.encode("utf-16-le")
    total = 0x4C + 0x1C + 2 + len(base) + 2
    buf = bytearray(total)
    struct.pack_into("<I", buf, 0, 0x4C)  # header size
    clsid = bytes.fromhex("0114020000000000c000000000000046")
    buf[4:4 + 16] = clsid
    struct.pack_into("<I", buf, 0x14, 0x02)  # HasLinkInfo only
    struct.pack_into("<Q", buf, 0x1C, _ft(t))
    struct.pack_into("<Q", buf, 0x24, _ft(t))
    struct.pack_into("<Q", buf, 0x2C, _ft(t))
    struct.pack_into("<I", buf, 0x34, 4096)
    # LinkInfo
    pos = 0x4C
    li_size = 0x1C
    struct.pack_into("<I", buf, pos, li_size)
    struct.pack_into("<I", buf, pos + 4, 0x1C)  # header size
    struct.pack_into("<I", buf, pos + 0x10, 0x1C)  # local base path offset (from LinkInfo start)
    struct.pack_into("<I", buf, pos + 0x18, 0x1C + 2 + len(base))  # common suffix offset
    bo = pos + 0x1C
    struct.pack_into("<H", buf, bo, len(target))
    buf[bo + 2:bo + 2 + len(base)] = base
    so = bo + 2 + len(base)
    struct.pack_into("<H", buf, so, 0)
    return bytes(buf)


def test_lnk_target_path():
    t = datetime.datetime(2023, 1, 1, tzinfo=datetime.timezone.utc)
    data = _lnk_file("C:\\Programs\\app.exe", t)
    f = _write_tmp(data, "app.lnk")
    obs = registry.run("windows.lnk", {"path": str(f)})
    assert obs.status.value == "ok", obs.errors
    assert obs.facts["target_path"] == "C:\\Programs\\app.exe"
    assert obs.facts["timestamps"]["creation"] is not None


def test_recyclebin_i():
    target = "confidential.pdf"
    t = datetime.datetime(2024, 7, 7, 10, 0, 0, tzinfo=datetime.timezone.utc)
    buf = bytearray(0x18 + len(target) * 2)
    struct.pack_into("<I", buf, 0, 2)  # version
    struct.pack_into("<Q", buf, 0x04, 99999)  # original size
    struct.pack_into("<Q", buf, 0x0C, _ft(t))  # deletion time
    struct.pack_into("<I", buf, 0x14, len(target))
    buf[0x18:0x18 + len(target) * 2] = target.encode("utf-16-le")
    f = _write_tmp(bytes(buf), "$IABCDEFG.pdf")
    obs = registry.run("windows.recyclebin", {"path": str(f)})
    assert obs.status.value == "ok", obs.errors
    assert obs.facts["original_name"] == target
    assert obs.facts["original_size"] == 99999
    assert obs.facts["deletion_time"] == t.isoformat()
