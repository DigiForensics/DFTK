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

"""Pure-Python Registry HIVE deleted-key recovery — DFTK 3.5.0.

Builds a minimal but format-correct hive in memory (no external lib), then
asserts the live tree parses and a deleted (freed + unlinked) key is recovered.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone

import pytest

from dftk.core.hive import parse_hive, parse_hive_header, recover_deleted_keys

HBASE = 0x1000
UTC = timezone.utc


def _filetime(dt: datetime) -> int:
    return int((dt - datetime(1601, 1, 1, tzinfo=UTC)).total_seconds() * 1e7)


def _cell(ref_holder: dict, payload: bytes) -> tuple[int, bytes]:
    """Append a cell; return (ref, full_cell_bytes). ref is relative to HBASE."""
    total = len(payload) + 4
    cell = struct.pack("<i", -total) + payload  # negative size = allocated
    ref = ref_holder["cursor"] - HBASE
    ref_holder["cells"].append(cell)
    ref_holder["cursor"] += total
    return ref, cell


def _nk(name: str, last_write: int, *, flags: int = 0, parent: int = 0,
        subkey_list: int = 0, subkey_count: int = 0, value_list: int = 0,
        value_count: int = 0) -> bytes:
    name_b = name.encode("utf-16-le")
    p = b"nk"
    p += struct.pack("<H", flags)
    p += struct.pack("<Q", last_write)
    p += b"\x00" * 4                       # access bits / spare
    p += struct.pack("<I", parent)
    p += struct.pack("<II", subkey_count, 0)   # stable, volatile subkey counts
    p += struct.pack("<II", subkey_list, 0)   # stable, volatile subkey lists
    p += struct.pack("<II", value_count, value_list)  # value list {count, offset}
    p += struct.pack("<I", 0)              # security
    p += struct.pack("<I", 0)              # class
    p += b"\x00" * 0x14                   # max* fields
    p += struct.pack("<H", len(name_b))   # name length
    p += struct.pack("<H", 0)             # class length
    p += name_b
    return p


def _vk(name: str, data: bytes, data_cell_ref: int, data_type: int = 1) -> bytes:
    """Build a spec-correct ``vk`` cell (CM_KEY_VALUE layout).

    Layout: vk(2) name_len-chars(2) data_len(4) data_off(4) type(4)
    flags(2) spare(2) name(UTF-16LE). The previous builder placed the name at
    0x10 with no flags/spare field, which *matched* hive.parse_vk's old (wrong)
    0x10 read and masked the bug. Name is stored in a separate cell here, so the
    inline dword at 0x08 holds the data cell reference.
    """
    name_b = name.encode("utf-16-le")
    p = b"vk"
    p += struct.pack("<H", len(name_b) // 2)   # name length, in characters
    p += struct.pack("<I", len(data))
    p += struct.pack("<I", data_cell_ref)
    p += struct.pack("<I", data_type)
    p += struct.pack("<H", 0)                  # flags @ 0x10
    p += struct.pack("<H", 0)                  # spare @ 0x12
    p += name_b                                 # name @ 0x14
    return p


def _lf(entries: list[int]) -> bytes:
    p = b"lf"
    p += struct.pack("<H", len(entries))
    for e in entries:
        p += struct.pack("<I", 0x12345678)  # name-hash hint (ignored)
        p += struct.pack("<I", e)
    return p


def build_hive(child_last_write: int) -> tuple[bytes, dict]:
    """Return (hive_bytes, offsets). Includes root + ChildKey(with value).

    Cells are appended in dependency order (data -> vk -> child -> lf -> root)
    so every referenced offset is known before the referring cell is built.
    No placeholder cells, no post-hoc rebuilds (which would shift later cells).
    """
    rh = {"cells": [], "cursor": HBASE + 32}  # start after 32-byte hbin header

    # data cell for the child's value
    data = "hello world".encode("utf-16-le")
    dref, _ = _cell(rh, data)

    # child value (vk)
    vref, _ = _cell(rh, _vk("Note", data, dref, data_type=1))

    # value-list cell: an array of 4-byte vk refs (what nk.value_list points to)
    vlist_ref, _ = _cell(rh, struct.pack("<I", vref))

    # child key node (parent left 0; path reconstruction just needs the name)
    cref, _ = _cell(rh, _nk("ChildKey", child_last_write, parent=0,
                           value_list=vlist_ref, value_count=1))

    # root subkey list (lf) -> child (now that cref is known)
    lref, _ = _cell(rh, _lf([cref]))

    # root key node
    rref, _ = _cell(rh, _nk("RootKey", child_last_write + 1, flags=0x0004,
                           subkey_list=lref, subkey_count=1))

    # assemble: base block + hbin header + cells
    base = bytearray(HBASE)
    base[0:4] = b"regf"
    base[4:8] = struct.pack("<I", 1)    # primary seq
    base[8:12] = struct.pack("<I", 1)   # secondary seq (clean)
    base[0x0C:0x14] = struct.pack("<Q", child_last_write + 100)
    base[0x14:0x18] = struct.pack("<I", 1)  # major
    base[0x18:0x1C] = struct.pack("<I", 5)  # minor
    base[0x24:0x28] = struct.pack("<I", rref)  # root cell offset
    base[0x30:0x30 + len("TESTHIVE") * 2] = "TESTHIVE".encode("utf-16-le")

    hbin = bytearray(32)
    hbin[0:4] = b"hbin"
    hbin[4:8] = struct.pack("<I", 0)  # offset of this hbin (first = 0)
    hbin_size = 32 + sum(len(c) for c in rh["cells"])
    hbin[8:12] = struct.pack("<I", hbin_size)
    hbin[0x10:0x18] = struct.pack("<Q", child_last_write + 200)

    blob = bytes(base) + bytes(hbin) + b"".join(rh["cells"])
    return blob, {"root": rref, "child": cref, "lf": lref, "vk": vref,
                  "data": dref, "hbin_size": hbin_size,
                  "child_last_write": child_last_write}


def _free_cell(buf: bytearray, cell_abs: int) -> None:
    """Mark a cell free (positive size = unallocated)."""
    size = struct.unpack_from("<i", buf, cell_abs)[0]
    total = abs(size)
    buf[cell_abs:cell_abs + 4] = struct.pack("<i", total)


def _zero_lf_count(buf: bytearray, lf_ref: int) -> None:
    """Drop all entries from an lf subkey list (count -> 0)."""
    abs_off = HBASE + lf_ref
    # content starts at abs_off+4; count is at content offset 0x02
    buf[abs_off + 4 + 2 : abs_off + 4 + 4] = struct.pack("<H", 0)


def test_hive_live_tree_parses():
    lw = _filetime(datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC))
    blob, off = build_hive(lw)
    hdr = parse_hive_header(blob)
    assert hdr.signature == "regf"
    assert hdr.clean is True
    assert hdr.root_cell_offset == off["root"]

    parsed = parse_hive(blob)
    root = parsed["root"]
    assert root["name"] == "RootKey"
    assert root["subkey_count"] == 1
    assert len(root["subkeys"]) == 1
    child = root["subkeys"][0]
    assert child["name"] == "ChildKey"
    assert child["last_write"] == datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC).isoformat()
    assert child["value_count"] == 1
    assert child["values"][0]["name"] == "Note"
    assert child["values"][0]["type"] == "REG_SZ"
    assert child["values"][0]["data_hex"] == "hello world".encode("utf-16-le").hex()
    # No deleted keys while the child is still linked.
    assert parsed["deleted_keys"] == []


def test_hive_deleted_key_recovered():
    lw = _filetime(datetime(2023, 6, 7, 8, 9, 10, tzinfo=UTC))
    blob, off = build_hive(lw)
    buf = bytearray(blob)
    # "Delete" the child key: free its cell + unlink from the lf list.
    _free_cell(buf, HBASE + off["child"])
    _zero_lf_count(buf, off["lf"])

    parsed = parse_hive(bytes(buf))
    # live tree no longer reaches the child
    root = parsed["root"]
    assert root["subkey_count"] == 1  # stored count unchanged, but:
    assert len(root["subkeys"]) == 0  # list is now empty -> not reachable

    deleted = recover_deleted_keys(bytes(buf))
    matches = [d for d in deleted if d["name"] == "ChildKey"]
    assert matches, f"deleted ChildKey not recovered; got {[d['name'] for d in deleted]}"
    d = matches[0]
    assert d["free"] is True
    assert d["reason"] == "free_cell"
    assert d["subkey_count"] == 0
    assert d["value_count"] == 1
    assert d["last_write"] == datetime(2023, 6, 7, 8, 9, 10, tzinfo=UTC).isoformat()
    assert d["partial_path"].endswith("ChildKey")


def test_registry_tools_end_to_end(tmp_path):
    """Drive the pure-Python windows.* tools through the registry runner."""
    import dftk

    lw = _filetime(datetime(2022, 3, 4, 5, 6, 7, tzinfo=UTC))
    blob, off = build_hive(lw)
    hive = tmp_path / "SOFTWARE"
    hive.write_bytes(blob)

    # Live tree inventory (pure-Python, no python-registry needed).
    obs = dftk.run_tool("windows.registry_tree", {"path": str(hive), "depth": 3})
    assert obs.status.value == "ok", obs.summary
    paths = [k["path"] for k in obs.facts["keys"]]
    assert "RootKey" in paths
    assert any(p.endswith("ChildKey") for p in paths)

    # Deleted-key recovery: free + unlink the child, then re-run.
    buf = bytearray(blob)
    _free_cell(buf, HBASE + off["child"])
    _zero_lf_count(buf, off["lf"])
    hive.write_bytes(bytes(buf))
    obs = dftk.run_tool("windows.registry_deleted_keys", {"path": str(hive)})
    assert obs.status.value == "ok", obs.summary
    names = [d["name"] for d in obs.facts["deleted_keys"]]
    assert "ChildKey" in names
    assert obs.facts["deleted_key_count"] >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
