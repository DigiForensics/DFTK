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

"""Pure-Python Windows Registry (REGF / hive) parser — DFTK 3.5.0.

Zero external dependencies. Parses the on-disk REGF format:

  * base block (4096 bytes, signature ``regf``) — root cell offset, sequence
    numbers, hive name, last-written FILETIME.
  * one or more ``hbin`` blocks (4096-byte aligned, signature ``hbin``) holding
    variable-length *cells*. Each cell is ``[int32 size][payload]``; a negative
    size means *allocated*, a positive size means *free / unallocated*.
  * cell types: ``nk`` (key node), ``vk`` (value), ``lf``/``lh``/``li``/``ri``
    (subkey index lists), ``sk`` (security), ``db`` (big data).

Cell references inside the file are relative to the start of the first hbin
(``0x1000``); absolute offset = ``0x1000 + ref``.

Deleted-key recovery: a ``DELETE`` leaves the key node's bytes in the hive but
marks its cell *free* (size positive) and unlinks it from its parent's subkey
list, so it is no longer reachable from the root. We walk the live tree to learn
which ``nk`` cells are reachable, then scan *every* cell for an ``nk`` signature
that is either free or unreachable — those are deleted-key candidates. The first
signature byte being zeroed (``00 6B``) is also accepted as an explicit
tombstone marker left by some writers.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

HBASE = 0x1000  # first hbin starts here; cell refs are relative to this

# Value types (REG_*).
VALUE_TYPES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    6: "REG_LINK",
    7: "REG_MULTI_SZ",
    8: "REG_RESOURCE_LIST",
    9: "REG_FULL_RESOURCE_DESCRIPTOR",
    10: "REG_RESOURCE_REQUIREMENTS_LIST",
    11: "REG_QWORD",
}

# Key node flags.
NK_FLAG_VOLATILE = 0x0001
NK_FLAG_HIVE_EXIT = 0x0002
NK_FLAG_HIVE_ENTRY = 0x0004  # root key
NK_FLAG_NO_DELETE = 0x0008
NK_FLAG_SYM_LINK = 0x0010


def filetime_to_iso(ft: int) -> str | None:
    """Convert a Windows FILETIME (100-ns ticks since 1601-01-01) to ISO-8601."""
    if not ft:
        return None
    try:
        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft // 10)
        return dt.isoformat()
    except (OverflowError, OSError, ValueError):
        return None


@dataclass
class HiveHeader:
    signature: str
    primary_seq: int
    secondary_seq: int
    last_write: int
    major: int
    minor: int
    root_cell_offset: int  # relative to HBASE
    hive_name: str
    clean: bool  # primary == secondary
    total_bytes: int


@dataclass
class Value:
    name: str
    type_id: int
    type_name: str
    data: bytes
    data_length: int
    inline: bool


@dataclass
class KeyNode:
    name: str
    flags: int
    last_write: int
    last_write_iso: str | None
    subkey_count: int
    value_count: int
    class_name: str | None
    parent_offset: int
    value_list_offset: int
    subkey_list_offset: int
    cell_offset: int  # absolute file offset of the cell (size prefix)
    raw: bytes = b""


def _u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def _u16(buf: bytes, off: int) -> int:
    return struct.unpack_from("<H", buf, off)[0]


def _i32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<i", buf, off)[0]


def _u64(buf: bytes, off: int) -> int:
    return struct.unpack_from("<Q", buf, off)[0]


def parse_hive_header(buf: bytes) -> HiveHeader:
    if len(buf) < HBASE:
        raise ValueError("hive too small for base block")
    sig = buf[0:4]
    if sig != b"regf":
        raise ValueError(f"not a registry hive (signature={sig!r})")
    # A valid hive has its first hbin block at offset HBASE (0x1000). Without it
    # the file is junk (e.g. a bare "regf" header), not a parseable hive.
    if buf[HBASE : HBASE + 4] != b"hbin":
        raise ValueError("no hbin block found (not a valid hive)")
    primary = _u32(buf, 4)
    secondary = _u32(buf, 8)
    last_write = _u64(buf, 0x0C)
    major = _u32(buf, 0x14)
    minor = _u32(buf, 0x18)
    root = _u32(buf, 0x24)
    # Hive name is UTF-16LE, NUL-terminated, located at 0x30.
    raw_name = buf[0x30:0x80]
    name = ""
    try:
        name = raw_name.split(b"\x00\x00", 1)[0].decode("utf-16-le", "replace")
    except UnicodeDecodeError:
        name = ""
    total = _u32(buf, 0x40) if len(buf) > 0x44 else len(buf)
    return HiveHeader(
        signature="regf",
        primary_seq=primary,
        secondary_seq=secondary,
        last_write=last_write,
        major=major,
        minor=minor,
        root_cell_offset=root,
        hive_name=name,
        clean=(primary == secondary),
        total_bytes=total,
    )


def _cell_content(buf: bytes, abs_offset: int) -> tuple[int, bytes]:
    """Return (signed_size, content) for the cell whose size prefix is at ``abs_offset``."""
    if abs_offset + 4 > len(buf):
        raise ValueError("cell offset past EOF")
    size = _i32(buf, abs_offset)
    content = buf[abs_offset + 4 : abs_offset + abs(size)]
    return size, content


def _cell_abs(ref: int) -> int:
    return HBASE + ref


def parse_nk(buf: bytes, abs_offset: int) -> KeyNode | None:
    """Parse a key node (``nk``) cell. ``abs_offset`` is the cell size prefix."""
    size, c = _cell_content(buf, abs_offset)
    if len(c) < 0x4C + 2:
        return None
    if c[0:2] not in (b"nk", b"\x00k"):  # live or tombstoned
        return None
    flags = _u16(c, 0x02)
    last_write = _u64(c, 0x04)
    parent = _u32(c, 0x10)
    stable_count = _u32(c, 0x14)
    stable_list = _u32(c, 0x1C)
    value_count = _u32(c, 0x24)
    value_list = _u32(c, 0x28)
    class_off = _u32(c, 0x30)
    name_len = _u16(c, 0x48)
    class_len = _u16(c, 0x4A)
    if name_len <= 0 or name_len > 0x2000:
        return None
    name_bytes = c[0x4C : 0x4C + name_len]
    try:
        name = name_bytes.decode("utf-16-le", "strict")
    except UnicodeDecodeError:
        # Some legacy/odd hives store an ANSI-ish name; fall back loosely.
        try:
            name = name_bytes.decode("latin-1", "replace")
        except UnicodeDecodeError:
            return None
    if "\x00" in name:
        name = name.split("\x00", 1)[0]
    class_name = None
    if class_off and class_len:
        try:
            ca = _cell_abs(class_off)
            _, cc = _cell_content(buf, ca)
            class_name = cc[:class_len].decode("utf-16-le", "replace")
        except (ValueError, UnicodeDecodeError):
            class_name = None
    return KeyNode(
        name=name,
        flags=flags,
        last_write=last_write,
        last_write_iso=filetime_to_iso(last_write),
        subkey_count=stable_count,
        value_count=value_count,
        class_name=class_name,
        parent_offset=parent,
        value_list_offset=value_list,
        subkey_list_offset=stable_list,
        cell_offset=abs_offset,
    )


def parse_vk(buf: bytes, abs_offset: int) -> Value | None:
    """Parse a value (``vk``) cell."""
    size, c = _cell_content(buf, abs_offset)
    # vk body layout (CM_KEY_VALUE): vk(2) name_len(2) data_len(4) data(4)
    # type(4) flags(2) spare(2) name(UTF-16LE). A valid value cell needs at
    # least through the name offset field (0x14).
    if len(c) < 0x14:
        return None
    if c[0:2] != b"vk":
        return None
    name_len = _u16(c, 0x02)        # name length, in *characters* (UTF-16LE)
    data_len = _u32(c, 0x04)
    data_off = _u32(c, 0x08)
    data_type = _u32(c, 0x0C)
    name = ""
    if name_len:
        # Name starts at 0x14 (after the 2-byte flags/spare fields at 0x10).
        nb = c[0x14 : 0x14 + name_len * 2]
        try:
            name = nb.decode("utf-16-le", "replace")
        except UnicodeDecodeError:
            name = nb.decode("latin-1", "replace")
        if "\x00" in name:
            name = name.split("\x00", 1)[0]
    # Data: small values (< 5 bytes) are stored inline in the 0x08 dword; larger
    # values are referenced by a separate data cell at data_off. Big-data values
    # (high bit of DataLength set) span multiple db cells and are out of scope.
    inline = False
    data = b""
    if data_len == 0:
        data = b""
    elif data_len >= 0x80000000:
        data = b""
    elif data_len < 5:
        inline = True
        data = c[0x08 : 0x08 + data_len]
    else:
        try:
            da = _cell_abs(data_off)
            _, dc = _cell_content(buf, da)
            data = dc[:data_len]
        except ValueError:
            data = b""
    return Value(
        name=name,
        type_id=data_type,
        type_name=VALUE_TYPES.get(data_type, f"REG_{data_type:#x}"),
        data=data,
        data_length=data_len,
        inline=inline,
    )


def _subkey_nk_refs(buf: bytes, subkey_list_ref: int, visited: set[int]) -> list[int]:
    """Yield ``nk`` cell *refs* reachable from a subkey-list cell ref (handles ri)."""
    out: list[int] = []
    if not subkey_list_ref:
        return out
    stack = [subkey_list_ref]
    while stack:
        ref = stack.pop()
        if ref in visited:
            continue
        visited.add(ref)
        try:
            _, c = _cell_content(buf, _cell_abs(ref))
        except ValueError:
            continue
        if len(c) < 4:
            continue
        sig = c[0:2]
        count = _u16(c, 0x02)
        if sig in (b"lf", b"lh"):  # hash(4) + nk_ref(4) per entry
            for i in range(count):
                o = 4 + i * 8 + 4
                nk_ref = _u32(c, o)
                if nk_ref:
                    out.append(nk_ref)
        elif sig == b"li":  # nk_ref(4) per entry
            for i in range(count):
                nk_ref = _u32(c, 4 + i * 4)
                if nk_ref:
                    out.append(nk_ref)
        elif sig == b"ri":  # subkey-list ref(4) per entry → recurse
            for i in range(count):
                sl_ref = _u32(c, 4 + i * 4)
                if sl_ref and sl_ref not in visited:
                    stack.append(sl_ref)
    return out


def _read_value_list(buf: bytes, value_list_ref: int, value_count: int) -> list[Value]:
    """A value-list cell holds ``value_count`` raw 4-byte vk refs (no signature)."""
    if not value_list_ref or value_count == 0:
        return []
    try:
        _, c = _cell_content(buf, _cell_abs(value_list_ref))
    except ValueError:
        return []
    vals: list[Value] = []
    for i in range(value_count):
        if 4 * i + 4 > len(c):
            break
        vk_ref = _u32(c, 4 * i)
        if not vk_ref:
            continue
        try:
            v = parse_vk(buf, _cell_abs(vk_ref))
        except ValueError:
            v = None
        if v is not None:
            vals.append(v)
    return vals


def _build_tree(buf: bytes, root_ref: int, max_depth: int = 64,
                max_keys: int = 200000) -> dict[str, Any]:
    """Build the live key tree from the root cell ref."""
    root = {"keys": 0}

    def _visit(ref: int, depth: int, chain: list[str]) -> dict[str, Any] | None:
        if root["keys"] >= max_keys or depth > max_depth:
            return None
        if not ref:
            return None
        try:
            nk = parse_nk(buf, _cell_abs(ref))
        except ValueError:
            return None
        if nk is None:
            return None
        root["keys"] += 1
        node: dict[str, Any] = {
            "name": nk.name,
            "path": "\\".join(chain + [nk.name]),
            "last_write": nk.last_write_iso,
            "flags": nk.flags,
            "class": nk.class_name,
            "subkey_count": nk.subkey_count,
            "value_count": nk.value_count,
            "values": [],
            "subkeys": [],
        }
        # values
        try:
            node["values"] = [
                {"name": v.name or "(Default)", "type": v.type_name, "data_hex": v.data[:256].hex()}
                for v in _read_value_list(buf, nk.value_list_offset, nk.value_count)
            ]
        except Exception:
            node["values"] = []
        # subkeys
        visited: set[int] = set()
        for sub_ref in _subkey_nk_refs(buf, nk.subkey_list_offset, visited):
            child = _visit(sub_ref, depth + 1, chain + [nk.name])
            if child is not None:
                node["subkeys"].append(child)
        return node

    return _visit(root_ref, 0, []) or {}


def recover_deleted_keys(buf: bytes, header: HiveHeader | None = None,
                         limit: int = 2000) -> list[dict[str, Any]]:
    """Scan all cells for deleted/unreachable key nodes (``nk``).

    Returns a list of candidate dicts with name, LastWrite, partial path
    reconstructed from parent pointers, cell offset, and counts.
    """
    if header is None:
        header = parse_hive_header(buf)

    # 1) Learn the set of reachable nk cell offsets from the live tree.
    reachable: set[int] = set()

    def _mark(ref: int, seen: set[int]) -> None:
        if not ref or ref in seen:
            return
        seen.add(ref)
        try:
            nk = parse_nk(buf, _cell_abs(ref))
        except ValueError:
            return
        if nk is None:
            return
        reachable.add(_cell_abs(ref))
        visited: set[int] = set()
        for sub in _subkey_nk_refs(buf, nk.subkey_list_offset, visited):
            _mark(sub, seen)

    try:
        _mark(header.root_cell_offset, set())
    except ValueError:
        pass

    # 2) Scan every cell for an nk signature. Iterate hbins by their size so
    #    we never mistake an ``hbin`` header for a cell size prefix.
    candidates: list[dict[str, Any]] = []
    n = len(buf)
    off = HBASE  # first hbin header
    while off + 4 <= n and len(candidates) < limit:
        if buf[off : off + 4] != b"hbin":
            break
        hbin_size = _u32(buf, off + 0x08)
        if hbin_size <= 0:
            break
        hbin_end = off + hbin_size
        cell_off = off + 32  # first cell starts after the 32-byte hbin header
        while cell_off + 4 <= hbin_end and cell_off < n and len(candidates) < limit:
            try:
                size, c = _cell_content(buf, cell_off)
            except ValueError:
                break
            cell_len = abs(size)
            if len(c) >= 0x4C + 2 and c[0:2] in (b"nk", b"\x00k"):
                try:
                    nk = parse_nk(buf, cell_off)
                except ValueError:
                    nk = None
                if nk is not None and (size > 0 or cell_off not in reachable):
                    partial = _reconstruct_path(buf, nk)
                    candidates.append({
                        "name": nk.name,
                        "last_write": nk.last_write_iso,
                        "last_write_raw": nk.last_write,
                        "flags": nk.flags,
                        "subkey_count": nk.subkey_count,
                        "value_count": nk.value_count,
                        "class": nk.class_name,
                        "cell_offset": cell_off,
                        "free": size > 0,
                        "tombstoned": c[0:2] == b"\x00k",
                        "reason": "free_cell" if size > 0 else "unreachable",
                        "partial_path": partial,
                    })
            cell_off += max(cell_len, 1)
        off = hbin_end

    # Sort: most-recently-written first (most forensically interesting).
    candidates.sort(key=lambda d: d["last_write_raw"] or 0, reverse=True)
    return candidates


def _reconstruct_path(buf: bytes, nk: KeyNode, max_depth: int = 32) -> str:
    """Best-effort ancestor path via parent pointers (may be partial)."""
    parts: list[str] = [nk.name]
    seen: set[int] = {nk.cell_offset}
    ref = nk.parent_offset
    for _ in range(max_depth):
        if not ref or ref in seen:
            break
        try:
            parent = parse_nk(buf, _cell_abs(ref))
        except ValueError:
            break
        if parent is None:
            break
        seen.add(_cell_abs(ref))
        parts.append(parent.name)
        ref = parent.parent_offset
    parts.reverse()
    return "\\".join(parts)


def parse_hive(buf: bytes, max_depth: int = 64, max_keys: int = 200000) -> dict[str, Any]:
    """Parse a hive into a structured dict: header + live tree + deleted keys."""
    header = parse_hive_header(buf)
    tree = _build_tree(buf, header.root_cell_offset, max_depth, max_keys)
    deleted = recover_deleted_keys(buf, header)
    return {
        "header": {
            "signature": header.signature,
            "clean": header.clean,
            "primary_seq": header.primary_seq,
            "secondary_seq": header.secondary_seq,
            "last_write": filetime_to_iso(header.last_write),
            "major": header.major,
            "minor": header.minor,
            "hive_name": header.hive_name,
            "root_cell_offset": header.root_cell_offset,
            "total_bytes": header.total_bytes,
        },
        "root": tree,
        "live_key_count": _count_keys(tree),
        "deleted_keys": deleted,
    }


def _count_keys(node: dict[str, Any]) -> int:
    if not node:
        return 0
    return 1 + sum(_count_keys(s) for s in node.get("subkeys", []))
