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

"""Pure-Python REGF (Windows registry hive) reader — zero external dependencies.

This is a *bounded* parser: it walks the nk/vk/lf/lh/ri/li cell graph of a
registry hive file and returns a tree of keys + values. It deliberately does not
implement every esoteric cell type (security descriptors, big-data cells,
deleted-cell recovery) — those are out of scope for DFTK 3.5.0 and would add
attack surface. It is enough to read forensic artifacts stored in hives such as
``Amcache.hve``.

Offsets follow the well-documented REGF layout (see also python-registry /
RECmd for cross-checks). All cell references are absolute file offsets, matching
the REGF convention.
"""

from __future__ import annotations

import struct
from typing import Any


class RegfError(ValueError):
    """Raised when the buffer is not a parseable REGF hive."""


def _u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def _u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def _u64(b: bytes, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]


def filetime_to_iso(ft: int) -> str | None:
    """Convert a Windows FILETIME (100ns ticks since 1601-01-01) to ISO-8601 UTC."""
    if not ft or ft <= 0:
        return None
    try:
        import datetime

        us = ft / 10.0
        dt = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=us)
        return dt.isoformat()
    except (OverflowError, OSError, ValueError):
        return None


class RegistryHive:
    """A read-only view over a registry hive file loaded into memory."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        if len(data) < 0x1000 or data[0:4] != b"regf":
            raise RegfError("not a REGF hive (missing 'regf' magic)")
        self.root_offset = _u32(data, 0x24)
        # A few well-known version fields, surfaced for provenance only.
        self.major = _u32(data, 0x14)
        self.minor = _u32(data, 0x18)
        self.sequence1 = _u32(data, 0x1C)
        self.sequence2 = _u32(data, 0x20)

    # -- cell layer --------------------------------------------------------
    def _cell_body(self, off: int) -> bytes | None:
        """Return the body (after the 4-byte size field) of the cell at ``off``."""
        if off <= 0 or off + 4 > len(self.data):
            return None
        size = struct.unpack_from("<i", self.data, off)[0]
        if size == 0:
            return None
        used = abs(size)
        if off + used > len(self.data):
            return None
        # Body starts after the 4-byte size field; `used` includes that field,
        # so the body is [off+4, off+used).
        return self.data[off + 4 : off + used]

    # -- nk (key node) ------------------------------------------------------
    def _nk(self, off: int) -> dict[str, Any] | None:
        body = self._cell_body(off)
        if not body or body[0:2] != b"nk":
            return None
        if len(body) < 0x4C:  # nk header is 0x4C bytes; name follows
            return None
        last_write = _u64(body, 4)
        nr_subkeys = _u32(body, 0x14)
        nr_values = _u32(body, 0x24)
        subkey_list = _u32(body, 0x1C)
        value_list = _u32(body, 0x28)
        name_len = _u16(body, 0x48)
        name = body[0x4C : 0x4C + name_len * 2].decode("utf-16-le", "replace")
        key: dict[str, Any] = {
            "offset": off,
            "name": name,
            "last_write": filetime_to_iso(last_write),
            "last_write_raw": last_write,
            "subkeys": [],
            "values": {},
        }
        if subkey_list and nr_subkeys:
            for sk_off in self._subkey_offsets(subkey_list):
                sk = self._nk(sk_off)
                if sk is not None:
                    key["subkeys"].append(sk)
        if value_list and nr_values:
            for vo in self._value_offsets(value_list, nr_values):
                vk = self._vk(vo)
                if vk is not None:
                    key["values"][vk["name"]] = vk
        return key

    def _subkey_offsets(self, list_off: int) -> list[int]:
        body = self._cell_body(list_off)
        if not body:
            return []
        tag = body[0:2]
        n = _u16(body, 2)
        offs: list[int] = []
        if tag in (b"lf", b"lh"):
            for i in range(n):
                offs.append(_u32(body, 4 + i * 8 + 4))
        elif tag in (b"ri", b"li"):
            for i in range(n):
                offs.append(_u32(body, 4 + i * 4))
        return offs

    def _value_offsets(self, list_off: int, n: int) -> list[int]:
        body = self._cell_body(list_off)
        if not body:
            return []
        return [_u32(body, i * 4) for i in range(n)]

    # -- vk (value) ---------------------------------------------------------
    # VK record layout (Windows CM_KEY_VALUE, confirmed against python-registry):
    #   0x00 "vk" | 0x02 name_len(chars) | 0x04 data_len | 0x08 data (inline if
    #   data_len<5) / data offset | 0x0C type | 0x10 flags | 0x12 spare | 0x14 name
    # NB: the value NAME starts at 0x14, NOT 0x10. A 2-byte flags field sits at
    # 0x10. Reading the name from 0x10 corrupts it (shifts UTF-16LE by 2 bytes).
    def _vk(self, off: int) -> dict[str, Any] | None:
        body = self._cell_body(off)
        if not body or body[0:2] != b"vk":
            return None
        name_len = _u16(body, 2)
        data_len = _u32(body, 4)
        data_off = _u32(body, 8)
        vtype = _u32(body, 0x0C)
        name = body[0x14 : 0x14 + name_len * 2].decode("utf-16-le", "replace")
        data = self._read_value_data(body, data_len, data_off, name_len)
        return {
            "name": name,
            "type": vtype,
            "data": data,
            "data_len": data_len,
            "offset": off,
        }

    def _read_value_data(self, body: bytes, data_len: int, data_off: int, name_len: int) -> bytes:
        if data_len == 0:
            return b""
        if data_len >= 0x80000000:
            # Big-data value (length field has the high bit set, 0x08 points to a
            # segment list, not a single cell). Out of scope for the bounded reader;
            # return empty rather than reading garbage.
            return b""
        if data_len < 5:
            # Inline: the data lives in the 4-byte field at 0x08 (the data offset
            # dword is repurposed as the value data for <=4-byte values).
            return body[0x08 : 0x08 + data_len]
        # External: data cell at absolute offset.
        cell = self._cell_body(data_off)
        if cell is None:
            return b""
        return cell[:data_len]

    # -- public tree API ----------------------------------------------------
    def root(self) -> dict[str, Any] | None:
        return self._nk(self.root_offset)

    def get_key(self, path: str) -> dict[str, Any] | None:
        """Resolve a ``\\``-separated key path (case-insensitive) from root."""
        cur = self.root()
        if cur is None:
            return None
        parts = [p for p in path.strip("\\").split("\\") if p]
        for part in parts:
            nxt = None
            for sk in cur["subkeys"]:
                if sk["name"].lower() == part.lower():
                    nxt = sk
                    break
            if nxt is None:
                return None
            cur = nxt
        return cur

    def walk(self, key: dict[str, Any] | None = None, _depth: int = 0, _limit: int = 200000):
        """Yield (path, keydict) for every key under ``key`` (root by default)."""
        if key is None:
            key = self.root()
        if key is None:
            return
        stack = [(key["name"], key)]
        seen = 0
        while stack and seen < _limit:
            name, k = stack.pop()
            yield name, k
            seen += 1
            for sk in k["subkeys"]:
                stack.append((f"{name}\\{sk['name']}", sk))


def load_hive(path: str) -> RegistryHive:
    from pathlib import Path

    return RegistryHive(Path(path).read_bytes())
