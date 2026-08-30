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

"""Regression tests for the REGF nk/vk field offsets in ``dftk.core.regf``.

These tests deliberately build hives with a *standalone* builder that hardcodes
the real REGF byte offsets (cross-checked against python-registry's
``RegistryParse.py`` NKRecord), and does NOT call ``regf._nk`` / ``regf._put_cell``.
That keeps the test independent of the parser it exercises, so a regression in
the offsets (the bug fixed on 2026-08-29, where nk fields were shifted 4-8 bytes)
is caught instead of passing by circular self-consistency.

Real REGF nk layout (authoritative):
    +0x04  last-write FILETIME (8 bytes)
    +0x14  subkey count          (4 bytes)
    +0x1C  subkey-list offset    (4 bytes)
    +0x24  value count           (4 bytes)
    +0x28  value-list offset     (4 bytes)
    +0x48  name length (chars)   (2 bytes)
    +0x4C  name (UTF-16LE)
Cell size field = total cell size INCLUDING the 4-byte size header.
"""

import struct

import pytest

from dftk.core.registry import registry
from dftk.core.regf import load_hive


# --- standalone, canonical-offset hive builder (independent of regf.py) --------

def _cell(buf: bytearray, off: int, body: bytes) -> None:
    # Real REGF: size field = total cell size including the 4-byte header.
    struct.pack_into("<i", buf, off, 4 + len(body))
    buf[off + 4 : off + 4 + len(body)] = body


def _nk(name: str, nr_subkeys: int, subkey_list: int,
        nr_values: int, value_list: int) -> bytes:
    name_b = name.encode("utf-16-le")
    body = bytearray(0x4C + len(name_b))
    body[0:2] = b"nk"
    struct.pack_into("<H", body, 2, 0x0020)
    ft = 133000000000000000  # arbitrary 2022-ish FILETIME
    struct.pack_into("<Q", body, 4, ft)
    struct.pack_into("<I", body, 0x14, nr_subkeys)
    struct.pack_into("<I", body, 0x1C, subkey_list)
    struct.pack_into("<I", body, 0x24, nr_values)
    struct.pack_into("<I", body, 0x28, value_list)
    struct.pack_into("<H", body, 0x48, len(name))
    body[0x4C : 0x4C + len(name_b)] = name_b
    return bytes(body)


def _lf(entries: list[int]) -> bytes:
    body = bytearray(4 + 8 * len(entries))
    body[0:2] = b"lf"
    struct.pack_into("<H", body, 2, len(entries))
    for i, nk_off in enumerate(entries):
        struct.pack_into("<I", body, 4 + i * 8, 0xAABBCCDD)        # hash (ignored)
        struct.pack_into("<I", body, 4 + i * 8 + 4, nk_off)         # nk offset
    return bytes(body)


def _vl(entries: list[int]) -> bytes:
    body = bytearray(4 * len(entries))
    for i, v in enumerate(entries):
        struct.pack_into("<I", body, i * 4, v)
    return bytes(body)


def _vk(name: str, vtype: int, data: bytes) -> bytes:
    name_b = name.encode("utf-16-le")
    inline = len(data) <= 4
    body = bytearray(0x14 + len(name_b) + (len(data) if inline else 0))
    body[0:2] = b"vk"
    struct.pack_into("<H", body, 2, len(name))
    struct.pack_into("<I", body, 4, len(data))
    struct.pack_into("<I", body, 8, 0)            # data inline (<=4 bytes) lives at 0x08
    struct.pack_into("<I", body, 0x0C, vtype)
    struct.pack_into("<H", body, 0x10, 0)         # flags
    body[0x14 : 0x14 + len(name_b)] = name_b
    if inline:
        body[0x08 : 0x08 + len(data)] = data
    return bytes(body)


def _build_canonical_hive() -> bytes:
    SIZE = 0x2000
    buf = bytearray(SIZE)
    buf[0:4] = b"regf"
    struct.pack_into("<I", buf, 0x24, 0x1000)      # root cell offset
    # hbin header so the file is structurally plausible
    buf[0x1000:0x1004] = b"hbin"
    _cell(buf, 0x1000, _nk("Root", nr_subkeys=1, subkey_list=0x1100,
                           nr_values=1, value_list=0x1500))
    _cell(buf, 0x1100, _lf([0x1200]))
    _cell(buf, 0x1200, _nk("Sub", nr_subkeys=0, subkey_list=0,
                           nr_values=1, value_list=0x1600))
    _cell(buf, 0x1300, _vk("Data", 1, b"OKAY"))
    _cell(buf, 0x1400, _vk("SubVal", 1, b"SUB!"))
    _cell(buf, 0x1500, _vl([0x1300]))
    _cell(buf, 0x1600, _vl([0x1400]))
    return bytes(buf)


# --- tests -------------------------------------------------------------------

def test_regf_reads_canonical_hive(tmp_path):
    p = tmp_path / "real.hve"
    p.write_bytes(_build_canonical_hive())
    h = load_hive(str(p))
    root = h.root()
    assert root["name"] == "Root", root["name"]
    assert len(root["subkeys"]) == 1
    assert root["values"]["Data"]["data"] == b"OKAY"
    assert root["values"]["Data"]["type"] == 1
    sub = root["subkeys"][0]
    assert sub["name"] == "Sub"
    assert sub["values"]["SubVal"]["data"] == b"SUB!"
    assert sub["values"]["SubVal"]["type"] == 1


def test_regf_get_key_subpath(tmp_path):
    p = tmp_path / "real.hve"
    p.write_bytes(_build_canonical_hive())
    h = load_hive(str(p))
    # get_key walks from the root's *children* (registry convention: the path
    # does NOT include the root key's own name).
    sub = h.get_key("Sub")
    assert sub is not None
    assert sub["name"] == "Sub"
    assert h.get_key("Nonexistent") is None


def test_regf_wrong_offsets_rejected(tmp_path):
    """A hive built with the OLD (buggy) shifted offsets must NOT be read as a
    valid tree. This locks in the correct offset layout: if regf.py regresses to
    the shifted offsets, this test fails."""
    name_b = "Root".encode("utf-16-le")
    # OLD offsets: subkey count @0x18, subkey list @0x20, value count @0x1C,
    # value list @0x24, name len @0x4C, name @0x50
    body = bytearray(0x50 + len(name_b))
    body[0:2] = b"nk"
    struct.pack_into("<H", body, 2, 0x0020)
    struct.pack_into("<Q", body, 4, 133000000000000000)
    struct.pack_into("<I", body, 0x18, 1)          # OLD: subkey count
    struct.pack_into("<I", body, 0x20, 0x1100)     # OLD: subkey list
    struct.pack_into("<I", body, 0x1C, 0)          # OLD: value count
    struct.pack_into("<I", body, 0x24, 0)          # OLD: value list
    struct.pack_into("<H", body, 0x4C, len("Root"))  # OLD: name len
    body[0x50 : 0x50 + len(name_b)] = name_b       # OLD: name
    SIZE = 0x2000
    buf = bytearray(SIZE)
    buf[0:4] = b"regf"
    struct.pack_into("<I", buf, 0x24, 0x1000)
    _cell(buf, 0x1000, bytes(body))
    p = tmp_path / "wrong.hve"
    p.write_bytes(bytes(buf))
    h = load_hive(str(p))
    root = h.root()
    # Under the OLD layout the parser would misread these fields; with the
    # corrected parser they must NOT resolve to a populated tree.
    assert root["name"] != "Root"
    assert len(root["subkeys"]) == 0
