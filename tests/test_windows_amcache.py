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

"""Tests for windows.amcache using a synthetic (in-memory) REGF hive."""

from __future__ import annotations

import datetime
import struct

from dftk.core.registry import registry
from dftk.primitives import windows_amcache as ac


def _ft_2020() -> int:
    epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    return int((datetime.datetime(2020, 5, 4, tzinfo=datetime.timezone.utc) - epoch).total_seconds() * 10_000_000)


def _put_cell(buf: bytearray, off: int, body: bytes) -> None:
    # REGF stores the TOTAL cell size (4-byte header included) in the size field.
    struct.pack_into("<i", buf, off, 4 + len(body))
    buf[off + 4 : off + 4 + len(body)] = body


def _nk(name: str, nr_subkeys: int, subkey_list: int, value_list: int, nr_values: int) -> bytes:
    name_b = name.encode("utf-16-le")
    body = bytearray(0x50 + len(name_b))
    body[0:2] = b"nk"
    struct.pack_into("<H", body, 2, 0x0020)
    struct.pack_into("<Q", body, 4, _ft_2020())
    struct.pack_into("<I", body, 0x14, nr_subkeys)   # subkey count
    struct.pack_into("<I", body, 0x1C, subkey_list)  # subkey list offset
    struct.pack_into("<I", body, 0x24, nr_values)    # value count
    struct.pack_into("<I", body, 0x28, value_list)   # value list offset
    struct.pack_into("<H", body, 0x48, len(name))    # name length
    if name_b:
        body[0x4C : 0x4C + len(name_b)] = name_b      # name (utf-16-le)
    return bytes(body)


def _lf(entries: list[int]) -> bytes:
    body = bytearray(4 + 2 + len(entries) * 8)
    body[0:2] = b"lf"
    struct.pack_into("<H", body, 2, len(entries))
    for i, nk_off in enumerate(entries):
        struct.pack_into("<I", body, 4 + i * 8, 0x12340000 + i)
        struct.pack_into("<I", body, 4 + i * 8 + 4, nk_off)
    return bytes(body)


def _vk(name: str, vtype: int, data: bytes) -> tuple[bytes, int]:
    """Return (vk_body, external_data_len). External data is written to a data cell."""
    name_b = name.encode("utf-16-le")
    if len(data) <= 4:
        body = bytearray(0x14 + len(name_b) + len(data))
        inline = True
    else:
        body = bytearray(0x14 + len(name_b))
        inline = False
    body[0:2] = b"vk"
    struct.pack_into("<H", body, 2, len(name))
    struct.pack_into("<I", body, 4, len(data))
    struct.pack_into("<I", body, 8, 0)  # data_off filled by caller if external; inline data at 0x08
    struct.pack_into("<I", body, 0x0C, vtype)
    struct.pack_into("<H", body, 0x10, 0)  # flags
    body[0x14 : 0x14 + len(name_b)] = name_b
    if inline:
        body[0x08 : 0x08 + len(data)] = data
    return bytearray(body), (0 if inline else len(data))


def _build_amcache_hive() -> bytes:
    buf = bytearray(0x1800)
    # base block
    buf[0:4] = b"regf"
    struct.pack_into("<I", buf, 0x24, 0x1020)  # root_offset -> root nk
    # hbin header
    buf[0x1000:0x1004] = b"hbin"
    struct.pack_into("<I", buf, 0x1004, 0x1000)
    struct.pack_into("<I", buf, 0x1008, 0x60C)

    root_lf = 0x10A0
    iaf = 0x1100
    iaf_lf = 0x1184
    file_nk = 0x1200
    vklist = 0x1300
    vk_size = 0x1380
    vk_path = 0x13C0
    path_data = 0x1440
    vk_id = 0x1480
    id_data = 0x1500
    vk_lmt = 0x1580
    lmt_data = 0x1600

    _put_cell(buf, 0x1020, _nk("", 1, root_lf, 0, 0))
    _put_cell(buf, root_lf, _lf([iaf]))
    _put_cell(buf, iaf, _nk("InventoryApplicationFile", 1, iaf_lf, 0, 0))
    _put_cell(buf, iaf_lf, _lf([file_nk]))
    _put_cell(buf, file_nk, _nk("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", 0, 0, vklist, 4))

    # value list (4 dwords)
    vlist = struct.pack("<IIII", vk_size, vk_path, vk_id, vk_lmt)
    _put_cell(buf, vklist, vlist)

    # FileSize (REG_DWORD, inline)
    vb, ext = _vk("FileSize", 0x4, struct.pack("<I", 12345))
    assert ext == 0
    _put_cell(buf, vk_size, vb)

    # FilePath (REG_SZ, external)
    _path = r"C:\x\a.exe"
    vb, ext = _vk("FilePath", 0x1, _path.encode("utf-16-le"))
    assert ext == 20
    struct.pack_into("<I", vb, 8, path_data)
    _put_cell(buf, vk_path, vb)
    _put_cell(buf, path_data, _path.encode("utf-16-le"))

    # FileId (REG_SZ, external SHA1 — stored as UTF-16LE, like a real REG_SZ)
    sha = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709".encode("utf-16-le")
    vb, ext = _vk("FileId", 0x1, sha)
    assert ext == 80
    struct.pack_into("<I", vb, 8, id_data)
    _put_cell(buf, vk_id, vb)
    _put_cell(buf, id_data, sha)

    # LastModifiedTime (REG_QWORD, external FILETIME)
    ft = struct.pack("<Q", _ft_2020())
    vb, ext = _vk("LastModifiedTime", 0xB, ft)
    assert ext == 8
    struct.pack_into("<I", vb, 8, lmt_data)
    _put_cell(buf, vk_lmt, vb)
    _put_cell(buf, lmt_data, ft)

    return bytes(buf)


def test_registered():
    assert registry.get("windows.amcache") is not None


def test_parse_synthetic_hive(tmp_path):
    p = tmp_path / "Amcache.hve"
    p.write_bytes(_build_amcache_hive())
    obs = registry.run("windows.amcache", {"path": str(p)})
    assert obs.status.value == "ok", obs.warnings
    assert obs.facts["file_count"] == 1
    f = obs.facts["files"][0]
    assert f["FilePath"] == "C:\\x\\a.exe"
    assert f["FileSize"] == 12345
    assert f["FileId"] == "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
    assert isinstance(f["LastModifiedTime"], dict)
    assert f["LastModifiedTime"]["iso"] is not None
    assert obs.meta["source_sha256"]
