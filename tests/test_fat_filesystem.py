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

"""Pure-Python FAT backend tests — DFTK 3.5.0.

Builds a real (if tiny) FAT12 volume wrapped in an MBR partition, then drives
the registry tools to prove that ``filesystem.list/walk/stat/read/extract/
deleted`` work on FAT *without* pytsk3, and that deleted directory entries are
recovered. The image is constructed entirely in Python (no mkfs/mount/sudo).
"""

from __future__ import annotations

import struct
from pathlib import Path

from dftk import get_registry
from dftk.core.registry import registry
from dftk.core.models import SafetyLevel
from dftk.core.safety import SafetyPolicy

get_registry()  # register image.partitions + filesystem.*

_STATEFUL = SafetyPolicy(max_level=SafetyLevel.STATEFUL)

_BPS = 512
_SPC = 1
_NUM_FATS = 2
_ROOT_ENTRIES = 224
_TOTAL_SECTORS = 2880
_FAT_SIZE = 9
_RESERVED = 1
_ROOT_DIR_SECTORS = (_ROOT_ENTRIES * 32 + _BPS - 1) // _BPS   # 14
_DATA_START = _RESERVED + _NUM_FATS * _FAT_SIZE + _ROOT_DIR_SECTORS  # 33
_PART_START_LBA = 2048


def _dos_date(y: int, mo: int, d: int) -> int:
    return ((y - 1980) << 9) | (mo << 5) | d


def _dos_time(h: int, mi: int, s: int) -> int:
    return (h << 11) | (mi << 5) | (s // 2)


def _enc_name(name: str) -> bytes:
    if "." in name:
        base, ext = name.split(".", 1)
    else:
        base, ext = name, ""
    base = base.upper()[:8].ljust(8, " ")
    ext = ext.upper()[:3].ljust(3, " ")
    return (base + ext).encode("ascii")


def _entry(name: str, first_cluster: int, size: int, attr: int) -> bytes:
    rec = bytearray(32)
    rec[0:11] = _enc_name(name)
    rec[11] = attr
    rec[20:22] = (first_cluster >> 16).to_bytes(2, "little")
    rec[26:28] = (first_cluster & 0xFFFF).to_bytes(2, "little")
    rec[28:32] = size.to_bytes(4, "little")
    rec[14:16] = _dos_time(10, 30, 0).to_bytes(2, "little")
    rec[16:18] = _dos_date(2024, 1, 2).to_bytes(2, "little")
    rec[22:24] = rec[16:18]
    return bytes(rec)


def _dot_entry(this_cluster: int, parent_cluster: int) -> bytes:
    rec = bytearray(32)
    rec[0] = 0x2E
    # NOTE: a single b" " would *resize* the slice (replace 10 bytes with 1);
    # the name field is 11 bytes, so pad the remaining 10 with spaces.
    rec[1:11] = b" " * 10
    rec[11] = 0x10
    rec[20:22] = (this_cluster >> 16).to_bytes(2, "little")
    rec[26:28] = (this_cluster & 0xFFFF).to_bytes(2, "little")
    return bytes(rec)


def _fat12_pack(fat_list: list[int]) -> bytes:
    n = len(fat_list)
    out = bytearray((n * 3) // 2)
    for i in range(0, n, 2):
        e0 = fat_list[i] & 0x0FFF
        e1 = fat_list[i + 1] & 0x0FFF if i + 1 < n else 0
        o = i * 3 // 2
        out[o] = e0 & 0xFF
        out[o + 1] = ((e0 >> 8) & 0x0F) | ((e1 & 0x0F) << 4)
        out[o + 2] = (e1 >> 4) & 0xFF
    return bytes(out)


def _build_fat12_volume(*, delete: frozenset[str] = frozenset()) -> bytes:
    readme = b"FAT12 forensic read test\r\n"
    data = bytes(range(256)) * 2  # exactly 512 bytes -> 1 cluster
    note = b"subdir note content"
    # Cluster assignment: 2=README, 3=DATA, 4=SUBDIR(dir), 5=NOTE
    fat = [0] * 3072
    fat[0] = 0xFFF
    fat[1] = 0xFFF
    for c in (2, 3, 4, 5):
        fat[c] = 0xFFF
    fatbytes = _fat12_pack(fat)

    root = bytearray()
    e_readme = _entry("README.TXT", 2, len(readme), 0x20)
    e_data = _entry("DATA.BIN", 3, len(data), 0x20)
    if "DATA.BIN" in delete:
        e_data = b"\xe5" + e_data[1:]  # deletion marker over first name byte
    e_sub = _entry("SUBDIR", 4, 0, 0x10)
    root += e_readme + e_data + e_sub
    root_bytes = bytes(root).ljust(_ROOT_DIR_SECTORS * _BPS, b"\x00")

    subdir = bytearray()
    subdir += _dot_entry(4, 0) + _dot_entry(0, 0)
    subdir += _entry("NOTE.TXT", 5, len(note), 0x20)
    subdir_bytes = bytes(subdir).ljust(_SPC * _BPS, b"\x00")

    data_region = bytearray((_TOTAL_SECTORS - _DATA_START) * _BPS)
    data_region[(2 - 2) * _BPS:(2 - 2) * _BPS + len(readme)] = readme
    data_region[(3 - 2) * _BPS:(3 - 2) * _BPS + len(data)] = data
    data_region[(4 - 2) * _BPS:(4 - 2) * _BPS + len(subdir_bytes)] = subdir_bytes
    data_region[(5 - 2) * _BPS:(5 - 2) * _BPS + len(note)] = note

    # Boot sector.
    boot = bytearray(512)
    boot[0:3] = b"\xeb\x3c\x90"
    boot[3:11] = b"MSDOS5.0"
    struct.pack_into("<H", boot, 11, _BPS)
    boot[13] = _SPC
    struct.pack_into("<H", boot, 14, _RESERVED)
    boot[16] = _NUM_FATS
    struct.pack_into("<H", boot, 17, _ROOT_ENTRIES)
    struct.pack_into("<H", boot, 19, _TOTAL_SECTORS)
    boot[21] = 0xF0
    struct.pack_into("<H", boot, 22, _FAT_SIZE)
    struct.pack_into("<H", boot, 24, 0x20)
    struct.pack_into("<H", boot, 26, 0x40)
    boot[38] = 0x29
    struct.pack_into("<I", boot, 39, 0x12345678)
    boot[43:54] = b"NO NAME    "
    boot[54:62] = b"FAT12   "
    boot[510] = 0x55
    boot[511] = 0xAA

    vol = bytearray()
    vol += boot
    for _ in range(_NUM_FATS):
        vol += fatbytes.ljust(_FAT_SIZE * _BPS, b"\x00")
    vol += root_bytes
    vol += data_region
    return bytes(vol)


def _build_disk(image: Path, *, delete: frozenset[str] = frozenset()) -> None:
    mbr = bytearray(512)
    entry = bytearray(16)
    entry[4] = 0x01  # FAT12
    struct.pack_into("<I", entry, 8, _PART_START_LBA)
    struct.pack_into("<I", entry, 12, _TOTAL_SECTORS)
    mbr[446:446 + 16] = entry
    mbr[510] = 0x55
    mbr[511] = 0xAA
    vol = _build_fat12_volume(delete=delete)
    img = bytearray()
    img += mbr
    img += b"\x00" * (_PART_START_LBA * _BPS - 512)
    img += vol
    image.write_bytes(bytes(img))


def test_image_partitions_fat(tmp_path: Path):
    img = tmp_path / "fat.dsk"
    _build_disk(img)
    obs = registry.run("image.partitions", {"path": str(img)})
    assert obs.status.value == "ok", obs.summary
    assert len(obs.facts["partitions"]) == 1
    p = obs.facts["partitions"][0]
    assert p["scheme"] == "MBR"
    assert p["type"] == "FAT12"
    assert p["start_lba"] == _PART_START_LBA
    assert p["start_byte"] == _PART_START_LBA * _BPS


def test_filesystem_fat_list_walk_stat(tmp_path: Path):
    img = tmp_path / "fat.dsk"
    _build_disk(img)
    # list root
    obs = registry.run("filesystem.list", {"path": str(img), "partition": 1, "path_in_fs": "/"})
    assert obs.status.value == "ok", obs.summary
    names = {e["name"] for e in obs.facts["entries"]}
    assert {"README.TXT", "DATA.BIN", "SUBDIR"} <= names
    # walk (recursive)
    obs = registry.run("filesystem.walk", {"path": str(img), "partition": 1, "path_in_fs": "/"})
    assert obs.status.value == "ok", obs.summary
    paths = {e["path"] for e in obs.facts["entries"]}
    assert "README.TXT" in paths
    assert "SUBDIR" in paths
    assert "SUBDIR/NOTE.TXT" in paths
    # stat a regular file
    obs = registry.run("filesystem.stat", {"path": str(img), "partition": 1, "path_in_fs": "/README.TXT"})
    assert obs.status.value == "ok", obs.summary
    assert obs.facts["stat"]["is_dir"] is False
    assert obs.facts["stat"]["size"] == len(b"FAT12 forensic read test\r\n")
    # stat the subdir
    obs = registry.run("filesystem.stat", {"path": str(img), "partition": 1, "path_in_fs": "/SUBDIR"})
    assert obs.status.value == "ok", obs.summary
    assert obs.facts["stat"]["is_dir"] is True


def test_filesystem_fat_read_and_extract(tmp_path: Path):
    img = tmp_path / "fat.dsk"
    _build_disk(img)
    content = bytes(range(256)) * 2
    # read by file path
    obs = registry.run("filesystem.read", {"path": str(img), "partition": 1,
                                           "path_in_fs": "/DATA.BIN", "length": len(content)})
    assert obs.status.value == "ok", obs.summary
    assert obs.facts["mode"] == "fs_file"
    assert bytes.fromhex(obs.facts["hex_preview"])[:20] == content[:20]
    # extract to workspace
    ws = tmp_path / "workspace"
    ws.mkdir()
    obs = registry.run("filesystem.extract", {"path": str(img), "output_dir": str(ws),
                                              "partition": 1, "path_in_fs": "/DATA.BIN",
                                              "length": len(content), "name": "out.bin"},
                       policy=_STATEFUL)
    assert obs.status.value == "ok", obs.summary
    assert (ws / "out.bin").read_bytes() == content
    kinds = {a.kind for a in obs.derived_artifacts}
    assert {"evidence", "derived"} <= kinds


def test_filesystem_fat_deleted_recovered(tmp_path: Path):
    img = tmp_path / "fat.dsk"
    _build_disk(img, delete=frozenset({"DATA.BIN"}))
    # The deleted file should no longer appear live in list ...
    obs = registry.run("filesystem.list", {"path": str(img), "partition": 1, "path_in_fs": "/"})
    assert obs.status.value == "ok", obs.summary
    assert "DATA.BIN" not in {e["name"] for e in obs.facts["entries"]}
    # ... but its directory entry is recovered. Under real FAT deletion only the
    # first name byte is overwritten with 0xE5, so the leading character is
    # unrecoverable — the parser renders it as "_" (here: "_ATA.BIN").
    obs = registry.run("filesystem.deleted", {"path": str(img), "partition": 1})
    assert obs.status.value == "ok", obs.summary
    dropped = [d for d in obs.facts["deleted_entries"] if d["name"] == "_ATA.BIN"]
    assert dropped, "deleted DATA.BIN not recovered"
    assert dropped[0]["size"] == len(bytes(range(256)) * 2)
    assert dropped[0]["cluster"] == 3
