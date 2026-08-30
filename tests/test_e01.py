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

"""Pure-Python E01 block source tests — DFTK 3.5.0.

Builds a real (tiny) single-segment E01 wrapping the same FAT12 volume used by
``test_fat_filesystem``, then proves the image -> partition -> filesystem ->
deleted pipeline works on E01 *without* libewf/pytsk3. Both uncompressed
(``compress=False``) and zlib-compressed (``compress=True``) chunk encodings
are exercised, so the chunk wrapper (``[size+flag][payload][adler32]``) and the
table-driven random access are both validated.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

from dftk import get_registry
from dftk.core.registry import registry
from dftk.core.models import SafetyLevel
from dftk.core.safety import SafetyPolicy

get_registry()  # register image.partitions + filesystem.*

import test_fat_filesystem as fatmod  # reuse the FAT12 volume builder

_STATEFUL = SafetyPolicy(max_level=SafetyLevel.STATEFUL)
_CHUNK = 32768  # 64 sectors * 512 bytes


def _build_e01(vol: bytes, compress: bool = False) -> bytes:
    chunks = [vol[i:i + _CHUNK] for i in range(0, len(vol), _CHUNK)]
    n = len(chunks)

    def _block(ch: bytes) -> tuple[bytes, int]:
        if compress:
            payload = zlib.compress(ch)
            h = len(payload)            # chunk-header MSB 0 -> compressed
            entry_flag = 0x80000000     # table-entry MSB 1 -> compressed
        else:
            payload = ch
            h = 0x80000000 | len(payload)  # chunk-header MSB 1 -> stored
            entry_flag = 0x00000000     # table-entry MSB 0 -> uncompressed
        crc = zlib.adler32(ch) & 0xFFFFFFFF
        return struct.pack("<I", h) + payload + struct.pack("<I", crc), payload

    blocks = []
    sizes = []
    for ch in chunks:
        blk, _ = _block(ch)
        blocks.append(blk)
        sizes.append(len(blk))
    data_content = b"".join(blocks)

    # header section (zlib-compressed case metadata)
    case = ("main\tc\nn\ta\ne\tt\nm\tu\np\tr\n"
            "Case Number\tCASE-1\nEvidence Number\tEV-1\n"
            "Examiner Name\tDynooob\nNotes\tfat-e01\n")
    content_h = zlib.compress(case.encode())

    # volume section (166 bytes)
    cv = bytearray(166)
    struct.pack_into("<I", cv, 0x50, n)               # chunk count
    struct.pack_into("<I", cv, 0x54, 64)              # sectors per chunk
    struct.pack_into("<I", cv, 0x58, 512)             # bytes per sector
    struct.pack_into("<I", cv, 0x5C, len(vol) // 512)  # sector count
    content_v = bytes(cv)

    # table section (24-byte header + entries + 4-byte footer)
    content_t_size = 24 + n * 4 + 4
    # Lay out absolute positions so the table can record the data base offset.
    p = 13
    pos_header = p; p += 76 + len(content_h)
    pos_volume = p; p += 76 + len(content_v)
    pos_table = p; p += 76 + content_t_size
    pos_data = p; data_content_start = pos_data + 76
    pos_done = p + 76 + len(data_content)

    ct = bytearray(content_t_size)
    struct.pack_into("<I", ct, 0, n)                  # number of entries
    struct.pack_into("<Q", ct, 8, data_content_start)  # table base offset
    struct.pack_into("<I", ct, 20, zlib.adler32(bytes(ct[0:20])) & 0xFFFFFFFF)
    rel = 0
    for i, sz in enumerate(sizes):
        entry = (0x80000000 if compress else 0x00000000) | (rel & 0x7FFFFFFF)
        struct.pack_into("<I", ct, 24 + i * 4, entry)
        rel += sz
    arr = bytes(ct[24:24 + n * 4])
    struct.pack_into("<I", ct, 24 + n * 4, zlib.adler32(arr) & 0xFFFFFFFF)
    content_t = bytes(ct)

    def _section(stype: str, content: bytes, next_pos: int) -> bytes:
        desc = bytearray(76)
        desc[0:16] = stype.encode().ljust(16, b"\x00")
        struct.pack_into("<Q", desc, 0x10, next_pos)
        struct.pack_into("<Q", desc, 0x18, len(content))
        struct.pack_into("<I", desc, 0x48, zlib.crc32(content) & 0xFFFFFFFF)
        return bytes(desc) + content

    out = bytearray()
    out += b"EVF\x09\x0d\x0a\xff\x00" + bytes([0x01]) + struct.pack("<H", 1) + struct.pack("<H", 0)
    out += _section("header", content_h, pos_volume)
    out += _section("volume", content_v, pos_table)
    out += _section("table", content_t, pos_data)
    out += _section("data", data_content, pos_done)
    out += _section("done", b"", pos_done)
    return bytes(out)


def _make_e01(tmp_path: Path, compress: bool) -> Path:
    # Wrap the *whole disk* (MBR + gap + FAT12 volume) so the partition table
    # lives at E01 offset 0, matching what raw _build_disk produces.
    import struct
    mbr = bytearray(512)
    entry = bytearray(16)
    entry[4] = 0x01  # FAT12
    struct.pack_into("<I", entry, 8, fatmod._PART_START_LBA)
    struct.pack_into("<I", entry, 12, fatmod._TOTAL_SECTORS)
    mbr[446:446 + 16] = entry
    mbr[510] = 0x55
    mbr[511] = 0xAA
    vol = fatmod._build_fat12_volume()
    disk = bytes(mbr) + b"\x00" * (fatmod._PART_START_LBA * fatmod._BPS - 512) + vol
    img = tmp_path / ("fat.e01" if not compress else "fat_cmp.e01")
    img.write_bytes(_build_e01(disk, compress=compress))
    return img


def test_e01_uncompressed_pipeline(tmp_path: Path):
    img = _make_e01(tmp_path, compress=False)
    # Partition table parses through the E01 block source.
    obs = registry.run("image.partitions", {"path": str(img)})
    assert obs.status.value == "ok", obs.summary
    assert len(obs.facts["partitions"]) == 1
    part = obs.facts["partitions"][0]
    assert part["scheme"] == "MBR"
    assert part["type"] == "FAT12"
    assert part["start_lba"] == fatmod._PART_START_LBA

    # FAT filesystem traversal works over E01 (no pytsk3).
    obs = registry.run("filesystem.list", {"path": str(img), "partition": 1, "path_in_fs": "/"})
    assert obs.status.value == "ok", obs.summary
    names = {e["name"] for e in obs.facts["entries"]}
    assert {"README.TXT", "DATA.BIN", "SUBDIR"} <= names

    # Read a named file through the E01 -> partition -> FAT chain.
    content = bytes(range(256)) * 2
    obs = registry.run("filesystem.read", {"path": str(img), "partition": 1,
                                           "path_in_fs": "/DATA.BIN", "length": len(content)})
    assert obs.status.value == "ok", obs.summary
    assert obs.facts["mode"] == "fs_file"
    assert bytes.fromhex(obs.facts["hex_preview"])[:20] == content[:20]

    # Walk finds the subdir child.
    obs = registry.run("filesystem.walk", {"path": str(img), "partition": 1, "path_in_fs": "/"})
    assert obs.status.value == "ok", obs.summary
    paths = {e["path"] for e in obs.facts["entries"]}
    assert "SUBDIR/NOTE.TXT" in paths


def test_e01_compressed_pipeline(tmp_path: Path):
    img = _make_e01(tmp_path, compress=True)
    obs = registry.run("image.partitions", {"path": str(img)})
    assert obs.status.value == "ok", obs.summary
    part = obs.facts["partitions"][0]
    assert part["type"] == "FAT12"
    assert part["start_lba"] == fatmod._PART_START_LBA

    obs = registry.run("filesystem.list", {"path": str(img), "partition": 1, "path_in_fs": "/"})
    assert obs.status.value == "ok", obs.summary
    names = {e["name"] for e in obs.facts["entries"]}
    assert {"README.TXT", "DATA.BIN", "SUBDIR"} <= names

    content = bytes(range(256)) * 2
    obs = registry.run("filesystem.read", {"path": str(img), "partition": 1,
                                           "path_in_fs": "/DATA.BIN", "length": len(content)})
    assert obs.status.value == "ok", obs.summary
    assert bytes.fromhex(obs.facts["hex_preview"])[:20] == content[:20]
