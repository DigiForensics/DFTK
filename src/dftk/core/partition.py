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

"""Partition-table parsing — DFTK 3.5.0.

Pure-Python MBR (DOS) and GPT partition parsing over an abstract block source.
No external dependencies, so ``image.partitions`` works on a raw ``dd`` image
and on an E01 image (via the EWF block source) without pytsk3.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Well-known MBR partition type bytes -> human label (forensic subset).
_MBR_TYPES = {
    0x00: "empty",
    0x01: "FAT12",
    0x04: "FAT16 <32M",
    0x05: "extended",
    0x06: "FAT16",
    0x07: "NTFS/HPFS/exFAT",
    0x0B: "FAT32",
    0x0C: "FAT32 LBA",
    0x0E: "FAT16 LBA",
    0x0F: "extended LBA",
    0x11: "hidden FAT12",
    0x12: "Compaq diagnostics",
    0x14: "hidden FAT16",
    0x1B: "hidden FAT32",
    0x1C: "hidden FAT32 LBA",
    0x1E: "hidden FAT16 LBA",
    0x27: "Windows RE",
    0x39: "Plan 9",
    0x3C: "PMagic",
    0x42: "dynamic disk (LDM)",
    0x44: "GoBack",
    0x82: "Linux swap",
    0x83: "Linux",
    0x84: "Hibernation",
    0x85: "Linux extended",
    0x86: "NTFS volume set",
    0x87: "NTFS volume set",
    0x8E: "Linux LVM",
    0xA0: "Hibernation",
    0xA5: "FreeBSD",
    0xA6: "OpenBSD",
    0xA8: "macOS UFS",
    0xA9: "NetBSD",
    0xAB: "macOS boot",
    0xAF: "macOS HFS+",
    0xBE: "Solaris boot",
    0xBF: "Solaris",
    0xEE: "GPT protective",
    0xEF: "EFI system partition",
    0xFB: "VMware VMFS",
    0xFC: "VMware VMKCORE",
    0xFD: "Linux raid",
}


@dataclass
class Partition:
    index: int
    scheme: str            # "MBR" | "GPT"
    type: str              # human label or GUID string
    start_lba: int
    num_sectors: int
    start_byte: int
    size_byte: int
    name: str = ""
    guid: str = ""
    flags: str = ""


class BlockSource:
    """Abstract readable block device / image. Subclasses implement ``read``."""

    def __init__(self, sector_size: int = 512) -> None:
        self.sector_size = sector_size

    def size(self) -> int:
        raise NotImplementedError

    def read(self, offset: int, length: int) -> bytes:
        raise NotImplementedError

    def read_sectors(self, lba: int, count: int) -> bytes:
        return self.read(lba * self.sector_size, count * self.sector_size)


class RawBlockSource(BlockSource):
    def __init__(self, path: str, sector_size: int = 512) -> None:
        super().__init__(sector_size)
        self._path = path
        import os
        self._size = os.path.getsize(path)

    def size(self) -> int:
        return self._size

    def read(self, offset: int, length: int) -> bytes:
        with open(self._path, "rb") as fh:
            fh.seek(offset)
            return fh.read(length)


class EwfBlockSource(BlockSource):
    """Block source over an E01/EWF image via pyewf (optional)."""

    def __init__(self, path: str, sector_size: int = 512) -> None:
        super().__init__(sector_size)
        try:
            import pyewf
        except ImportError as e:
            raise RuntimeError(f"pyewf is required for E01 block source: {e}") from e
        names = pyewf.glob(path)
        self._handle = pyewf.handle()
        self._handle.open(names)

    def size(self) -> int:
        return self._handle.get_media_size()

    def read(self, offset: int, length: int) -> bytes:
        self._handle.seek(offset)
        return self._handle.read(length)

    def close(self) -> None:
        try:
            self._handle.close()
        except Exception:
            pass


def open_block_source(path: str, sector_size: int = 512) -> BlockSource:
    """Pick the right block source: EWF for E01 images, raw otherwise.

    E01 detection is by magic bytes (not extension), so a renamed image still
    opens. The pure-Python ``E01BlockSource`` is preferred (no external
    dependency); ``EwfBlockSource`` (pyewf) is used only as a fallback.
    """
    try:
        with open(path, "rb") as fh:
            magic = fh.read(8)
    except OSError:
        magic = b""
    if magic[:8] in (b"EVF\x09\x0d\x0a\xff\x00", b"LVF\x09\x0d\x0a\xff\x00"):
        try:
            from .e01 import E01BlockSource
            return E01BlockSource(path, sector_size)
        except Exception as e1:  # pure-Python reader failed -> try pyewf
            try:
                return EwfBlockSource(path, sector_size)
            except Exception:
                raise e1
    return RawBlockSource(path, sector_size)


def parse_partitions(src: BlockSource) -> list[Partition]:
    """Parse MBR (and GPT if present) from a block source. Returns partitions."""
    sector = src.sector_size
    mbr = src.read_sectors(0, 1)
    parts: list[Partition] = []
    if len(mbr) < 512:
        return parts
    # MBR partition entries live at offset 446, 16 bytes each.
    for i in range(4):
        off = 446 + i * 16
        status = mbr[off]
        ptype = mbr[off + 4]
        start_lba = int.from_bytes(mbr[off + 8:off + 12], "little")
        num = int.from_bytes(mbr[off + 12:off + 16], "little")
        if ptype == 0 or num == 0:
            continue
        label = _MBR_TYPES.get(ptype, f"type_{ptype:02X}")
        flags = "bootable" if (status & 0x80) else ""
        parts.append(Partition(index=i, scheme="MBR", type=label,
                               start_lba=start_lba, num_sectors=num,
                               start_byte=start_lba * sector, size_byte=num * sector,
                               flags=flags))
        if ptype == 0xEE:
            # GPT protective partition — parse the real GPT.
            parts.extend(_parse_gpt(src, sector))
    # De-duplicate: if GPT parsed, the 0xEE protective entry remains as metadata.
    return parts


def _parse_gpt(src: BlockSource, sector: int) -> list[Partition]:
    out: list[Partition] = []
    hdr = src.read_sectors(1, 1)  # GPT header at LBA 1
    if len(hdr) < 92 or hdr[0:8] != b"EFI PART":
        return out
    revision = int.from_bytes(hdr[8:12], "little")
    num_entries = int.from_bytes(hdr[80:84], "little")
    entry_size = int.from_bytes(hdr[84:88], "little")
    part_lba = int.from_bytes(hdr[72:80], "little")
    # Read enough sectors to cover all entries.
    entries_sectors = ((num_entries * entry_size) + sector - 1) // sector
    buf = src.read_sectors(part_lba, min(entries_sectors, 1024))
    for i in range(num_entries):
        eoff = i * entry_size
        if eoff + 128 > len(buf):
            break
        type_guid = _guid_be(buf[eoff:eoff + 16])
        if type_guid == "00000000-0000-0000-0000-000000000000":
            continue
        unique = _guid_be(buf[eoff + 16:eoff + 32])
        start = int.from_bytes(buf[eoff + 32:eoff + 40], "little")
        last = int.from_bytes(buf[eoff + 40:eoff + 48], "little")
        name = buf[eoff + 56:eoff + 128].decode("utf-16-le", "replace").split("\x00", 1)[0]
        out.append(Partition(index=i, scheme="GPT", type=type_guid,
                             start_lba=start, num_sectors=(last - start + 1),
                             start_byte=start * sector, size_byte=(last - start + 1) * sector,
                             name=name, guid=unique))
    _ = revision
    return out


def _guid_be(b: bytes) -> str:
    if len(b) < 16:
        return ""
    # GPT GUIDs are mixed-endian: Data1/2/3 little, Data4 big.
    d1 = int.from_bytes(b[0:4], "little")
    d2 = int.from_bytes(b[4:6], "little")
    d3 = int.from_bytes(b[6:8], "little")
    d4 = b[8:10].hex()
    d5 = b[10:16].hex()
    return f"{d1:08X}-{d2:04X}-{d3:04X}-{d4}-{d5}"
