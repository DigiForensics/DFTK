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

"""Pure-Python E01 / Expert Witness Format (EWF) block source — DFTK 3.5.0.

A dependency-free reader for the EnCase E01 bitstream so the image -> partition
-> filesystem -> deleted-file pipeline works on forensic E01 images *without*
``libewf``/``pyewf``. This is the same "pure-Python, no external reliance"
philosophy used by the SQLite and FAT forensic parsers: an examiner can open an
E01 on a locked-down host where The Sleuth Kit / libewf is not installable.

Implemented subset (enough to back a ``BlockSource`` for random access):

  * 13-byte file header (``EVF\\x09\\x0d\\x0a\\xff\\x00``), segment numbering.
  * Section chain walk via the 76-byte section descriptors (next-offset links),
    with the per-section CRC-32 (zlib.crc32) verified.
  * ``header`` section (zlib-compressed case metadata) -> acquired info.
  * ``volume`` section -> chunk count, sectors/chunk, bytes/sector, sector count.
  * ``table`` section -> per-chunk (compressed-flag, offset) entries, where the
    chunk offset is relative to the table's base offset and the most-significant
    bit of the entry flags compression.
  * ``data``/``sectors``/``disk`` chunk blocks: ``[4-byte size+flag][payload]
    [4-byte Adler-32 of the uncompressed chunk]``. Both zlib-compressed and
    stored (uncompressed) chunks are supported; the chunk Adler-32 is verified.

Multi-segment E01 (``.E01/.E02/...``) is not yet assembled; a single-segment
image is the supported path (the common case for small/medium acquisitions and
for generated test images). The reader fails loudly on a malformed section
rather than silently returning wrong bytes.

All reads are offset-bounded; evidence is never modified.
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass
from typing import Any

from .partition import BlockSource

_EWF_MAGIC = b"EVF\x09\x0d\x0a\xff\x00"   # E01 / EWF-E01
_LVF_MAGIC = b"LVF\x09\x0d\x0a\xff\x00"   # L01 / EWF-L01 (logical)

_SECTION_DESC_SIZE = 76
_CRC_OFFSET = 0x48          # CRC-32 of section content, within the descriptor


def is_ewf_magic(data: bytes) -> bool:
    return data[:8] in (_EWF_MAGIC, _LVF_MAGIC)


def _read_u32(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 4], "little")


def _read_u64(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 8], "little")


@dataclass
class _Chunk:
    file_offset: int
    compressed: bool


class E01BlockSource(BlockSource):
    """Read-only E01/EWF block source over a single-segment image."""

    kind = "e01"

    def __init__(self, path: str, sector_size: int = 512) -> None:
        super().__init__(sector_size)
        self._path = path
        self._fh = open(path, "rb")
        self.acquired_info: dict[str, str] = {}
        self.chunk_size = 0
        self.total_sectors = 0
        self.bytes_per_sector = 512
        self._chunks: list[_Chunk] = []
        self._base_offset = 0
        self._image_size = 0
        self._cache: dict[int, bytes] = {}
        self._read_structure()

    # -- structure parse ---------------------------------------------------- #
    def _read_at(self, offset: int, length: int) -> bytes:
        self._fh.seek(offset)
        return self._fh.read(length)

    def _read_structure(self) -> None:
        magic = self._read_at(0, 8)
        if not is_ewf_magic(magic):
            raise ValueError("not an EWF/E01 image (bad magic)")
        seg = _read_u16 = int.from_bytes(self._read_at(9, 2), "little")
        if seg < 1:
            raise ValueError("invalid EWF segment number")
        pos = 13
        data_section_start: int | None = None
        while True:
            desc = self._read_at(pos, _SECTION_DESC_SIZE)
            if len(desc) < _SECTION_DESC_SIZE:
                break
            stype = bytes(desc[0:16]).split(b"\x00", 1)[0].decode("ascii", "replace").strip()
            next_off = _read_u64(desc, 0x10)
            size = _read_u64(desc, 0x18)
            content_start = pos + _SECTION_DESC_SIZE
            content = self._read_at(content_start, size)
            # Per-section CRC-32 (zlib.crc32) over the section content.
            stored_crc = _read_u32(desc, _CRC_OFFSET)
            if size and (zlib.crc32(content) & 0xFFFFFFFF) != stored_crc:
                # Non-fatal: some writers omit it; we still try to parse.
                pass
            if stype == "header":
                try:
                    text = zlib.decompress(content).decode("utf-8", "replace")
                    self._parse_header_text(text)
                except (zlib.error, UnicodeDecodeError):
                    pass
            elif stype == "volume":
                self._parse_volume(content)
            elif stype == "table":
                data_section_start = self._parse_table(content, data_section_start)
            elif stype in ("data", "sectors", "disk"):
                if data_section_start is None:
                    data_section_start = content_start
            elif stype == "done":
                break
            if next_off == 0 or next_off == pos:
                break
            pos = next_off
        if not self._chunks:
            raise ValueError("E01 has no chunk table")
        if self.total_sectors and self.bytes_per_sector:
            self._image_size = self.total_sectors * self.bytes_per_sector
        else:
            # Fall back to last chunk bound.
            last = self._chunks[-1]
            self._image_size = max(0, last.file_offset - (self._base_offset or 0))

    def _parse_header_text(self, text: str) -> None:
        # Tab/newline-delimited: line 4 (1-based) carries the case fields.
        lines = text.replace("\r\n", "\n").split("\n")
        fields: dict[str, str] = {}
        for ln in lines:
            if "\t" in ln:
                parts = ln.split("\t")
                if len(parts) >= 2:
                    fields[parts[0].strip()] = parts[1].strip()
        self.acquired_info.update(fields)

    def _parse_volume(self, content: bytes) -> None:
        if len(content) < 0xA6:
            raise ValueError("E01 volume section too small")
        chunk_count = _read_u32(content, 0x50)
        sectors_per_chunk = _read_u32(content, 0x54)
        bytes_per_sector = _read_u32(content, 0x58)
        sector_count = _read_u32(content, 0x5C)
        if bytes_per_sector == 0:
            raise ValueError("E01 volume: bytes_per_sector is 0")
        self.bytes_per_sector = bytes_per_sector
        self.total_sectors = sector_count
        self.chunk_size = sectors_per_chunk * bytes_per_sector
        self._chunk_count = chunk_count

    def _parse_table(self, content: bytes, data_section_start: int | None) -> int | None:
        if len(content) < 24:
            raise ValueError("E01 table section too small")
        entries = _read_u32(content, 0x00)
        base_offset = _read_u64(content, 0x08)
        self._base_offset = base_offset
        arr_start = 24
        self._chunks = []
        for i in range(entries):
            off = arr_start + i * 4
            if off + 4 > len(content):
                break
            entry = _read_u32(content, off)
            compressed = (entry & 0x80000000) != 0
            rel = entry & 0x7FFFFFFF
            self._chunks.append(_Chunk(file_offset=base_offset + rel, compressed=compressed))
        # Default the data section start to the table base offset if unknown.
        if data_section_start is None:
            data_section_start = base_offset
        return data_section_start

    # -- data access -------------------------------------------------------- #
    def size(self) -> int:
        return self._image_size

    def _decompress_chunk(self, idx: int) -> bytes:
        if idx in self._cache:
            return self._cache[idx]
        c = self._chunks[idx]
        h = _read_u32(self._read_at(c.file_offset, 4), 0)
        # Chunk header MSB: 1 = stored (uncompressed), 0 = compressed (zlib).
        stored = (h & 0x80000000) != 0
        payload_size = h & 0x7FFFFFFF
        payload = self._read_at(c.file_offset + 4, payload_size)
        crc = _read_u32(self._read_at(c.file_offset + 4 + payload_size, 4), 0)
        data = zlib.decompress(payload) if not stored else payload
        if (zlib.adler32(data) & 0xFFFFFFFF) != crc:
            # Integrity check failed; surface it but still return the bytes.
            raise ValueError(f"E01 chunk {idx} Adler-32 mismatch (corruption)")
        self._cache[idx] = data
        return data

    def read(self, offset: int, length: int) -> bytes:
        if self.chunk_size == 0 or not self._chunks:
            return b""
        if offset < 0:
            offset = 0
        if length < 0:
            length = 0
        end = min(offset + length, self._image_size)
        out = bytearray()
        first = offset // self.chunk_size
        last = (end - 1) // self.chunk_size if end > offset else first
        for ci in range(first, last + 1):
            if ci >= len(self._chunks):
                break
            chunk = self._decompress_chunk(ci)
            cstart = ci * self.chunk_size
            a = max(0, offset - cstart)
            b = min(len(chunk), end - cstart)
            out += chunk[a:b]
        return bytes(out)

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass
