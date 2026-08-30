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

"""Pure-Python FAT filesystem reader — DFTK 3.5.0.

A dependency-free FAT12/FAT16/FAT32 backend that lets ``filesystem.list``,
``filesystem.walk``, ``filesystem.stat``, ``filesystem.read``,
``filesystem.extract`` and ``filesystem.deleted`` work on FAT images *without*
``pytsk3``. This is the same "pure-Python, no external reliance" philosophy
used by the SQLite forensic parser: an examiner can carve a FAT volume even on
a locked-down host where The Sleuth Kit is not installable.

The backend also recovers deleted directory entries (the ``0xE5`` marker):
the file's first cluster and size survive deletion, so we can report what was
removed — a common field request on USB sticks, SD cards and firmware dumps.

All reads are offset-bounded against the underlying block source; evidence is
never modified.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .fs_backend import FilesystemBackend, UnsupportedFilesystem


def _dos_date(b: bytes) -> tuple[int, int, int]:
    v = int.from_bytes(b[:2], "little")
    day = v & 0x1F
    month = (v >> 5) & 0x0F
    year = 1980 + (v >> 9)
    return year, month, day


def _dos_time(b: bytes) -> tuple[int, int, int]:
    v = int.from_bytes(b[:2], "little")
    sec = (v & 0x1F) * 2
    minute = (v >> 5) & 0x3F
    hour = (v >> 11) & 0x1F
    return hour, minute, sec


def _dos_iso(time_b: bytes, date_b: bytes) -> str | None:
    try:
        y, mo, d = _dos_date(date_b)
        h, mi, s = _dos_time(time_b)
        return datetime(y, mo, d, h, mi, s).isoformat()
    except (ValueError, IndexError):
        return None


class FatFS(FilesystemBackend):
    """Read-only FAT12/FAT16/FAT32 parser over a block source."""

    kind = "fat"

    def __init__(self, src, partition_offset: int, sector_size: int = 512) -> None:
        self._src = src
        self._base = partition_offset
        self._ss = sector_size
        self._read_boot()

    # -- low level --------------------------------------------------------- #
    def _read(self, offset: int, length: int) -> bytes:
        return self._src.read(self._base + offset, length)

    def _read_boot(self) -> None:
        boot = self._read(0, 512)
        if len(boot) < 512 or boot[510] != 0x55 or boot[511] != 0xAA:
            raise UnsupportedFilesystem("not a FAT volume (missing 0x55AA boot signature)")
        self.bps = int.from_bytes(boot[11:13], "little")
        if self.bps not in (512, 1024, 2048, 4096):
            raise UnsupportedFilesystem(f"invalid bytes_per_sector: {self.bps}")
        self.spc = boot[13]
        if self.spc == 0:
            raise UnsupportedFilesystem("invalid sectors_per_cluster: 0")
        self.reserved = int.from_bytes(boot[14:16], "little")
        self.num_fats = boot[16]
        self.root_entries = int.from_bytes(boot[17:19], "little")
        total16 = int.from_bytes(boot[19:21], "little")
        self.total_sectors = int.from_bytes(boot[32:36], "little") or total16
        if self.total_sectors == 0:
            raise UnsupportedFilesystem("cannot determine volume size")
        self.media = boot[21]
        self.fat_size = int.from_bytes(boot[22:24], "little")
        if self.fat_size == 0:
            self.fat_size = int.from_bytes(boot[36:40], "little")  # FAT32
        if self.fat_size == 0:
            raise UnsupportedFilesystem("cannot determine FAT size")

        self.root_dir_sectors = ((self.root_entries * 32) + (self.bps - 1)) // self.bps
        self.first_root_sector = self.reserved + self.num_fats * self.fat_size
        self.data_start_sector = self.first_root_sector + self.root_dir_sectors
        data_sectors = self.total_sectors - self.data_start_sector
        count_of_clusters = data_sectors // self.spc if self.spc else 0
        if count_of_clusters < 4085:
            self.fat_type = 12
        elif count_of_clusters < 65525:
            self.fat_type = 16
        else:
            self.fat_type = 32
        self.root_cluster = int.from_bytes(boot[44:48], "little") if self.fat_type == 32 else 0

        # Read the first FAT (copies are identical).
        fat_start = self.reserved * self.bps
        self._fat = self._read(fat_start, self.fat_size * self.bps)

    # -- FAT chain --------------------------------------------------------- #
    def _next_cluster(self, c: int) -> int | None:
        if c < 2:
            return None
        if self.fat_type == 12:
            o = c * 3 // 2
            if o + 1 >= len(self._fat):
                return None
            if c % 2 == 0:
                v = self._fat[o] | ((self._fat[o + 1] & 0x0F) << 8)
            else:
                v = ((self._fat[o] >> 4) | (self._fat[o + 1] << 4)) & 0x0FFF
            if v >= 0xFF8 or v == 0:
                return None
            return v
        if self.fat_type == 16:
            o = c * 2
            if o + 1 >= len(self._fat):
                return None
            v = int.from_bytes(self._fat[o:o + 2], "little")
            if v >= 0xFFF8 or v == 0:
                return None
            return v
        # FAT32
        o = c * 4
        if o + 3 >= len(self._fat):
            return None
        v = int.from_bytes(self._fat[o:o + 4], "little") & 0x0FFFFFFF
        if v >= 0x0FFFFFF8 or v == 0:
            return None
        return v

    def _cluster_first_sector(self, c: int) -> int:
        return self.data_start_sector + (c - 2) * self.spc

    def _cluster_chain(self, c: int) -> list[int]:
        out: list[int] = []
        seen: set[int] = set()
        while c and c not in seen:
            seen.add(c)
            out.append(c)
            nxt = self._next_cluster(c)
            if nxt is None:
                break
            c = nxt
        return out

    def _read_clusters(self, chain: list[int]) -> bytes:
        out = bytearray()
        n = self.spc * self.bps
        for c in chain:
            s = self._cluster_first_sector(c) * self.bps
            out += self._read(s, n)
        return bytes(out)

    def _read_root_dir(self) -> bytes:
        if self.fat_type == 32:
            return self._read_clusters(self._cluster_chain(self.root_cluster))
        s = self.first_root_sector * self.bps
        return self._read(s, self.root_dir_sectors * self.bps)

    def _read_dir_data(self, first_cluster: int) -> bytes:
        if first_cluster == 0:
            return self._read_root_dir()
        return self._read_clusters(self._cluster_chain(first_cluster))

    # -- directory parsing ------------------------------------------------- #
    @staticmethod
    def _decode_entry(rec: bytes, deleted: bool) -> dict[str, Any] | None:
        name_bytes = bytearray(rec[0:11])
        if deleted:
            # The leading 0xE5 is the deletion marker; the real first byte is
            # unrecoverable, so show it as '_' in the recovered name.
            name_bytes[0] = ord("_")
        else:
            if name_bytes[0] == 0x05:
                # 0x05 was used in place of a genuine 0xE5 first character.
                name_bytes[0] = 0xE5
        name = bytes(name_bytes[0:8]).rstrip(b" ")
        ext = bytes(name_bytes[8:11]).rstrip(b" ")
        fullname = name + (b"." + ext if ext else b"")
        try:
            fname = fullname.decode("ascii", "strict")
        except UnicodeDecodeError:
            fname = fullname.decode("latin-1")
        attr = rec[11]
        first_cluster = int.from_bytes(rec[26:28], "little") | (
            int.from_bytes(rec[20:22], "little") << 16)
        size = int.from_bytes(rec[28:32], "little")
        return {
            "name": fname,
            "attr": attr,
            "is_dir": bool(attr & 0x10),
            "is_volume": bool(attr & 0x08),
            "deleted": deleted,
            "first_cluster": first_cluster,
            "size": size,
            "cluster": first_cluster,
            "mtime": _dos_iso(rec[14:16], rec[16:18]),
            "ctime": _dos_iso(rec[14:16], rec[16:18]),
            "atime": _dos_iso(rec[22:24], rec[22:24]),
        }

    def _live_and_deleted(self, data: bytes) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        live: list[dict[str, Any]] = []
        deleted: list[dict[str, Any]] = []
        for off in range(0, len(data) - 31, 32):
            rec = data[off:off + 32]
            if rec[0] == 0x00:
                break  # end-of-directory
            if rec[0] == 0xE5:
                e = self._decode_entry(rec, deleted=True)
                if e:
                    deleted.append(e)
                continue
            if rec[11] & 0x0F == 0x0F:
                continue  # long-file-name entry — skip
            e = self._decode_entry(rec, deleted=False)
            if e:
                live.append(e)
        return live, deleted

    # -- path resolution --------------------------------------------------- #
    def _resolve(self, path_in_fs: str) -> dict[str, Any] | None:
        parts = [p for p in path_in_fs.replace("\\", "/").split("/") if p and p not in (".", "..")]
        if not parts:
            return None  # root
        first_cluster = 0
        for depth, name in enumerate(parts):
            live, _ = self._live_and_deleted(self._read_dir_data(first_cluster))
            match = next((e for e in live
                          if not e["is_volume"] and e["name"].upper() == name.upper()), None)
            if match is None:
                raise UnsupportedFilesystem(f"path not found: {path_in_fs}")
            if depth == len(parts) - 1:
                return match
            if not match["is_dir"]:
                raise UnsupportedFilesystem(f"not a directory: {name}")
            first_cluster = match["first_cluster"]
        return None  # unreachable

    # -- FilesystemBackend interface -------------------------------------- #
    def read(self, offset: int, length: int) -> bytes:
        return self._read(offset, length)

    def read_file(self, path_in_fs: str, offset: int, length: int) -> bytes:
        e = self._resolve(path_in_fs)
        if e is None or e["is_dir"]:
            raise UnsupportedFilesystem(f"not a regular file: {path_in_fs}")
        chain = self._cluster_chain(e["first_cluster"])
        full = self._read_clusters(chain)
        if e["size"] and e["size"] < len(full):
            full = full[:e["size"]]
        return full[offset:offset + length]

    def list_dir(self, path_in_fs: str, entry_limit: int) -> list[dict[str, Any]]:
        if not path_in_fs or path_in_fs in ("/", "\\"):
            live, _ = self._live_and_deleted(self._read_root_dir())
        else:
            e = self._resolve(path_in_fs)
            if e is None:
                live, _ = self._live_and_deleted(self._read_root_dir())
            elif not e["is_dir"]:
                raise UnsupportedFilesystem(f"not a directory: {path_in_fs}")
            else:
                live, _ = self._live_and_deleted(self._read_dir_data(e["first_cluster"]))
        out = [{"name": x["name"], "is_dir": x["is_dir"], "size": x["size"],
                "mtime": x["mtime"], "cluster": x["cluster"], "attr": x["attr"]}
               for x in live if not x["is_volume"] and x["name"] not in (".", "..")]
        return out[:entry_limit]

    def walk(self, path_in_fs: str, max_depth: int, max_entries: int,
             include_deleted: bool) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        visited: set[int] = set()

        def _visit(first_cluster: int, prefix: str, depth: int) -> None:
            if first_cluster in visited or len(out) >= max_entries:
                return
            visited.add(first_cluster)
            live, deleted = self._live_and_deleted(self._read_dir_data(first_cluster))
            if include_deleted:
                for d in deleted:
                    if d["is_volume"] or d["name"] in (".", ".."):
                        continue
                    rec = {"path": (prefix + "/" + d["name"] + " (deleted)").lstrip("/"),
                           "depth": depth, "deleted": True, "size": d["size"],
                           "cluster": d["cluster"]}
                    out.append(rec)
                    if len(out) >= max_entries:
                        return
            for e in live:
                if e["is_volume"] or e["name"] in (".", ".."):
                    continue
                p = (prefix + "/" + e["name"]).lstrip("/")
                out.append({"path": p, "depth": depth, "is_dir": e["is_dir"],
                            "size": e["size"], "mtime": e["mtime"], "cluster": e["cluster"]})
                if len(out) >= max_entries:
                    return
                if e["is_dir"] and depth < max_depth:
                    _visit(e["first_cluster"], p, depth + 1)

        _visit(0, "", 0)
        return out

    def stat(self, path_in_fs: str) -> dict[str, Any]:
        e = self._resolve(path_in_fs)
        if e is None:
            return {"name": "", "is_dir": True, "cluster": 0, "size": 0,
                    "mtime": None, "fat_type": self.fat_type}
        return {"name": e["name"], "is_dir": e["is_dir"], "size": e["size"],
                "mtime": e["mtime"], "cluster": e["cluster"], "attr": e["attr"],
                "fat_type": self.fat_type}

    def list_deleted(self, entry_limit: int) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        visited: set[int] = set()

        def _scan(first_cluster: int, prefix: str) -> None:
            if first_cluster in visited or len(out) >= entry_limit:
                return
            visited.add(first_cluster)
            live, deleted = self._live_and_deleted(self._read_dir_data(first_cluster))
            for d in deleted:
                if d["is_volume"] or d["name"] in (".", ".."):
                    continue
                out.append({"name": d["name"], "size": d["size"], "cluster": d["cluster"],
                            "path": (prefix + "/" + d["name"]).lstrip("/")})
                if len(out) >= entry_limit:
                    return
            for e in live:
                if e["is_dir"] and e["first_cluster"] not in (0,):
                    _scan(e["first_cluster"], (prefix + "/" + e["name"]).lstrip("/"))

        _scan(0, "")
        return out

    def close(self) -> None:
        pass
