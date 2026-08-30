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

"""Filesystem backend abstraction — DFTK 3.5.0.

Three backends share one interface:

  * ``TSKFS``      — full filesystem traversal via pytsk3 (requires the
                     ``pytsk3`` dependency; degrades gracefully when it is
                     absent). This is the production path for NTFS / ext / HFS+
                     and any FAT image where pytsk3 is installed.
  * ``FatFS``      — pure-Python FAT12/FAT16/FAT32 reader (no external
                     dependencies). Activated automatically when pytsk3 is
                     unavailable, so FAT evidence (USB sticks, SD cards,
                     firmware dumps) can be listed/walked/stat'd and deleted
                     entries recovered on a locked-down host.
  * ``RawFS``      — offset-based read/extract over a block source without any
                     filesystem parser. Always available. Useful for pulling a
                     known byte range (e.g. a carved object, a registry hive at a
                     known offset).

The block source (raw file or E01) is supplied by ``partition.open_block_source``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .partition import BlockSource


class UnsupportedFilesystem(RuntimeError):
    """Raised by RawFS for operations that need a real filesystem parser."""


class FilesystemBackend:
    """Base class; subclasses implement the FS operations."""

    kind: str = "base"

    def read(self, offset: int, length: int) -> bytes:  # pragma: no cover
        raise NotImplementedError

    def extract(self, output_dir: str, offset: int, length: int, name: str) -> dict[str, Any]:
        raise NotImplementedError

    def list_dir(self, path_in_fs: str, entry_limit: int) -> list[dict[str, Any]]:
        raise UnsupportedFilesystem("filesystem listing requires pytsk3")

    def walk(self, path_in_fs: str, max_depth: int, max_entries: int,
             include_deleted: bool) -> list[dict[str, Any]]:
        raise UnsupportedFilesystem("filesystem walk requires pytsk3")

    def stat(self, path_in_fs: str) -> dict[str, Any]:
        raise UnsupportedFilesystem("filesystem stat requires pytsk3")

    def list_deleted(self, entry_limit: int) -> list[dict[str, Any]]:
        raise UnsupportedFilesystem("deleted-file recovery requires pytsk3")

    def close(self) -> None:  # pragma: no cover - overridden by TSK
        pass


class RawFS(FilesystemBackend):
    """Offset-based read/extract over a block source; no FS parser."""

    kind = "raw"

    def __init__(self, src: BlockSource, partition_offset: int) -> None:
        self._src = src
        self._base = partition_offset

    def read(self, offset: int, length: int) -> bytes:
        return self._src.read(self._base + offset, length)

    def extract(self, output_dir: str, offset: int, length: int, name: str) -> dict[str, Any]:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        data = self.read(offset, length)
        dest = out / name
        dest.write_bytes(data)
        import hashlib
        return {"path": str(dest), "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest()}


class TSKFS(FilesystemBackend):
    """Full filesystem access via pytsk3."""

    kind = "tsk"

    def __init__(self, src: BlockSource, partition_offset: int) -> None:
        import pytsk3
        self._pytsk3 = pytsk3

        class _Img(pytsk3.Img_Info):
            def __init__(self, block_src: BlockSource):
                self._src = block_src
                super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

            def close(self):  # pragma: no cover - pytsk3 interface
                return None

            def read(self, offset: int, size: int) -> bytes:
                return self._src.read(offset, size)

            def get_size(self) -> int:
                return self._src.size()

        self._img = _Img(src)
        self._fs = pytsk3.FS_Info(self._img, offset=partition_offset)
        self._ftype = int(self._fs.info.ftype)

    # -- helpers ----------------------------------------------------------- #
    @staticmethod
    def _name(entry: Any) -> str:
        try:
            n = entry.info.name.name
            return n.decode("utf-8", "replace") if isinstance(n, bytes) else str(n)
        except (AttributeError, TypeError):
            return "?"

    def _meta(self, entry: Any) -> dict[str, Any]:
        meta = getattr(entry.info, "meta", None)
        if meta is None:
            return {}
        out = {
            "meta_addr": int(meta.addr) if meta.addr is not None else None,
            "size": int(meta.size) if meta.size is not None else None,
            "type": int(meta.type) if meta.type is not None else None,
            "flags": int(meta.flags) if meta.flags is not None else None,
        }
        try:
            out["atime"] = meta.atime
            out["mtime"] = meta.mtime
            out["ctime"] = meta.ctime
            out["crtime"] = meta.crtime
        except (AttributeError, TypeError, ValueError):
            pass
        return out

    # -- operations --------------------------------------------------------- #
    def list_dir(self, path_in_fs: str, entry_limit: int) -> list[dict[str, Any]]:
        root = self._fs.open_dir(path=path_in_fs or "/")
        out: list[dict[str, Any]] = []
        for entry in root:
            nm = self._name(entry)
            if nm in (".", ".."):
                continue
            rec = {"name": nm, **self._meta(entry)}
            out.append(rec)
            if len(out) >= entry_limit:
                break
        return out

    def walk(self, path_in_fs: str, max_depth: int, max_entries: int,
             include_deleted: bool) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        flags = 0
        if include_deleted and hasattr(self._pytsk3, "TSK_FS_DIR_WALK_FLAG_UNALLOC"):
            flags = self._pytsk3.TSK_FS_DIR_WALK_FLAG_UNALLOC

        def _visit(dir_obj, depth: int) -> None:
            for entry in dir_obj:
                nm = self._name(entry)
                if nm in (".", ".."):
                    continue
                rec = {"path": nm, "depth": depth, **self._meta(entry)}
                out.append(rec)
                if len(out) >= max_entries:
                    return
                if depth < max_depth:
                    meta = getattr(entry.info, "meta", None)
                    is_dir = meta is not None and meta.type == self._pytsk3.TSK_FS_META_TYPE_DIR
                    if is_dir:
                        try:
                            _visit(entry.as_directory(), depth + 1)
                        except (OSError, IOError, RuntimeError):
                            continue

        _visit(self._fs.open_dir(path=path_in_fs or "/"), 0)
        return out

    def stat(self, path_in_fs: str) -> dict[str, Any]:
        found = self._fs.open(path_in_fs)
        return {"path": path_in_fs, **self._meta(found)}

    def read(self, offset: int, length: int) -> bytes:
        # TSK path: open the file by path is complex; for raw byte read within a
        # partition we expose offset read via the underlying image.
        return self._img.read(offset, length)

    def read_file(self, path_in_fs: str, offset: int, length: int) -> bytes:
        f = self._fs.open(path_in_fs)
        return f.read(length, offset)

    def extract(self, output_dir: str, offset: int, length: int, name: str) -> dict[str, Any]:
        data = self.read(offset, length)
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        dest = out / name
        dest.write_bytes(data)
        import hashlib
        return {"path": str(dest), "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest()}

    def extract_file(self, output_dir: str, path_in_fs: str, name: str,
                     max_bytes: int) -> dict[str, Any]:
        f = self._fs.open(path_in_fs)
        data = f.read(max_bytes, 0)
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        dest = out / name
        dest.write_bytes(data)
        import hashlib
        return {"path": str(dest), "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest()}

    def list_deleted(self, entry_limit: int) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        try:
            self._fs.dir_walk("/", self._pytsk3.TSK_FS_DIR_WALK_FLAG_UNALLOC,
                              lambda entry: out.append({"name": self._name(entry), **self._meta(entry)})
                              if len(out) < entry_limit else None)
        except (OSError, IOError, RuntimeError):
            pass
        return out

    def close(self) -> None:
        try:
            self._fs.close()
        except Exception:
            pass
        try:
            self._img.close()
        except Exception:
            pass


def open_filesystem(src: BlockSource, partition_offset: int,
                    prefer_tsk: bool = True) -> FilesystemBackend:
    """Open a filesystem.

    Order: TSK (if pytsk3 present and can mount the layout) → pure-Python FAT
    (when the partition is a FAT volume and pytsk3 is absent or could not mount
    it) → RawFS (offset access only). FAT is therefore usable on hosts without
    The Sleuth Kit installed.
    """
    if prefer_tsk:
        try:
            return TSKFS(src, partition_offset)
        except ImportError:
            pass
        except (OSError, IOError, RuntimeError):
            pass
    # pytsk3 absent or couldn't mount this layout: try pure-Python FAT.
    try:
        from .fat import FatFS
        return FatFS(src, partition_offset)
    except UnsupportedFilesystem:
        return RawFS(src, partition_offset)
