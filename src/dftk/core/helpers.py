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

from __future__ import annotations
from pathlib import Path
from dataclasses import dataclass, field, asdict
import hashlib, os, re, stat
from typing import Iterable

CHUNK = 1024 * 1024

def sha256_file(path: str | os.PathLike[str]) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()

def hash_file(path: str | os.PathLike[str], algorithms: Iterable[str]) -> dict[str, str]:
    hs = {}
    for name in algorithms:
        try:
            hs[name.lower()] = hashlib.new(name.lower())
        except ValueError as e:
            raise ValueError(f"unsupported hash algorithm: {name}") from e
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            for h in hs.values(): h.update(chunk)
    return {k: v.hexdigest() for k, v in hs.items()}

def printable_strings(data: bytes, min_length: int = 4) -> list[tuple[int, str]]:
    rx = re.compile(rb"[\x20-\x7e]{%d,}" % max(1, min_length))
    return [(m.start(), m.group().decode("ascii", "replace")) for m in rx.finditer(data)]

def safe_rel(path: Path, root: Path) -> str:
    try: return str(path.relative_to(root))
    except ValueError: return str(path)

@dataclass
class TraversalReport:
    """Traversal coverage; an exhausted iterator alone does not imply full access."""
    yielded_files: int = 0
    skipped_symlinks: int = 0
    errors: list[str] = field(default_factory=list)
    truncated: bool = False
    exhausted: bool = False

    def to_dict(self) -> dict:
        return {**asdict(self), "complete": self.exhausted and not (
            self.truncated or self.errors or self.skipped_symlinks)}


def bounded_files(root: Path, *, max_files: int = 10000, report: TraversalReport | None = None):
    report = report if report is not None else TraversalReport()
    if max_files < 1:
        report.truncated = True
        return
    def onerror(exc):
        report.errors.append(str(exc))
    for base, dirs, files in os.walk(root, onerror=onerror):
        retained = []
        for name in sorted(dirs):
            if (Path(base) / name).is_symlink():
                report.skipped_symlinks += 1
            else:
                retained.append(name)
        dirs[:] = retained
        for name in sorted(files):
            candidate = Path(base) / name
            if candidate.is_symlink():
                report.skipped_symlinks += 1
                continue
            try:
                if not stat.S_ISREG(candidate.stat().st_mode):
                    continue
            except OSError as exc:
                report.errors.append(f"{candidate}: {exc}")
                continue
            # Look ahead by one regular file to distinguish exactly-at-limit
            # from genuinely truncated traversal.
            if report.yielded_files >= max_files:
                report.truncated = True
                return
            report.yielded_files += 1
            yield candidate
    report.exhausted = True

# In-memory read ceiling for tools that must load the whole file. Forensic
# evidence can legitimately be large, but loading multi-GB inputs unconditionally
# risks out-of-memory; per-tool overrides are allowed.
DEFAULT_MAX_READ = 4 * 1024 * 1024 * 1024

def read_file_bounded(path: str | os.PathLike[str], max_bytes: int = DEFAULT_MAX_READ):
    """Read a file fully, refusing inputs above ``max_bytes`` to avoid OOM.

    Returns ``(data, None)`` on success, or ``(None, err)`` where ``err`` is a
    dict with ``kind`` of ``"too_large"`` or ``"stat"`` and supporting fields.
    The caller is responsible for converting ``err`` into an ``Observation``.
    """
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError as e:
        return None, {"kind": "stat", "error": str(e)}
    if size > max_bytes:
        return None, {"kind": "too_large", "size": size, "limit": max_bytes}
    try:
        with p.open("rb") as stream:
            data = stream.read(max_bytes + 1)
    except OSError as exc:
        return None, {"kind": "read", "error": str(exc)}
    if len(data) > max_bytes:
        return None, {"kind": "too_large", "size": len(data), "limit": max_bytes}
    return data, None

def read_file_bounded_observation(name: str, path: str | os.PathLike[str], max_bytes: int = DEFAULT_MAX_READ):
    """Like :func:`read_file_bounded`, but returns ``(data, None, sha256)`` on success
    or ``(None, Observation, None)`` on failure.

    The SHA-256 is hashed from the in-memory ``data`` in a single pass, so callers
    must NOT re-read the file from disk to hash it (that would double the I/O and
    memory pressure on large evidence). On oversized input the Observation is
    ``UNSUPPORTED``; on a stat/read failure it is ``ERROR``. We deliberately do not
    hash in those branches: hashing would force the very full read we are avoiding.
    """
    from .models import Observation, Status
    data, err = read_file_bounded(path, max_bytes)
    if err is not None:
        if err["kind"] == "too_large":
            return (None,
                    Observation(name, Status.UNSUPPORTED, "File exceeds in-memory read limit",
                                errors=[f"size={err['size']} > limit={err['limit']}"]),
                    None)
        return (None,
                Observation(name, Status.ERROR, "File read failed", errors=[err["error"]]),
                None)
    source_sha256 = hashlib.sha256(data).hexdigest()
    return data, None, source_sha256


def sqlite_immutable_warnings(path: str | Path) -> list[str]:
    """Immutable engine reads intentionally omit sidecar transaction state."""
    if any(Path(str(path) + suffix).exists() or Path(str(path) + suffix).is_symlink()
           for suffix in ("-wal", "-journal")):
        return ["SQLite sidecar present: immutable mode examines the main DB only; uncheckpointed WAL/rollback state is excluded. Preserve sidecars and inspect database.sqlite_wal/database.sqlite_recover before a negative finding."]
    return []
