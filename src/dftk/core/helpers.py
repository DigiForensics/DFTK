from __future__ import annotations
from pathlib import Path
import hashlib, os, re
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

def bounded_files(root: Path, *, max_files: int = 10000):
    n = 0
    for base, dirs, files in os.walk(root):
        dirs.sort(); files.sort()
        for name in files:
            yield Path(base) / name
            n += 1
            if n >= max_files:
                return
