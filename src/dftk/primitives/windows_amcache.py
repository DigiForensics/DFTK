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

"""Windows Amcache parser — DFTK 3.5.0.

Amcache (``Amcache.hve``) is a standard Windows registry hive. DFTK parses it
with the pure-Python :mod:`dftk.core.regf` reader (no external dependency), so the
artifact is fully analysable even where ``python-registry`` / ``regrippy`` are not
installed.

The parser extracts:

* ``InventoryApplicationFile`` records → per-file evidence (path, SHA1, size,
  version, last-modified, linked ProgramId);
* ``InventoryApplication`` records → program-level evidence (name, publisher,
  version, install date, language).

These map file paths to program identities and timestamps, which is the pivot
for correlating an on-disk binary with its install/execution context — the same
chain the USN / MFT / Prefetch artifacts support.
"""

from __future__ import annotations

import struct
from pathlib import Path

from dftk.core.helpers import sha256_file
from dftk.core.regf import load_hive, filetime_to_iso
from dftk.core.registry import registry
from dftk.core.models import Observation, Evidence, Status, SafetyLevel

VALUE_TYPE_NAMES = {
    0x1: "REG_SZ",
    0x2: "REG_EXPAND_SZ",
    0x3: "REG_BINARY",
    0x4: "REG_DWORD",
    0x7: "REG_MULTI_SZ",
    0xB: "REG_QWORD",
}


def _decode_value(vtype: int, data: bytes):
    """Decode a registry value's raw bytes into a JSON-friendly value."""
    if vtype in (0x1, 0x2, 0x7):  # string types
        return data.decode("utf-16-le", "replace").rstrip("\x00")
    if vtype == 0x4 and len(data) >= 4:  # DWORD
        return struct.unpack_from("<I", data, 0)[0]
    if vtype == 0xB and len(data) >= 8:  # QWORD — treat as possible FILETIME
        ft = struct.unpack_from("<Q", data, 0)[0]
        iso = filetime_to_iso(ft)
        return {"raw": ft, "iso": iso} if iso else ft
    if vtype == 0x3:  # binary → hex
        return data.hex()
    return data.hex() if data else ""


def _extract_key_values(key: dict) -> dict:
    out: dict = {"name": key["name"], "last_write": key.get("last_write")}
    for vname, vk in key.get("values", {}).items():
        out[vname] = _decode_value(vk["type"], vk["data"])
    return out


def _find_subkey(root: dict | None, name: str) -> dict | None:
    if root is None:
        return None
    for sk in root.get("subkeys", []):
        if sk["name"] == name:
            return sk
    return None


@registry.tool(
    name="windows.amcache",
    description=(
        "Parse Amcache.hve (pure-Python REGF reader) for program/file evidence: file "
        "paths, SHA1 hashes, sizes, versions, last-modified timestamps, and the linked "
        "ProgramId. Also extracts InventoryApplication program metadata."
    ),
    parameters={
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "path to Amcache.hve (read-only evidence)"},
        },
        "required": ["path"],
    },
    safety=SafetyLevel.READ_ONLY,
    tags=("windows", "amcache", "program"),
    produces=("amcache_files", "amcache_programs"),
    path_roles={"path": "EVIDENCE_INPUT"},
)
def amcache(path: str) -> Observation:
    h = sha256_file(Path(path))
    try:
        hive = load_hive(path)
        root = hive.root()
    except Exception as e:
        return Observation(
            "windows.amcache",
            Status.UNSUPPORTED,
            "could not parse hive as REGF",
            errors=[str(e)],
            meta={"source_sha256": h},
        )

    files: list[dict] = []
    programs: list[dict] = []
    warnings: list[str] = []

    iaf = _find_subkey(root, "InventoryApplicationFile")
    if iaf is not None:
        for fk in iaf.get("subkeys", []):
            files.append(_extract_key_values(fk))
    else:
        warnings.append("InventoryApplicationFile key not found")

    ia = _find_subkey(root, "InventoryApplication")
    if ia is not None:
        for pk in ia.get("subkeys", []):
            programs.append(_extract_key_values(pk))
    else:
        warnings.append("InventoryApplication key not found (program metadata unavailable)")

    sha1_hits = [f.get("FileId") for f in files if f.get("FileId")]
    return Observation(
        "windows.amcache",
        Status.PARTIAL if warnings and not files else (Status.OK if files else Status.PARTIAL),
        f"Extracted {len(files)} Amcache file record(s), {len(programs)} program record(s)",
        facts={"file_count": len(files), "program_count": len(programs), "files": files, "programs": programs},
        evidence=[Evidence(str(path), "amcache", f"{len(files)} files / {len(programs)} programs", locator="InventoryApplicationFile", source_sha256=h, confidence=0.85, state="LIVE")],
        warnings=warnings,
        meta={"source_sha256": h, "sha1_hits": sha1_hits},
    )
