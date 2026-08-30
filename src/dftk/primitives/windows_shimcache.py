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

"""Windows Application Compatibility Cache (Shimcache) parser — DFTK 3.5.0.

The Shimcache is a registry blob (``SYSTEM\\...\\AppCompatCache\\AppCompatCache``)
that records *files the OS considered for application compatibility*. It is
frequently cited as an execution indicator, but **DFTK deliberately does NOT
infer execution from a Shimcache entry.** Per the 3.5.0 confidence philosophy the
output marks every entry ``execution_inference = "unsupported"`` and leaves
execution conclusions to correlation with Prefetch / Amcache / MFT / USN.

Three on-disk layouts exist (entry sizes 0x228 / 0x80 / 0x70). Exact byte
offsets in real samples vary by Windows build, so this parser extracts the
reliable signals — a UTF-16LE path and an 8-byte FILETIME-style timestamp
scanned within each entry — and reports them with explicit low confidence rather
than fabricating precise field values. Validate against known-good samples
before relying on exact offsets in a case.
"""

from __future__ import annotations

import struct
from pathlib import Path

from dftk.core.helpers import sha256_file
from dftk.core.registry import registry
from dftk.core.models import Observation, Evidence, Status, SafetyLevel
from dftk.primitives.windows_host import _filetime_to_iso, _plausible_ft  # reuse MFT time helpers


def _scan_utf16_path(entry: bytes) -> str:
    """Return the longest printable UTF-16LE run in the entry (the file path)."""
    best = ""
    i = 0
    n = len(entry)
    while i + 1 < n:
        # Find a run of plausible UTF-16LE chars (letters, digits, path punctuation).
        j = i
        run = ""
        while j + 1 < n:
            ch = entry[j] | (entry[j + 1] << 8)
            if 0x20 <= ch < 0x7F or ch in (0x5C, 0x3A, 0x2E, 0x2F, 0x2D, 0x20, 0x9, 0xAD):
                run += chr(ch)
                j += 2
            else:
                break
        if len(run) > len(best) and any(c.isalnum() for c in run):
            best = run
        i += 2
    return best


def _scan_filetime(entry: bytes) -> tuple[int, str | None]:
    """Return (raw_filetime, iso) of the first plausible 8-byte LE FILETIME."""
    best_raw = 0
    for o in range(0, len(entry) - 7, 2):
        ft = struct.unpack_from("<Q", entry, o)[0]
        if _plausible_ft(ft):
            best_raw = ft
            return ft, _filetime_to_iso(ft)
    return 0, None


def _parse_entries(blob: bytes) -> tuple[str, list[dict]]:
    """Detect layout and yield normalised Shimcache entries."""
    entries: list[dict] = []
    # XP / 2003: 0x228 (552) byte entries, optional 0xDEADBEEF signature at start.
    if len(blob) >= 4 and blob[0:4] == b"\xef\xbe\xad\xde":
        layout = "xp_2003"
        body = blob[8:]
        esize = 0x228
    elif len(blob) >= 0x228 and len(blob) % 0x228 == 0:
        layout = "xp_2003"
        body = blob
        esize = 0x228
    elif len(blob) % 0x80 == 0 and len(blob) >= 0x80:
        layout = "win7_8_10_pre1511"
        body = blob
        esize = 0x80
    elif len(blob) % 0x70 == 0 and len(blob) >= 0x70:
        layout = "win10_1511_plus"
        body = blob
        esize = 0x70
    else:
        # Unknown; treat as win7-sized blocks best-effort.
        layout = "unknown"
        body = blob
        esize = 0x80

    for off in range(0, len(body) - esize + 1, esize):
        entry = body[off : off + esize]
        if not entry.strip(b"\x00"):
            continue
        path = _scan_utf16_path(entry)
        ft_raw, ft_iso = _scan_filetime(entry)
        if not path and not ft_iso:
            continue
        entries.append(
            {
                "layout": layout,
                "offset": off,
                "path": path,
                "last_modified": ft_iso,
                "last_modified_raw": ft_raw,
                "execution_inference": "unsupported",
                "confidence": "low",
            }
        )
    return layout, entries


@registry.tool(
    name="windows.shimcache",
    description=(
        "Parse the AppCompatCache (Shimcache) registry blob. Extracts per-entry file "
        "paths and last-modified timestamps. Execution is explicitly NOT inferred "
        "(execution_inference='unsupported'); correlate with Prefetch/Amcache/MFT/USN."
    ),
    parameters={
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "raw Shimcache blob (.bin) or a registry hive containing the value"},
            "is_hive": {"type": "boolean", "default": False, "description": "set True if 'path' is a SYSTEM hive to extract the value from"},
        },
        "required": ["path"],
    },
    safety=SafetyLevel.READ_ONLY,
    tags=("windows", "shimcache", "appcompat"),
    produces=("shimcache_entries",),
    path_roles={"path": "EVIDENCE_INPUT"},
)
def shimcache(path: str, is_hive: bool = False) -> Observation:
    h = sha256_file(Path(path))
    try:
        raw = Path(path).read_bytes()
    except OSError as e:
        return Observation("windows.shimcache", Status.ERROR, "cannot read input", errors=[str(e)], meta={"source_sha256": h})

    blob = raw
    if is_hive:
        try:
            from dftk.core.regf import load_hive

            hive = load_hive(path)
            key = hive.get_key("ControlSet001\\Control\\Session Manager\\AppCompatCache")
            if key is None:
                key = hive.get_key("ControlSet002\\Control\\Session Manager\\AppCompatCache")
            if key is None:
                return Observation(
                    "windows.shimcache",
                    Status.PARTIAL,
                    "AppCompatCache key not found in hive",
                    warnings=["tried ControlSet001/002"],
                    meta={"source_sha256": h},
                )
            val = key["values"].get("AppCompatCache")
            blob = val["data"] if val else b""
        except Exception as e:  # regf parse issue
            return Observation("windows.shimcache", Status.PARTIAL, "could not extract value from hive", errors=[str(e)], meta={"source_sha256": h})

    if not blob:
        return Observation("windows.shimcache", Status.PARTIAL, "empty Shimcache data", meta={"source_sha256": h})

    layout, entries = _parse_entries(blob)
    return Observation(
        "windows.shimcache",
        Status.PARTIAL if not entries else Status.OK,
        f"Parsed {len(entries)} Shimcache entr(y/ies) [{layout}] — execution NOT inferred",
        facts={"layout": layout, "entry_count": len(entries), "entries": entries},
        evidence=[Evidence(str(path), "shimcache", f"{len(entries)} entries", locator="appcompat", source_sha256=h, confidence=0.4, state="LIVE")],
        warnings=[
            "Shimcache records file *consideration* for compatibility, not execution. "
            "execution_inference is explicitly 'unsupported' — do not cite as proof of run.",
            "Path/timestamp extraction is heuristic (longest UTF-16LE run + first plausible FILETIME per entry); validate offsets against known-good samples.",
        ],
        meta={"source_sha256": h, "layout": layout},
    )
