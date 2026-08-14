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

"""Discovery of external forensic binaries kept on the analyst host.

dftk never executes these; this module only resolves their location so the
operator / agent knows which capabilities are present, and so a tool can
declare an external dependency via its `requires` field and be reported
`unsupported` at call time when the binary is absent.

Add entries to `_EXTERNAL_TOOLS` as new domains are supported. `binaries` are
candidate executable names probed via PATH; `extra_dirs_env` names an env var
with ";" / ":" separated directories to also search (for tools kept off PATH).
"""

from __future__ import annotations

import os
import shutil
from typing import Any

_EXTERNAL_TOOLS: list[dict[str, Any]] = [
    {
        "name": "jadx",
        "category": "apk",
        "purpose": "Android DEX/Dalvik decompiler for static APK analysis",
        "binaries": ["jadx"],
        "extra_dirs_env": "DFTK_APK_TOOL_DIRS",
    },
    {
        "name": "apktool",
        "category": "apk",
        "purpose": "APK decoding / rebuilding and resource extraction",
        "binaries": ["apktool"],
        "extra_dirs_env": "DFTK_APK_TOOL_DIRS",
    },
    {
        "name": "dex2jar",
        "category": "apk",
        "purpose": "Convert DEX to JAR for Java-level review",
        "binaries": ["d2j-dex2jar"],
        "extra_dirs_env": "DFTK_APK_TOOL_DIRS",
    },
    {
        "name": "tshark",
        "category": "pcap",
        "purpose": "Wireshark capture CLI for packet/HTTP analysis",
        "binaries": ["tshark"],
        "extra_dirs_env": "DFTK_PCAP_TOOL_DIRS",
    },
    {
        "name": "capinfos",
        "category": "pcap",
        "purpose": "Summarize capture file properties",
        "binaries": ["capinfos"],
        "extra_dirs_env": "DFTK_PCAP_TOOL_DIRS",
    },
    {
        "name": "wireshark",
        "category": "pcap",
        "purpose": "Wireshark GUI (rarely scriptable, presence only)",
        "binaries": ["wireshark"],
        "extra_dirs_env": "DFTK_PCAP_TOOL_DIRS",
    },
    {
        "name": "ghidra",
        "category": "reverse",
        "purpose": "Ghidra reverse-engineering suite launcher",
        "binaries": ["ghidraRun"],
        "extra_dirs_env": "DFTK_REVERSE_TOOL_DIRS",
    },
    {
        "name": "radare2",
        "category": "reverse",
        "purpose": "r2 framework for binary disassembly / scripting",
        "binaries": ["r2", "radare2"],
        "extra_dirs_env": "DFTK_REVERSE_TOOL_DIRS",
    },
    {
        "name": "volatility",
        "category": "memory",
        "purpose": "Volatility memory-image analysis",
        "binaries": ["vol", "volatility"],
        "extra_dirs_env": "DFTK_MEMORY_TOOL_DIRS",
    },
    {
        "name": "strings",
        "category": "generic",
        "purpose": "Extract printable strings from binaries",
        "binaries": ["strings"],
        "extra_dirs_env": None,
    },
    {
        "name": "file",
        "category": "generic",
        "purpose": "Determine file type by content",
        "binaries": ["file"],
        "extra_dirs_env": None,
    },
]

# Names a tool may reference in `requires` to declare an external dependency.
EXTERNAL_TOOL_NAMES: frozenset[str] = frozenset(t["name"] for t in _EXTERNAL_TOOLS)


def _resolve_binary(candidates: list[str], extra_dirs: list[str]) -> str | None:
    """Resolve the first available executable among candidates.

    PATH is always searched (covers PATHEXT variants on Windows). When a tool
    lives off PATH, the analyst points `extra_dirs_env` at its directory.
    """
    for cand in candidates:
        found = shutil.which(cand)
        if found:
            return found
    exts = (".exe", ".bat", ".cmd", ".ps1")
    for d in extra_dirs:
        if not d or not os.path.isdir(d):
            continue
        for cand in candidates:
            names = [cand] + [cand + e for e in exts if not cand.lower().endswith(e)]
            for n in names:
                fp = os.path.join(d, n)
                if os.path.isfile(fp) and os.access(fp, os.X_OK):
                    return fp
    return None


def _entry_dirs(entry: dict[str, Any]) -> list[str]:
    env = entry.get("extra_dirs_env")
    if not env:
        return []
    return [p for p in os.environ.get(env, "").split(os.pathsep) if p]


def external_tool_available(name: str) -> bool:
    """Return True if the named external tool is resolvable on this host."""
    for entry in _EXTERNAL_TOOLS:
        if entry["name"] == name:
            return _resolve_binary(entry["binaries"], _entry_dirs(entry)) is not None
    return False


def detect_external_tools() -> list[dict[str, Any]]:
    """Report which external forensic binaries are present on this host.

    Pure discovery: PATH/known-dir resolution only, no execution. Used by
    `doctor` and as the source of truth for external-dependency gating.
    """
    results: list[dict[str, Any]] = []
    for entry in _EXTERNAL_TOOLS:
        path = _resolve_binary(entry["binaries"], _entry_dirs(entry))
        results.append(
            {
                "name": entry["name"],
                "category": entry["category"],
                "purpose": entry["purpose"],
                "available": path is not None,
                "path": path,
            }
        )
    return results
