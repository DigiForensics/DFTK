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

Resolution order for each tool (first hit wins):

1. PATH (covers PATHEXT variants on Windows);
2. the per-category env var named in the tool entry (`DFTK_APK_TOOL_DIRS`, …);
3. a single unified toolkit root from ``$DFTK_TOOLS`` or the config written by
   ``dftk prepare`` — searched directly, under ``<root>/bin``, ``<root>/<name>``
   and ``<root>/<category>``. This is what makes tools discoverable even when
   they live off PATH on an exotic / non-readable drive;
4. the DFTK-managed shim directory written by ``dftk prepare`` (always under the
   user home, so it is readable by the agent regardless of the toolkit drive).

The discovery is pure: PATH/known-dir resolution only, no execution. Used by
`doctor` and as the source of truth for external-dependency gating.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
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

# Human-readable labels for the `source` field reported by detection.
_SOURCE_LABELS = {
    "PATH": "PATH",
    "env": "DFTK_*_TOOL_DIRS",
    "dftk_tools": "DFTK_TOOLS / dftk prepare root",
    "dftk_shims": "dftk prepare shims",
}


def _toolchain_config() -> dict[str, Any]:
    """Load the persistent toolchain config written by ``dftk prepare``.

    Search order: explicit ``$DFTK_TOOLCHAIN_CONFIG`` → ``./.dftk/toolchain.json``
    (case-local) → ``~/.dftk/toolchain.json`` (persistent, agent-readable). The
    last location is always under the user home, so the agent can read it even
    when the toolkit itself lives on an exotic / non-PATH drive.
    """
    candidates: list[Path] = []
    env_cfg = os.environ.get("DFTK_TOOLCHAIN_CONFIG")
    if env_cfg:
        candidates.append(Path(env_cfg))
    candidates.append(Path.cwd() / ".dftk" / "toolchain.json")
    candidates.append(Path.home() / ".dftk" / "toolchain.json")
    for p in candidates:
        try:
            if p.is_file():
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
        except (OSError, ValueError):
            continue
    return {}


def toolchain_roots() -> dict[str, str]:
    """Return the active toolkit root and shim dir (empty strings if unset)."""
    roots: dict[str, str] = {"toolkit_root": "", "bin_dir": ""}
    cfg = _toolchain_config()
    ut = os.environ.get("DFTK_TOOLS")
    if ut:
        roots["toolkit_root"] = ut
    if cfg.get("toolkit_root"):
        roots["toolkit_root"] = cfg["toolkit_root"]
    if cfg.get("bin_dir"):
        roots["bin_dir"] = cfg["bin_dir"]
    return roots


def _entry_dirs(entry: dict[str, Any]) -> list[str]:
    env = entry.get("extra_dirs_env")
    if not env:
        return []
    return [p for p in os.environ.get(env, "").split(os.pathsep) if p]


def _tagged_search_dirs(entry: dict[str, Any]) -> list[tuple[str, str]]:
    """Directories to scan for a tool, each tagged with its discovery source."""
    tagged: list[tuple[str, str]] = []
    for d in _entry_dirs(entry):
        tagged.append((d, "env"))
    roots: list[tuple[str, str]] = []
    ut = os.environ.get("DFTK_TOOLS")
    if ut:
        roots.append(("toolkit_root", ut))
    cfg = _toolchain_config()
    if cfg.get("toolkit_root"):
        roots.append(("toolkit_root", cfg["toolkit_root"]))
    if cfg.get("bin_dir"):
        roots.append(("shims", cfg["bin_dir"]))
    for label, r in roots:
        r = (r or "").rstrip("/\\")
        if not r or not os.path.isdir(r):
            continue
        source = "dftk_shims" if label == "shims" else "dftk_tools"
        tagged.append((r, source))
        tagged.append((os.path.join(r, "bin"), source))
        tagged.append((os.path.join(r, entry["name"]), "dftk_tools"))
        tagged.append((os.path.join(r, entry["category"]), "dftk_tools"))
    return tagged


def _resolve_binary(
    candidates: list[str], dirs: list[str] | list[tuple[str, str]]
) -> tuple[str | None, str | None]:
    """Resolve the first available executable among candidates.

    ``dirs`` may be a plain list of directory strings (legacy) or a list of
    ``(dir, source)`` tuples (tagged). Returns ``(path, source)``; ``source`` is
    ``None`` when nothing was found. PATH is always searched first (PATHEXT on
    Windows); then the provided dirs.
    """
    tagged: list[tuple[str, str]]
    if dirs and isinstance(dirs[0], tuple):
        tagged = [tuple(d) for d in dirs]  # type: ignore[misc]
    else:
        tagged = [(d, "env") for d in dirs]  # type: ignore[assignment]

    for cand in candidates:
        found = shutil.which(cand)
        if found:
            return found, "PATH"

    exts = (".exe", ".bat", ".cmd", ".ps1")
    for d, source in tagged:
        if not d or not os.path.isdir(d):
            continue
        for cand in candidates:
            names = [cand] + [cand + e for e in exts if not cand.lower().endswith(e)]
            for n in names:
                fp = os.path.join(d, n)
                if os.path.isfile(fp) and os.access(fp, os.X_OK):
                    return fp, source
    return None, None


def external_tool_available(name: str) -> bool:
    """Return True if the named external tool is resolvable on this host."""
    for entry in _EXTERNAL_TOOLS:
        if entry["name"] == name:
            path, _ = _resolve_binary(entry["binaries"], _tagged_search_dirs(entry))
            return path is not None
    return False


def resolve_external_tool(name: str) -> str | None:
    """Return the absolute path to the named external tool, or None if absent.

    Use this inside a tool body that needs to invoke the binary, instead of
    re-implementing PATH / DFTK_TOOLS / shim-dir discovery.
    """
    for entry in _EXTERNAL_TOOLS:
        if entry["name"] == name:
            path, _ = _resolve_binary(entry["binaries"], _tagged_search_dirs(entry))
            return path
    return None


def external_tool_source(name: str) -> str | None:
    """Return where a tool was resolved from (PATH / env / dftk_tools / dftk_shims)."""
    for entry in _EXTERNAL_TOOLS:
        if entry["name"] == name:
            _, src = _resolve_binary(entry["binaries"], _tagged_search_dirs(entry))
            return _SOURCE_LABELS.get(src, src)
    return None


def detect_external_tools() -> list[dict[str, Any]]:
    """Report which external forensic binaries are present on this host.

    Pure discovery: PATH/known-dir resolution only, no execution. Used by
    `doctor` and as the source of truth for external-dependency gating.
    """
    results: list[dict[str, Any]] = []
    for entry in _EXTERNAL_TOOLS:
        path, src = _resolve_binary(entry["binaries"], _tagged_search_dirs(entry))
        results.append(
            {
                "name": entry["name"],
                "category": entry["category"],
                "purpose": entry["purpose"],
                "available": path is not None,
                "path": path,
                "source": _SOURCE_LABELS.get(src, src) if path else None,
            }
        )
    return results
