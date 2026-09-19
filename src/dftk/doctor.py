# Copyright 2026 DyNooob @ DigiForensics
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

import importlib.util
import importlib.metadata
import os
import platform
import sys
from pathlib import Path
from typing import Any

from .catalog import load_builtin_tools
from .core.external_tools import detect_external_tools, toolchain_roots, _resolve_binary
from .core.readiness import readiness_summary
from .core.registry import registry


# Host skill directories, kept in sync with cli.AGENT_SKILL_DIRS. Deliberately
# duplicated: importing cli from doctor would risk an import cycle (cli imports
# doctor lazily inside _cmd_doctor, but a top-level cli import here would pull the
# whole CLI module whenever doctor is imported).
_AGENT_SKILL_DIRS = {
    "workbuddy": ".workbuddy/skills",
    "codebuddy": ".codebuddy/skills",
    "kimi": ".kimi-code/skills",
    "claude": ".claude/skills",
    "codex": ".codex/skills",
    "hermes": ".hermes/skills",
    "agents": ".agents/skills",
    "cursor": ".cursor/skills",
    "gemini": ".gemini/skills",
}

# (host, env_var, value_substring); substring None means "env var present".
_HOST_MARKERS = [
    ("workbuddy", "WORKBUDDY_PRODUCT_NAME", "workbuddy"),
    ("workbuddy", "CODEBUDDY_HOST", "workbuddy"),
    ("codebuddy", "CODEBUDDY_HOST", "codebuddy"),
    ("kimi", "KIMI_CODE_HOST", "kimi"),
    ("claude", "CLAUDE_CODE", None),
    ("claude", "CLAUDECODE", None),
    ("codex", "CODEX_HOME", None),
    ("hermes", "HERMES_HOST", None),
    ("agents", "AGENTS_HOST", None),
    ("cursor", "CURSOR_TRACE_ID", None),
    ("gemini", "GEMINI_CLI", None),
]


def _current_agent_host() -> str | None:
    """Best-effort detection of the Agent host driving this dftk invocation."""
    for host, env_var, substring in _HOST_MARKERS:
        value = os.environ.get(env_var)
        if not value:
            continue
        if substring is None or substring in value.lower():
            return host
    return None


def _skill_install_status(home: Path | None = None) -> dict[str, Any]:
    """Report whether the main dftk skill is installed at the expected location.

    Detects the active Agent host, then checks whether ``dftk/SKILL.md`` exists
    in that host's skills directory and whether it was mistakenly placed in a
    different host directory (the bug fixed in cli._resolve_targets, surfaced
    here so stale installs are caught).
    """
    home = home or Path.home()
    expected_host = _current_agent_host()
    expected_dir = home / _AGENT_SKILL_DIRS[expected_host] if expected_host else None
    found_at = []
    for host, relative in _AGENT_SKILL_DIRS.items():
        if (home / relative / "dftk" / "SKILL.md").exists():
            found_at.append(host)
    installed_here = bool(
        expected_dir and (expected_dir / "dftk" / "SKILL.md").exists()
    )
    misplaced = bool(expected_host is not None and found_at and not installed_here)
    return {
        "expected_host": expected_host,
        "expected_dir": str(expected_dir) if expected_dir else None,
        "installed": installed_here,
        "found_at": found_at,
        "misplaced": misplaced,
    }


def _mcp_version_supported(installed: str | None) -> bool:
    """True when the installed ``mcp`` SDK is in the supported 2.x line.

    DFTK is validated against mcp 2.0.0 but tracks the 2.x series, so any
    2.y.z release is accepted; 1.x is too old and 3.x is unvalidated.
    """
    if not installed:
        return False
    try:
        major = int(installed.split(".")[0])
    except (ValueError, IndexError):
        return False
    return major == 2


_OPTIONAL_IMPORTS = {
    "ssh:paramiko": "paramiko",
    "malware:yara": "yara",
    "windows:registry": "Registry",
    "windows:evtx": "Evtx",
    "email:dkim": "dkim",
    "email:dns": "dns",
    "email:spf": "spf",
    "disk:pyewf": "pyewf",
    "disk:pytsk3": "pytsk3",
}


def _dist_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None



def doctor_report() -> dict[str, Any]:
    """Return deterministic environment and capability health information.

    ``ok`` is derived from the actual environment (registry loaded, MCP SDK
    version compatible) rather than a constant. Non-fatal gaps are surfaced
    under ``warnings`` so callers and humans can act on them.
    """
    load_builtin_tools()
    specs = list(registry.specs())
    readiness = readiness_summary(specs)
    safety_counts: dict[str, int] = {}
    network_tools = 0
    for spec in specs:
        name = getattr(getattr(spec, "safety", None), "name", "UNKNOWN")
        safety_counts[name] = safety_counts.get(name, 0) + 1
        if bool(getattr(spec, "network", False)):
            network_tools += 1

    optional: dict[str, dict[str, Any]] = {}
    optional_missing = []
    for label, module in _OPTIONAL_IMPORTS.items():
        try:
            available = importlib.util.find_spec(module) is not None
        except (ImportError, AttributeError, ValueError):
            available = False
        optional[label] = {"available": available}
        if not available:
            optional_missing.append(label)

    try:
        from . import __version__ as toolkit_version
    except Exception:
        toolkit_version = _dist_version("dftk") or "unknown"

    mcp_version = _dist_version("mcp")
    mcp_installed = mcp_version is not None
    mcp_ready = _mcp_version_supported(mcp_version)
    external = detect_external_tools()
    external_available = sum(1 for t in external if t["available"])
    external_missing = [t["name"] for t in external if not t["available"]]
    toolchain = toolchain_roots()
    skill_install = _skill_install_status()

    warnings = []
    if not mcp_installed:
        warnings.append({
            "code": "mcp-not-installed",
            "detail": "Agent MCP tool surface is unavailable.",
            "remediation": 'pip install "dftk[mcp]"',
        })
    if optional_missing:
        warnings.append({
            "code": "optional-missing",
            "detail": "Optional Python integrations are not importable.",
            "items": optional_missing,
        })
    if external_missing:
        warnings.append({
            "code": "external-missing",
            "detail": "Some external forensic tools are not discoverable on PATH.",
            "items": external_missing,
        })
    if skill_install["expected_host"] is not None and not skill_install["installed"]:
        warnings.append({
            "code": "skill-not-installed",
            "detail": (
                f"DFTK skill is not installed for the detected host "
                f"'{skill_install['expected_host']}'."
            ),
            "expected_dir": skill_install["expected_dir"],
            "remediation": "dftk skill --install",
        })
    if skill_install["misplaced"]:
        target = skill_install["expected_host"] or "workbuddy"
        warnings.append({
            "code": "skill-misplaced",
            "detail": (
                "DFTK skill is installed in a non-default host directory; the "
                "active Agent host will not load it."
            ),
            "found_at": skill_install["found_at"],
            "expected_dir": skill_install["expected_dir"],
            "remediation": f"dftk skill --install --target {target}",
        })

    # Always-on chain-of-custody ledger: if DFTK_AUDIT_LOG is configured but the
    # ledger cannot be opened, or it has started dropping records, the audit trail
    # is silently incomplete. Surface that before the analyst trusts a missing log.
    audit_env = os.environ.get("DFTK_AUDIT_LOG")
    if audit_env:
        from .core.audit import _DEFAULT_AUDIT_LOG_ERROR, _get_default_audit_log

        audit_log = _get_default_audit_log()
        if audit_log is None:
            detail = _DEFAULT_AUDIT_LOG_ERROR or (
                f"always-on audit ledger at {audit_env!r} could not be opened"
            )
            warnings.append({
                "code": "audit-ledger-unavailable",
                "detail": detail,
                "remediation": "point DFTK_AUDIT_LOG at a writable path,"
                " or unset it to disable the always-on ledger",
            })
        elif audit_log.dropped:
            warnings.append({
                "code": "audit-ledger-dropping",
                "detail": (
                    f"audit ledger at {audit_log.path!r} dropped "
                    f"{audit_log.dropped} record(s): {audit_log.last_error}"
                ),
                "remediation": "check disk space and ledger path permissions",
            })

    ok = bool(specs) and (not mcp_installed or mcp_ready)
    return {
        "ok": ok,
        "toolkit": "dftk",
        "version": toolkit_version,
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "executable": sys.executable,
        "capabilities": {
            "tools": len(specs),
            "safety": safety_counts,
            "network_declared": network_tools,
        },
        "readiness": readiness,
        "mcp": {
            "installed": mcp_installed,
            "version": mcp_version,
            "supported_version": ">=2.0.0,<3",
            "ready": mcp_ready,
        },
        "optional": optional,
        "external": {
            "available": external_available,
            "total": len(external),
            "tools": external,
        },
        "toolchain": {
            "toolkit_root": toolchain["toolkit_root"],
            "bin_dir": toolchain["bin_dir"],
        },
        "skill_install": skill_install,
        "warnings": warnings,
    }
