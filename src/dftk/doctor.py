# Copyright 2026 DyNooob @ DigiForensics
# Licensed under the Apache License, Version 2.0.
from __future__ import annotations

import importlib.util
import importlib.metadata
import platform
import sys
from typing import Any

from .catalog import load_builtin_tools
from .core.external_tools import detect_external_tools, toolchain_roots, _resolve_binary
from .core.registry import registry


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
    """Return deterministic environment and capability health information."""
    load_builtin_tools()
    specs = list(registry.specs())
    safety_counts: dict[str, int] = {}
    network_tools = 0
    for spec in specs:
        name = getattr(getattr(spec, "safety", None), "name", "UNKNOWN")
        safety_counts[name] = safety_counts.get(name, 0) + 1
        if bool(getattr(spec, "network", False)):
            network_tools += 1

    optional: dict[str, dict[str, Any]] = {}
    for label, module in _OPTIONAL_IMPORTS.items():
        try:
            available = importlib.util.find_spec(module) is not None
        except (ImportError, AttributeError, ValueError):
            available = False
        optional[label] = {"available": available}

    try:
        from . import __version__ as toolkit_version
    except Exception:
        toolkit_version = _dist_version("dftk") or "unknown"

    mcp_version = _dist_version("mcp")
    external = detect_external_tools()
    external_available = sum(1 for t in external if t["available"])
    toolchain = toolchain_roots()
    return {
        "ok": True,
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
        "mcp": {
            "installed": mcp_version is not None,
            "version": mcp_version,
            "supported_version": ">=2.0.0,<3",
            "ready": _mcp_version_supported(mcp_version),
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
    }
