"""Versioned capability-manifest contract for DFTK integrations."""
from __future__ import annotations

from collections import Counter
from typing import Any

from . import __version__ as TOOLKIT_VERSION
from .catalog import load_builtin_tools
from .core.registry import registry


MANIFEST_SCHEMA_VERSION = "3"


def capability_manifest() -> dict[str, Any]:
    """Return the deterministic, agent-readable description of registered tools."""
    load_builtin_tools()
    tools = []
    safety = Counter()
    domains = Counter()
    for spec in registry.specs():
        safety[spec.safety.name] += 1
        domains[spec.name.split(".", 1)[0]] += 1
        tools.append(
            {
                "name": spec.name,
                "description": spec.description,
                "safety": spec.safety.name,
                "network": spec.network,
                "parameters": spec.parameters,
                "tags": list(spec.tags),
                "produces": list(spec.produces),
                "requires": list(spec.requires),
                "deterministic": spec.deterministic,
                "cost_hint": spec.cost_hint,
            }
        )
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "toolkit_version": TOOLKIT_VERSION,
        "tool_count": len(tools),
        "safety_counts": dict(sorted(safety.items())),
        "domain_counts": dict(sorted(domains.items())),
        "tools": tools,
    }
