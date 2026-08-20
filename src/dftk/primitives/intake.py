# Copyright 2026 DyNooob @ DigiForensics
# Licensed under the Apache License, Version 2.0.
"""Agent-oriented, read-only evidence intake and routing."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from dftk.core.helpers import bounded_files, safe_rel
from dftk.core.models import Evidence, Observation, SafetyLevel, Status
from dftk.core.registry import registry
from dftk.core.safety import SafetyPolicy


_EXTENSION_HINTS = {
    ".apk": "apk", ".dex": "dex", ".pcap": "pcap", ".pcapng": "pcapng",
    ".sqlite": "sqlite", ".db": "sqlite", ".eml": "email", ".msg": "email",
    ".evtx": "evtx", ".e01": "ewf_e01", ".zip": "zip", ".jar": "jar_or_zip",
    ".exe": "pe", ".dll": "pe", ".so": "elf", ".elf": "elf",
}


def _route(kind: str, path: str, filename: str) -> dict[str, Any] | None:
    """Return one conservative next DFTK call for an identified artifact."""
    if kind == "apk":
        return {"tool": "recipe.android.deep_static_triage", "params": {"path": path}, "reason": "Android package"}
    if kind in {"pcap", "pcapng"}:
        return {"tool": "recipe.network.capture_triage", "params": {"path": path}, "reason": "network capture"}
    if kind == "sqlite":
        tool = "recipe.browser.history_triage" if filename.lower() in {"history", "places.sqlite"} else "recipe.database.triage"
        return {"tool": tool, "params": {"path": path}, "reason": "SQLite database"}
    if kind == "email":
        return {"tool": "recipe.email.full_offline_triage", "params": {"path": path}, "reason": "email message"}
    if kind in {"pe", "elf"}:
        return {"tool": "binary.native_indicator_scan", "params": {"path": path}, "reason": "native executable"}
    if kind == "windows_registry_hive":
        return {"tool": "windows.registry_inventory", "params": {"path": path}, "reason": "Windows Registry hive"}
    if kind == "ewf_e01":
        return {"tool": "image.e01_inventory", "params": {"path": path}, "reason": "E01/EWF image"}
    if kind in {"zip", "jar_or_zip"}:
        return {"tool": "archive.inventory", "params": {"path": path}, "reason": "archive container"}
    return None


def _directory_routes(root: Path) -> list[dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    if (root / "etc" / "os-release").is_file() or (root / "var" / "log").is_dir():
        routes.append({"tool": "recipe.server.deep_offline_triage", "params": {"root": str(root)}, "reason": "offline Linux root indicators"})
    if (root / "var" / "lib" / "docker").is_dir():
        routes.append({"tool": "docker.offline_inventory", "params": {"root": str(root)}, "reason": "offline Docker data"})
    if (root / "data" / "data").is_dir() or (root / "shared_prefs").is_dir():
        routes.append({"tool": "recipe.android.appdata_triage", "params": {"root": str(root)}, "reason": "Android app-data indicators"})
    return routes


@registry.tool(
    name="evidence.intake",
    description="Create a bounded, read-only evidence intake manifest for a file or directory and return source-linked next DFTK calls for an Agent.",
    safety=SafetyLevel.READ_ONLY,
    tags=("evidence", "intake", "triage", "agent", "forensics"),
    produces=("evidence_manifest", "triage_plan", "hash"),
    cost_hint="medium",
    parameters={
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Evidence file or extracted evidence directory."},
            "max_files": {"type": "integer", "default": 5000, "minimum": 1, "maximum": 50000},
            "inspect_limit": {"type": "integer", "default": 200, "minimum": 1, "maximum": 1000},
        },
        "required": ["path"],
    },
)
def evidence_intake(path: str, max_files: int = 5000, inspect_limit: int = 200) -> Observation:
    """Inventory evidence without extraction or mutation, then propose bounded routes."""
    source = Path(path)
    if not source.exists():
        return Observation("evidence.intake", Status.ERROR, "Evidence path not found", errors=[str(source)])
    if max_files < 1 or inspect_limit < 1:
        return Observation("evidence.intake", Status.ERROR, "Limits must be positive integers")

    root = source if source.is_dir() else source.parent
    files = list(bounded_files(source, max_files=max_files)) if source.is_dir() else [source]
    extension_counts: Counter[str] = Counter()
    kinds: Counter[str] = Counter()
    candidates: list[dict[str, Any]] = []
    evidence: list[Evidence] = []
    warnings: list[str] = []
    policy = SafetyPolicy()

    for index, item in enumerate(files):
        try:
            stat = item.stat()
        except OSError as exc:
            warnings.append(f"could not stat {item}: {exc}")
            continue
        extension = item.suffix.lower() or "<none>"
        extension_counts[extension] += 1
        hint = _EXTENSION_HINTS.get(item.suffix.lower(), "unknown")
        row: dict[str, Any] = {
            "path": str(item), "relative_path": safe_rel(item, root), "size": stat.st_size,
            "extension": extension, "kind": hint, "identified": False,
        }
        if index < inspect_limit:
            observation = registry.run("artifact.inspect", {"path": str(item)}, policy)
            if observation.status == Status.OK:
                detected_kind = observation.facts["kind"]
                row.update({
                    # A known magic/container signature outranks an extension. For
                    # text-like artifacts that magic intentionally leaves unknown,
                    # retain a conservative extension hint so an Agent can route
                    # EML/EVTX files without pretending the hint is a signature.
                    "kind": detected_kind if detected_kind != "unknown" or hint == "unknown" else hint,
                    "confidence": observation.facts["confidence"],
                    "sha256": observation.facts["sha256"], "identified": True,
                })
        kind = row["kind"]
        kinds[kind] += 1
        route = _route(kind, str(item), item.name)
        if route:
            row["next_tool"] = route["tool"]
        candidates.append(row)
        if row.get("sha256"):
            evidence.append(Evidence(
                source=str(item), kind="evidence_intake_item", value=kind,
                locator=f"path:{row['relative_path']}", source_sha256=row["sha256"],
                confidence=float(row.get("confidence", 0.0)), method="magic/container inspection",
            ))

    if source.is_dir() and len(files) >= max_files:
        warnings.append(f"file traversal limited to {max_files}; intake may not cover the complete tree")
    if len(files) > inspect_limit:
        warnings.append(f"magic inspection and SHA-256 limited to first {inspect_limit} deterministic path(s)")

    routes: list[dict[str, Any]] = _directory_routes(source) if source.is_dir() else []
    seen = {route["tool"] + repr(route["params"]) for route in routes}
    for item in candidates:
        route = _route(item["kind"], item["path"], Path(item["path"]).name)
        if route and (key := route["tool"] + repr(route["params"])) not in seen:
            routes.append(route)
            seen.add(key)
        if len(routes) >= 25:
            warnings.append("next-step plan limited to 25 calls")
            break

    facts = {
        "scope": str(source), "scope_type": "directory" if source.is_dir() else "file",
        "file_count": len(files), "inspected_files": min(len(files), inspect_limit),
        "total_size": sum(item["size"] for item in candidates),
        "extension_counts": dict(extension_counts.most_common()), "kind_counts": dict(kinds.most_common()),
        "candidates": candidates, "next_steps": routes,
    }
    return Observation(
        "evidence.intake", Status.PARTIAL if warnings else Status.OK,
        f"Created evidence intake manifest for {len(files)} file(s)", facts=facts,
        evidence=evidence[:300], warnings=warnings,
        meta={"read_only": True, "source_evidence_modified": False},
    )
