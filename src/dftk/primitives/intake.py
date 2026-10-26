# Copyright 2026 DyNooob @ DigiForensics
# Licensed under the Apache License, Version 2.0.
"""Agent-oriented, read-only evidence intake and routing."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from dftk.core.helpers import bounded_files, safe_rel, TraversalReport
from dftk.core.models import Evidence, Observation, SafetyLevel, Status
from dftk.core.registry import registry
from dftk.core.safety import SafetyPolicy
from dftk.core.media_types import IMAGE_EXTENSIONS, VIDEO_EXTENSIONS, media_type


_EXTENSION_HINTS = {
    ".apk": "apk", ".dex": "dex", ".pcap": "pcap", ".pcapng": "pcapng",
    ".sqlite": "sqlite", ".db": "sqlite", ".eml": "email", ".msg": "email",
    ".evtx": "evtx", ".e01": "ewf_e01", ".zip": "zip", ".jar": "jar_or_zip",
    ".exe": "pe", ".dll": "pe", ".so": "elf", ".elf": "elf",
}
_EXTENSION_HINTS.update({suffix: 'image_hint' for suffix in IMAGE_EXTENSIONS})
_EXTENSION_HINTS.update({suffix: 'video_hint' for suffix in VIDEO_EXTENSIONS})
_EXTENSION_HINTS.update({'.enc': 'encrypted_hint', '.7z': '7z', '.rar': 'rar', '.tar': 'tar', '.tgz': 'gzip'})


def _route(kind: str, path: str, filename: str) -> dict[str, Any] | None:
    """Return one conservative next DFTK call for an identified artifact."""
    if media_type(kind, filename):
        return {'tool': 'media.inspect', 'params': {'path': path}, 'reason': 'media metadata only; visual content requires user consent and a capable model'}
    if kind == "apk":
        return {"tool": "recipe.android.deep_static_triage", "params": {"path": path}, "reason": "Android package"}
    if kind in {"pcap", "pcapng"}:
        return {"tool": "recipe.network.capture_triage", "params": {"path": path}, "reason": "network capture"}
    if kind == "sqlite_wal":
        return {"tool": "database.sqlite_wal", "params": {"wal_path": path}, "reason": "SQLite transaction WAL"}
    if kind == "sqlite":
        tool = "recipe.browser.history_triage" if filename.lower() in {"history", "places.sqlite"} else "recipe.database.triage"
        return {"tool": tool, "params": {"path": path}, "reason": "SQLite database"}
    if kind == "email":
        return {"tool": "recipe.email.full_offline_triage", "params": {"path": path}, "reason": "email message"}
    if kind in {"pe", "elf"}:
        return {"tool": "binary.native_indicator_scan", "params": {"path": path}, "reason": "native executable"}
    if kind in {"macho", "macho_universal"}:
        return {"tool": "binary.macho_inventory", "params": {"path": path}, "reason": "Mach-O executable"}
    if kind == "windows_registry_hive":
        return {"tool": "windows.registry_inventory", "params": {"path": path}, "reason": "Windows Registry hive"}
    if kind == "ewf_e01":
        return {"tool": "image.e01_inventory", "params": {"path": path}, "reason": "E01/EWF image"}
    if kind in {"zip", "jar_or_zip", "tar", "gzip"}:
        return {"tool": "archive.inventory", "params": {"path": path}, "reason": "archive container"}
    if kind == 'evtx':
        return {'tool': 'windows.evtx_summary', 'params': {'path': path}, 'reason': 'Windows event log'}
    if Path(filename).suffix.lower() in {'.txt', '.log', '.json', '.xml', '.csv', '.ini', '.conf', '.env', '.yaml', '.yml', '.md'}:
        return {'tool': 'file.read_text', 'params': {'path': path}, 'reason': 'bounded text window; follow continuation if needed'}
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
            "offset": {"type": "integer", "default": 0, "minimum": 0, "maximum": 1000000},
        },
        "required": ["path"],
    },
)
def evidence_intake(path: str, max_files: int = 5000, inspect_limit: int = 200, offset: int = 0) -> Observation:
    """Inventory evidence without extraction or mutation, then propose bounded routes."""
    source = Path(path)
    if not source.exists():
        return Observation("evidence.intake", Status.ERROR, "Evidence path not found", errors=[str(source)])
    if max_files < 1 or inspect_limit < 1:
        return Observation("evidence.intake", Status.ERROR, "Limits must be positive integers")

    root = source if source.is_dir() else source.parent
    traversal = TraversalReport()
    files = list(bounded_files(source, max_files=offset + max_files, report=traversal))[offset:] if source.is_dir() else [source]
    extension_counts: Counter[str] = Counter()
    kinds: Counter[str] = Counter()
    candidates: list[dict[str, Any]] = []
    evidence: list[Evidence] = []
    warnings: list[str] = []
    policy = SafetyPolicy()
    attempted = inspected = failed_stats = 0
    inspection_failures: list[dict[str, Any]] = []

    for index, item in enumerate(files):
        try:
            stat = item.stat()
        except OSError as exc:
            failed_stats += 1
            warnings.append(f"could not stat {item}: {exc}")
            continue
        extension = item.suffix.lower() or "<none>"
        extension_counts[extension] += 1
        hint = _EXTENSION_HINTS.get(item.suffix.lower(), "unknown")
        row: dict[str, Any] = {
            "path": str(item), "relative_path": safe_rel(item, root), "size": stat.st_size,
            "extension": extension, "kind": hint, "identified": False,
            "inspected": False, "inspection_status": "not_attempted",
            "identification_basis": "extension_hint" if hint != "unknown" else "unknown",
        }
        if index < inspect_limit:
            attempted += 1
            observation = registry.run("artifact.inspect", {"path": str(item)}, policy)
            row["inspection_status"] = observation.status.value
            if observation.status == Status.OK:
                inspected += 1
                detected_kind = observation.facts["kind"]
                row.update({
                    # A known magic/container signature outranks an extension. For
                    # text-like artifacts that magic intentionally leaves unknown,
                    # retain a conservative extension hint so an Agent can route
                    # EML/EVTX files without pretending the hint is a signature.
                    "kind": detected_kind if detected_kind != "unknown" or hint == "unknown" else hint,
                    "confidence": observation.facts["confidence"],
                    "sha256": observation.facts["sha256"], "inspected": True,
                    "identified": detected_kind != "unknown",
                    "identification_basis": "signature" if detected_kind != "unknown" else row["identification_basis"],
                })
            else:
                inspection_failures.append({"path": str(item), "status": observation.status.value,
                                            "errors": observation.errors, "warnings": observation.warnings})
                warnings.append(f"inspection failed for {item}: {observation.status.value}")
            warnings.extend(f"{item}: {warning}" for warning in observation.warnings)
        kind = row["kind"]
        row['content_examined'] = False
        if category := media_type(kind, item.name):
            row.update(media_type=category, review_state='awaiting_visual_consent_or_local_ocr')
        elif kind in {'openssl_salted', 'encrypted_hint'}:
            row.update(review_state='encrypted_content_unread', encryption_basis='signature' if kind == 'openssl_salted' else 'extension_hint')
        elif kind in {'7z', 'rar'}:
            row.update(review_state='container_parser_unavailable')
        elif not row['inspected']:
            row['review_state'] = 'not_inspected'
        elif kind == 'unknown':
            row['review_state'] = 'unclassified'
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

    if traversal.truncated:
        warnings.append(f"file traversal limited to {max_files}; intake may not cover the complete tree")
    if traversal.errors:
        warnings.append(f"{len(traversal.errors)} traversal error(s); some paths were not inventoried")
    if traversal.skipped_symlinks:
        warnings.append(f"{traversal.skipped_symlinks} symlink(s) excluded; linked evidence was not examined")
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

    if len(evidence) > 300:
        warnings.append("evidence item list limited to 300; full per-file hashes remain in candidates")

    facts = {
        "scope": str(source), "scope_type": "directory" if source.is_dir() else "file",
        "file_count": len(files), "inspected_files": inspected,
        "inspection_attempted": attempted, "inspection_failures": inspection_failures,
        "coverage": {"traversal": traversal.to_dict() if source.is_dir() else {"complete": True},
                     "stat_failures": failed_stats, "uninspected_files": len(files) - inspected,
                     "inspection_complete": inspected == len(files) and not failed_stats,
                     "plan_truncated": any("next-step plan limited" in warning for warning in warnings),
                     "evidence_items_omitted": max(0, len(evidence) - 300)},
        "total_size": sum(item["size"] for item in candidates),
        "extension_counts": dict(extension_counts.most_common()), "kind_counts": dict(kinds.most_common()),
        "candidates": candidates, "next_steps": routes,
        "offset": offset,
        "next_offset": offset + len(files) if traversal.truncated else None,
        "next_inspection": {'tool': 'evidence.intake', 'params': {'path': path, 'offset': offset + inspect_limit, 'max_files': inspect_limit, 'inspect_limit': inspect_limit}} if len(files) > inspect_limit else None,
        "media_found": [row['path'] for row in candidates if row.get('media_type')],
        "unread_content": [{'path': row['path'], 'reason': row['review_state']} for row in candidates if row.get('review_state')],
    }
    return Observation(
        "evidence.intake", Status.PARTIAL if warnings else Status.OK,
        f"Created evidence intake manifest for {len(files)} file(s)", facts=facts,
        evidence=evidence[:300], warnings=warnings,
        meta={"read_only": True, "source_evidence_modified": False},
    )
