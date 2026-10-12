# Copyright 2026 DyNooob @ DigiForensics
# Licensed under the Apache License, Version 2.0.
"""Agent-native capability suggestion: "what can I do with this evidence?".

An LLM Agent that is handed a piece of evidence (a file path, a bare
forensic filename such as ``$MFT``, or an evidence *kind* such as ``tls`` /
``registry``) needs a single entry point that answers: "which DFTK
capabilities apply here, and why?". This module is that entry point. It is a
thin, dependency-free relevance layer over the live :class:`ToolRegistry`, so
it stays correct as tools are added or renamed -- nothing here is hard-coded
to a specific tool name.

Two query directions are supported:

* ``consume`` (default): tools that can *operate on* the given input --
  i.e. the analyst handed you an ``.evtx`` and wants to know which tools
  ingest Windows event logs.
* ``produce``: tools that can *emit* the given evidence kind -- i.e. "which capabilities declare TLS evidence outputs?".

Matching is deliberately layered and explained: every returned tool carries a
``why`` string so the Agent (and a human reviewer) can see *why* it was
suggested, rather than trusting an opaque score.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .core.registry import ToolRegistry, registry
from .core.safety import SafetyPolicy

# File extension -> forensic evidence kind(s). Order does not matter; ranking
# is by match specificity later.
_EXTENSION_KINDS: dict[str, list[str]] = {
    ".pcap": ["pcap", "network", "capture"],
    ".pcapng": ["pcap", "network", "capture"],
    ".cap": ["pcap", "network"],
    ".evtx": ["evtx", "windows_event", "windows"],
    ".mft": ["mft", "filesystem", "ntfs"],
    ".hve": ["registry", "amcache", "windows"],
    ".reg": ["registry", "windows"],
    ".lnk": ["lnk", "windows", "shortcut"],
    ".pf": ["prefetch", "windows"],
    ".wal": ["sqlite", "wal", "database"],
    ".prefetch": ["prefetch", "windows"],
    ".sqlite": ["sqlite", "database"],
    ".sqlite3": ["sqlite", "database"],
    ".db": ["sqlite", "database"],
    ".apk": ["apk", "android", "archive"],
    ".dex": ["dex", "android"],
    ".dylib": ["macho", "macos", "binary"],
    ".macho": ["macho", "macos", "binary"],
    ".elf": ["elf", "binary", "linux"],
    ".exe": ["pe", "binary", "windows"],
    ".dll": ["pe", "binary", "windows"],
    ".sys": ["pe", "binary", "windows"],
    ".pe": ["pe", "binary"],
    ".raw": ["memory", "disk", "image"],
    ".dd": ["disk", "image"],
    ".img": ["disk", "image"],
    ".e01": ["disk", "image", "ewf"],
    ".aff": ["disk", "image"],
    ".vmdk": ["disk", "image", "vmware"],
    ".vhdx": ["disk", "image"],
    ".vhd": ["disk", "image"],
    ".qcow2": ["disk", "image"],
    ".pdf": ["pdf", "doc"],
    ".eml": ["email", "mime"],
    ".msg": ["email", "outlook"],
    ".pst": ["email", "outlook"],
    ".mbox": ["email"],
    ".har": ["http", "har", "json"],
    ".json": ["json"],
    ".jsonl": ["json", "log"],
    ".ndjson": ["json", "log"],
    ".csv": ["csv"],
    ".tsv": ["csv"],
    ".plist": ["plist", "macos"],
    ".lock": ["browser", "chromium"],
    ".zip": ["archive"],
    ".gz": ["archive"],
    ".tar": ["archive"],
    ".tgz": ["archive"],
    ".7z": ["archive"],
}

# Well-known forensic basenames (case-insensitive) -> kind(s). These catch the
# extension-less carves that are bread-and-butter in real investigations.
_WELLKNOWN: dict[str, list[str]] = {
    "$mft": ["mft", "filesystem", "ntfs"],
    "$j": ["usnjrnl", "usn", "filesystem", "ntfs"],
    "$logfile": ["logfile", "ntfs"],
    "$bitmap": ["bitmap", "ntfs"],
    "$boot": ["boot", "ntfs"],
    "$secure": ["secure", "ntfs"],
    "$extent": ["extent", "ntfs"],
    "$attrdef": ["attrdef", "ntfs"],
    "amcache.hve": ["amcache", "registry", "windows"],
    "system": ["registry", "windows"],
    "software": ["registry", "windows"],
    "security": ["registry", "windows"],
    "sam": ["registry", "windows"],
    "ntuser.dat": ["registry", "windows"],
    "usrclass.dat": ["registry", "windows"],
    "pagefile.sys": ["memory", "windows"],
    "hiberfil.sys": ["memory", "windows"],
    "swapfile.sys": ["memory", "windows"],
    "index.dat": ["browser", "ie"],
    "webcachev01.dat": ["browser", "ie"],
    "webcachev01": ["browser", "ie"],
    "history": ["history", "browser", "chromium", "sqlite"],
    "cookies": ["cookies", "browser", "chromium", "sqlite"],
    "places.sqlite": ["history", "browser", "firefox", "sqlite"],
    "cookies.sqlite": ["cookies", "browser", "firefox", "sqlite"],
    "favicons.sqlite": ["browser", "firefox"],
    "formhistory.sqlite": ["browser", "firefox"],
    "downloads.sqlite": ["browser", "firefox"],
    "login data": ["browser", "chromium", "credentials"],
    "web data": ["browser", "chromium"],
    "bookmarks": ["bookmarks", "browser", "chromium"],
    "bookmarks.bak": ["bookmarks", "browser", "chromium"],
    "prefetch": ["prefetch", "windows"],
    "recentfilecache.bcf": ["shimcache", "windows"],
    "srudb.dat": ["srum", "windows"],
    "activitiescache.db": ["timeline", "windows"],
}

# Magic-byte signatures -> kind(s). Best-effort: only consulted when the path
# is actually readable, so a planning Agent can still query a not-yet-fetched
# path. Carved evidence frequently has no extension, so this matters.
_MAGIC_KINDS: list[tuple[bytes, int, list[str]]] = [
    (b'\xce\xfa\xed\xfe', 0, ["macho", "macos", "binary"]),
    (b'\xfe\xed\xfa\xce', 0, ["macho", "macos", "binary"]),
    (b'\xcf\xfa\xed\xfe', 0, ["macho", "macos", "binary"]),
    (b'\xfe\xed\xfa\xcf', 0, ["macho", "macos", "binary"]),
    (b'\xca\xfe\xba\xbe', 0, ["macho", "macos", "binary"]),
    (b'\xbe\xba\xfe\xca', 0, ["macho", "macos", "binary"]),
    (b'\xca\xfe\xba\xbf', 0, ["macho", "macos", "binary"]),
    (b'\xbf\xba\xfe\xca', 0, ["macho", "macos", "binary"]),
    (b"MZ", 0, ["pe", "binary", "windows"]),
    (b"\x7fELF", 0, ["elf", "binary", "linux"]),
    (b"PK\x03\x04", 0, ["archive", "zip"]),
    (b"PK\x05\x06", 0, ["archive", "zip"]),
    (b"PK\x07\x08", 0, ["archive", "zip"]),
    (b"SQLite format 3\x00", 0, ["sqlite", "database"]),
    (b"%PDF-", 0, ["pdf", "doc"]),
    (b"OggS", 0, ["media", "ogg"]),
    (b"\x1f\x8b", 0, ["archive", "gzip"]),
    (b"DICM", 128, ["dicom", "medical"]),
    (b"PAR1", 0, ["parquet"]),
    (b"\x89PNG\r\n\x1a\n", 0, ["image", "png"]),
    (b"\xff\xd8\xff", 0, ["image", "jpeg"]),
    (b"BM", 0, ["image", "bmp"]),
    (b"GIF8", 0, ["image", "gif"]),
    (b"RIFF", 0, ["media", "riff"]),
    (b"regf", 0, ["registry", "windows"]),
    (b"ElfFile\x00", 0, ["evtx", "windows_event", "windows"]),
    (b"dex\n", 0, ["dex", "android"]),
    (b"SCCA", 4, ["prefetch", "windows"]),
    (b"MAM\x04", 0, ["prefetch", "windows"]),
    (b"FILE", 0, ["mft", "ntfs", "filesystem"]),
    (b"EVF\x09\x0d\x0a\xff\x00", 0, ["e01", "ewf", "disk"]),
    (b"\xd4\xc3\xb2\xa1", 0, ["pcap", "capture", "network"]),
    (b"\xa1\xb2\xc3\xd4", 0, ["pcap", "capture", "network"]),
    (b"\x4d\x3c\xb2\xa1", 0, ["pcap", "capture", "network"]),
    (b"\xa1\xb2\x3c\x4d", 0, ["pcap", "capture", "network"]),
    (b"\x0a\x0d\x0d\x0a", 0, ["pcapng", "pcap", "capture", "network"]),
]

_BROAD_KINDS = {"windows", "linux", "android", "binary", "network", "database", "filesystem", "image", "archive"}


def _tokens(text: str) -> set[str]:
    words = set(re.findall(r"[a-z0-9]+(?:_[a-z0-9]+)*", text.lower()))
    return words | {part for word in words for part in word.split("_")}


def _magic_kinds(path: Path) -> list[str]:
    """Read at most 4096 bytes from a regular file, never a pipe/device."""
    import os
    import stat

    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                return []
            head = fh.read(4096)
    except OSError:
        return []
    return list(dict.fromkeys(kind for sig, offset, kinds in _MAGIC_KINDS
                              if head[offset:offset + len(sig)] == sig for kind in kinds))


def _is_path_like(query: str) -> bool:
    return "/" in query or "\\" in query or "." in query or bool(re.match(r"^[a-zA-Z]:", query))


def suggest(
    query: str,
    *,
    direction: str = "consume",
    limit: int = 12,
    registry_ref: ToolRegistry | None = None,
    evidence_root: Path | None = None,
    policy: SafetyPolicy | None = None,
) -> dict[str, Any]:
    """Rank candidate capabilities, without executing them.

    Consume uses names/tags/descriptions as input hints (not proof of format
    support). Produce matches declared output kinds only, and never probes files.
    A configured evidence_root confines even optional header probes. Missing paths
    still allow name-based planning. Policy eligibility does not check dependencies.
    """
    def error(message: str) -> dict[str, Any]:
        return {"ok": False, "error": message, "results": []}

    if not isinstance(query, str) or not query.strip():
        return error("query must be a non-empty string")
    query = query.strip()
    if len(query) > 4096 or "\x00" in query:
        return error("query is too long or contains a NUL byte")
    if direction not in {"consume", "produce"}:
        return error("direction must be 'consume' or 'produce'")
    try:
        limit = min(max(1, int(limit)), 50)
    except (TypeError, ValueError, OverflowError):
        return error("limit must be an integer")
    if registry_ref is None:
        from .catalog import load_builtin_tools
        load_builtin_tools()
    reg = registry if registry_ref is None else registry_ref
    specs = reg.specs()

    bare = re.split(r"[/\\]", query)[-1].lower()
    suffix = Path(bare).suffix
    hints: list[tuple[str, str, list[str]]] = []
    warnings: list[str] = []
    if direction == "consume":
        if bare in _WELLKNOWN:
            hints.append(("filename", bare, _WELLKNOWN[bare]))
        if suffix in _EXTENSION_KINDS:
            hints.append(("extension", suffix, _EXTENSION_KINDS[suffix]))
        try:
            candidate = Path(query)
            if evidence_root is not None:
                root = Path(evidence_root).resolve()
                # Windows paths cannot be resolved on a non-Windows host.
                import os
                if os.name != "nt" and (re.match(r"^[a-zA-Z]:", query) or query.startswith("\\")):
                    return error("path is outside the local evidence-root model")
                if not candidate.is_absolute():
                    candidate = root / candidate
                candidate = candidate.resolve()
                if not candidate.is_relative_to(root):
                    return error("path escapes MCP evidence root")
            if _is_path_like(query) or bare in _WELLKNOWN or candidate.is_file():
                magic = _magic_kinds(candidate)
                if magic:
                    # A header is a stronger hint than an arbitrary extension.
                    extension_hints = {kind for source, _, kinds in hints if source == "extension" for kind in kinds}
                    if extension_hints and not extension_hints.intersection(magic):
                        warnings.append("File signature differs from filename extension; verify with artifact.inspect.")
                    hints.append(("magic", "header", magic))
        except (OSError, ValueError, RuntimeError):
            if evidence_root is not None:
                return error("cannot resolve query inside MCP evidence root")
    text_kinds = sorted(_tokens(query))
    if not hints:
        hints = [("query", query, text_kinds if direction == "produce" or not _is_path_like(query) else [])]
    inferred = sorted({kind for _, _, kinds in hints for kind in kinds})
    ranked: list[dict[str, Any]] = []
    for spec in specs:
        reasons: list[tuple[int, str]] = []
        names = _tokens(spec.name)
        tags = {tok for tag in spec.tags for tok in _tokens(tag)}
        description = _tokens(spec.description)
        if direction == "produce":
            for kind in text_kinds:
                for output in spec.produces:
                    if kind == output.lower():
                        reasons.append((120, f"declares output evidence kind '{output}'"))
                    elif kind in _tokens(output):
                        reasons.append((90, f"output evidence kind '{output}' references '{kind}'"))
        else:
            for source, label, kinds in hints:
                for kind in kinds:
                    strength = 100 if source == "magic" else 100 if source == "filename" else 75 if source == "extension" else 60
                    if source == "filename" and kind == kinds[0]:
                        strength += 10
                    if kind in _BROAD_KINDS and len(kinds) > 1:
                        strength -= 45
                    if kind in names:
                        reasons.append((strength + 5, f"{source} '{label}' suggests '{kind}'; capability name matches"))
                    elif kind in tags:
                        reasons.append((strength, f"{source} '{label}' suggests '{kind}'; capability name/tag matches"))
                    elif kind in description:
                        reasons.append((strength - 15, f"{source} '{label}' suggests '{kind}'; capability description matches"))
        if not reasons:
            continue
        reasons = sorted(set(reasons), key=lambda item: (-item[0], item[1]))
        blocked: list[str] = []
        if policy is not None:
            if spec.safety > policy.max_level:
                blocked.append(f"requires {spec.safety.name}; policy allows {policy.max_level.name}")
            if spec.network and not policy.allow_network:
                blocked.append("network access is disabled by policy")
        ranked.append({
            "name": spec.name, "description": spec.description,
            "safety": spec.safety.name, "network": bool(spec.network),
            "tags": list(spec.tags), "produces": list(spec.produces),
            "requires": list(spec.requires), "deterministic": spec.deterministic,
            "cost_hint": spec.cost_hint, "parameters": spec.parameters,
            "path_roles": spec.path_roles,
            "why": reasons[0][1], "reasons": [reason for _, reason in reasons],
            "score": reasons[0][0],
            **({"policy_allowed": not blocked, "policy_blockers": blocked} if policy is not None else {}),
        })
    ranked.sort(key=lambda item: (-item["score"], item["name"]))
    return {"ok": True, "query": query, "direction": direction,
            "inferred_kinds": inferred, "warnings": warnings,
            "total": len(ranked), "count": min(len(ranked), limit),
            "results": ranked[:limit]}
