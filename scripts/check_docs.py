"""Validate local DFTK documentation against the registry and local links."""
from __future__ import annotations

import re
import sys
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import dftk  # noqa: E402
from dftk.manifest import capability_manifest  # noqa: E402

LINK = re.compile(r"\]\(([^)#]+)(?:#[^)]+)?\)")
OBSOLETE_COUNT = re.compile(r"\b68(?:\+)?\s+(?:read-only\s+)?(?:tools|capabilities)\b", re.I)


def markdown_files() -> list[Path]:
    return sorted(
        path for path in ROOT.rglob("*.md")
        if not any(part.startswith(".") for part in path.relative_to(ROOT).parts)
    )


def check_links(files: list[Path]) -> list[str]:
    errors: list[str] = []
    for path in files:
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for match in LINK.finditer(line):
                target = match.group(1)
                if target.startswith(("http://", "https://", "mailto:", "/", "<")):
                    continue
                if not (path.parent / target).exists():
                    errors.append(f"{path.relative_to(ROOT)}:{line_no}: missing {target}")
    return errors


def main() -> int:
    files = markdown_files()
    errors = check_links(files)
    for path in (path for path in files if path.name != "CHANGELOG.md"):
        if OBSOLETE_COUNT.search(path.read_text(encoding="utf-8")):
            errors.append(f"{path.relative_to(ROOT)}: obsolete current capability count")

    manifest = capability_manifest()
    count = manifest["tool_count"]
    capability_map = (ROOT / "CAPABILITIES.md").read_text(encoding="utf-8")
    documented = re.search(r"contains (\d+) tools", capability_map)
    if documented is None or int(documented.group(1)) != count:
        errors.append("CAPABILITIES.md count does not match the registry")
    manifest_path = ROOT / "docs" / "capabilities.json"
    try:
        committed_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"cannot read generated capability manifest: {exc}")
    else:
        if committed_manifest != manifest:
            errors.append("docs/capabilities.json is stale; run dftk export-manifest --out docs/capabilities.json")

    for error in errors:
        print(error)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
