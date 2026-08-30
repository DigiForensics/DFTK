"""Guard the user-facing documentation against capability/version drift.

Every count and version string that the README, capability map and architecture
notes *advertise* is asserted against the live registry here. This exists
because the numbers silently rotted before: the 3.5.0 tree shipped a README
still claiming "DFTK 3.3.0 ... 72 tools (71 READ_ONLY, 1 STATEFUL)" while the
registry actually held 113 tools, and a CAPABILITIES.md claiming "99 tools ...
primitives plus recipes" when 99 was the primitives-only figure.

Documentation drift is a correctness problem for a forensic tool: an examiner
who trusts a stale safety table can assume no `STATEFUL` tool exists. So the
docs are treated as assertions about the code, and a mismatch fails the suite
rather than waiting to be noticed by eye.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import dftk

ROOT = Path(__file__).resolve().parents[1]

README = ROOT / "README.md"
README_ZH = ROOT / "README.zh-CN.md"
CAPABILITIES = ROOT / "CAPABILITIES.md"
ARCHITECTURE = ROOT / "ARCHITECTURE.md"
AGENT_INTEGRATION = ROOT / "AGENT_INTEGRATION.md"

VERSION_CLAIM_DOCS = (README, README_ZH, CAPABILITIES, ARCHITECTURE, AGENT_INTEGRATION)


def _registry_counts() -> dict[str, int]:
    specs = dftk.get_registry().specs()
    recipes = [s for s in specs if s.name.startswith("recipe.")]
    return {
        "total": len(specs),
        "read_only": sum(1 for s in specs if s.safety.name == "READ_ONLY"),
        "stateful": sum(1 for s in specs if s.safety.name == "STATEFUL"),
        "destructive": sum(1 for s in specs if s.safety.name == "DESTRUCTIVE"),
        "recipes": len(recipes),
        "primitives": len(specs) - len(recipes),
    }


def _read(path: Path) -> str:
    if not path.is_file():
        pytest.skip(f"{path.name} not present in this checkout")
    return path.read_text(encoding="utf-8")


# "113 tools (109 `READ_ONLY`, 4 `STATEFUL`)" — optional bold/backtick noise.
_EN_BREAKDOWN = re.compile(
    r"(\d+)\s+tools\*{0,2}\s*\(\s*(\d+)\s+`?READ_ONLY`?\s*,\s*(\d+)\s+`?STATEFUL`?\s*\)"
)
# "113 个工具**（109 个 `READ_ONLY`、4 个 `STATEFUL`）"
_ZH_BREAKDOWN = re.compile(
    r"(\d+)\s*个工具\*{0,2}（\s*(\d+)\s*个\s*`?READ_ONLY`?\s*、\s*(\d+)\s*个\s*`?STATEFUL`?\s*）"
)


def test_registry_is_not_empty():
    """Sanity anchor: the counts below are meaningless if nothing registered."""
    counts = _registry_counts()
    assert counts["total"] > 0
    assert counts["read_only"] > 0
    # Tools are registered as a side effect of importing dftk.primitives; a
    # bare `from dftk.core.registry import registry` yields an empty registry.
    assert counts["total"] == counts["read_only"] + counts["stateful"] + counts["destructive"]


@pytest.mark.parametrize("path", [README, CAPABILITIES], ids=["README", "CAPABILITIES"])
def test_english_docs_tool_breakdown(path: Path):
    text = _read(path)
    matches = _EN_BREAKDOWN.findall(text)
    assert matches, f"{path.name} no longer states a 'N tools (N READ_ONLY, N STATEFUL)' breakdown"
    counts = _registry_counts()
    for total, read_only, stateful in matches:
        assert int(total) == counts["total"], (
            f"{path.name} advertises {total} tools, registry has {counts['total']}"
        )
        assert int(read_only) == counts["read_only"], (
            f"{path.name} advertises {read_only} READ_ONLY, registry has {counts['read_only']}"
        )
        assert int(stateful) == counts["stateful"], (
            f"{path.name} advertises {stateful} STATEFUL, registry has {counts['stateful']}"
        )


def test_chinese_readme_tool_breakdown():
    text = _read(README_ZH)
    matches = _ZH_BREAKDOWN.findall(text)
    assert matches, "README.zh-CN.md no longer states a tool/safety-level breakdown"
    counts = _registry_counts()
    for total, read_only, stateful in matches:
        assert int(total) == counts["total"]
        assert int(read_only) == counts["read_only"]
        assert int(stateful) == counts["stateful"]


def test_readme_headline_tool_count():
    """The 'Why DFTK' bullet advertises a bare total; it drifted to 72 before."""
    counts = _registry_counts()

    en = re.search(r"One registry,\s*(\d+)\s+tools", _read(README))
    assert en, "README.md lost its 'One registry, N tools' bullet"
    assert int(en.group(1)) == counts["total"], (
        f"README.md headline says {en.group(1)} tools, registry has {counts['total']}"
    )

    zh = re.search(r"一个注册表，\s*(\d+)\s*个工具", _read(README_ZH))
    assert zh, "README.zh-CN.md lost its '一个注册表，N 个工具' bullet"
    assert int(zh.group(1)) == counts["total"]


def test_docs_primitive_and_recipe_split():
    """`99 primitives plus 14 recipes` must reflect the real namespace split."""
    counts = _registry_counts()
    pattern = re.compile(r"(\d+)\s+\*{0,2}primitives\*{0,2}\s+plus\s+\*{0,2}(\d+)\s+\*{0,2}recipes")
    found = False
    for path in (README, CAPABILITIES):
        for primitives, recipes in pattern.findall(_read(path)):
            found = True
            assert int(primitives) == counts["primitives"], (
                f"{path.name} advertises {primitives} primitives, registry has {counts['primitives']}"
            )
            assert int(recipes) == counts["recipes"], (
                f"{path.name} advertises {recipes} recipes, registry has {counts['recipes']}"
            )
    assert found, "no doc states the primitives/recipes split any more"


def test_architecture_safety_section():
    """ARCHITECTURE.md states the READ_ONLY count, total, and STATEFUL names."""
    text = _read(ARCHITECTURE)
    counts = _registry_counts()

    m = re.search(r"(\d+)\s+tools are\s+`?READ_ONLY`?\s*\((\d+)\s+registered in total\)", text)
    assert m, "ARCHITECTURE.md lost its READ_ONLY/total safety statement"
    assert int(m.group(1)) == counts["read_only"]
    assert int(m.group(2)) == counts["total"]

    # Every STATEFUL tool must be named in the safety section, and the section
    # must not name a tool that is no longer STATEFUL.
    stateful = {s.name for s in dftk.get_registry().specs() if s.safety.name == "STATEFUL"}
    section = text.split("## Safety model", 1)[-1].split("\n## ", 1)[0]
    named = set(re.findall(r"`([a-z_]+\.[a-z_]+)`", section))
    missing = stateful - named
    assert not missing, f"ARCHITECTURE.md safety section does not mention STATEFUL tools: {sorted(missing)}"

    all_names = {s.name for s in dftk.get_registry().specs()}
    wrongly_named = {n for n in named if n in all_names and n not in stateful}
    assert not wrongly_named, (
        f"ARCHITECTURE.md safety section lists non-STATEFUL tools as STATEFUL: {sorted(wrongly_named)}"
    )


def test_no_destructive_tool_claim_holds():
    """Docs promise no DESTRUCTIVE tool is registered — verify that promise."""
    counts = _registry_counts()
    assert counts["destructive"] == 0, (
        "a DESTRUCTIVE tool is registered, but README/ARCHITECTURE still promise none"
    )


@pytest.mark.parametrize(
    "path",
    VERSION_CLAIM_DOCS,
    ids=[p.name for p in VERSION_CLAIM_DOCS],
)
def test_docs_reference_current_version(path: Path):
    """Any 'DFTK X.Y.Z' claim in prose docs must match the shipped version.

    CHANGELOG.md and RELEASE_NOTES_*.md are intentionally excluded: they are
    historical records and must keep naming old versions.
    """
    text = _read(path)
    claimed = re.findall(r"DFTK\s+(\d+\.\d+\.\d+)", text)
    if not claimed:
        pytest.skip(f"{path.name} makes no explicit version claim")
    for version in claimed:
        assert version == dftk.__version__, (
            f"{path.name} claims DFTK {version}, package version is {dftk.__version__}"
        )
