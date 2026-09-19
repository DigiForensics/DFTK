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

"""Tests for the per-tool readiness classification (WS3 readiness contract).

These tests stub ``_import_available`` so they are deterministic regardless of
whether optional forensic Python packages happen to be installed in the test
environment.
"""
from __future__ import annotations

import pytest

from dftk.core.models import SafetyLevel, ToolSpec
from dftk.core.readiness import (
    OPTIONAL_REQUIREMENTS,
    _requirement_status,
    readiness_summary,
    tool_readiness,
)


def _spec(name: str = "demo.tool", safety: SafetyLevel = SafetyLevel.READ_ONLY, requires=()) -> ToolSpec:
    return ToolSpec(
        name=name,
        description="fixture",
        safety=safety,
        parameters={"type": "object", "properties": {}, "required": []},
        requires=tuple(requires),
    )


def test_tool_readiness_runnable_without_requires():
    assert tool_readiness(_spec()) == {"state": "runnable", "missing": []}


def test_tool_readiness_runnable_when_requires_present(monkeypatch):
    monkeypatch.setattr("dftk.core.readiness._import_available", lambda module: True)
    r = tool_readiness(_spec(name="disk.image", requires=("pyewf", "yara-python")))
    assert r["state"] == "runnable"
    assert r["missing"] == []


def test_tool_readiness_degraded_when_optional_missing(monkeypatch):
    monkeypatch.setattr("dftk.core.readiness._import_available", lambda module: False)
    r = tool_readiness(_spec(name="disk.image_info", requires=("pyewf",)))
    assert r["state"] == "degraded"
    assert len(r["missing"]) == 1
    gap = r["missing"][0]
    assert gap == {"name": "pyewf", "label": "disk:pyewf", "install": "pip install pyewf"}


def test_tool_readiness_degraded_lists_every_gap(monkeypatch):
    monkeypatch.setattr("dftk.core.readiness._import_available", lambda module: False)
    r = tool_readiness(_spec(requires=("pyewf", "pytsk3")))
    assert r["state"] == "degraded"
    names = {g["name"] for g in r["missing"]}
    assert names == {"pyewf", "pytsk3"}


def test_tool_readiness_blocked_for_destructive():
    # Safety gating takes precedence over dependency availability.
    r = tool_readiness(_spec(name="fs.wipe", safety=SafetyLevel.DESTRUCTIVE, requires=("pyewf",)))
    assert r["state"] == "blocked"
    assert r["reason"] == "destructive-requires-opt-in"


def test_requirement_status_mapped_name_carries_label_and_install():
    s = _requirement_status("yara-python")
    assert s["name"] == "yara-python"
    assert s["label"] == "malware:yara"
    assert s["install"] == 'pip install "dftk[yara]"'


def test_requirement_status_unknown_name_falls_back():
    s = _requirement_status("nonexistent-pkg")
    assert s["name"] == "nonexistent-pkg"
    assert s["label"] == "nonexistent-pkg"
    assert s["install"] == "pip install nonexistent-pkg"
    assert "available" in s


def test_optional_requirements_mapping_is_complete():
    assert OPTIONAL_REQUIREMENTS  # non-empty
    for name, info in OPTIONAL_REQUIREMENTS.items():
        assert info["label"], f"missing label for {name}"
        assert info["install"], f"missing install command for {name}"
        assert info["module"], f"missing module for {name}"


def test_readiness_summary_aggregates_counts():
    specs = [
        _spec(name="a.runnable"),
        _spec(name="b.degraded", requires=("pyewf",)),
        _spec(name="c.blocked", safety=SafetyLevel.DESTRUCTIVE),
    ]
    summary = readiness_summary(specs)
    assert summary["counts"] == {"runnable": 1, "degraded": 1, "blocked": 1}
    assert summary["registered"] == 3
    assert summary["degraded"] == [{"name": "b.degraded", "missing": summary["degraded"][0]["missing"]}]
    assert summary["blocked"] == ["c.blocked"]


def test_readiness_summary_empty():
    summary = readiness_summary([])
    assert summary["counts"] == {"runnable": 0, "degraded": 0, "blocked": 0}
    assert summary["registered"] == 0
    assert summary["degraded"] == []
    assert summary["blocked"] == []
