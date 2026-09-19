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

"""Tests for ``dftk selftest`` (WS3 runtime self-test).

``run_selftest`` proves the *runnable* capabilities are actually wired by
executing them end-to-end with schema-shaped parameters. These tests exercise
its contract (structure, the runnable/skipped split, crash accounting) and
verify the readiness data is surfaced through the manifest and doctor report.
"""
from __future__ import annotations

from dftk.core.selftest import run_selftest
from dftk.doctor import doctor_report
from dftk.manifest import capability_manifest


def test_run_selftest_structure():
    report = run_selftest()
    assert report["schema_version"] == "1"
    assert set(report) == {"schema_version", "total_runnable", "passed", "crashed", "results"}
    # Invariant: every executed tool is accounted for exactly once.
    assert report["passed"] + report["crashed"] == report["total_runnable"]
    # The selftest must actually load the builtin tools (regression guard for the
    # missing load_builtin_tools() call).
    assert report["total_runnable"] >= 1
    executed = [r for r in report["results"] if "skipped" not in r]
    assert len(executed) == report["total_runnable"]
    for r in report["results"]:
        assert "name" in r
        # Exactly one of status / skipped is present per entry.
        assert ("status" in r) != ("skipped" in r), r


def test_run_selftest_reports_no_crash_in_clean_env():
    report = run_selftest()
    crashed = [r["name"] for r in report["results"] if r.get("status") == "crash"]
    assert not crashed, f"self-test found crashes: {crashed}"


def test_run_selftest_skips_non_runnable():
    report = run_selftest()
    manifest = capability_manifest()
    readiness_by_name = {t["name"]: t["readiness"]["state"] for t in manifest["tools"]}
    for r in report["results"]:
        if "skipped" in r:
            # A skipped tool must be reported non-runnable by the manifest too.
            assert readiness_by_name[r["name"]] in ("degraded", "blocked"), r
        else:
            assert readiness_by_name[r["name"]] == "runnable", r


def test_capability_manifest_carries_readiness():
    manifest = capability_manifest()
    assert manifest["tool_count"] >= 1
    for tool in manifest["tools"]:
        assert "readiness" in tool
        r = tool["readiness"]
        assert r["state"] in ("runnable", "degraded", "blocked")
        assert "missing" in r


def test_doctor_report_carries_readiness_summary():
    rep = doctor_report()
    assert "readiness" in rep
    r = rep["readiness"]
    assert set(r) == {"counts", "registered", "degraded", "blocked"}
    assert r["registered"] == (
        r["counts"]["runnable"] + r["counts"]["degraded"] + r["counts"]["blocked"]
    )
    # Each degraded entry references a concrete missing dependency.
    for entry in r["degraded"]:
        assert "name" in entry and "missing" in entry
