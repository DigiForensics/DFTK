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

import json

from dftk.catalog import load_builtin_tools
from dftk.core.case import CaseSession, CaseError


def _make_evidence_dir(base):
    d = base / "evidence"
    d.mkdir()
    (d / "f.txt").write_text("hello", encoding="utf-8")
    return d


def test_new_case_appears_in_list(tmp_path):
    load_builtin_tools()
    sess = CaseSession(tmp_path / ".dftk")
    manifest = sess.new("demo")
    assert manifest["case_id"].startswith("case-")
    listed = sess.list()
    assert len(listed) == 1
    assert listed[0]["name"] == "demo"
    assert listed[0]["case_id"] == manifest["case_id"]


def test_run_records_artifact_and_timeline_correlates(tmp_path):
    load_builtin_tools()
    sess = CaseSession(tmp_path / ".dftk")
    cid = sess.new("fs-case")["case_id"]
    ev = _make_evidence_dir(tmp_path)
    obs = sess.run(cid, "timeline.file_metadata", {"root": str(ev)})
    assert obs.status.value in ("ok", "partial")
    # artifact stored
    manifest = json.loads((tmp_path / ".dftk" / "cases" / cid / "manifest.json").read_text(encoding="utf-8"))
    assert len(manifest["runs"]) == 1
    assert (tmp_path / ".dftk" / "cases" / cid / manifest["runs"][0]["artifact"]).exists()
    # timeline correlates recorded events
    tl = sess.timeline(cid)
    assert tl.status.value in ("ok", "partial")
    assert tl.facts["source_count"] >= 1
    assert tl.facts["span"]["count"] >= 1


def test_export_formats(tmp_path):
    load_builtin_tools()
    sess = CaseSession(tmp_path / ".dftk")
    cid = sess.new("exp")["case_id"]
    ev = _make_evidence_dir(tmp_path)
    sess.run(cid, "timeline.file_metadata", {"root": str(ev)})
    js = sess.export(cid, fmt="json")
    data = json.loads(js)
    assert data["schema"] == "dftk.case.report/1"
    assert data["case"]["case_id"] == cid
    assert "timeline" in data
    md = sess.export(cid, fmt="md")
    assert md.startswith("# Case report")
    assert "Timeline" in md


def test_case_entity_graph_correlates_persisted_observations(tmp_path):
    load_builtin_tools()
    sess = CaseSession(tmp_path / ".dftk")
    cid = sess.new("graph") ["case_id"]
    evidence = tmp_path / "indicators.txt"
    evidence.write_text("alice@example.test 203.0.113.5 evil.example", encoding="utf-8")
    sess.run(cid, "file.strings", {"path": str(evidence)})
    graph = sess.entity_graph(cid)
    assert graph.facts["case_id"] == cid
    assert graph.facts["entity_count"] >= 3


def test_case_next_actions_start_with_intake_then_offer_case_correlation(tmp_path):
    load_builtin_tools()
    sess = CaseSession(tmp_path / ".dftk")
    cid = sess.new("next") ["case_id"]
    first = sess.next_actions(cid)
    assert first["actions"][0]["tool"] == "evidence.intake"
    evidence = _make_evidence_dir(tmp_path)
    sess.run(cid, "evidence.intake", {"path": str(evidence)})
    sess.run(cid, "timeline.file_metadata", {"root": str(evidence)})
    next_actions = sess.next_actions(cid)
    assert any(action.get("operation") == "graph" for action in next_actions["actions"])


def test_case_guided_intake_persists_each_child_run(tmp_path):
    load_builtin_tools()
    sess = CaseSession(tmp_path / ".dftk")
    cid = sess.new("guided") ["case_id"]
    evidence = tmp_path / "message.eml"
    evidence.write_text("From: analyst@example.test\n\nhello", encoding="utf-8")
    result = sess.guided_intake(cid, str(evidence), objective="email", max_steps=1)
    assert result["executed_actions"]
    manifest = sess.show(cid)
    assert [run["tool"] for run in manifest["runs"]] == ["evidence.intake", "recipe.email.full_offline_triage"]


def test_case_brief_is_bounded_and_contains_recovery_actions(tmp_path):
    load_builtin_tools()
    sess = CaseSession(tmp_path / ".dftk")
    cid = sess.new("brief") ["case_id"]
    evidence = tmp_path / "indicators.txt"
    evidence.write_text("alice@example.test evil.example 203.0.113.5", encoding="utf-8")
    sess.run(cid, "file.strings", {"path": str(evidence)})
    brief = sess.brief(cid)
    assert brief["schema"] == "dftk.case.brief/1"
    assert brief["runs"][0]["tool"] == "file.strings"
    assert brief["next_actions"]["actions"][0]["tool"] == "evidence.intake"


def test_unknown_case_raises(tmp_path):
    load_builtin_tools()
    sess = CaseSession(tmp_path / ".dftk")
    try:
        sess.timeline("nope")
        assert False, "expected CaseError"
    except CaseError:
        pass


def test_workspaces_are_isolated(tmp_path):
    load_builtin_tools()
    a = CaseSession(tmp_path / "wa")
    b = CaseSession(tmp_path / "wb")
    a.new("only-a")
    assert len(a.list()) == 1
    assert len(b.list()) == 0
