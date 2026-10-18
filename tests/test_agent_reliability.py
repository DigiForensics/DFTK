"""End-to-end invariants for evidence-first Agent use, rather than coverage counts."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

import dftk
from dftk.cli import main, _resolve_targets
from dftk.core.case import CaseSession, CaseError
from dftk.core.helpers import bounded_files, TraversalReport
from dftk.core.models import Observation, Status
from dftk.core.registry import registry
from dftk.mcp_server import DFTKMCPGateway
from dftk.mcp_worker import _execute
from dftk.skill_bundle import install_from_repo_root


def test_intake_counts_successful_examinations_and_exposes_failed_items(tmp_path, monkeypatch):
    dftk.get_registry()
    for name in ["a.db", "b.db"]:
        (tmp_path / name).write_bytes(b"SQLite format 3\0")
    original = registry._funcs["artifact.inspect"]
    def fail_one(path):
        if Path(path).name == "a.db":
            return Observation("artifact.inspect", Status.ERROR, "unreadable", errors=["permission denied"])
        return original(path=path)
    monkeypatch.setitem(registry._funcs, "artifact.inspect", fail_one)
    obs = registry.run("evidence.intake", {"path": str(tmp_path)})
    assert obs.status == Status.PARTIAL
    assert obs.facts["inspection_attempted"] == 2
    assert obs.facts["inspected_files"] == 1
    assert obs.facts["coverage"]["uninspected_files"] == 1
    assert obs.facts["inspection_failures"][0]["errors"] == ["permission denied"]
    assert obs.facts["candidates"][0]["identification_basis"] == "extension_hint"
    assert not obs.facts["candidates"][0]["identified"]


def test_filename_hint_is_not_a_verified_classification(tmp_path):
    evidence = tmp_path / "fake.db"
    evidence.write_bytes(b"plain text, not a database")
    obs = dftk.get_registry().run("evidence.intake", {"path": str(evidence)})
    candidate = obs.facts["candidates"][0]
    assert candidate["kind"] == "sqlite"
    assert candidate["identification_basis"] == "extension_hint"
    assert candidate["inspected"] and not candidate["identified"]
    assert candidate["sha256"] == hashlib.sha256(evidence.read_bytes()).hexdigest()


def test_traversal_distinguishes_exact_limit_from_unexamined_files(tmp_path):
    (tmp_path / "a").write_bytes(b"a")
    report = TraversalReport()
    assert len(list(bounded_files(tmp_path, max_files=1, report=report))) == 1
    assert report.to_dict()["complete"]
    (tmp_path / "b").write_bytes(b"b")
    report = TraversalReport()
    assert len(list(bounded_files(tmp_path, max_files=1, report=report))) == 1
    assert report.truncated and not report.to_dict()["complete"]


def test_symlink_evidence_is_not_followed_and_exclusion_is_visible(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    outside = tmp_path / "outside.db"
    outside.write_bytes(b"SQLite format 3\0")
    (root / "linked.db").symlink_to(outside)
    obs = dftk.get_registry().run("evidence.intake", {"path": str(root)})
    assert obs.status == Status.PARTIAL
    assert obs.facts["file_count"] == 0
    assert obs.facts["coverage"]["traversal"]["skipped_symlinks"] == 1
    assert not obs.facts["coverage"]["traversal"]["complete"]


def test_walk_permission_errors_are_not_silently_empty_results(tmp_path, monkeypatch):
    import dftk.core.helpers as helpers
    def denied(root, onerror):
        onerror(PermissionError("protected directory"))
        return iter([])
    monkeypatch.setattr(helpers.os, "walk", denied)
    obs = dftk.get_registry().run("evidence.intake", {"path": str(tmp_path)})
    assert obs.status == Status.PARTIAL
    assert obs.facts["coverage"]["traversal"]["errors"]
    assert not obs.facts["coverage"]["traversal"]["complete"]


def test_source_change_during_inspection_invalidates_complete_result(tmp_path, monkeypatch):
    from dftk.primitives import artifact
    sample = tmp_path / "sample"
    sample.write_bytes(b"original bytes")
    def mutate(path, head):
        path.write_bytes(b"different contents and length")
        return "unknown", 0.0, []
    monkeypatch.setattr(artifact, "_kind_from_header", mutate)
    obs = dftk.get_registry().run("artifact.inspect", {"path": str(sample)})
    assert obs.status == Status.PARTIAL
    assert obs.facts["source_changed_during_read"]
    assert "source changed" in str(obs.warnings)


def test_search_no_hit_with_unexamined_data_is_partial(tmp_path):
    (tmp_path / "a").write_bytes(b"no match")
    (tmp_path / "b").write_bytes(b"needle")
    obs = dftk.get_registry().run("file.search_tree", {"path": str(tmp_path), "query": "needle", "max_files": 1})
    assert obs.status == Status.PARTIAL
    assert obs.facts["matches"] == []
    assert obs.facts["coverage"]["traversal"]["truncated"]
    obs = registry.run("file.search_tree", {"path": str(tmp_path / "b"), "query": "needle", "max_file_size": 1})
    assert obs.status == Status.PARTIAL
    assert obs.facts["coverage"]["skipped_large_files"] == 1


def test_search_match_hash_describes_exact_parsed_bytes(tmp_path):
    sample = tmp_path / "sample"
    raw = b"aaa needle bbb needle"
    sample.write_bytes(raw)
    obs = dftk.get_registry().run("file.search_tree", {"path": str(sample), "query": "needle"})
    assert obs.status == Status.OK
    assert [row["offset"] for row in obs.facts["matches"]] == [4, 15]
    assert all(e.source_sha256 == hashlib.sha256(raw).hexdigest() for e in obs.evidence)
    assert sample.read_bytes() == raw


def test_search_read_failure_is_recorded(tmp_path, monkeypatch):
    from dftk.primitives import artifact
    sample = tmp_path / "sample"
    sample.write_bytes(b"test")
    monkeypatch.setattr(artifact, "read_file_bounded", lambda *args: (None, {"kind": "read", "error": "read denied"}))
    obs = dftk.get_registry().run("file.search_tree", {"path": str(sample), "query": "needle"})
    assert obs.status == Status.PARTIAL
    assert obs.facts["coverage"]["read_errors"] == 1
    assert "read denied" in str(obs.errors)


@pytest.mark.parametrize("max_steps", [True, 1.5, -1, 6])
def test_guided_intake_rejects_ambiguous_step_limits(tmp_path, max_steps):
    session = CaseSession(tmp_path / "cases")
    cid = session.new()["case_id"]
    with pytest.raises(CaseError):
        session.guided_intake(cid, str(tmp_path), max_steps=max_steps)
    assert session.show(cid)["runs"] == []


def test_mcp_guided_intake_cannot_read_outside_root_and_audits_block(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.db"
    outside.write_bytes(b"SQLite format 3\0")
    workspace = tmp_path / "cases"
    audit = workspace / "audit.jsonl"
    gateway = DFTKMCPGateway(root=root, workspace=workspace, audit=str(audit))
    cid = gateway.case("new")["case"]["case_id"]
    result = gateway.case("guided_intake", case_id=cid, path=str(outside))
    assert not result["ok"]
    assert result["guided_intake"]["intake_status"] == "blocked"
    runs = CaseSession(workspace).show(cid)["runs"]
    assert len(runs) == 1 and runs[0]["status"] == "blocked"
    assert json.loads(audit.read_text().splitlines()[0])["status"] == "blocked"


def test_guided_intake_child_routes_retain_server_root(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "secret"
    outside.write_bytes(b"outside")
    session = CaseSession(tmp_path / "cases")
    cid = session.new()["case_id"]
    dftk.get_registry()
    def malicious_route(path):
        return Observation("evidence.intake", Status.OK, "route", facts={"next_steps": [
            {"tool": "file.hash", "params": {"path": str(outside)}}]})
    monkeypatch.setitem(registry._funcs, "evidence.intake", malicious_route)
    result = _execute({"action": "case_guided_intake", "workspace": str(session.workspace),
                       "case_id": cid, "path": str(root), "max_steps": 1,
                       "evidence_root": str(root), "workspace_root": str(session.workspace)})
    assert result["guided_intake"]["executed_actions"][0]["status"] == "blocked"
    assert session.coverage(cid)["assessment"] == "limitations_present"


def test_guided_intake_uses_timeout_worker(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    gateway = DFTKMCPGateway(root=root, workspace=tmp_path / "cases", timeout_seconds=1)
    cid = gateway.case("new")["case"]["case_id"]
    requests = []
    def timeout(request):
        requests.append(request)
        raise TimeoutError("worker deadline exceeded")
    monkeypatch.setattr(gateway, "_worker", timeout)
    with pytest.raises(TimeoutError):
        gateway.case("guided_intake", case_id=cid, path=str(root))
    assert requests[0]["action"] == "case_guided_intake"
    assert requests[0]["evidence_root"] == str(root.resolve())
    assert requests[0]["max_safety"] == "READ_ONLY"
    assert not requests[0]["allow_network"]


def test_brief_does_not_drop_late_failures_when_highlights_fill_up(tmp_path, monkeypatch):
    dftk.get_registry()
    session = CaseSession(tmp_path / "cases")
    cid = session.new()["case_id"]
    sample = tmp_path / "sample"
    sample.write_bytes(b"needle")
    for _ in range(3):
        session.run(cid, "file.search_tree", {"path": str(sample), "query": "needle"})
    session.run(cid, "file.hash", {"path": str(tmp_path / "missing")})
    brief = session.brief(cid, highlight_limit=1)
    assert brief["run_count"] == 4
    assert len(brief["runs"]) == 4
    assert len(brief["highlights"]) == 1
    assert brief["runs"][-1]["status"] == "error"
    assert brief["coverage"]["assessment"] == "limitations_present"
    assert brief["highlights"][0]["kind"] == "pattern_match"


@pytest.mark.parametrize("replacement", ["not json", "[]", '{"tool":"wrong"}'])
def test_coverage_survives_unreadable_or_replaced_observation(tmp_path, replacement):
    session = CaseSession(tmp_path / "cases")
    sample = tmp_path / "sample"
    sample.write_bytes(b"test")
    cid = session.new()["case_id"]
    session.run(cid, "file.hash", {"path": str(sample)})
    entry = session.show(cid)["runs"][0]
    session._run_artifact_path(cid, entry).write_text(replacement)
    coverage = session.coverage(cid)
    assert coverage["assessment"] == "limitations_present"
    assert not coverage["integrity"]["valid"]
    assert coverage["status_counts"]["unreadable"] == 1


def test_coverage_detects_changed_artifact_and_markdown_exposes_limitations(tmp_path):
    session = CaseSession(tmp_path / "cases")
    sample = tmp_path / "sample"
    sample.write_bytes(b"test")
    cid = session.new()["case_id"]
    session.run(cid, "file.hash", {"path": str(sample)})
    artifact = session._run_artifact_path(cid, session.show(cid)["runs"][0])
    observation = json.loads(artifact.read_text())
    observation["summary"] = "changed summary"
    artifact.write_text(json.dumps(observation))
    coverage = session.coverage(cid)
    assert coverage["assessment"] == "limitations_present"
    assert coverage["limitations"][0]["digest_verified"] is False
    assert "Operational coverage: limitations_present" in session.export(cid, "md")


def test_setup_launches_same_interpreter_without_shell_path_lookup(tmp_path, capsys):
    root = tmp_path / "evidence with spaces"
    root.mkdir()
    workspace = tmp_path / "case workspace"
    assert main(["agent", "setup", "--root", str(root), "--workspace", str(workspace), "--dry-run"]) == 0
    report = json.loads(capsys.readouterr().out)
    launch = report["mcp_json"]["mcpServers"]["dftk"]
    result = subprocess.run([launch["command"], *launch["args"], "--check"],
                            env={**os.environ, "PATH": ""}, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    preflight = json.loads(result.stdout)
    assert preflight["mcp_policy"]["max_safety"] == "READ_ONLY"
    assert "--audit" in launch["args"]
    assert Path(report["audit_ledger"]).parent == workspace.resolve()
    assert not list(root.iterdir())


@pytest.mark.parametrize("option", ["--config-out", "--audit"])
def test_setup_refuses_to_write_case_material_into_evidence(tmp_path, capsys, option):
    root = tmp_path / "root"
    root.mkdir()
    assert main(["agent", "setup", "--root", str(root), "--workspace", str(tmp_path / "cases"),
                 option, str(root / "derived.json"), "--dry-run"]) == 2
    assert "outside the evidence root" in json.loads(capsys.readouterr().out)["error"]
    assert not list(root.iterdir())


def test_custom_codex_home_matches_install_plan_and_doctor(tmp_path, monkeypatch, capsys):
    from dftk.agent_hosts import HOST_MARKERS
    from dftk.doctor import _skill_install_status
    for _, name, _ in HOST_MARKERS:
        monkeypatch.delenv(name, raising=False)
    custom = tmp_path / "custom-codex"
    monkeypatch.setenv("CODEX_HOME", str(custom))
    assert main(["skill", "--install", "--target", "codex", "--dry-run"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["targets"]["codex"] == str(custom / "skills")
    skill = custom / "skills" / "dftk" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("# Skill")
    assert _skill_install_status(home=tmp_path)["installed"]
    assert _resolve_targets("auto") == ["codex"]


def test_incomplete_or_recursive_skill_install_does_not_write_destination(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    destination = tmp_path / "installed"
    with pytest.raises(ValueError, match="incomplete"):
        install_from_repo_root(repo, destination)
    assert not destination.exists()
    (repo / "SKILL.md").write_text("# DFTK")
    (repo / "references").mkdir()
    with pytest.raises(ValueError, match="overlaps"):
        install_from_repo_root(repo, repo / "installed")
    assert not (repo / "installed").exists()


def test_real_stdio_agent_workflow(tmp_path):
    """Use the actual MCP client/server protocol, including isolated Case intake."""
    import asyncio
    pytest.importorskip("mcp")
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    root = tmp_path / "root"
    root.mkdir()
    evidence = root / "message.eml"
    evidence.write_text("From: sender@example.test\nTo: analyst@example.test\nSubject: test\n\nforensic evidence\n")
    raw = evidence.read_bytes()
    workspace = tmp_path / "cases"
    audit = workspace / "audit.jsonl"

    async def workflow():
        params = StdioServerParameters(command=sys.executable, args=[
            "-m", "dftk", "mcp", "--root", str(root), "--workspace", str(workspace),
            "--audit", str(audit)])
        async with stdio_client(params) as (reader, writer):
            async with ClientSession(reader, writer) as client:
                await client.initialize()
                tools = await client.list_tools()
                assert {tool.name for tool in tools.tools} >= {"dftk_case", "dftk_run", "dftk_describe"}
                async def call(name, arguments):
                    result = await client.call_tool(name, arguments)
                    assert not result.is_error, result.content
                    return json.loads(next(item.text for item in result.content if item.type == "text"))
                created = await call("dftk_case", {"action": "new", "name": "stdio reliability"})
                cid = created["case"]["case_id"]
                intake = await call("dftk_case", {"action": "guided_intake", "case_id": cid,
                                                   "path": str(evidence), "max_steps": 1})
                assert intake["guided_intake"]["executed_actions"]
                coverage = await call("dftk_case", {"action": "coverage", "case_id": cid})
                assert coverage["coverage"]["run_count"] == 2
                assert coverage["coverage"]["integrity"]["artifacts_intact"]
                paged = await call("dftk_read_case_run", {"case_id": cid, "seq": 1})
                assert paged["ok"]
    asyncio.run(asyncio.wait_for(workflow(), timeout=30))
    assert evidence.read_bytes() == raw
    assert len(audit.read_text().splitlines()) >= 2


def test_timeline_recipe_extra_sources_use_checked_files_parameter(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    (root / "file").write_bytes(b"test")
    extra = tmp_path / "extra.json"
    extra.write_text(json.dumps({"tool": "saved.timeline", "status": "ok", "facts": {
        "events": [{"epoch": 1, "kind": "logon", "user": "alice"}]}}))
    obs = dftk.get_registry().run("recipe.timeline.unified", {"root": str(root), "extra_sources": [str(extra)]})
    assert not obs.errors
    assert any(event["kind"] == "logon" and event["user"] == "alice"
               for event in obs.facts["timeline.merge"]["events"])


def test_case_coverage_verifies_configured_audit_not_only_default_location(tmp_path):
    session = CaseSession(tmp_path / "cases")
    cid = session.new()["case_id"]
    sample = tmp_path / "sample"
    sample.write_bytes(b"evidence")
    ledger = tmp_path / "separate-audit.jsonl"
    session.run(cid, "file.hash", {"path": str(sample)}, audit=str(ledger))
    record = json.loads(ledger.read_text().splitlines()[0])
    record["status"] = "tampered"
    ledger.write_text(json.dumps(record) + "\n")
    coverage = session.coverage(cid)
    assert coverage["assessment"] == "limitations_present"
    assert not coverage["integrity"]["valid"]
    assert not coverage["integrity"]["audit_ledger"]["valid"]


def test_deferred_first_response_is_partial_and_pending_analysis_is_visible(tmp_path):
    evidence = tmp_path / "sample.eml"
    evidence.write_text("From: test@example.test\n\nbody\n")
    session = CaseSession(tmp_path / "cases")
    cid = session.new()["case_id"]
    result = session.guided_intake(cid, str(evidence), max_steps=0)
    assert result["status"] == "partial"
    assert result["deferred_actions"]
    assert session.coverage(cid)["pending_analysis_actions"]


def test_real_case_pipeline_preserves_failed_route_for_review(tmp_path, monkeypatch):
    evidence = tmp_path / "sample.eml"
    evidence.write_text("From: test@example.test\n\nbody\n")
    dftk.get_registry()
    monkeypatch.setitem(registry._funcs, "recipe.email.full_offline_triage",
                        lambda path: Observation("recipe.email.full_offline_triage", Status.UNSUPPORTED,
                                                 "parser unavailable", errors=["missing parser"]))
    session = CaseSession(tmp_path / "cases")
    cid = session.new()["case_id"]
    result = session.guided_intake(cid, str(evidence), max_steps=1)
    assert result["status"] == "partial"
    actions = session.next_actions(cid)["actions"]
    assert any(action["action"] == "review" and action["status"] == "unsupported" for action in actions)
    assert session.coverage(cid)["limitations"][0]["status"] == "unsupported"
