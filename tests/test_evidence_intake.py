from __future__ import annotations

from pathlib import Path

from dftk.catalog import load_builtin_tools
from dftk.core.registry import registry
from dftk.core.safety import SafetyPolicy


def test_evidence_intake_builds_manifest_hashes_and_next_steps(tmp_path: Path):
    db = tmp_path / "messages.db"
    db.write_bytes(b"SQLite format 3\x00" + b"\x00" * 256)
    mail = tmp_path / "message.eml"
    mail.write_text("From: analyst@example.test\nTo: team@example.test\n\nhello\n", encoding="utf-8")

    load_builtin_tools()
    observation = registry.run("evidence.intake", {"path": str(tmp_path)}, SafetyPolicy())

    assert observation.status.value == "ok"
    assert observation.facts["scope_type"] == "directory"
    assert observation.facts["kind_counts"]["sqlite"] == 1
    assert len(observation.evidence) == 2
    routes = {step["tool"] for step in observation.facts["next_steps"]}
    assert "recipe.database.triage" in routes
    assert "recipe.email.full_offline_triage" in routes
    assert all(item["sha256"] for item in observation.facts["candidates"])


def test_evidence_intake_detects_offline_linux_root_and_bounds_inspection(tmp_path: Path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "os-release").write_text("ID=test\n", encoding="utf-8")
    (tmp_path / "var" / "log").mkdir(parents=True)
    (tmp_path / "var" / "log" / "auth.log").write_text("sshd\n", encoding="utf-8")

    load_builtin_tools()
    observation = registry.run(
        "evidence.intake", {"path": str(tmp_path), "max_files": 10, "inspect_limit": 1}, SafetyPolicy()
    )

    assert observation.facts["inspected_files"] == 1
    assert any(step["tool"] == "recipe.server.deep_offline_triage" for step in observation.facts["next_steps"])
    assert any("limited to first 1" in warning for warning in observation.warnings)


def test_agent_guided_intake_is_bounded_and_reports_deferred_actions(tmp_path: Path):
    (tmp_path / "message.eml").write_text("From: test@example.test\n\nhello", encoding="utf-8")
    load_builtin_tools()
    observation = registry.run(
        "recipe.agent.guided_intake", {"path": str(tmp_path), "max_steps": 0}, SafetyPolicy()
    )
    assert observation.facts["executed_actions"] == []
    assert observation.facts["deferred_actions"]
    assert observation.facts["guidance"].startswith("Review each child")
