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

import pytest
import json

from dftk import __version__
from dftk.cli import _observation_exit_code, main
from dftk.core.models import Status


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"dftk {__version__}"


def test_observation_exit_codes_are_automation_safe():
    assert _observation_exit_code(Status.OK) == 0
    assert _observation_exit_code(Status.PARTIAL) == 0
    assert _observation_exit_code(Status.ERROR) == 1
    assert _observation_exit_code(Status.UNSUPPORTED) == 2
    assert _observation_exit_code(Status.BLOCKED) == 2


def test_cli_returns_distinct_codes_for_unsupported_and_blocked(tmp_path, capsys):
    evidence = tmp_path / "not-a-database.txt"
    evidence.write_text("not sqlite", encoding="utf-8")
    unsupported = main([
        "run",
        "database.sqlite_inventory",
        "--params",
        json.dumps({"path": str(evidence)}),
    ])
    blocked = main(["run", "archive.extract_safe", "--params", "{}"])
    assert unsupported == 2
    assert blocked == 2
    capsys.readouterr()


def test_cli_exports_versioned_capability_manifest(tmp_path, capsys):
    output = tmp_path / "capabilities.json"
    assert main(["export-manifest", "--out", str(output)]) == 0
    manifest = json.loads(output.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "3"
    assert manifest["tool_count"] == len(manifest["tools"])
    assert manifest["safety_counts"] == {"READ_ONLY": 78, "STATEFUL": 1}
    capsys.readouterr()


def test_cli_mcp_check_reports_workspace_isolation(tmp_path, capsys):
    evidence = tmp_path / "evidence"
    workspace = tmp_path / "case-workspace"
    evidence.mkdir()
    assert main(["mcp", "--root", str(evidence), "--workspace", str(workspace), "--check"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["preflight"]["safe_evidence_isolation"] is True
    assert workspace.is_dir()


def test_cli_skill_dry_run_is_single_target_by_default(capsys):
    assert main(["skill", "--install", "--dry-run"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert len(report["targets"]) == 1
    assert report["writes"] is False

    assert main(["skill", "--install", "--dir", "custom-skills", "--dry-run"]) == 0
    custom = json.loads(capsys.readouterr().out)
    assert set(custom["targets"]) == {"custom"}


def test_cli_agent_setup_is_reviewable_and_keeps_case_data_outside_evidence(tmp_path, capsys):
    evidence = tmp_path / "evidence"
    workspace = tmp_path / "cases"
    evidence.mkdir()
    assert main([
        "agent", "setup", "--root", str(evidence), "--workspace", str(workspace),
        "--dry-run",
    ]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["mcp_json"]["mcpServers"]["dftk"]["command"] == "dftk"
    assert "[mcp_servers.dftk]" in report["codex_toml"]
    assert report["writes"] == {"workspace": False, "config": False, "skills": False}
    assert not workspace.exists()

    assert main([
        "agent", "setup", "--root", str(evidence), "--workspace", str(evidence / "cases"),
        "--dry-run",
    ]) == 2
    assert "outside the evidence root" in json.loads(capsys.readouterr().out)["error"]


def test_cli_search_uses_capability_discovery(capsys):
    assert main(["search", "浏览器记录", "--limit", "3"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["results"]
    assert len(report["results"]) <= 3


def test_cli_refuses_to_overwrite_output_without_force(tmp_path, capsys):
    evidence = tmp_path / "sample.bin"
    output = tmp_path / "report.json"
    evidence.write_bytes(b"evidence")
    output.write_text("original", encoding="utf-8")
    assert main(["run", "file.hash", "--params", json.dumps({"path": str(evidence)}), "--out", str(output)]) == 2
    assert output.read_text(encoding="utf-8") == "original"
    assert main([
        "run", "file.hash", "--params", json.dumps({"path": str(evidence)}),
        "--out", str(output), "--force",
    ]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "ok"
    capsys.readouterr()
