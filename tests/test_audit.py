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

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dftk.core.audit import ToolAuditLog, _get_default_audit_log
from dftk.core.models import Observation, Status, SafetyLevel
from dftk.core.registry import ToolRegistry
from dftk.core.safety import SafetyPolicy


def _read_records(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8").strip()
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def test_audit_log_records_invocation(tmp_path: Path):
    log = ToolAuditLog(tmp_path / "audit.jsonl")
    reg = ToolRegistry()

    @reg.tool(name="demo.x", description="d", safety=SafetyLevel.READ_ONLY,
             parameters={"type": "object", "properties": {}})
    def demo() -> Observation:
        return Observation("demo.x", Status.OK, "did thing")

    out = reg.run("demo.x", {}, audit=log, caller="test")
    assert out.status.value == "ok"
    recs = _read_records(tmp_path / "audit.jsonl")
    assert len(recs) == 1
    rec = recs[0]
    assert rec["tool"] == "demo.x"
    assert rec["status"] == "ok"
    assert rec["caller"] == "test"
    assert rec["safety"] == "READ_ONLY"
    assert "ts" in rec


def test_audit_redacts_secrets(tmp_path: Path):
    log = ToolAuditLog(tmp_path / "audit.jsonl")
    reg = ToolRegistry()

    @reg.tool(name="demo.secret", description="d", safety=SafetyLevel.READ_ONLY,
             parameters={"type": "object", "properties": {"token": {"type": "string"}}})
    def secret(token: str) -> Observation:
        return Observation("demo.secret", Status.OK, "ok")

    reg.run("demo.secret", {"token": "supersecret", "api_key": "abc"}, audit=log)
    rec = _read_records(tmp_path / "audit.jsonl")[0]
    assert rec["params"]["token"] == "<redacted>"
    assert rec["params"]["api_key"] == "<redacted>"


def test_audit_truncates_long_params(tmp_path: Path):
    log = ToolAuditLog(tmp_path / "audit.jsonl")
    reg = ToolRegistry()

    @reg.tool(name="demo.big", description="d", safety=SafetyLevel.READ_ONLY,
             parameters={"type": "object", "properties": {"data": {"type": "string"}}})
    def big(data: str) -> Observation:
        return Observation("demo.big", Status.OK, "ok")

    reg.run("demo.big", {"data": "x" * 5000}, audit=log)
    rec = _read_records(tmp_path / "audit.jsonl")[0]
    assert "omitted:" in rec["params"]["data"]


def test_audit_logs_blocked_and_unknown(tmp_path: Path):
    log = ToolAuditLog(tmp_path / "audit.jsonl")
    reg = ToolRegistry()

    @reg.tool(name="demo.state", description="d", safety=SafetyLevel.STATEFUL,
             parameters={"type": "object", "properties": {}})
    def st() -> Observation:
        return Observation("demo.state", Status.OK, "ok")

    out = reg.run("nope", {}, audit=log, caller="t")
    assert out.status.value == "error"
    out2 = reg.run("demo.state", {}, policy=SafetyPolicy(max_level=SafetyLevel.READ_ONLY),
                   audit=log, caller="t")
    assert out2.status.value == "blocked"

    recs = _read_records(tmp_path / "audit.jsonl")
    assert len(recs) == 2
    assert {r["status"] for r in recs} == {"error", "blocked"}


def test_get_default_audit_log_from_env(monkeypatch, tmp_path: Path):
    import dftk.core.audit as audit_mod

    monkeypatch.setenv("DFTK_AUDIT_LOG", str(tmp_path / "env.jsonl"))
    monkeypatch.setattr(audit_mod, "_DEFAULT_AUDIT_LOG_RESOLVED", False)
    monkeypatch.setattr(audit_mod, "_DEFAULT_AUDIT_LOG", None)

    log = _get_default_audit_log()
    assert log is not None
    assert log.path == tmp_path / "env.jsonl"
    # Cached across calls within the process.
    assert _get_default_audit_log() is log


def test_registry_run_auto_logs_via_env(monkeypatch, tmp_path: Path):
    import dftk.core.audit as audit_mod
    import dftk.primitives.files  # ensure file.strings is registered
    from dftk.core.registry import registry

    monkeypatch.setenv("DFTK_AUDIT_LOG", str(tmp_path / "auto.jsonl"))
    monkeypatch.setattr(audit_mod, "_DEFAULT_AUDIT_LOG_RESOLVED", False)
    monkeypatch.setattr(audit_mod, "_DEFAULT_AUDIT_LOG", None)

    (tmp_path / "f.txt").write_text("hi")
    out = registry.run("file.strings", {"path": str(tmp_path / "f.txt")})
    assert out.status.value == "ok"
    recs = _read_records(tmp_path / "auto.jsonl")
    assert any(r["tool"] == "file.strings" for r in recs)


def test_mcp_gateway_audit_path_resolution(tmp_path: Path):
    from dftk.mcp_server import DFTKMCPGateway

    workspace = tmp_path.parent / f"{tmp_path.name}-cases"
    g_default = DFTKMCPGateway(root=tmp_path, workspace=workspace, audit=True)
    assert g_default.audit_path == (workspace / "audit.jsonl")

    g_custom = DFTKMCPGateway(root=tmp_path, workspace=workspace, audit="chain.jsonl")
    assert g_custom.audit_path == (workspace / "chain.jsonl")

    g_off = DFTKMCPGateway(root=tmp_path, workspace=workspace, audit=False)
    assert g_off.audit_path is None


def test_mcp_worker_logs_audit(tmp_path: Path):
    from dftk.mcp_worker import _execute

    (tmp_path / "f.txt").write_text("hi")
    audit_path = tmp_path / "mcp_audit.jsonl"
    res = _execute({
        "action": "run",
        "name": "file.strings",
        "params": {"path": str(tmp_path / "f.txt")},
        "max_safety": "READ_ONLY",
        "allow_network": False,
        "audit": str(audit_path),
    })
    assert res["ok"] is True
    recs = _read_records(audit_path)
    assert any(r["tool"] == "file.strings" and r["caller"] == "mcp" for r in recs)
