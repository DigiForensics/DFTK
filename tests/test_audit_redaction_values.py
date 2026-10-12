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
from pathlib import Path

from dftk.core.audit import ToolAuditLog
from dftk.core.registry import ToolRegistry
from dftk.core.models import Observation, Status, SafetyLevel


def _read_records(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8").strip()
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def test_audit_redacts_credentials_in_nonsecret_keys(tmp_path: Path):
    # B1: a secret stored under a key that does NOT match the secret-key regex
    # (e.g. connectionString / dsn / url) must still be masked, because the
    # value itself carries credentials.
    log = ToolAuditLog(tmp_path / "audit.jsonl")
    reg = ToolRegistry()

    @reg.tool(name="demo.conn", description="d", safety=SafetyLevel.READ_ONLY,
              parameters={"type": "object",
                          "properties": {"connectionString": {"type": "string"}}})
    def conn(connectionString: str) -> Observation:
        return Observation("demo.conn", Status.OK, "ok")

    reg.run("demo.conn",
            {"connectionString": "postgresql://admin:supersecret@db.example.com/app"},
            audit=log)
    rec = _read_records(tmp_path / "audit.jsonl")[0]
    val = rec["params"]["connectionString"]
    assert "supersecret" not in val
    assert "<redacted>" in val
    assert val.startswith("postgresql://admin:<redacted>@")


def test_audit_redacts_password_assignment_in_value(tmp_path: Path):
    log = ToolAuditLog(tmp_path / "audit.jsonl")
    reg = ToolRegistry()

    @reg.tool(name="demo.dsn", description="d", safety=SafetyLevel.READ_ONLY,
              parameters={"type": "object", "properties": {"dsn": {"type": "string"}}})
    def dsn(dsn: str) -> Observation:
        return Observation("demo.dsn", Status.OK, "ok")

    reg.run("demo.dsn", {"dsn": "Server=foo;Password=hunter2;Database=bar"}, audit=log)
    rec = _read_records(tmp_path / "audit.jsonl")[0]
    val = rec["params"]["dsn"]
    assert "hunter2" not in val
    assert "Password=<redacted>" in val


def test_audit_redacts_secrets_in_summary_and_errors(tmp_path: Path):
    # B1: the summary and error strings are also scanned for embedded secrets.
    log = ToolAuditLog(tmp_path / "audit.jsonl")
    obs = Observation(
        "demo.t", Status.ERROR,
        "connect failed postgresql://admin:topsecret@db:5432/app",
        errors=["Password=topsecret rejected"],
    )
    log.record(tool="demo.t", params={}, observation=obs, spec=None, caller="test")
    rec = _read_records(tmp_path / "audit.jsonl")[0]
    assert "topsecret" not in rec["summary"]
    assert "topsecret" not in rec["errors"][0]
    assert "<redacted>" in rec["summary"]
    assert "<redacted>" in rec["errors"][0]
