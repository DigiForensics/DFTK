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

"""Tests for case.verify (audit ledger 2.0 verification)."""

from __future__ import annotations

import json
from pathlib import Path

from dftk.core.audit import ToolAuditLog
from dftk.core.models import Observation, Evidence, Status
from dftk.core.registry import registry
from dftk.primitives import case_verify as cv


def _write_ledger(path: Path, n: int = 3) -> list[Observation]:
    log = ToolAuditLog(str(path))
    made: list[Observation] = []
    for i in range(n):
        obs = Observation(f"tool{i}", Status.OK, f"summary {i}",
                          facts={"i": i},
                          evidence=[Evidence("/evidence/x", "kind", f"v{i}",
                                             source_sha256=("b" * 64))])
        log.record(tool=f"tool{i}", params={"p": i}, observation=obs, spec=None, caller="test")
        made.append(obs)
    return made


def test_registered():
    assert registry.get("case.verify") is not None


def test_valid_ledger(tmp_path):
    led = tmp_path / "ledger.jsonl"
    obs = _write_ledger(led, 3)
    out = cv.case_verify(str(led), [o.to_dict() for o in obs])
    assert out.facts["verdict"] == "VALID", out.facts.get("mismatches")
    assert out.facts["records"] == 3
    assert out.status.value == "ok"
    assert all(c["ok"] for c in out.facts["checks"])


def test_tampered_ledger_detected(tmp_path):
    led = tmp_path / "ledger.jsonl"
    _write_ledger(led, 3)
    lines = led.read_text(encoding="utf-8").strip().splitlines()
    rec = json.loads(lines[1])
    rec["summary"] = "TAMPERED"          # change content, keep hashes
    lines[1] = json.dumps(rec, ensure_ascii=False, sort_keys=True, default=str)
    led.write_text("\n".join(lines) + "\n", encoding="utf-8")

    out = cv.case_verify(str(led))
    assert out.facts["verdict"] == "BROKEN"
    assert out.status.value != "ok"
    assert any("mismatch" in m for m in out.facts["mismatches"])
    assert out.facts["broken_at"] is not None


def test_observation_mismatch(tmp_path):
    led = tmp_path / "ledger.jsonl"
    _write_ledger(led, 2)
    wrong = [{"tool": "tool0", "status": "ok"}, {"tool": "WRONG", "status": "ok"}]
    out = cv.case_verify(str(led), wrong)
    assert out.facts["verdict"] == "BROKEN"
    names = [c["name"] for c in out.facts["checks"]]
    assert "observations_match" in names
    assert any(not c["ok"] for c in out.facts["checks"] if c["name"] == "observations_match")


def test_manifest_count_mismatch(tmp_path):
    led = tmp_path / "ledger.jsonl"
    _write_ledger(led, 2)
    out = cv.case_verify(str(led), None, {"record_count": 5})
    assert out.facts["verdict"] == "BROKEN"
    chk = [c for c in out.facts["checks"] if c["name"] == "manifest_record_count"][0]
    assert not chk["ok"]


def test_missing_ledger(tmp_path):
    out = cv.case_verify(str(tmp_path / "nope.jsonl"))
    assert out.status.value == "error"
    assert out.facts["verdict"] == "BROKEN"
