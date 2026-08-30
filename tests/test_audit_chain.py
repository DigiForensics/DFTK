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
import tempfile
from pathlib import Path

import pytest

from dftk.core.audit import ToolAuditLog
from dftk.core.models import Observation, Status, SafetyLevel, ToolSpec


def _spec(name: str, safety: SafetyLevel = SafetyLevel.READ_ONLY) -> ToolSpec:
    return ToolSpec(name, "desc", safety, {"type": "object", "properties": {}})


def _obs(name: str, status: Status = Status.OK) -> Observation:
    return Observation(name, status, "summary", evidence=[], errors=[])


def test_chain_valid_after_several_records(tmp_path: Path):
    log = ToolAuditLog(tmp_path / "audit.jsonl")
    for i in range(5):
        log.record(tool=f"t{i}", params={"x": i}, observation=_obs(f"t{i}"),
                   spec=_spec(f"t{i}"), caller="test")
    res = ToolAuditLog.verify(tmp_path / "audit.jsonl")
    assert res["valid"] is True
    assert res["records"] == 5


def test_tamper_middle_record_breaks_chain(tmp_path: Path):
    log = ToolAuditLog(tmp_path / "audit.jsonl")
    for i in range(3):
        log.record(tool=f"t{i}", params={"x": i}, observation=_obs(f"t{i}"),
                   spec=_spec(f"t{i}"), caller="test")
    # Corrupt the middle (2nd) line's status field.
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[1])
    rec["status"] = "ERROR"
    lines[1] = json.dumps(rec, ensure_ascii=False, sort_keys=True)
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

    res = ToolAuditLog.verify(tmp_path / "audit.jsonl")
    assert res["valid"] is False
    assert res["broken_at"] == 2
    assert "record_hash" in res["reason"]


def test_record_carries_chain_envelope(tmp_path: Path):
    log = ToolAuditLog(tmp_path / "audit.jsonl")
    log.record(tool="t0", params={"p": 1}, observation=_obs("t0"), spec=_spec("t0"), caller="test")
    line = json.loads((tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert line["sequence"] == 1
    assert line["previous_hash"]
    assert line["record_hash"]
    assert "params_digest" in line and "result_digest" in line and "evidence_digest" in line


def test_derived_artifacts_feed_evidence_digest(tmp_path: Path):
    from dftk.core.provenance import ProvenanceIndex
    idx = ProvenanceIndex()
    art = idx.add(source_artifact="", locator="file:x", tool="t", version="3.5.0", sha256="e" * 64)
    obs = _obs("t0")
    obs.derived_artifacts.append(art)
    log = ToolAuditLog(tmp_path / "audit.jsonl")
    log.record(tool="t0", params={}, observation=obs, spec=_spec("t0"), caller="test")
    res = ToolAuditLog.verify(tmp_path / "audit.jsonl")
    assert res["valid"] is True
