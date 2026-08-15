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

import hashlib
import json
from pathlib import Path

from dftk.core.audit import ToolAuditLog
from dftk.core.registry import registry
from dftk.primitives.files import file_hash


def _read_records(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8").strip()
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def test_file_hash_sets_source_sha256(tmp_path: Path):
    f = tmp_path / "sample.bin"
    payload = b"chain-of-custody regression"
    f.write_bytes(payload)
    expected = hashlib.sha256(payload).hexdigest()

    obs = file_hash(str(f))
    assert obs.status.value == "ok"
    # The observation must publish SHA-256 provenance so the registry can stamp it
    # onto evidence items and the audit ledger can record it.
    assert obs.meta.get("source_sha256") == expected
    # The Evidence object itself is stamped by registry.run (see
    # test_file_hash_propagates_to_evidence_via_registry); the direct call only
    # advertises provenance via meta.
    assert obs.facts["hashes"]["sha256"] == expected


def test_file_hash_propagates_to_evidence_via_registry(tmp_path: Path):
    f = tmp_path / "sample.bin"
    payload = b"registry propagation"
    f.write_bytes(payload)
    expected = hashlib.sha256(payload).hexdigest()

    out = registry.run("file.hash", {"path": str(f)})
    assert out.status.value == "ok"
    assert out.evidence, "file.hash should return evidence"
    # registry.run stamps meta.source_sha256 onto every evidence item.
    for ev in out.evidence:
        assert ev.source_sha256 == expected


def test_file_hash_audit_records_evidence_hashes(tmp_path: Path):
    f = tmp_path / "sample.bin"
    payload = b"audit ledger regression"
    f.write_bytes(payload)
    expected = hashlib.sha256(payload).hexdigest()

    log = ToolAuditLog(tmp_path / "audit.jsonl")
    out = registry.run("file.hash", {"path": str(f)}, audit=log)
    assert out.status.value == "ok"

    recs = _read_records(tmp_path / "audit.jsonl")
    assert len(recs) == 1
    rec = recs[0]
    assert rec["tool"] == "file.hash"
    # Broken contract: evidence_hashes was empty because file.hash never set meta.source_sha256.
    assert rec["evidence_hashes"] == [expected]


def test_file_hash_without_sha256_does_not_synthesize(tmp_path: Path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"md5 only")
    obs = file_hash(str(f), algorithms=["md5"])
    assert "sha256" not in obs.facts["hashes"]
    # When SHA-256 was not requested, no provenance hash should be published.
    assert "source_sha256" not in obs.meta
    assert all(not ev.source_sha256 for ev in obs.evidence)
