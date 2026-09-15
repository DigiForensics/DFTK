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
from dftk.core.case import CaseError, CaseSession, FINDING_STATUSES


def _run_hash(sess, case_id, tmp_path, audit=None):
    """Run file.hash on a fresh file and return the run sequence number."""
    evidence = tmp_path / "evidence"
    evidence.mkdir(exist_ok=True)
    f = evidence / "blob.bin"
    f.write_bytes(b"fixed-content-for-hashing\n")
    obs = sess.run(
        case_id,
        "file.hash",
        {"path": str(f)},
        audit=audit,
        caller=f"case:{case_id}",
    )
    assert obs.status.value == "ok"
    manifest = sess._manifest(case_id)
    return manifest["runs"][-1]["seq"]


def test_finding_status_enum_matches_skill_contract():
    assert FINDING_STATUSES == (
        "VERIFIED",
        "SUPPORTED",
        "CANDIDATE",
        "UNRESOLVED",
        "UNSUPPORTED",
    )


def test_add_finding_captures_evidence_hash(tmp_path):
    load_builtin_tools()
    sess = CaseSession(tmp_path / ".dftk")
    case_id = sess.new("finding")["case_id"]
    seq = _run_hash(sess, case_id, tmp_path)

    finding = sess.add_finding(
        case_id,
        "blob.bin hashes to a stable SHA-256",
        "VERIFIED",
        [{"run_seq": seq, "evidence_index": 0}],
        need_verify="",
        analyst="agent:demo",
    )
    assert finding["id"] == "F001"
    assert finding["status"] == "VERIFIED"
    assert finding["citations"][0]["run_seq"] == seq
    # The evidence source_sha256 was captured at registration time.
    assert finding["citations"][0]["evidence_sha256"]

    report = sess.findings_report(case_id)
    assert report["finding_count"] == 1
    assert report["stale_citation_count"] == 0
    cit = report["findings"][0]["citations"][0]
    assert cit["resolved"] is True
    assert cit["stale"] is False
    assert cit["current_sha256"] == finding["citations"][0]["evidence_sha256"]


def test_add_finding_rejects_unknown_status_and_empty_claim(tmp_path):
    load_builtin_tools()
    sess = CaseSession(tmp_path / ".dftk")
    case_id = sess.new("finding")["case_id"]
    seq = _run_hash(sess, case_id, tmp_path)
    citations = [{"run_seq": seq, "evidence_index": 0}]

    for bad in ("VERIFY", "", "verified", "CONFIRMED"):
        try:
            sess.add_finding(case_id, "x", bad, citations)
        except CaseError:
            pass
        else:
            raise AssertionError(f"expected CaseError for status {bad!r}")

    try:
        sess.add_finding(case_id, "  ", "VERIFIED", citations)
    except CaseError:
        pass
    else:
        raise AssertionError("expected CaseError for empty claim")


def test_add_finding_rejects_dangling_citation(tmp_path):
    load_builtin_tools()
    sess = CaseSession(tmp_path / ".dftk")
    case_id = sess.new("finding")["case_id"]
    seq = _run_hash(sess, case_id, tmp_path)

    # Bad run sequence.
    try:
        sess.add_finding(case_id, "x", "SUPPORTED", [{"run_seq": 999, "evidence_index": 0}])
    except CaseError:
        pass
    else:
        raise AssertionError("expected CaseError for unknown run_seq")

    # Out-of-range evidence index.
    try:
        sess.add_finding(case_id, "x", "SUPPORTED", [{"run_seq": seq, "evidence_index": 50}])
    except CaseError:
        pass
    else:
        raise AssertionError("expected CaseError for out-of-range evidence index")


def test_stale_citation_flagged_when_evidence_hash_changes(tmp_path):
    load_builtin_tools()
    sess = CaseSession(tmp_path / ".dftk")
    case_id = sess.new("finding")["case_id"]
    seq = _run_hash(sess, case_id, tmp_path)

    sess.add_finding(
        case_id,
        "stable hash",
        "VERIFIED",
        [{"run_seq": seq, "evidence_index": 0}],
    )

    # Simulate the underlying evidence having been altered after registration:
    # rewrite the run artifact with a different source_sha256 on evidence[0].
    entry, observation_dict = sess.read_run(case_id, seq)
    observation_dict["evidence"][0]["source_sha256"] = "0" * 64
    artifact = sess._run_artifact_path(case_id, entry)
    artifact.write_text(json.dumps(observation_dict, ensure_ascii=False, indent=2), encoding="utf-8")

    report = sess.findings_report(case_id)
    assert report["stale_citation_count"] == 1
    assert report["findings"][0]["stale_citations"] == 1
    assert report["findings"][0]["citations"][0]["stale"] is True


def test_export_includes_conclusions_section(tmp_path):
    load_builtin_tools()
    sess = CaseSession(tmp_path / ".dftk")
    case_id = sess.new("finding")["case_id"]
    seq = _run_hash(sess, case_id, tmp_path)
    sess.add_finding(
        case_id,
        "blob is hashed",
        "SUPPORTED",
        [{"run_seq": seq, "evidence_index": 0}],
        need_verify="cross-check with a second tool",
    )

    report = json.loads(sess.export(case_id, fmt="json"))
    assert "conclusions" in report
    assert report["conclusions"]["finding_count"] == 1
    assert report["conclusions"]["findings"][0]["status"] == "SUPPORTED"

    md = sess.export(case_id, fmt="md")
    assert "## Conclusions & traceability" in md
    assert "blob is hashed" in md

    # No findings registered -> the report mentions none.
    sess2 = CaseSession(tmp_path / ".dftk2")
    case_id2 = sess2.new("empty")["case_id"]
    md2 = sess2.export(case_id2, fmt="md")
    assert "## Conclusions: none registered yet" in md2


def test_answers_produces_answer_slots_shape(tmp_path):
    load_builtin_tools()
    sess = CaseSession(tmp_path / ".dftk")
    case_id = sess.new("finding")["case_id"]
    seq = _run_hash(sess, case_id, tmp_path)
    sess.add_finding(
        case_id,
        "blob is hashed",
        "VERIFIED",
        [{"run_seq": seq, "evidence_index": 0}],
    )

    payload = sess.answers(case_id)
    assert payload["schema"] == "dftk.case.answers/1"
    slots = payload["slots"]
    assert "F001" in slots
    slot = slots["F001"]
    assert slot["status"] == "VERIFIED"
    assert slot["question"] == "blob is hashed"
    assert slot["evidence"] and slot["evidence"][0]["hash"]
    assert slot["evidence"][0]["path"].endswith(".json")

    # Writes to disk when --out is given.
    out = tmp_path / "answers" / "answer_slots.json"
    sess.answers(case_id, out=str(out))
    assert out.exists()
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["slots"]["F001"]["status"] == "VERIFIED"
