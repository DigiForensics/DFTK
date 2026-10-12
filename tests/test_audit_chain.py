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

"""Hash-chain and verification tests for the chain-of-custody ledger."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from dftk import get_registry
from dftk.cli import main
from dftk.core.audit import (
    LEDGER_GENESIS_HASH,
    ToolAuditLog,
    compute_record_hash,
    seal_ledger,
    verify_ledger,
)
from dftk.core.models import Observation, Status

TOOLS = ("file.hash", "file.strings", "artifact.inspect")


def _append(path: Path, tools=TOOLS, *, caller: str = "test") -> ToolAuditLog:
    """Append one record per tool name using a fresh ledger writer."""
    log = ToolAuditLog(path)
    for name in tools:
        log.record(
            tool=name,
            params={"path": "evidence.bin"},
            observation=Observation(name, Status.OK, f"ran {name}"),
            caller=caller,
        )
    return log


def _lines(path: Path) -> list[str]:
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _rewrite(path: Path, lines: list[str]) -> None:
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")


def test_chain_links_records_across_writers(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    _append(path, TOOLS[:1])
    _append(path, TOOLS[1:])  # a second writer must continue the same chain
    records = [json.loads(line) for line in _lines(path)]

    assert [r["seq"] for r in records] == [0, 1, 2]
    assert records[0]["prev_hash"] == LEDGER_GENESIS_HASH
    assert records[1]["prev_hash"] == records[0]["record_hash"]
    assert records[2]["prev_hash"] == records[1]["record_hash"]
    for record in records:
        assert compute_record_hash(record) == record["record_hash"]

    report = verify_ledger(path)
    assert report["verdict"] == "intact"
    assert report["ok"] is True
    assert report["defects"] == []
    assert report["records"] == 3
    assert report["chained_records"] == 3
    assert report["legacy_records"] == 0
    assert report["last_seq"] == 2
    assert report["last_record_hash"] == records[2]["record_hash"]
    assert report["tools"] == {"artifact.inspect": 1, "file.hash": 1, "file.strings": 1}


def test_edited_record_is_detected(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    _append(path)
    lines = _lines(path)
    lines[1] = lines[1].replace("file.strings", "file.stringz")
    _rewrite(path, lines)

    report = verify_ledger(path)
    assert report["ok"] is False
    assert report["verdict"] == "defective"
    assert any("record_hash mismatch" in defect for defect in report["defects"])
    assert any("chain break" in defect for defect in report["defects"])


def test_deleted_record_is_detected(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    _append(path)
    lines = _lines(path)
    del lines[1]
    _rewrite(path, lines)

    report = verify_ledger(path)
    assert report["verdict"] == "defective"
    assert report["records"] == 2
    assert any("chain break" in defect for defect in report["defects"])
    assert any("sequence gap" in defect for defect in report["defects"])


def test_reordered_records_are_detected(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    _append(path)
    lines = _lines(path)
    _rewrite(path, [lines[0], lines[2], lines[1]])

    report = verify_ledger(path)
    assert report["verdict"] == "defective"
    assert any("chain break" in defect for defect in report["defects"])


def test_truncated_tail_needs_a_seal(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    _append(path)
    seal_path = tmp_path / "ledger.seal.json"
    seal_path.write_text(json.dumps(seal_ledger(path)), encoding="utf-8")

    report = verify_ledger(path, seal=seal_path)
    assert report["verdict"] == "intact"
    assert report["seal"]["loaded"] is True
    assert report["seal"]["matches"] is True

    # Dropping the final record leaves the remaining chain internally
    # consistent: without an external anchor the file cannot prove its own tail.
    _rewrite(path, _lines(path)[:2])
    assert verify_ledger(path)["ok"] is True

    sealed_report = verify_ledger(path, seal=seal_path)
    assert sealed_report["verdict"] == "defective"
    assert sealed_report["seal"]["matches"] is False
    assert any("seal mismatch" in defect for defect in sealed_report["defects"])


def test_legacy_records_are_reported_not_condemned(tmp_path: Path):
    path = tmp_path / "legacy.jsonl"
    path.write_text(
        json.dumps({"ts": "2026-01-01T00:00:00+00:00", "tool": "file.hash", "caller": "old"}) + "\n",
        encoding="utf-8",
    )

    report = verify_ledger(path)
    assert report["verdict"] == "legacy"
    assert report["ok"] is False
    assert report["legacy_records"] == 1
    assert report["chained_records"] == 0
    assert report["defects"] == []  # unchained history is a caveat, not tampering
    assert any("legacy record" in warning for warning in report["warnings"])

    # A current writer appends a chained record after the legacy history.
    _append(path, TOOLS[:1])
    report = verify_ledger(path)
    assert report["legacy_records"] == 1
    assert report["chained_records"] == 1
    assert report["chain_starts"] == 1
    assert report["defects"] == []


def test_unchained_record_after_chain_is_a_defect(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    _append(path, TOOLS[:1])
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": "2026-09-13T00:00:00+00:00", "tool": "file.hash"}) + "\n")

    report = verify_ledger(path)
    assert report["verdict"] == "defective"
    assert any("downgraded" in defect for defect in report["defects"])


def test_partial_tail_is_reported_as_partial(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    _append(path, TOOLS[:1])
    with path.open("a", encoding="utf-8") as fh:
        fh.write('{"ts": "2026-09-13T00:00')  # interrupted append, no newline

    report = verify_ledger(path)
    assert report["verdict"] == "partial"
    assert report["ok"] is False
    assert report["defects"] == []
    assert any("partial line" in warning for warning in report["warnings"])


def test_concurrent_appends_keep_the_chain_contiguous(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    writers, per_writer = 6, 5
    logs: list[ToolAuditLog] = []
    logs_lock = threading.Lock()

    def worker(index: int) -> None:
        log = ToolAuditLog(path)
        with logs_lock:
            logs.append(log)
        for step in range(per_writer):
            log.record(
                tool=f"demo.{index}",
                params={"step": step},
                observation=Observation("demo", Status.OK, "ok"),
                caller=f"t{index}",
            )

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(writers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    report = verify_ledger(path)
    dropped = sum(log.dropped for log in logs)
    # The contract is that no record disappears silently: each one is either in
    # the file or counted as dropped and explained by last_error. A hostile
    # environment can deny an individual append (Windows does this under load);
    # that is reported rather than hidden, so it must not fail this test — but a
    # record that is neither written nor counted would.
    assert report["records"] + dropped == writers * per_writer
    assert report["defects"] == [], report["defects"]
    assert report["ok"] is True
    if dropped == 0:
        assert report["last_seq"] == writers * per_writer - 1


def test_case_report_embeds_a_verifiable_ledger_digest(tmp_path: Path):
    """A case report should be able to attest to its own chain of custody."""
    from dftk.catalog import load_builtin_tools
    from dftk.core.case import CaseSession

    load_builtin_tools()
    session = CaseSession(tmp_path / ".dftk")
    case_id = session.new("chain")["case_id"]
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "f.txt").write_text("hello", encoding="utf-8")
    ledger = tmp_path / "ledger.jsonl"

    session.run(case_id, "timeline.file_metadata", {"root": str(evidence)}, audit=ledger)

    report = json.loads(session.export(case_id, fmt="json"))
    assert report["audit"]["verdict"] == "intact"
    assert report["audit"]["records"] == 1
    assert report["audit"]["file_sha256"] == verify_ledger(ledger)["file_sha256"]

    markdown = session.export(case_id, fmt="md")
    assert "Audit ledger: intact" in markdown

    # Tampering after export is visible because the digest travels with the report.
    lines = _lines(ledger)
    _rewrite(ledger, [lines[0].replace("timeline.file_metadata", "timeline.file_metaX")])
    exported = json.loads(session.export(case_id, fmt="json"))
    assert exported["audit"]["verdict"] == "defective"
    assert exported["audit"]["file_sha256"] != report["audit"]["file_sha256"]


def test_ledger_verify_capability_reports_verdict(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    _append(path)

    obs = get_registry().run("custody.ledger_verify", {"path": str(path)})
    assert obs.status == Status.OK
    assert obs.facts["verdict"] == "intact"
    assert obs.facts["chain_ok"] is True
    assert obs.facts["records"] == 3
    assert obs.facts["defects"] == []
    assert obs.evidence and obs.evidence[0].source_sha256 == obs.facts["file_sha256"]
    assert obs.meta["source_sha256"] == obs.facts["file_sha256"]

    lines = _lines(path)
    lines[0] = lines[0].replace("file.hash", "file.hashX")
    _rewrite(path, lines)
    tampered = get_registry().run("custody.ledger_verify", {"path": str(path)})
    # A negative integrity finding is a result, not a tool failure.
    assert tampered.status == Status.OK
    assert tampered.facts["chain_ok"] is False
    assert any("LEDGER DEFECT" in warning for warning in tampered.warnings)


def test_ledger_verify_capability_reports_unreadable_ledger(tmp_path: Path):
    obs = get_registry().run("custody.ledger_verify", {"path": str(tmp_path / "missing.jsonl")})
    assert obs.status == Status.ERROR
    assert obs.facts["verdict"] == "unreadable"
    assert obs.errors


def test_cli_audit_verify_exit_codes(tmp_path: Path, capsys):
    path = tmp_path / "ledger.jsonl"
    _append(path)

    assert main(["audit", "verify", str(path)]) == 0
    capsys.readouterr()

    lines = _lines(path)
    lines[1] = lines[1].replace("file.strings", "file.stringz")
    _rewrite(path, lines)
    assert main(["audit", "verify", str(path)]) == 1
    capsys.readouterr()

    assert main(["audit", "verify", str(tmp_path / "missing.jsonl")]) == 2
    capsys.readouterr()


def test_cli_audit_seal_round_trip(tmp_path: Path, capsys):
    path = tmp_path / "ledger.jsonl"
    _append(path)

    assert main(["audit", "seal", str(path)]) == 0
    seal_path = Path(str(path) + ".seal.json")
    assert seal_path.is_file()
    capsys.readouterr()

    assert main(["audit", "verify", str(path), "--seal", str(seal_path)]) == 0
    capsys.readouterr()

    _rewrite(path, _lines(path)[:2])
    assert main(["audit", "verify", str(path), "--seal", str(seal_path)]) == 1
    capsys.readouterr()

    # Truncation alone leaves the chain internally consistent, so the seal is
    # what condemns it; an edited record is defective on its own and must not
    # be sealed at all.
    lines = _lines(path)
    lines[0] = lines[0].replace("file.hash", "file.hashX")
    _rewrite(path, lines)
    assert main(["audit", "seal", str(path), "--out", str(tmp_path / "defective.seal.json")]) == 1
    capsys.readouterr()
    assert main(["audit", "seal", str(tmp_path / "missing.jsonl")]) == 2
    capsys.readouterr()
    assert not (tmp_path / "defective.seal.json").exists()
