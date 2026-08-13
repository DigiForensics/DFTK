from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from dftk.catalog import load_builtin_tools
from dftk.core.case import CaseSession


def test_case_run_sequence_is_serialized(tmp_path: Path):
    load_builtin_tools()
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"DFTK case concurrency")
    session = CaseSession(tmp_path / ".dftk")
    case_id = session.new("concurrency")["case_id"]

    def run_once(_index: int):
        obs = session.run(case_id, "artifact.inspect", {"path": str(evidence)})
        assert obs.status.value in {"ok", "partial"}

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(run_once, range(12)))

    manifest = session.show(case_id)
    assert [run["seq"] for run in manifest["runs"]] == list(range(1, 13))
    assert len({run["artifact"] for run in manifest["runs"]}) == 12


def test_case_read_run(tmp_path: Path):
    load_builtin_tools()
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"read run")
    session = CaseSession(tmp_path / ".dftk")
    case_id = session.new("read-run")["case_id"]
    session.run(case_id, "artifact.inspect", {"path": str(evidence)})
    entry, observation = session.read_run(case_id, 1)
    assert entry["seq"] == 1
    assert observation["tool"] == "artifact.inspect"


def test_missing_case_does_not_create_directory(tmp_path: Path):
    load_builtin_tools()
    session = CaseSession(tmp_path / ".dftk")
    missing = "case-missing"
    try:
        session.run(missing, "artifact.inspect", {"path": str(tmp_path / "x")})
    except Exception:
        pass
    else:
        raise AssertionError("missing case unexpectedly ran")
    assert not (session.cases_dir / missing).exists()


def test_timeline_rejects_manifest_artifact_escape(tmp_path: Path):
    import json
    import pytest
    from dftk.core.case import CaseError

    session = CaseSession(tmp_path / ".dftk")
    case_id = session.new("tampered")['case_id']
    manifest_path = session.cases_dir / case_id / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["runs"].append({
        "seq": 1,
        "tool": "artifact.inspect",
        "params": {},
        "artifact": "../../outside.json",
        "status": "ok",
        "ran_at": "2026-01-01T00:00:00+00:00",
    })
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(CaseError):
        session.timeline(case_id)
