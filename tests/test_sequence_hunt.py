"""Forensic sequence correctness, coverage, and evidence-boundary regressions."""
import copy
import hashlib
import json

import pytest

import dftk
from dftk.core.models import Status
from dftk.core import sequence_hunt, timeline_core


def rule(**changes):
    return {"id": "download-execute-connect", "group_by": ["host", "user"],
            "within_seconds": 120, "steps": [
                {"kind": "download"}, {"kind": "execute"}, {"kind": "connect"}], **changes}


def event(epoch, kind, **changes):
    return {"epoch": epoch, "kind": kind, "host": "host-a", "user": "alice", **changes}


def run(events, rules=None, **params):
    return dftk.get_registry().run("timeline.hunt_sequences", {
        "inline": [{"source": "test", "events": events}],
        "rules": rules or [rule()], **params})


def test_cross_source_chain_keeps_fields_and_original_file_locators(tmp_path):
    first = tmp_path / "browser.json"
    raw = json.dumps({"tool": "browser", "facts": {"events": [
        event(10, "download", path="/tmp/payload", locator="sqlite:downloads:42")
    ]}}).encode()
    first.write_bytes(raw)
    obs = dftk.get_registry().run("timeline.hunt_sequences", {
        "files": [str(first)], "inline": [{"source": "host", "events": [
            event(20, "execute", confidence=0.6), event(25, "connect")]}], "rules": [rule()]})
    assert obs.status == Status.OK
    match = obs.facts["matches"][0]
    assert match["duration_seconds"] == 15
    assert match["group"] == {"host": "host-a", "user": "alice"}
    assert match["confidence"] == 0.6
    assert match["input_refs"][0] == {
        "source": str(first), "locator": "facts.events[0]",
        "source_sha256": hashlib.sha256(raw).hexdigest()}
    assert obs.evidence[0].value["locator"] == "sqlite:downloads:42"
    assert obs.evidence[0].source_sha256 == hashlib.sha256(raw).hexdigest()
    assert len(obs.evidence) == 3


@pytest.mark.parametrize("events", [
    [event(10, "download"), event(20, "execute", user="bob"), event(30, "connect")],
    [event(10, "download"), event(20, "execute", host="host-b"), event(30, "connect")],
    [event(10, "download"), event(20, "execute", user=None), event(30, "connect")],
    [event(10, "download"), event(20, "execute", user=""), event(30, "connect")],
    [event(10, "download", user=True), event(20, "execute", user=1), event(30, "connect", user=1)],
    [event(10, "download"), event(10, "execute"), event(30, "connect")],
    [event(10, "download"), event(20, "execute"), event(131, "connect")],
    [event(10, "execute"), event(20, "download"), event(30, "connect")],
])
def test_does_not_infer_chain_across_missing_entities_time_or_order(events):
    obs = run(events)
    assert obs.status == Status.OK
    assert obs.facts["match_count"] == 0


def test_window_inclusive_overlap_and_nested_exact_selectors():
    events = [event(0, "download"), event(1, "download"),
              event(50, "execute", process={"name": "sh"}), event(120, "connect")]
    original = copy.deepcopy(events)
    obs = run(events, [rule(steps=[{"kind": "download"},
                                 {"kind": "execute", "process.name": ["bash", "sh"]},
                                 {"kind": "connect"}])])
    assert obs.facts["match_count"] == 2
    assert {tuple(m["event_indices"]) for m in obs.facts["matches"]} == {(0, 2, 3), (1, 2, 3)}
    assert events == original


@pytest.mark.parametrize("rules", [
    [rule(), rule()], [rule(steps=[{}, {"kind": "connect"}])],
    [rule(steps=[{"kind": {"regex": ".*"}}, {"kind": "connect"}])],
    [rule(within_seconds=0)], [rule(group_by=[])], [rule(steps=[{"kind": "x"}])],
    [rule(steps=[{"kind": []}, {"kind": "connect"}])],
    [rule(steps=[{"process..name": "sh"}, {"kind": "connect"}])],
])
def test_invalid_rules_are_explicit_errors(rules):
    obs = run([], rules)
    assert obs.status == Status.ERROR
    assert obs.errors


@pytest.mark.parametrize("budget", ["matches", "states", "comparisons"])
def test_resource_limits_report_partial_coverage(monkeypatch, budget):
    params = {}
    if budget == "matches":
        params["limit"] = 1
    elif budget == "states":
        monkeypatch.setattr(sequence_hunt, "MAX_STATES", 1)
    else:
        monkeypatch.setattr(sequence_hunt, "MAX_COMPARISONS", 1)
    obs = run([event(1, "download"), event(2, "download"),
               event(3, "execute"), event(4, "connect")], **params)
    assert obs.status == Status.PARTIAL
    assert obs.facts["coverage"]["truncated"]
    assert obs.warnings


def test_event_limit_and_bad_timestamp_do_not_look_like_complete_negative():
    obs = run([event(1, "download"), event(2, "execute"), event(3, "connect")], event_limit=2)
    assert obs.status == Status.PARTIAL
    assert obs.facts["coverage"]["omitted"] == 1
    obs = run([event("broken", "download"), event(2, "execute")])
    assert obs.status == Status.PARTIAL
    assert obs.facts["coverage"]["skipped"] == 1


def test_inline_cannot_open_files(tmp_path):
    secret = tmp_path / "outside.json"
    secret.write_text(json.dumps({"facts": {"events": [event(1, "download")]}}))
    for tool in ("timeline.merge", "timeline.hunt_sequences"):
        params = {"inline": [{"file": str(secret)}]}
        if tool.endswith("hunt_sequences"):
            params["rules"] = [rule()]
        obs = dftk.get_registry().run(tool, params)
        assert obs.status == Status.ERROR
        assert "inline file references" in str(obs.errors)


def test_merge_reports_read_failures_truncation_and_malformed_bundles(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("[]")
    result = timeline_core.merge_events([
        {"file": str(bad)}, {"events": "bad"},
        {"source": "a", "events": [event(5, "x"), event(1, "x")]}], limit=1)
    assert len(result["errors"]) == 2
    assert result["events"][0]["epoch"] == 1
    assert result["truncated"] and result["omitted"] == 1
    obs = dftk.get_registry().run("timeline.merge", {"files": [str(bad)]})
    assert obs.status == Status.ERROR


def test_file_read_bound_and_event_scan_bound_are_explicit(monkeypatch, tmp_path):
    monkeypatch.setattr(timeline_core, "MAX_SOURCE_BYTES", 10)
    large = tmp_path / "large.json"
    large.write_text(" " * 11)
    out = timeline_core.merge_events([{"file": str(large)}])
    assert "byte input bound" in out["errors"][0]
    monkeypatch.setattr(timeline_core, "DEFAULT_LIMIT", 2)
    out = timeline_core.merge_events([{"events": [event(i, "x") for i in range(3)]}], limit=2)
    assert out["scanned"] == 2
    assert out["truncated"]


@pytest.mark.parametrize("value", [True, float("inf"), float("nan"), 10**100, "bad"])
def test_invalid_epoch_is_not_a_normalized_event(value):
    out = timeline_core.merge_events([{"events": [event(value, "x")]}])
    assert out["events"] == []
    assert out["skipped"] == 1


def test_mixed_sources_are_partial_when_one_file_cannot_be_read(tmp_path):
    obs = dftk.get_registry().run("timeline.hunt_sequences", {
        "rules": [rule()], "files": [str(tmp_path / "missing.json")],
        "inline": [{"events": [event(1, "download"), event(2, "execute"), event(3, "connect")]}]})
    assert obs.status == Status.PARTIAL
    assert obs.facts["match_count"] == 1
    assert obs.errors


def test_timezone_normalization_and_assumption_are_explicit():
    obs = run([
        event("unused", "download", time="2026-01-01T08:00:00+08:00"),
        event("unused", "execute", time="2026-01-01T00:00:30Z"),
        event("unused", "connect", time="2026-01-01T00:01:00"),
    ])
    assert obs.status == Status.PARTIAL
    assert obs.facts["match_count"] == 1
    assert obs.facts["matches"][0]["duration_seconds"] == 60
    assert obs.facts["events"][0]["original_time"] == "2026-01-01T08:00:00+08:00"
    assert obs.facts["events"][-1]["time_basis"] == "iso8601_assumed_utc"
    assert any("UTC was assumed" in warning for warning in obs.warnings)


def test_malformed_confidence_does_not_become_full_confidence():
    obs = run([event(1, "download", confidence="unknown"),
               event(2, "execute"), event(3, "connect")])
    assert obs.facts["matches"][0]["confidence"] == 0


def test_case_timeline_preserves_fields_and_reports_incomplete_coverage(tmp_path):
    from dftk.core.case import CaseSession
    session = CaseSession(tmp_path)
    case_id = session.new("sequence coverage")["case_id"]
    session.run(case_id, "timeline.merge", {"inline": [{"events": [
        event(1, "download"), event(2, "execute")]}]})
    obs = session.timeline(case_id, limit=1)
    assert obs.status == Status.PARTIAL
    assert obs.facts["truncated"]
    assert obs.facts["events"][0]["user"] == "alice"


def test_sequences_agree_with_independent_exhaustive_oracle():
    from itertools import combinations
    from random import Random
    rng = Random(42)
    for _ in range(30):
        events = [event(index, rng.choice(["download", "execute", "connect"]),
                        user=rng.choice(["alice", "bob"])) for index in range(9)]
        expected = {indices for indices in combinations(range(9), 3)
                    if [events[i]["kind"] for i in indices] == ["download", "execute", "connect"]
                    and len({events[i]["user"] for i in indices}) == 1
                    and indices[-1] - indices[0] <= 5}
        obs = run(events, [rule(within_seconds=5)])
        actual = {tuple(match["event_indices"]) for match in obs.facts["matches"]}
        assert obs.status == Status.OK
        assert actual == expected


def test_mcp_rule_path_values_are_data_and_inline_file_references_fail(tmp_path):
    from dftk.mcp_server import DFTKMCPGateway
    gateway = DFTKMCPGateway(root=tmp_path)
    events = [event(1, "download", path="/recorded/host/file"), event(2, "connect")]
    params = {"inline": [{"events": events}], "rules": [rule(steps=[
        {"kind": "download", "path": "/recorded/host/file"}, {"kind": "connect"}])]}
    result = gateway.run("timeline.hunt_sequences", params)
    assert result["observation"]["status"] == "ok"
    assert result["observation"]["facts"]["match_count"] == 1
    params["inline"] = [{"file": "/outside/evidence.json"}]
    result = gateway.run("timeline.hunt_sequences", params)
    assert result["observation"]["status"] == "error"
    assert "inline file references" in str(result["observation"]["errors"])


@pytest.mark.parametrize("status", ["partial", "unsupported", "error", "blocked"])
def test_incomplete_upstream_observations_cannot_produce_complete_negative(tmp_path, status):
    source = tmp_path / "incomplete.json"
    source.write_text(json.dumps({"status": status, "facts": {"events": []}}))
    obs = dftk.get_registry().run("timeline.hunt_sequences", {
        "files": [str(source)], "rules": [rule()],
        "inline": [{"events": [event(1, "execute")]}]})
    assert obs.status == Status.PARTIAL
    assert obs.facts["match_count"] == 0
    assert any(f"status={status}" in warning for warning in obs.warnings)
