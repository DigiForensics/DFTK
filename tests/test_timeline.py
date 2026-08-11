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

from dftk.catalog import load_builtin_tools
from dftk.core.registry import registry
from dftk.core.models import Status
from dftk.core.timeline_core import merge_events, _to_epoch


def test_epoch_parsing_variants():
    load_builtin_tools()
    assert _to_epoch({"epoch": 123.0}) == 123.0
    assert _to_epoch({"time": 123.0}) == 123.0
    assert _to_epoch({"time": "2020-01-01T00:00:00Z"}) == 1577836800.0
    # naive ISO is treated as UTC
    assert _to_epoch({"time": "2020-01-01T00:00:00"}) == 1577836800.0
    assert _to_epoch({"no_time": True}) is None
    assert _to_epoch({}) is None


def test_merge_inline_sorts_and_attributes():
    load_builtin_tools()
    sources = [
        {"source": "a", "events": [
            {"time": "2020-01-01T00:00:00Z", "kind": "x", "path": "p1"},
            {"epoch": 1.0, "kind": "y", "path": "p2"},
        ]},
        {"source": "b", "events": [{"epoch": 2.0, "kind": "z", "path": "p3"}]},
    ]
    out = merge_events(sources)
    assert [e["epoch"] for e in out["events"]] == [1.0, 2.0, 1577836800.0]
    assert out["per_source"] == {"a": 2, "b": 1}
    assert out["span"]["count"] == 3
    assert out["skipped"] == 0


def test_merge_skips_timestampless_events():
    out = merge_events([{"source": "a", "events": [{"kind": "no-ts"}, {"epoch": 5.0}]}])
    assert out["skipped"] == 1
    assert len(out["events"]) == 1


def test_merge_limit_is_applied():
    events = [{"epoch": float(i)} for i in range(100)]
    out = merge_events([{"source": "a", "events": events}], limit=10)
    assert len(out["events"]) == 10


def test_timeline_merge_tool_end_to_end():
    load_builtin_tools()
    obs = registry.run("timeline.merge", {
        "inline": [
            {"source": "fs", "events": [{"epoch": 30.0, "kind": "mtime", "path": "a"}]},
            {"source": "auth", "events": [{"epoch": 10.0, "kind": "login", "path": "b"}]},
        ]
    })
    assert obs.status == Status.OK
    assert obs.facts["events"][0]["epoch"] == 10.0
    assert obs.facts["source_count"] == 2


def test_timeline_merge_from_file(tmp_path):
    load_builtin_tools()
    obs_file = tmp_path / "run.json"
    obs_file.write_text(__import__("json").dumps({
        "tool": "timeline.file_metadata",
        "status": "ok",
        "facts": {"events": [
            {"epoch": 100.0, "kind": "mtime", "path": "a"},
            {"epoch": 50.0, "kind": "mtime", "path": "b"},
        ]},
        "evidence": [], "warnings": [], "errors": [], "meta": {},
    }), encoding="utf-8")
    obs = registry.run("timeline.merge", {"files": [str(obs_file)]})
    assert obs.status == Status.OK
    assert [e["epoch"] for e in obs.facts["events"]] == [50.0, 100.0]
    assert obs.facts["per_source"] == {"timeline.file_metadata": 2}


def test_timeline_merge_empty_is_partial():
    load_builtin_tools()
    obs = registry.run("timeline.merge", {"inline": []})
    assert obs.status == Status.PARTIAL
    assert obs.facts["events"] == []
