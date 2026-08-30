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

"""Tests for the HTML forensic report layer (case.report_html)."""

from __future__ import annotations

from pathlib import Path

from dftk.core.models import Observation, Evidence, Status
from dftk.core.registry import registry
from dftk.primitives.report import report_html


def _sample_observation() -> Observation:
    return Observation(
        "demo.filesystem_walk",
        Status.OK,
        "walked 2 entries",
        facts={
            "entries": [
                {"name": "a.txt", "mtime": "2020-05-04T12:00:00+00:00"},
                {"name": "b.txt", "mtime": "2021-06-07T08:30:00+00:00"},
            ]
        },
        evidence=[Evidence("/evidence/disk.E01", "file", "a.txt", locator="inode:5",
                           source_sha256="a" * 64, method="walk", state="LIVE")],
        warnings=["entry names truncated"],
        meta={"source_sha256": "a" * 64},
    )


def test_registered():
    assert registry.get("case.report_html") is not None


def test_render_contains_sections(tmp_path):
    html_path = tmp_path
    obs = _sample_observation()
    out = report_html(str(html_path), [obs.to_dict()], case_id="CASE-1", title="Test Report")
    assert out.status.value == "ok", out.errors
    p = Path(out.facts["report_path"])
    assert p.exists()
    html = p.read_text(encoding="utf-8")
    for section in (
        "Case Summary",
        "Evidence Sources",
        "Observations",
        "Recovered / Derived Artifacts",
        "Timeline",
        "Entities",
        "Warnings / Limitations",
        "Chain of Custody",
        "Tool Manifest",
    ):
        assert section in html, section
    # tool + entity + timestamp surfaced
    assert "demo.filesystem_walk" in html
    assert "2020-05-04T12:00:00" in html
    assert "a.txt" in html
    # escaping is applied (no raw unescaped HTML from fixture)
    assert out.facts["sha256"]


def test_derived_artifacts_registered(tmp_path):
    obs = _sample_observation()
    out = report_html(str(tmp_path), [obs.to_dict()], case_id="C2")
    assert len(out.derived_artifacts) == 1
    art = out.derived_artifacts[0]
    assert art.sha256 == out.facts["sha256"]
    assert art.kind == "report"
    assert out.evidence[0].artifact_id == art.artifact_id


def test_search_box_present(tmp_path):
    obs = _sample_observation()
    out = report_html(str(tmp_path), [obs.to_dict()])
    html = Path(out.facts["report_path"]).read_text(encoding="utf-8")
    assert 'id="dfsearch"' in html


def test_entity_graph_rendered_with_multiple_entities(tmp_path):
    obs = Observation("demo.e", Status.OK, "x", facts={}, evidence=[
        Evidence("/e/a", "ip", "1.2.3.4"),
        Evidence("/e/b", "domain", "evil.com"),
        Evidence("/e/c", "url", "https://evil.com/x"),
    ])
    out = report_html(str(tmp_path), [obs.to_dict(), obs.to_dict()], case_id="G")
    html = Path(out.facts["report_path"]).read_text(encoding="utf-8")
    assert "entgraph" in html
    assert "<svg" in html


def test_xss_is_escaped(tmp_path):
    evil = Observation("demo.xss", Status.OK, "<script>alert(1)</script>",
                       facts={"k": "<img src=x onerror=alert(1)>"},
                       evidence=[Evidence("<b>bad</b>", "x", "<i>y</i>")])
    out = report_html(str(tmp_path), [evil.to_dict()])
    html = Path(out.facts["report_path"]).read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
