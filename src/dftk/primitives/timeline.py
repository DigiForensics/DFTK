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

"""Unified timeline correlation tool."""
from __future__ import annotations

from dftk.core.registry import registry
from dftk.core.models import Observation, Status, SafetyLevel, Evidence
from dftk.core.timeline_core import merge_events


@registry.tool(
    name="timeline.merge",
    description=(
        "Merge time-bearing events from multiple dftk tool outputs or inline "
        "sources into one normalized, source-attributed timeline. Inputs are "
        "read-only; nothing is modified."
    ),
    safety=SafetyLevel.READ_ONLY,
    tags=("timeline", "correlation"),
    produces=("timeline",),
    cost_hint="low",
    parameters={
        "type": "object",
        "properties": {
            "files": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Paths to dftk Observation JSON files (each should contain facts.events)",
            },
            "inline": {
                "type": "array",
                "items": {"type": "object"},
                "description": "Inline sources: {\"source\": label, \"events\": [...]} bundles or flat events with a 'source' key",
            },
            "limit": {"type": "integer", "default": 200000},
        },
    },
)
def timeline_merge(files=None, inline=None, limit=200000) -> Observation:
    files = files or []
    inline = inline or []
    sources = [{"file": f} for f in files] + list(inline)
    result = merge_events(sources, limit=limit)
    events = result["events"]
    facts = {
        "events": events,
        "per_source": result["per_source"],
        "span": result["span"],
        "skipped": result["skipped"],
        "source_count": len(result["per_source"]),
    }
    status = Status.OK if events else Status.PARTIAL
    summary = (
        f"Merged {len(events)} event(s) from {len(result['per_source'])} source(s)"
        + (f" ({result['skipped']} skipped)" if result["skipped"] else "")
    )
    evidence = [Evidence("<multiple>", "timeline", len(events), locator="merged")]
    warnings = (
        [f"{result['skipped']} event(s) had no parseable timestamp and were skipped"]
        if result["skipped"]
        else []
    )
    return Observation(
        "timeline.merge",
        status,
        summary,
        facts=facts,
        evidence=evidence,
        warnings=warnings,
    )
