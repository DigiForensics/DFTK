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
                "maxItems": 64,
                "description": "Paths to dftk Observation JSON files (each should contain facts.events)",
            },
            "inline": {
                "type": "array",
                "items": {"type": "object"},
                "description": "Inline sources: {\"source\": label, \"events\": [...]} bundles or flat events with a 'source' key",
            },
            "limit": {"type": "integer", "default": 200000, "minimum": 1, "maximum": 200000},
        },
    },
)
def timeline_merge(files=None, inline=None, limit=200000) -> Observation:
    files = files or []
    inline = inline or []
    sources = timeline_sources(files, inline)
    result = merge_events(sources, limit=limit)
    events = result["events"]
    facts = {
        "events": events,
        "per_source": result["per_source"],
        "span": result["span"],
        "skipped": result["skipped"],
        "source_count": len(result["per_source"]),
        "scanned": result["scanned"],
        "omitted": result["omitted"],
        "truncated": result["truncated"],
    }
    status = timeline_status(result)
    summary = (
        f"Merged {len(events)} event(s) from {len(result['per_source'])} source(s)"
        + (f" ({result['skipped']} skipped)" if result["skipped"] else "")
    )
    evidence = [Evidence("<multiple>", "timeline", len(events), locator="merged")]
    warnings = result["warnings"]
    return Observation(
        "timeline.merge",
        status,
        summary,
        facts=facts,
        evidence=evidence,
        warnings=warnings,
        errors=result["errors"],
    )


def timeline_sources(files, inline):
    # Inline content is data, never a second filesystem input surface. In
    # particular, MCP deliberately does not apply path policy to inline facts.
    if any("file" in source and source.get("file") for source in inline):
        raise ValueError("inline file references are not allowed; use the files parameter")
    return [{"file": filename} for filename in files] + list(inline)


def timeline_status(result):
    if result["errors"] and not result["events"]:
        return Status.ERROR
    if not result["events"] or result["warnings"] or result["errors"]:
        return Status.PARTIAL
    return Status.OK


@registry.tool(
    name="timeline.hunt_sequences",
    description=("Find bounded ordered event chains across forensic timelines using exact-field "
                 "rules and shared entity fields. Returns source-linked investigative leads, "
                 "explicit coverage limits, and no automatic compromise verdict."),
    safety=SafetyLevel.READ_ONLY,
    tags=("timeline", "correlation", "hunting", "sequence", "incident-response"),
    produces=("sequence_matches", "timeline"),
    cost_hint="medium",
    parameters={
        "type": "object",
        "required": ["rules"],
        "properties": {
            "files": {"type": "array", "items": {"type": "string"}, "maxItems": 64},
            "inline": {"type": "array", "items": {"type": "object"}},
            "event_limit": {"type": "integer", "default": 200000, "minimum": 1, "maximum": 200000},
            "limit": {"type": "integer", "default": 1000, "minimum": 1, "maximum": 10000},
            "rules": {
                "type": "array", "minItems": 1, "maxItems": 32,
                "items": {
                    "type": "object", "additionalProperties": False,
                    "required": ["id", "steps", "group_by", "within_seconds"],
                    "properties": {
                        "id": {"type": "string", "minLength": 1, "maxLength": 128},
                        "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                        "steps": {"type": "array", "minItems": 2, "maxItems": 8,
                                  "description": "Ordered exact-field selectors (AND fields; array values mean OR; dotted paths supported).",
                                  "items": {"type": "object"}},
                        "group_by": {"type": "array", "minItems": 1, "maxItems": 8,
                                     "description": "Shared entity fields required in every step, such as host and user; missing values never join.",
                                     "items": {"type": "string", "minLength": 1, "maxLength": 128}},
                        "within_seconds": {"type": "number", "exclusiveMinimum": 0, "maximum": 604800,
                                           "description": "Inclusive first-to-last time window; step timestamps must strictly increase."},
                    },
                },
            },
        },
    },
)
def timeline_hunt_sequences(rules, files=None, inline=None, event_limit=200000, limit=1000):
    from dftk.core.sequence_hunt import hunt_sequences, validate_rules

    validate_rules(rules)
    merged = merge_events(timeline_sources(files or [], inline or []), limit=event_limit)
    result = hunt_sequences(merged["events"], rules, limit=limit)
    warnings = merged["warnings"] + result["warnings"]
    status = timeline_status(merged)
    if result["truncated"] and status == Status.OK:
        status = Status.PARTIAL
    evidence = []
    for match_index, match in enumerate(result["matches"]):
        for step, event_index in enumerate(match["event_indices"]):
            event = merged["events"][event_index]
            ref = event["input_ref"]
            evidence.append(Evidence(
                ref["source"], "sequence_event", event,
                locator=ref["locator"], source_sha256=ref["source_sha256"],
                confidence=event["confidence"], method="ordered exact-field sequence matching",
                note=f"match[{match_index}] rule={match['rule_id']} step={step + 1}",
            ))
    return Observation(
        "timeline.hunt_sequences", status,
        f"Matched {len(result['matches'])} event chain(s) using {len(rules)} rule(s)",
        facts={"matches": result["matches"], "match_count": len(result["matches"]),
               "events": merged["events"], "rule_count": len(rules), "rules": rules,
               "coverage": {"scanned": merged["scanned"], "skipped": merged["skipped"],
                            "omitted": merged["omitted"],
                            "truncated": merged["truncated"] or result["truncated"]}},
        evidence=evidence, warnings=warnings, errors=merged["errors"],
    )
