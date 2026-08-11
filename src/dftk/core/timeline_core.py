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

"""Pure, dependency-free timeline correlation primitives.

These helpers back both the :mod:`dftk.primitives.timeline` tool and the
:mod:`dftk.core.case` session, so the merge/correlation logic lives in one
place and is trivially unit-testable without touching the registry.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_LIMIT = 200_000


def _to_epoch(ev: dict[str, Any]) -> float | None:
    """Best-effort timestamp extraction from an event dict.

    Accepts an explicit ``epoch`` (unix seconds), a numeric ``time``, or an
    ISO-8601 ``time`` string (``Z`` suffix and naive datetimes are treated as
    UTC). Returns ``None`` when no usable timestamp is present.
    """
    ep = ev.get("epoch")
    if isinstance(ep, (int, float)):
        return float(ep)
    t = ev.get("time")
    if isinstance(t, (int, float)):
        return float(t)
    if isinstance(t, str):
        s = t.strip()
        if not s:
            return None
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    return None


def _iso(ep: float) -> str:
    return datetime.fromtimestamp(ep, tz=timezone.utc).isoformat()


def _norm_event(ev: dict[str, Any], source: str) -> dict[str, Any] | None:
    ep = _to_epoch(ev)
    if ep is None:
        return None
    return {
        "epoch": ep,
        "time": _iso(ep),
        "source": ev.get("source") or source,
        "kind": ev.get("kind") or ev.get("type") or "event",
        "path": ev.get("path") or "",
        "detail": ev.get("detail") or ev.get("path") or "",
        "confidence": float(ev.get("confidence", 1.0)),
    }


def _events_from_observation_file(path: str) -> tuple[list[dict[str, Any]], str]:
    """Read a dftk Observation JSON and pull out its time-bearing events.

    Returns ``(events, label)`` where ``label`` is the originating tool name
    (falling back to the file stem). Tolerates files whose ``facts`` use a
    different key for the event list.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    label = data.get("tool") or Path(path).stem
    facts = data.get("facts") or {}
    evs = facts.get("events")
    if isinstance(evs, list):
        return evs, label
    for v in facts.values():
        if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
            if any(("epoch" in x or "time" in x) for x in v):
                return v, label
    return [], label


def merge_events(
    sources: list[dict[str, Any]], *, limit: int = DEFAULT_LIMIT
) -> dict[str, Any]:
    """Merge several event sources into one normalized, sorted timeline.

    Each ``source`` is one of:

    * ``{"file": "<path>"}`` — a dftk Observation JSON file (reads ``facts.events``)
    * ``{"source": "<label>", "events": [...]}`` — an inline bundle
    * a flat event dict with its own ``source`` key

    The result is sorted by timestamp and attributed per source, with a span
    summary and a count of skipped (timestamp-less) events.
    """
    merged: list[dict[str, Any]] = []
    per_source: dict[str, int] = {}
    skipped = 0

    for src in sources:
        if not isinstance(src, dict):
            skipped += 1
            continue
        if "file" in src and src.get("file"):
            events, label = _events_from_observation_file(src["file"])
        elif "events" in src:
            label = src.get("source") or "inline"
            events = src.get("events") or []
        elif "time" in src or "epoch" in src or "kind" in src:
            label = src.get("source") or "inline"
            events = [src]
        else:
            skipped += 1
            continue

        for ev in events:
            if not isinstance(ev, dict):
                skipped += 1
                continue
            ne = _norm_event(ev, label)
            if ne is None:
                skipped += 1
                continue
            merged.append(ne)
            per_source[ne["source"]] = per_source.get(ne["source"], 0) + 1

    merged.sort(key=lambda e: (e["epoch"], e["source"], e["kind"], e["path"]))
    if limit and len(merged) > limit:
        merged = merged[:limit]

    span = None
    if merged:
        span = {
            "earliest": merged[0]["time"],
            "latest": merged[-1]["time"],
            "count": len(merged),
        }
    return {
        "events": merged,
        "per_source": per_source,
        "span": span,
        "skipped": skipped,
    }
