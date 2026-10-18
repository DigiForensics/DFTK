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
import hashlib
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_LIMIT = 200_000
MAX_SOURCE_BYTES = 32 * 1024 * 1024


def _to_epoch(ev: dict[str, Any]) -> float | None:
    """Best-effort timestamp extraction from an event dict.

    Accepts an explicit ``epoch`` (unix seconds), a numeric ``time``, or an
    ISO-8601 ``time`` string (``Z`` suffix and naive datetimes are treated as
    UTC). Returns ``None`` when no usable timestamp is present.
    """
    ep = ev.get("epoch")
    if isinstance(ep, (int, float)) and not isinstance(ep, bool):
        return float(ep) if math.isfinite(ep) else None
    t = ev.get("time")
    if isinstance(t, (int, float)) and not isinstance(t, bool):
        return float(t) if math.isfinite(t) else None
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
    raw_time = ev.get("time")
    numeric_epoch = isinstance(ev.get("epoch"), (int, float)) and not isinstance(ev.get("epoch"), bool)
    time_basis = "unix_seconds"
    if not numeric_epoch and isinstance(raw_time, str):
        parsed = datetime.fromisoformat(raw_time.strip().replace("Z", "+00:00"))
        time_basis = "iso8601_offset" if parsed.tzinfo is not None else "iso8601_assumed_utc"
    conf_raw = ev.get("confidence", 1.0)
    try:
        confidence = float(conf_raw)
    except (TypeError, ValueError):
        confidence = 0.0
    if not math.isfinite(confidence):
        confidence = 0.0
    return {
        **ev,
        "original_time": ev.get("original_time", raw_time),
        "time_basis": ev.get("time_basis", time_basis),
        "epoch": ep,
        "time": _iso(ep),
        "source": ev.get("source") or source,
        "kind": ev.get("kind") or ev.get("type") or "event",
        "path": ev.get("path") or "",
        "detail": ev.get("detail") or ev.get("path") or "",
        "confidence": max(0.0, min(1.0, confidence)),
    }


def _read_observation(path: str) -> tuple[list[dict[str, Any]], str, str, str, list[str]]:
    """Hash exactly the bounded bytes parsed, and retain the facts locator."""
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_SOURCE_BYTES + 1)
    if len(raw) > MAX_SOURCE_BYTES:
        raise ValueError(f"Observation exceeds {MAX_SOURCE_BYTES} byte input bound")
    data = json.loads(raw)
    if not isinstance(data, dict) or not isinstance(data.get("facts", {}), dict):
        raise ValueError("expected an Observation object with object facts")
    label = str(data.get("tool") or Path(path).stem)
    facts = data.get("facts") or {}
    digest = hashlib.sha256(raw).hexdigest()
    warnings = []
    status = data.get("status")
    if status is not None and status != "ok":
        warnings.append(f"{path}: input Observation status={str(status)[:100]}; coverage may be incomplete")
    if data.get("warnings") or data.get("errors"):
        warnings.append(f"{path}: input Observation carries warnings/errors; review the original run")
    if isinstance(facts.get("events"), list):
        return facts["events"], label, "events", digest, warnings
    for key, value in facts.items():
        if isinstance(value, list) and value and all(isinstance(x, dict) for x in value):
            if any("epoch" in x or "time" in x for x in value):
                return value, label, str(key), digest, warnings
    return [], label, "events", digest, warnings


def _events_from_observation_file(path: str) -> tuple[list[dict[str, Any]], str]:
    events, label, _, _, _ = _read_observation(path)
    return events, label


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
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= DEFAULT_LIMIT:
        raise ValueError(f"limit must be between 1 and {DEFAULT_LIMIT}")
    merged: list[dict[str, Any]] = []
    per_source: dict[str, int] = {}
    skipped = 0
    scanned = 0
    errors: list[str] = []
    warnings: list[str] = []
    incomplete = False

    for source_index, src in enumerate(sources):
        if scanned >= DEFAULT_LIMIT:
            incomplete = True
            break
        if not isinstance(src, dict):
            skipped += 1
            continue
        filename, digest, key = "", "", "events"
        if "file" in src and src.get("file"):
            filename = str(src["file"])
            try:
                events, label, key, digest, source_warnings = _read_observation(filename)
                warnings.extend(source_warnings)
            except (OSError, ValueError, TypeError, RecursionError) as exc:
                errors.append(f"{filename}: {exc}")
                continue
        elif "events" in src:
            label = str(src.get("source") or "inline")
            events = src.get("events")
        elif "time" in src or "epoch" in src or "kind" in src:
            label = str(src.get("source") or "inline")
            events = [src]
        else:
            skipped += 1
            continue
        if not isinstance(events, list):
            errors.append(f"source {source_index}: expected an events array")
            continue
        for index, ev in enumerate(events):
            if scanned >= DEFAULT_LIMIT:
                incomplete = True
                break
            scanned += 1
            try:
                ne = _norm_event(ev, label) if isinstance(ev, dict) else None
                if ne is not None:
                    ne["source"] = str(ne["source"])
                    ne["kind"] = str(ne["kind"])
                    ne["path"] = str(ne["path"])
            except (ValueError, TypeError, OverflowError, OSError):
                ne = None
            if ne is None:
                skipped += 1
                continue
            # Input reference is independent of event-supplied provenance fields.
            ne["input_ref"] = {
                "source": filename or f"inline:{source_index}",
                "locator": f"facts.{key}[{index}]" if filename else f"events[{index}]",
                "source_sha256": digest,
            }
            merged.append(ne)
            per_source[ne["source"]] = per_source.get(ne["source"], 0) + 1

    merged.sort(key=lambda e: (e["epoch"], e["source"], e["kind"], e["path"]))
    omitted = max(0, len(merged) - limit)
    merged = merged[:limit]
    if skipped:
        warnings.append(f"{skipped} invalid or timestamp-less event/source item(s) skipped")
    assumed_utc = sum(event.get("time_basis") == "iso8601_assumed_utc" for event in merged)
    if assumed_utc:
        warnings.append(f"{assumed_utc} returned event(s) lacked a timezone; UTC was assumed")
    if omitted:
        warnings.append(f"output limit reached: {omitted} valid event(s) omitted")
    if incomplete:
        warnings.append(f"scan limit reached ({DEFAULT_LIMIT}); remaining input was not examined")
    span = None
    if merged:
        span = {"earliest": merged[0]["time"], "latest": merged[-1]["time"], "count": len(merged)}
    return {
        "events": merged, "per_source": per_source, "span": span,
        "skipped": skipped, "scanned": scanned, "omitted": omitted,
        "truncated": bool(omitted or incomplete), "errors": errors, "warnings": warnings,
    }
