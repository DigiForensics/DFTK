"""Bounded, deterministic sequence matching over normalized forensic events."""
from __future__ import annotations

import math
from typing import Any

_MISSING = object()
MAX_STATES = 10_000
MAX_COMPARISONS = 1_000_000


def field_value(event: dict, field: str) -> Any:
    """Resolve a dotted object path; no expressions, regex, or code evaluation."""
    value: Any = event
    for part in field.split("."):
        if not isinstance(value, dict) or part not in value:
            return _MISSING
        value = value[part]
    return value


def _equal(left: Any, right: Any) -> bool:
    # In particular, an account id True must not join account id 1.
    return type(left) is type(right) and left == right


def _matches(event: dict, selector: dict) -> bool:
    for field, expected in selector.items():
        actual = field_value(event, field)
        choices = expected if isinstance(expected, list) else [expected]
        if actual is _MISSING or not any(_equal(actual, choice) for choice in choices):
            return False
    return True


def validate_rules(rules: list[dict]) -> None:
    ids: set[str] = set()
    for rule in rules:
        rule_id = rule["id"]
        if rule_id in ids:
            raise ValueError(f"duplicate rule id: {rule_id}")
        ids.add(rule_id)
        if not math.isfinite(rule["within_seconds"]):
            raise ValueError(f"{rule_id}: within_seconds must be finite")
        for selector in rule["steps"]:
            if not 1 <= len(selector) <= 16:
                raise ValueError(f"{rule_id}: step selectors require 1..16 fields")
            for field, expected in selector.items():
                if not field or len(field) > 128 or any(not part for part in field.split(".")):
                    raise ValueError(f"{rule_id}: invalid field path {field!r}")
                choices = expected if isinstance(expected, list) else [expected]
                if not choices or len(choices) > 100:
                    raise ValueError(f"{rule_id}: selectors require 1..100 choices")
                if any(not isinstance(v, (str, int, float, bool)) or
                       isinstance(v, float) and not math.isfinite(v) for v in choices):
                    raise ValueError(f"{rule_id}: selector values must be finite JSON scalars")


def hunt_sequences(events: list[dict], rules: list[dict], *, limit: int = 1000) -> dict:
    """Enumerate ordered chains, retaining overlapping candidates until bounded.

    Times must strictly increase: equal timestamps cannot establish an order.
    Missing/empty join fields never correlate, and input observations are never
    counted as independent corroboration merely because their labels differ.
    """
    matches: list[dict] = []
    comparisons = 0
    warnings: list[str] = []
    for rule in rules:
        states: list[tuple[tuple, tuple[int, ...]]] = []
        fields = rule["group_by"]
        window = rule["within_seconds"]
        steps = rule["steps"]
        for index, event in enumerate(events):
            values = [field_value(event, field) for field in fields]
            if any(value is _MISSING or value is None or value == "" or
                   not isinstance(value, (str, int, float, bool)) for value in values):
                continue
            group = tuple((type(value).__name__, value) for value in values)
            states = [(key, chain) for key, chain in states
                      if event["epoch"] - events[chain[0]]["epoch"] <= window]
            additions = []
            for key, chain in states:
                comparisons += 1
                if comparisons > MAX_COMPARISONS:
                    warnings.append("comparison budget reached; remaining candidates/rules were not examined")
                    return {"matches": matches, "warnings": warnings, "truncated": True}
                if key != group or event["epoch"] <= events[chain[-1]]["epoch"]:
                    continue
                if not _matches(event, steps[len(chain)]):
                    continue
                extended = chain + (index,)
                if len(extended) == len(steps):
                    matched_events = [events[i] for i in extended]
                    matches.append({
                        "rule_id": rule["id"], "severity": rule.get("severity", "medium"),
                        "group": dict(zip(fields, values)), "event_indices": list(extended),
                        "started": matched_events[0]["time"], "ended": event["time"],
                        "duration_seconds": event["epoch"] - matched_events[0]["epoch"],
                        "confidence": min(e["confidence"] for e in matched_events),
                        "input_refs": [e["input_ref"] for e in matched_events],
                        "basis": "ordered exact-field rule match; investigative lead, not proof of compromise",
                    })
                    if len(matches) >= limit:
                        warnings.append("match limit reached; remaining candidates/rules were not examined")
                        return {"matches": matches, "warnings": warnings, "truncated": True}
                else:
                    additions.append((group, extended))
            if _matches(event, steps[0]):
                additions.append((group, (index,)))
            if len(states) + len(additions) > MAX_STATES:
                warnings.append(f"active candidate limit reached ({MAX_STATES}); remaining candidates/rules were not examined")
                return {"matches": matches, "warnings": warnings, "truncated": True}
            states.extend(additions)
    return {"matches": matches, "warnings": warnings, "truncated": False}
