"""Deterministic, source-linked entity correlation for DFTK Observations."""
from __future__ import annotations

from collections import defaultdict
import ipaddress
import json
from pathlib import Path
import re
from typing import Any

from .models import Evidence, Observation, Status

_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_DOMAIN = re.compile(r"(?<![@\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![\w.-])")
_ACCOUNT_KEYS = re.compile(r"(?:^|_)(?:user(?:name)?|account|sender|recipient|email|login|uid)(?:$|_)", re.I)


def _entity_id(kind: str, value: str) -> str:
    return f"{kind}:{value.lower()}"


def _values(value: Any, key: str = "", path: str = "", budget: int = 10_000):
    """Yield bounded scalar strings from an Observation with a facts locator."""
    if budget <= 0:
        return
    if isinstance(value, dict):
        for child_key in sorted(value):
            child_path = f"{path}.{child_key}" if path else str(child_key)
            yield from _values(value[child_key], str(child_key), child_path, budget - 1)
    elif isinstance(value, list):
        for index, child in enumerate(value[:1000]):
            yield from _values(child, key, f"{path}[{index}]", budget - 1)
    elif isinstance(value, (str, int, float)):
        text = str(value)
        if len(text) <= 4096:
            yield text, key, path


def _extract(text: str, key: str, locator: str) -> list[tuple[str, str, str]]:
    found: list[tuple[str, str, str]] = []
    for value in _SHA256.findall(text):
        found.append(("sha256", value.lower(), locator))
    for value in _EMAIL.findall(text):
        found.append(("email", value.lower(), locator))
    for value in _IPV4.findall(text):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        found.append(("ip", value, locator))
    for value in _DOMAIN.findall(text):
        found.append(("domain", value.lower(), locator))
    if _ACCOUNT_KEYS.search(key) and text and len(text) <= 256 and not any(ch.isspace() for ch in text):
        found.append(("account", text.lower(), locator))
    return found


def correlate_observations(observations: list[tuple[str, dict[str, Any]]], *, limit: int = 5000, tool: str = "correlation.entity_graph") -> Observation:
    """Build entity nodes and source edges from persisted or inline Observations."""
    entities: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []
    co_occurrences: set[tuple[str, str, str]] = set()
    warnings: list[str] = []

    for source, observation in observations:
        per_source: set[str] = set()
        for section in ("facts", "evidence", "meta"):
            for text, key, locator in _values(observation.get(section, {}), path=section):
                for kind, value, entity_locator in _extract(text, key, locator):
                    entity_id = _entity_id(kind, value)
                    if entity_id not in entities:
                        if len(entities) >= limit:
                            warnings.append(f"entity limit reached ({limit})")
                            break
                        entities[entity_id] = {"id": entity_id, "type": kind, "value": value, "occurrences": []}
                    occurrence = {"source": source, "tool": str(observation.get("tool", "unknown")), "locator": entity_locator}
                    if occurrence not in entities[entity_id]["occurrences"]:
                        entities[entity_id]["occurrences"].append(occurrence)
                        edges.append({"source": source, "target": entity_id, "relation": "observed_in", "locator": entity_locator})
                    per_source.add(entity_id)
                if warnings and warnings[-1].startswith("entity limit"):
                    break
            if warnings and warnings[-1].startswith("entity limit"):
                break
        for left in sorted(per_source)[:100]:
            for right in sorted(per_source)[:100]:
                if left < right and len(co_occurrences) < limit * 4:
                    co_occurrences.add((left, right, source))

    nodes = sorted(entities.values(), key=lambda item: (item["type"], item["value"]))
    relations = [
        {"source": left, "target": right, "relation": "co_observed", "observation": source}
        for left, right, source in sorted(co_occurrences)
    ]
    facts = {
        "source_count": len(observations), "entity_count": len(nodes), "edge_count": len(edges),
        "nodes": nodes, "edges": edges, "relations": relations,
        "entity_counts": dict(sorted((kind, sum(1 for node in nodes if node["type"] == kind)) for kind in {node["type"] for node in nodes})),
    }
    status = Status.OK if nodes else Status.PARTIAL
    if not nodes:
        warnings.append("no supported entities found; entity correlation does not infer facts absent from source Observations")
    evidence = [Evidence("<multiple>", "entity_graph", len(nodes), locator="source-linked correlation", method="deterministic entity extraction")]
    return Observation(tool, status, f"Correlated {len(nodes)} entity node(s) from {len(observations)} Observation(s)", facts=facts, evidence=evidence, warnings=warnings)


def correlate_files(files: list[str] | None = None, inline: list[dict[str, Any]] | None = None, *, limit: int = 5000, tool: str = "correlation.entity_graph") -> Observation:
    observations: list[tuple[str, dict[str, Any]]] = []
    errors: list[str] = []
    for filename in files or []:
        try:
            raw = json.loads(Path(filename).read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("not a JSON object")
            observations.append((str(filename), raw))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{filename}: {exc}")
    for index, raw in enumerate(inline or []):
        if isinstance(raw, dict):
            observations.append((f"inline:{index}", raw))
        else:
            errors.append(f"inline:{index}: expected an Observation object")
    result = correlate_observations(observations, limit=limit, tool=tool)
    result.errors.extend(errors)
    if errors and result.status == Status.OK:
        result.status = Status.PARTIAL
    return result
