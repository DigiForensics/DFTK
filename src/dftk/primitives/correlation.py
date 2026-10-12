"""Public registry adapter for deterministic Observation entity correlation."""
from __future__ import annotations

from dftk.core.entity_graph import correlate_files
from dftk.core.models import Observation, SafetyLevel
from dftk.core.registry import registry


@registry.tool(
    name="correlation.entity_graph",
    description="Correlate domains, IPs, emails, SHA-256 values, and account identifiers across DFTK Observation JSON files or inline Observations, preserving source locators.",
    safety=SafetyLevel.READ_ONLY,
    tags=("correlation", "entity", "graph", "timeline", "agent"),
    produces=("entity_graph", "entities", "relationships"),
    cost_hint="medium",
    parameters={
        "type": "object",
        "properties": {
            "files": {"type": "array", "items": {"type": "string"}, "description": "Persisted DFTK Observation JSON files."},
            "inline": {"type": "array", "items": {"type": "object"}, "description": "Inline DFTK Observation objects."},
            "limit": {"type": "integer", "default": 5000, "minimum": 1, "maximum": 20000},
        },
    },
)
def entity_graph(files: list[str] | None = None, inline: list[dict] | None = None, limit: int = 5000) -> Observation:
    return correlate_files(files, inline, limit=limit)
