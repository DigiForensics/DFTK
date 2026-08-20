from __future__ import annotations

from dftk.catalog import load_builtin_tools
from dftk.core.registry import registry
from dftk.core.safety import SafetyPolicy


def test_entity_graph_preserves_source_locators_and_co_observations():
    sha256 = "a" * 64
    observations = [
        {
            "tool": "email.mime_inventory",
            "facts": {"sender": "alice@example.test", "body": f"contact 203.0.113.5 at evil.example {sha256}"},
            "evidence": [],
            "meta": {},
        },
        {
            "tool": "network.capture_protocols",
            "facts": {"host": "evil.example", "client_ip": "203.0.113.5"},
            "evidence": [],
            "meta": {},
        },
    ]
    load_builtin_tools()
    result = registry.run("correlation.entity_graph", {"inline": observations}, SafetyPolicy())

    assert result.status.value == "ok"
    nodes = {node["id"]: node for node in result.facts["nodes"]}
    assert "email:alice@example.test" in nodes
    assert "ip:203.0.113.5" in nodes
    assert "domain:evil.example" in nodes
    assert f"sha256:{sha256}" in nodes
    assert all(node["occurrences"] for node in nodes.values())
    assert any(edge["relation"] == "observed_in" for edge in result.facts["edges"])
    assert any(relation["relation"] == "co_observed" for relation in result.facts["relations"])
