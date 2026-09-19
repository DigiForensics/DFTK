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
"""Runtime self-test: prove the runnable capabilities are actually wired.

This is the user/agent-facing counterpart to ``tests/test_no_crash_schema.py``.
It runs every *runnable* capability (per ``core.readiness``) with schema-shaped
synthetic parameters under the default READ_ONLY policy and reports which ones
execute end-to-end without raising. It is an "installation availability" proof,
not a forensic-correctness proof: a tool that returns ``unsupported`` or
``blocked`` on synthetic input has still passed the self-test, while a tool that
lets an exception escape is reported as a crash.

Stateful/destructive tools are exercised only under the default READ_ONLY policy,
so they return BLOCKED without performing any side effect.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from ..catalog import load_builtin_tools
from .readiness import tool_readiness
from .registry import registry

_SENTINEL_FILE = Path(__file__).resolve()


def _placeholder(typ: str, key: str) -> object:
    if typ == "integer":
        return 1
    if typ == "number":
        return 1.0
    if typ == "boolean":
        return False
    if typ == "array":
        return []
    if typ == "object":
        return {}
    # string-like
    if any(tok in key.lower() for tok in ("path", "file", "root", "dir", "evidence", "apk", "image")):
        return str(_SENTINEL_FILE)
    return "x"


def _build_params(spec: Any) -> dict:
    """Build schema-shaped parameters so a malformed call is never the cause of failure."""
    schema = spec.parameters or {}
    props = schema.get("properties", {}) or {}
    required = schema.get("required", []) or []
    params: dict = {}
    for name in required:
        prop = props.get(name, {})
        params[name] = _placeholder(prop.get("type", "string"), name)
    for name, prop in props.items():
        if name in params:
            continue
        params[name] = _placeholder(prop.get("type", "string"), name)
    return params


def run_selftest() -> dict[str, Any]:
    """Run every runnable capability once and return a structured report.

    The report is deterministic and safe to feed to an Agent: it never mutates
    evidence and never raises for a single tool failure.
    """
    load_builtin_tools()
    results: list[dict[str, Any]] = []
    crashes = 0
    for spec in registry.specs():
        readiness = tool_readiness(spec)
        if readiness["state"] != "runnable":
            results.append({"name": spec.name, "skipped": readiness["state"]})
            continue
        params = _build_params(spec)
        try:
            obs = registry.run(spec.name, params)  # default READ_ONLY policy
        except Exception as exc:  # noqa: BLE001 - a crash is exactly what we report
            results.append({"name": spec.name, "status": "crash", "error": f"{type(exc).__name__}: {exc}"})
            crashes += 1
            continue
        status = getattr(obs.status, "value", str(obs.status)) if obs is not None else "none"
        results.append({"name": spec.name, "status": status})

    executed = [r for r in results if "skipped" not in r]
    total = len(executed)
    crashed = crashes
    passed = total - crashed
    return {
        "schema_version": "1",
        "total_runnable": total,
        "passed": passed,
        "crashed": crashed,
        "results": results,
    }
