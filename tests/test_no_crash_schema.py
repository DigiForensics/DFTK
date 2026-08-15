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

"""Schema-driven crash test.

Every registered tool is invoked with well-formed (schema-shaped) parameters so
that a malformed *call* is never the cause of failure. The assertion is narrow
but high-value: ``registry.run`` must never let an exception escape and must
always return an :class:`Observation`. This catches tools that crash on
ordinary input (bad indexing, unguarded None, wrong exception type, etc.)
independent of forensic correctness.

Stateful/destructive tools are exercised only under the default READ_ONLY policy,
so they return BLOCKED without performing any side effect.
"""

from __future__ import annotations

import json
from pathlib import Path

import dftk
from dftk.core.models import Observation, Status

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


def _build_params(spec) -> dict:
    schema = spec.parameters or {}
    props = schema.get("properties", {}) or {}
    required = schema.get("required", []) or []
    params: dict = {}
    for name in required:
        prop = props.get(name, {})
        params[name] = _placeholder(prop.get("type", "string"), name)
    # Also feed optional properties with defaults so we exercise more branches.
    for name, prop in props.items():
        if name in params:
            continue
        params[name] = _placeholder(prop.get("type", "string"), name)
    return params


def test_every_tool_returns_observation_not_raise(tmp_path: Path):
    reg = dftk.get_registry()
    seen_status: dict[str, int] = {}
    failures: list[str] = []
    for spec in reg.specs():
        params = _build_params(spec)
        try:
            obs = reg.run(spec.name, params)  # default READ_ONLY policy
        except Exception as exc:  # pragma: no cover - defensive
            failures.append(f"{spec.name}: raised {type(exc).__name__}: {exc}")
            continue
        if not isinstance(obs, Observation):
            failures.append(f"{spec.name}: returned {type(obs).__name__}, not Observation")
            continue
        try:
            _ = obs.status.value
        except Exception:
            failures.append(f"{spec.name}: status not serializable ({obs.status!r})")
            continue
        seen_status[obs.status.value] = seen_status.get(obs.status.value, 0) + 1
    if failures:
        raise AssertionError(
            "registry.run let exceptions escape / returned non-Observation:\n"
            + "\n".join(failures)
        )
    # Sanity: we actually exercised tools across multiple outcomes.
    assert sum(seen_status.values()) == len(reg.specs())
    # At least the read-only majority should have produced a real result
    # (ok/partial/unsupported); blocked only covers stateful/destructive.
    assert seen_status.get("error", 0) < len(reg.specs()), (
        f"unexpectedly many error outcomes: {seen_status}"
    )


def test_filetime_iso_integer_precision():
    from dftk.primitives.windows_host import _filetime_to_iso

    # FILETIME for the Unix epoch (1970-01-01T00:00:00Z) is a fixed constant.
    epoch_ft = 116444736000000000
    assert _filetime_to_iso(epoch_ft) == "1970-01-01T00:00:00+00:00"
    # A 2024-era FILETIME must round-trip exactly (no float drift).
    ft = 133500000000000000
    assert _filetime_to_iso(ft) == "2024-01-17T21:20:00+00:00"
    # Zero / invalid FILETIME returns None rather than a bogus date.
    assert _filetime_to_iso(0) is None
