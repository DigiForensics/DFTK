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

"""Volatility 3 adapter — DFTK 3.5.0.

DFTK does NOT re-implement a Windows memory forensic engine. Instead this module
is a *fixed-capability adapter* over `Volatility 3`_:

* every tool maps to one Volatility plugin (no arbitrary args are exposed to the
  Agent — matching the ``server.remote_snapshot`` design philosophy);
* the external binary is resolved via DFTK's toolchain discovery and the
  ``requires=('volatility',)`` gate returns ``UNSUPPORTED`` when it is absent;
* execution is bounded by a ``timeout`` and output by ``record_limit``;
* results are normalised into ``Observation`` with the source image hash and a
  provenance ``Evidence`` entry so a memory dump participates in the same
  chain-of-custody as every other artifact.

This keeps memory analysis a *fixed, audited* surface rather than a shell-escapable
command passthrough.

.. _Volatility 3: https://volatility3.readthedocs.io/
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from dftk.core.external_tools import resolve_external_tool
from dftk.core.helpers import sha256_file
from dftk.core.registry import registry
from dftk.core.models import Observation, Evidence, Status, SafetyLevel


def _parse_vol_table(text: str) -> tuple[list[dict[str, str]], list[str] | None]:
    """Best-effort parse of a Volatility 3 text-table into row dicts.

    Vol3's default text renderer separates columns with two-or-more spaces or a
    tab. Returns ``(rows, header)``; ``([], None)`` when no table structure is
    detected so the caller can fall back to a raw preview.
    """
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return [], None

    def _toks(ln: str) -> list[str]:
        return [t for t in re.split(r"\s{2,}|\t", ln.strip()) if t]

    header = _toks(lines[0])
    if len(header) < 2:
        return [], None
    rows: list[dict[str, str]] = []
    for ln in lines[1:]:
        t = _toks(ln)
        if len(t) == len(header):
            rows.append(dict(zip(header, t)))
    if not rows:
        return [], None
    return rows, header


def _run_plugin(
    tool_name: str,
    plugin: str,
    fact_key: str,
    image: str,
    timeout: int,
    record_limit: int,
) -> Observation:
    vol = resolve_external_tool("volatility")
    if not vol:
        return Observation(
            tool_name,
            Status.UNSUPPORTED,
            "Volatility 3 is not available",
            errors=[
                "install Volatility 3 and ensure `vol`/`volatility` is on PATH or "
                "$DFTK_MEMORY_TOOL_DIRS; DFTK does not bundle a memory engine"
            ],
        )
    h = sha256_file(Path(image))
    try:
        proc = subprocess.run(
            [vol, "-f", image, plugin],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return Observation(
            tool_name,
            Status.PARTIAL,
            f"plugin '{plugin}' exceeded timeout ({timeout}s)",
            warnings=[f"increase timeout for large images"],
            meta={"source_sha256": h, "plugin": plugin},
        )
    if proc.returncode != 0:
        return Observation(
            tool_name,
            Status.ERROR,
            f"plugin '{plugin}' failed (exit {proc.returncode})",
            errors=[proc.stderr.strip()[:2000]],
            meta={"source_sha256": h, "plugin": plugin},
        )

    text = proc.stdout
    rows, header = _parse_vol_table(text)
    truncated = False
    if record_limit and len(rows) > record_limit:
        rows = rows[:record_limit]
        truncated = True
    facts: dict[str, Any] = {fact_key: rows, "plugin": plugin}
    warnings: list[str] = []
    if not rows:
        # Non-tabular plugin (e.g. windows.info): keep a bounded raw preview.
        preview = [ln for ln in text.splitlines()][:60]
        facts["raw_preview"] = preview
        facts[fact_key] = []
    if truncated:
        warnings.append(f"output truncated to {record_limit} rows")
    status = Status.PARTIAL if warnings else Status.OK
    summary = (
        f"{tool_name}: parsed {len(rows)} row(s) via {plugin}"
        if rows
        else f"{tool_name}: no tabular output from {plugin}"
    )
    return Observation(
        tool_name,
        status,
        summary,
        facts=facts,
        evidence=[Evidence(str(image), "memory_image", plugin, locator=f"plugin:{plugin}", source_sha256=h, method="Volatility 3 adapter")],
        warnings=warnings,
        meta={"source_sha256": h, "plugin": plugin, "volatility": vol},
    )


# Fixed capability map. Each DFTK tool is one Volatility plugin; the Agent cannot
# inject arbitrary Volatility arguments.
_MEMORY_TOOLS = [
    ("memory.volatility_inventory", "windows.info", "system_overview", "system overview"),
    ("memory.processes", "windows.pslist", "processes", "process list"),
    ("memory.network", "windows.netscan", "network_connections", "network connections"),
    ("memory.malfind", "windows.malfind", "malfind_hits", "injected/ anomalous memory"),
    ("memory.modules", "windows.modules", "kernel_modules", "kernel modules"),
    ("memory.handles", "windows.handles", "handles", "open handles"),
]


def _make_tool(tool_name: str, plugin: str, fact_key: str, noun: str):
    @registry.tool(
        name=tool_name,
        description=(
            f"Run the fixed Volatility 3 plugin '{plugin}' against a memory image and "
            f"normalise the {noun} into a structured Observation. No arbitrary Volatility "
            f"args are exposed; the image is read-only evidence."
        ),
        parameters={
            "type": "object",
            "properties": {
                "image": {"type": "string", "description": "path to the memory dump (read-only evidence)"},
                "timeout": {"type": "integer", "default": 300, "description": "hard timeout in seconds"},
                "record_limit": {"type": "integer", "default": 2000, "description": "max rows to return"},
            },
            "required": ["image"],
        },
        safety=SafetyLevel.READ_ONLY,
        requires=("volatility",),
        tags=("memory", "volatility"),
        produces=(fact_key,),
        path_roles={"image": "EVIDENCE_INPUT"},
    )
    def _tool(image: str, timeout: int = 300, record_limit: int = 2000) -> Observation:
        return _run_plugin(tool_name, plugin, fact_key, image, timeout, record_limit)

    _tool.__name__ = tool_name.replace(".", "_")
    return _tool


for _name, _plugin, _fact, _noun in _MEMORY_TOOLS:
    _make_tool(_name, _plugin, _fact, _noun)
