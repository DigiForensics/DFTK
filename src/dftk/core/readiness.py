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
from __future__ import annotations

import importlib.util
from typing import Any

from .models import SafetyLevel


# Each entry maps a ``requires=`` package name (as declared on a tool) to how to
# detect it and how to install it. ``module`` is what importlib checks; ``extra``
# is the pyproject optional-dependency group (or None for standalone pip
# packages); ``install`` is the precise command a user runs to make the tool
# runnable. Unmapped names fall back to a generic pip install below.
OPTIONAL_REQUIREMENTS: dict[str, dict[str, Any]] = {
    "pyewf": {"module": "pyewf", "label": "disk:pyewf", "extra": None, "install": "pip install pyewf"},
    "pytsk3": {"module": "pytsk3", "label": "disk:pytsk3", "extra": None, "install": "pip install pytsk3"},
    "dkimpy": {"module": "dkim", "label": "email:dkim", "extra": "email", "install": 'pip install "dftk[email]"'},
    "dnspython": {"module": "dns", "label": "email:dns", "extra": "email", "install": 'pip install "dftk[email]"'},
    "pyspf": {"module": "spf", "label": "email:spf", "extra": "email", "install": 'pip install "dftk[email]"'},
    "paramiko": {"module": "paramiko", "label": "ssh:paramiko", "extra": "ssh", "install": 'pip install "dftk[ssh]"'},
    "yara-python": {"module": "yara", "label": "malware:yara", "extra": "yara", "install": 'pip install "dftk[yara]"'},
    "python-registry": {"module": "Registry", "label": "windows:registry", "extra": "windows", "install": 'pip install "dftk[windows]"'},
    "python-evtx": {"module": "Evtx", "label": "windows:evtx", "extra": "windows", "install": 'pip install "dftk[windows]"'},
}


def _import_available(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, AttributeError, ValueError):
        return False


def _requirement_status(name: str) -> dict[str, Any]:
    """Return availability + remediation for a single ``requires`` entry."""
    info = OPTIONAL_REQUIREMENTS.get(name)
    if info is None:
        return {
            "name": name,
            "label": name,
            "available": _import_available(name),
            "install": f"pip install {name}",
        }
    return {
        "name": name,
        "label": info["label"],
        "available": _import_available(info["module"]),
        "install": info["install"],
    }


def tool_readiness(spec: Any) -> dict[str, Any]:
    """Classify a tool's runnability in the current environment.

    States:
      - "runnable": all declared dependencies are importable and the tool is not
        gated by safety policy.
      - "degraded": at least one optional dependency is missing; the tool will
        return UNSUPPORTED until it is installed (``missing`` lists each gap with
        a precise install command).
      - "blocked": the tool is gated by safety policy (DESTRUCTIVE) and requires
        an explicit opt-in to run.

    This is a pure, dependency-free classification used by ``dftk list``,
    ``dftk doctor``, and ``dftk selftest``; it never performs the tool's work.
    """
    missing: list[dict[str, Any]] = []
    for req in getattr(spec, "requires", ()) or ():
        status = _requirement_status(req)
        if not status["available"]:
            missing.append({"name": status["name"], "label": status["label"], "install": status["install"]})
    if getattr(spec, "safety", None) == SafetyLevel.DESTRUCTIVE:
        return {"state": "blocked", "reason": "destructive-requires-opt-in", "missing": missing}
    if missing:
        return {"state": "degraded", "missing": missing}
    return {"state": "runnable", "missing": []}


def readiness_summary(specs: Any) -> dict[str, Any]:
    """Aggregate per-tool readiness into deterministic counts and detail."""
    counts = {"runnable": 0, "degraded": 0, "blocked": 0}
    degraded: list[dict[str, Any]] = []
    blocked: list[str] = []
    for spec in specs:
        r = tool_readiness(spec)
        counts[r["state"]] += 1
        if r["state"] == "degraded":
            degraded.append({"name": spec.name, "missing": r["missing"]})
        elif r["state"] == "blocked":
            blocked.append(spec.name)
    return {
        "counts": counts,
        "registered": counts["runnable"] + counts["degraded"] + counts["blocked"],
        "degraded": degraded,
        "blocked": blocked,
    }
