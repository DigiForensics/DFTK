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

"""Investigation case session.

A case accumulates the Observations produced by read-only tool runs in an
isolated workspace (``<workspace>/cases/<case_id>/``) and can correlate their
time-bearing events into a single unified timeline. The session only ever
writes under its explicit workspace directory; it never touches evidence.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .registry import registry
from .safety import SafetyPolicy
from .timeline_core import merge_events
from .models import SafetyLevel, Observation, Status

DEFAULT_WORKSPACE = ".dftk"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CaseError(RuntimeError):
    """Raised when a case session operation cannot proceed."""


class CaseSession:
    def __init__(self, workspace: str | Path = DEFAULT_WORKSPACE):
        self.workspace = Path(workspace)
        self.cases_dir = self.workspace / "cases"

    # -- discovery ---------------------------------------------------------
    def list(self) -> list[dict]:
        if not self.cases_dir.is_dir():
            return []
        out: list[dict] = []
        for d in sorted(self.cases_dir.iterdir()):
            if not d.is_dir():
                continue
            m = d / "manifest.json"
            if not m.exists():
                continue
            try:
                data = json.loads(m.read_text(encoding="utf-8"))
            except Exception:
                out.append({"case_id": d.name, "name": None, "created_at": None, "runs": 0})
                continue
            out.append(
                {
                    "case_id": data.get("case_id"),
                    "name": data.get("name"),
                    "created_at": data.get("created_at"),
                    "runs": len(data.get("runs", [])),
                }
            )
        return out

    # -- lifecycle ---------------------------------------------------------
    def new(self, name: str | None = None) -> dict:
        self.cases_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        case_id = f"case-{stamp}-{uuid.uuid4().hex[:6]}"
        manifest = {
            "schema": "dftk.case/1",
            "case_id": case_id,
            "name": name or case_id,
            "created_at": _now(),
            "toolkit": "dftk",
            "runs": [],
        }
        case_dir = self.cases_dir / case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        (case_dir / "artifacts").mkdir(exist_ok=True)
        (case_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return manifest

    def _manifest(self, case_id: str) -> dict:
        p = self.cases_dir / case_id / "manifest.json"
        if not p.exists():
            raise CaseError(f"no such case: {case_id}")
        return json.loads(p.read_text(encoding="utf-8"))

    def _save_manifest(self, case_id: str, manifest: dict) -> None:
        (self.cases_dir / case_id / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    # -- operations ---------------------------------------------------------
    def run(
        self,
        case_id: str,
        tool: str,
        params: dict[str, Any] | None = None,
        *,
        allow_network: bool = False,
        max_safety: str = "READ_ONLY",
    ) -> Observation:
        manifest = self._manifest(case_id)
        policy = SafetyPolicy(
            max_level=SafetyLevel[max_safety], allow_network=allow_network
        )
        obs = registry.run(tool, params or {}, policy)
        seq = len(manifest["runs"]) + 1
        fname = f"{seq:03d}_{tool.replace('.', '_')}.json"
        (self.cases_dir / case_id / "artifacts" / fname).write_text(
            json.dumps(obs.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        manifest["runs"].append(
            {
                "seq": seq,
                "tool": tool,
                "params": params or {},
                "artifact": f"artifacts/{fname}",
                "status": obs.status.value,
                "ran_at": _now(),
            }
        )
        self._save_manifest(case_id, manifest)
        return obs

    def timeline(self, case_id: str, *, limit: int = 200_000) -> Observation:
        manifest = self._manifest(case_id)
        sources = []
        for run in manifest.get("runs", []):
            ap = self.cases_dir / case_id / run["artifact"]
            if ap.exists():
                sources.append({"file": str(ap)})
        merged = merge_events(sources, limit=limit)
        events = merged["events"]
        facts = {
            "case_id": case_id,
            "events": events,
            "per_source": merged["per_source"],
            "span": merged["span"],
            "skipped": merged["skipped"],
            "source_count": len(merged["per_source"]),
        }
        status = Status.OK if events else Status.PARTIAL
        summary = (
            f"Case {case_id}: merged {len(events)} event(s) "
            f"from {len(merged['per_source'])} source(s)"
        )
        warnings = (
            [f"{merged['skipped']} event(s) skipped (no parseable timestamp)"]
            if merged["skipped"]
            else []
        )
        return Observation(
            "case.timeline", status, summary, facts=facts, warnings=warnings
        )

    def export(self, case_id: str, fmt: str = "json", *, limit: int = 200_000) -> str:
        manifest = self._manifest(case_id)
        tl = self.timeline(case_id, limit=limit)
        report = {
            "schema": "dftk.case.report/1",
            "case": {k: manifest.get(k) for k in ("case_id", "name", "created_at", "runs")},
            "timeline": tl.to_dict(),
        }
        if fmt == "md":
            return _render_markdown(report)
        return json.dumps(report, ensure_ascii=False, indent=2)


def _render_markdown(report: dict) -> str:
    case = report["case"]
    lines = [
        f"# Case report: {case.get('name')}",
        "",
        f"- Case ID: `{case.get('case_id')}`",
        f"- Created: {case.get('created_at')}",
        f"- Runs: {len(case.get('runs', []))}",
        "",
    ]
    tl = report["timeline"]["facts"]
    span = tl.get("span")
    if span:
        lines.append(
            f"## Timeline ({tl['source_count']} source(s), {len(tl['events'])} events)"
        )
        lines.append(f"- Span: {span['earliest']} → {span['latest']}")
        lines.append("")
        for e in tl["events"][:500]:
            line = f"- `{e['time']}` [{e['source']}] {e['kind']} {e['path']}".rstrip()
            lines.append(line)
    else:
        lines.append("## Timeline: no time-bearing events captured")
    return "\n".join(lines)
