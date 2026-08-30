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

"""HTML forensic report layer — DFTK 3.5.0.

3.5.0 ships **HTML first**: a single self-contained file is searchable,
collapsible, and needs no renderer, whereas PDF would add a heavyweight
dependency chain. The HTML → PDF step can be layered on later without changing
the report model.

The report model mirrors the sections a case review actually walks:

    Case Summary · Evidence Sources · Observations · Recovered Artifacts
    Timeline · Entities · Warnings / Limitations · Chain of Custody
    · Tool Manifest

Every rendered value is HTML-escaped and every section is bounded, so a hostile
or huge Observation cannot blow up the report. The report itself is registered
as a DerivedArtifact (provenance) and its SHA-256 is reported back.
"""

from __future__ import annotations

import hashlib
import html
import re
from datetime import datetime, timezone
from pathlib import Path

from dftk import __version__ as DFTK_VERSION
from dftk.core.helpers import sha256_file
from dftk.core.provenance import ProvenanceIndex
from dftk.core.registry import registry
from dftk.core.models import Observation, Evidence, Status, SafetyLevel

_ISO_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")

_CSS = """
:root{--bg:#0f1115;--panel:#161a21;--line:#242a34;--fg:#dfe4ec;--muted:#8f9bab;--accent:#6ea8fe;--warn:#e0b341;--bad:#e06c75;--ok:#98c379}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 ui-sans-serif,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
header{padding:24px 28px;border-bottom:1px solid var(--line);background:var(--panel)}
header h1{margin:0 0 6px;font-size:20px}header .meta{color:var(--muted);font-size:12px}
main{padding:20px 28px 60px;max-width:1200px}
section{margin:22px 0;border:1px solid var(--line);border-radius:10px;background:var(--panel);overflow:hidden}
section>h2{margin:0;padding:12px 16px;font-size:15px;border-bottom:1px solid var(--line);background:#12161d}
.body{padding:14px 16px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
pre{background:#0c0f14;border:1px solid var(--line);border-radius:6px;padding:10px;overflow:auto;max-height:320px}
details{border-top:1px solid var(--line)}details:first-of-type{border-top:0}
summary{cursor:pointer;padding:8px 16px;font-weight:600}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;border:1px solid var(--line);color:var(--muted)}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}
.muted{color:var(--muted)}.mono{font-family:ui-monospace,Menlo,monospace;font-size:12px}
.small{font-size:12px}
"""


def _e(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def _short(v, n: int = 120) -> str:
    s = "" if v is None else str(v)
    return s if len(s) <= n else s[:n] + "…"


def _collect_timeline(observations: list[dict], limit: int) -> list[dict]:
    """Extract ISO timestamps appearing anywhere in an observation's facts."""
    out: list[dict] = []

    def walk(node, tool: str, ctx: str) -> None:
        if len(out) >= limit:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, tool, f"{ctx}.{k}" if ctx else str(k))
        elif isinstance(node, list):
            for i, v in enumerate(node[:500]):
                walk(v, tool, f"{ctx}[{i}]")
        elif isinstance(node, str):
            m = _ISO_RE.search(node)
            if m:
                out.append({"time": m.group(0), "tool": tool, "context": _short(ctx, 80), "value": _short(node, 160)})

    for obs in observations:
        walk(obs.get("facts", {}) or {}, obs.get("tool", "?"), "")
    out.sort(key=lambda r: r["time"])
    return out[:limit]


def _render_report(
    *,
    case_id: str,
    title: str,
    observations: list[dict],
    timeline_limit: int,
    audit_status: dict | None,
) -> str:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    sources: dict[str, dict] = {}
    entities: dict[str, int] = {}
    warnings: list[tuple[str, str]] = []
    errors: list[tuple[str, str]] = []
    tools: dict[str, int] = {}
    derived: list[dict] = []
    statuses: dict[str, int] = {}

    for obs in observations:
        tool = obs.get("tool", "?")
        tools[tool] = tools.get(tool, 0) + 1
        st = obs.get("status", "?")
        statuses[st] = statuses.get(st, 0) + 1
        for ev in obs.get("evidence", []) or []:
            if not isinstance(ev, dict):
                continue
            src = ev.get("source", "")
            sha = ev.get("source_sha256", "") or (obs.get("meta", {}) or {}).get("source_sha256", "")
            if src:
                sources.setdefault(src, {"source": src, "sha256": sha, "kinds": set(), "tools": set()})
                sources[src]["kinds"].add(ev.get("kind", ""))
                sources[src]["tools"].add(tool)
            val = _short(ev.get("value", ""), 200)
            if val:
                entities[f"{ev.get('kind','')}: {val}"] = entities.get(f"{ev.get('kind','')}: {val}", 0) + 1
        for d in obs.get("derived_artifacts", []) or []:
            if isinstance(d, dict):
                derived.append(d)
        for w in obs.get("warnings", []) or []:
            warnings.append((tool, str(w)))
        for er in obs.get("errors", []) or []:
            errors.append((tool, str(er)))

    timeline = _collect_timeline(observations, timeline_limit)

    def _status_cls(s: str) -> str:
        return "ok" if s == "ok" else ("bad" if s in ("error", "blocked") else "warn")

    parts: list[str] = []
    parts.append(f"<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                 f"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                 f"<title>{_e(title)}</title><style>{_CSS}</style></head><body>")
    parts.append("<header>")
    parts.append(f"<h1>{_e(title)}</h1>")
    parts.append(f"<div class=\"meta\">case: {_e(case_id or '—')} · generated: {_e(now)} · "
                 f"DFTK {_e(DFTK_VERSION)} · {len(observations)} observation(s)</div>")
    parts.append("</header><main>")

    # Case Summary
    parts.append("<section><h2>Case Summary</h2><div class=\"body\"><table>")
    parts.append(f"<tr><th>Generated (UTC)</th><td class=\"mono\">{_e(now)}</td></tr>")
    parts.append(f"<tr><th>Case ID</th><td>{_e(case_id or '—')}</td></tr>")
    parts.append(f"<tr><th>Observations</th><td>{len(observations)}</td></tr>")
    parts.append(f"<tr><th>Toolkit version</th><td class=\"mono\">{_e(DFTK_VERSION)}</td></tr>")
    parts.append("<tr><th>Status breakdown</th><td>"
                 + ", ".join(f"<span class=\"{_status_cls(s)}\">{_e(s)}</span>: {n}" for s, n in sorted(statuses.items()))
                 + "</td></tr>")
    parts.append("</table></div></section>")

    # Evidence Sources
    parts.append("<section><h2>Evidence Sources</h2><div class=\"body\">")
    if sources:
        parts.append("<table><tr><th>Source</th><th>SHA-256</th><th>Kinds</th><th>Producing tools</th></tr>")
        for s in sources.values():
            parts.append(f"<tr><td class=\"mono\">{_e(_short(s['source'], 160))}</td>"
                         f"<td class=\"mono small\">{_e(_short(s['sha256'], 64))}</td>"
                         f"<td>{_e(', '.join(x for x in s['kinds'] if x))}</td>"
                         f"<td>{_e(', '.join(sorted(s['tools'])))}</td></tr>")
        parts.append("</table>")
    else:
        parts.append("<p class=\"muted\">No evidence sources recorded.</p>")
    parts.append("</div></section>")

    # Observations
    parts.append("<section><h2>Observations</h2><div class=\"body\">")
    for i, obs in enumerate(observations, 1):
        st = obs.get("status", "?")
        parts.append(f"<details><summary>#{i} <span class=\"badge {_status_cls(st)}\">{_e(st)}</span> "
                     f"{_e(obs.get('tool', '?'))} — {_e(_short(obs.get('summary', ''), 140))}</summary>")
        parts.append("<div class=\"body\">")
        parts.append(f"<pre>{_e(_short(obs.get('facts', {}), 6000))}</pre>")
        if obs.get("warnings"):
            parts.append("<div class=\"warn small\"><b>Warnings</b><ul>"
                         + "".join(f"<li>{_e(w)}</li>" for w in obs["warnings"][:50]) + "</ul></div>")
        if obs.get("errors"):
            parts.append("<div class=\"bad small\"><b>Errors</b><ul>"
                         + "".join(f"<li>{_e(x)}</li>" for x in obs["errors"][:50]) + "</ul></div>")
        parts.append("</div></details>")
    parts.append("</div></section>")

    # Recovered Artifacts
    parts.append("<section><h2>Recovered / Derived Artifacts</h2><div class=\"body\">")
    if derived:
        parts.append("<table><tr><th>Artifact</th><th>Source</th><th>Locator</th><th>Derivation</th>"
                     "<th>State</th><th>SHA-256</th><th>Size</th></tr>")
        for d in derived:
            der = d.get("derivation", {}) or {}
            parts.append(f"<tr><td class=\"mono\">{_e(d.get('artifact_id', '—'))}</td>"
                         f"<td class=\"mono small\">{_e(_short(d.get('source_artifact', '—'), 24))}</td>"
                         f"<td class=\"small\">{_e(_short(d.get('locator', ''), 60))}</td>"
                         f"<td class=\"small\">{_e(der.get('tool', '?'))} v{_e(der.get('version', '?'))}</td>"
                         f"<td>{_e(d.get('state', ''))}</td>"
                         f"<td class=\"mono small\">{_e(_short(d.get('sha256', ''), 40))}</td>"
                         f"<td>{_e(d.get('size', 0))}</td></tr>")
        parts.append("</table>")
    else:
        parts.append("<p class=\"muted\">No derived artifacts recorded.</p>")
    parts.append("</div></section>")

    # Timeline
    parts.append("<section><h2>Timeline</h2><div class=\"body\">")
    if timeline:
        parts.append("<table><tr><th>Time (UTC)</th><th>Tool</th><th>Context</th><th>Value</th></tr>")
        for t in timeline:
            parts.append(f"<tr><td class=\"mono\">{_e(t['time'])}</td><td>{_e(t['tool'])}</td>"
                         f"<td class=\"small\">{_e(t['context'])}</td><td class=\"small\">{_e(t['value'])}</td></tr>")
        parts.append("</table>")
    else:
        parts.append("<p class=\"muted\">No timestamps found in observation facts.</p>")
    parts.append("</div></section>")

    # Entities
    parts.append("<section><h2>Entities</h2><div class=\"body\">")
    if entities:
        parts.append("<table><tr><th>Entity</th><th>Occurrences</th></tr>")
        for ent, n in sorted(entities.items(), key=lambda kv: -kv[1])[:500]:
            parts.append(f"<tr><td class=\"small\">{_e(_short(ent, 220))}</td><td>{n}</td></tr>")
        parts.append("</table>")
    else:
        parts.append("<p class=\"muted\">No entities extracted.</p>")
    parts.append("</div></section>")

    # Warnings / Limitations
    parts.append("<section><h2>Warnings / Limitations</h2><div class=\"body\">")
    if warnings or errors:
        parts.append("<table><tr><th>Tool</th><th>Kind</th><th>Message</th></tr>")
        for tool, w in warnings[:500]:
            parts.append(f"<tr><td>{_e(tool)}</td><td class=\"warn\">warning</td><td class=\"small\">{_e(_short(w, 300))}</td></tr>")
        for tool, e in errors[:500]:
            parts.append(f"<tr><td>{_e(tool)}</td><td class=\"bad\">error</td><td class=\"small\">{_e(_short(e, 300))}</td></tr>")
        parts.append("</table>")
    else:
        parts.append("<p class=\"muted\">No warnings recorded.</p>")
    parts.append("</div></section>")

    # Chain of Custody
    parts.append("<section><h2>Chain of Custody</h2><div class=\"body\">")
    if audit_status is None:
        parts.append("<p class=\"muted\">No audit ledger supplied — chain of custody not verified.</p>")
    else:
        verdict = "VALID" if audit_status.get("valid") else "BROKEN"
        cls = "ok" if audit_status.get("valid") else "bad"
        parts.append(f"<p>Audit ledger verdict: <b class=\"{cls}\">{_e(verdict)}</b></p>")
        parts.append("<table>")
        parts.append(f"<tr><th>Records</th><td>{_e(audit_status.get('records', audit_status.get('broken_at', 0)))}</td></tr>")
        if not audit_status.get("valid"):
            parts.append(f"<tr><th>Broken at record</th><td class=\"bad\">{_e(audit_status.get('broken_at'))}</td></tr>")
            parts.append(f"<tr><th>Line</th><td>{_e(audit_status.get('line', '—'))}</td></tr>")
        parts.append(f"<tr><th>Reason</th><td>{_e(audit_status.get('reason'))}</td></tr>")
        parts.append("</table>")
    parts.append("</div></section>")

    # Tool Manifest
    parts.append("<section><h2>Tool Manifest</h2><div class=\"body\"><table>"
                 "<tr><th>Tool</th><th>Invocations</th></tr>")
    for t, n in sorted(tools.items()):
        parts.append(f"<tr><td class=\"mono\">{_e(t)}</td><td>{n}</td></tr>")
    parts.append("</table></div></section>")

    parts.append("</main></body></html>")
    return "".join(parts)


@registry.tool(
    name="case.report_html",
    description=(
        "Render a self-contained HTML forensic report from a list of Observations: "
        "case summary, evidence sources, observations, recovered artifacts, timeline, "
        "entities, warnings/limitations, chain of custody and tool manifest. "
        "STATEFUL: writes only to the workspace; the report is registered as a DerivedArtifact."
    ),
    parameters={
        "type": "object",
        "properties": {
            "output_dir": {"type": "string", "description": "workspace directory to write the report into"},
            "observations": {"type": "array", "items": {"type": "object"},
                             "description": "list of Observation.to_dict() objects"},
            "case_id": {"type": "string", "default": ""},
            "title": {"type": "string", "default": "DFTK Forensic Report"},
            "audit_log": {"type": "string", "default": "", "description": "optional audit ledger to verify for chain of custody"},
            "name": {"type": "string", "default": "dftk_report.html"},
            "timeline_limit": {"type": "integer", "default": 2000},
        },
        "required": ["output_dir", "observations"],
    },
    safety=SafetyLevel.STATEFUL,
    tags=("report", "html", "case"),
    produces=("html_report", "derived_artifact"),
    cost_hint="medium",
    path_roles={"output_dir": "WORKSPACE_OUTPUT", "audit_log": "WORKSPACE_INPUT"},
)
def report_html(
    output_dir: str,
    observations: list[dict],
    case_id: str = "",
    title: str = "DFTK Forensic Report",
    audit_log: str = "",
    name: str = "dftk_report.html",
    timeline_limit: int = 2000,
) -> Observation:
    if not output_dir:
        return Observation("case.report_html", Status.BLOCKED, "output_dir is required (workspace)",
                           errors=["workspace output not specified"])
    obs_list = [o for o in (observations or []) if isinstance(o, dict)]
    audit_status = None
    if audit_log:
        try:
            from dftk.core.audit import ToolAuditLog

            audit_status = ToolAuditLog.verify(audit_log)
        except Exception as e:  # ledger problems must not break reporting
            audit_status = {"valid": False, "reason": f"ledger verification failed: {e}", "broken_at": 0}

    html_text = _render_report(
        case_id=case_id,
        title=title,
        observations=obs_list,
        timeline_limit=timeline_limit,
        audit_status=audit_status,
    )
    data = html_text.encode("utf-8")
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / (name or "dftk_report.html")
    target.write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()

    prov = ProvenanceIndex()
    art = prov.add(
        source_artifact="",
        locator=f"case:{case_id or 'unnamed'};report:{target.name}",
        tool="case.report_html",
        version=DFTK_VERSION,
        sha256=sha,
        size=len(data),
        kind="report",
        state="LIVE",
        params={"case_id": case_id, "observations": len(obs_list), "audit_log": audit_log or ""},
    )
    return Observation(
        "case.report_html",
        Status.OK,
        f"Wrote HTML report ({len(data)} bytes) for {len(obs_list)} observation(s)",
        facts={
            "report_path": str(target),
            "sha256": sha,
            "size": len(data),
            "observation_count": len(obs_list),
            "audit_verdict": ("VALID" if audit_status and audit_status.get("valid")
                              else ("BROKEN" if audit_status else "not_checked")),
        },
        evidence=[Evidence(str(target), "html_report", f"{len(data)} bytes", locator="report",
                           source_sha256=sha, artifact_id=art.artifact_id,
                           derivation=art.derivation.to_dict(), state="LIVE",
                           method="DFTK HTML report renderer")],
        warnings=[] if (audit_status is None or audit_status.get("valid")) else
                 [f"audit ledger BROKEN at record {audit_status.get('broken_at')}: {audit_status.get('reason')}"],
        derived_artifacts=prov.all(),
        meta={"source_sha256": sha, "provenance": prov.to_dict()},
    )
