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

A case accumulates Observations in ``<workspace>/cases/<case_id>/`` and can
correlate time-bearing events into a unified timeline. Source evidence is never
modified. DFTK 3.1 makes manifest updates atomic and serializes each case across
threads/processes so CLI and MCP callers cannot race run sequence allocation.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .models import Observation, SafetyLevel, Status
from .audit import ToolAuditLog
from .filelock import exclusive_file_lock
from .registry import registry
from .safety import SafetyPolicy
from .timeline_core import merge_events


def default_workspace() -> Path:
    """Return the user-owned default location for persisted case material.

    Case files, locks, and audit records are derived evidence. Keeping them out
    of the current directory makes the safe path the default when a user starts
    DFTK from an acquired or read-only evidence volume. Set ``DFTK_WORKSPACE``
    to use an organisation-managed case root instead.
    """
    configured = os.environ.get("DFTK_WORKSPACE")
    return Path(configured).expanduser() if configured else Path.home() / ".dftk"


DEFAULT_WORKSPACE = default_workspace()

# Five-state conclusion enum, kept identical to the DFTK-skill answer-slots.md
# (SKILL.md §10) so a Case finding can be exported to answer_slots.json without
# translation. Adding a value here must be mirrored in the skill reference.
FINDING_STATUSES = ("VERIFIED", "SUPPORTED", "CANDIDATE", "UNRESOLVED", "UNSUPPORTED")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CaseError(RuntimeError):
    """Raised when a case session operation cannot proceed."""


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".tmp-{os.getpid()}-{uuid.uuid4().hex[:8]}")
    with tmp.open("w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
        fh.flush()
        try:
            os.fsync(fh.fileno())
        except OSError:
            pass
    os.replace(tmp, path)


def _exclusive_file_lock(path: Path):
    """Alias for the shared advisory lock helper (see core.filelock)."""
    return exclusive_file_lock(path)


class CaseSession:
    def __init__(self, workspace: str | Path | None = None):
        self.workspace = Path(workspace).expanduser() if workspace is not None else default_workspace()
        self.cases_dir = self.workspace / "cases"
        # Intra-process guard: serializes runs issued from multiple threads of
        # the *same* CaseSession (e.g. an Agent runtime fanning out tool calls).
        # The advisory file lock below still covers the cross-process case
        # (separate CLI / MCP worker processes); the two layers are independent
        # and both must be held to allocate a run sequence safely.
        self._run_lock = threading.Lock()

    # -- discovery ---------------------------------------------------------
    def list(self) -> list[dict]:
        if not self.cases_dir.is_dir():
            return []
        out: list[dict] = []
        for directory in sorted(self.cases_dir.iterdir()):
            if not directory.is_dir():
                continue
            manifest_path = directory / "manifest.json"
            if not manifest_path.exists():
                continue
            try:
                data = json.loads(manifest_path.read_text(encoding="utf-8"))
            except Exception:
                out.append(
                    {
                        "case_id": directory.name,
                        "name": None,
                        "created_at": None,
                        "runs": 0,
                    }
                )
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

    def _case_dir(self, case_id: str) -> Path:
        base = self.cases_dir.resolve(strict=False)
        candidate = (base / str(case_id)).resolve(strict=False)
        if candidate.parent != base:
            raise CaseError(f"invalid case id: {case_id}")
        return candidate

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
        _atomic_write_text(
            case_dir / "manifest.json",
            json.dumps(manifest, indent=2, ensure_ascii=False),
        )
        return manifest

    def _manifest(self, case_id: str) -> dict:
        path = self._case_dir(case_id) / "manifest.json"
        if not path.exists():
            raise CaseError(f"no such case: {case_id}")
        return json.loads(path.read_text(encoding="utf-8"))

    def _save_manifest(self, case_id: str, manifest: dict) -> None:
        _atomic_write_text(
            self._case_dir(case_id) / "manifest.json",
            json.dumps(manifest, indent=2, ensure_ascii=False),
        )

    def show(self, case_id: str) -> dict:
        """Return the current case manifest."""
        return self._manifest(case_id)

    def _run_artifact_path(self, case_id: str, run: dict) -> Path:
        """Resolve one manifest artifact path without allowing case-directory escape."""
        case_dir = self._case_dir(case_id)
        artifact = (case_dir / str(run.get("artifact", ""))).resolve(strict=False)
        try:
            artifact.relative_to(case_dir)
        except ValueError as exc:
            raise CaseError(
                f"invalid case run artifact path: seq {run.get('seq', '?')}"
            ) from exc
        return artifact

    def read_run(self, case_id: str, seq: int) -> tuple[dict, dict]:
        """Return ``(run_manifest_entry, Observation_dict)`` for one persisted run."""
        manifest = self._manifest(case_id)
        target = next(
            (run for run in manifest.get("runs", []) if int(run.get("seq", -1)) == int(seq)),
            None,
        )
        if target is None:
            raise CaseError(f"case {case_id} has no run seq {seq}")
        artifact = self._run_artifact_path(case_id, target)
        if not artifact.exists() or not artifact.is_file():
            raise CaseError(f"case run artifact is missing: seq {seq}")
        return target, json.loads(artifact.read_text(encoding="utf-8"))

    # -- operations ---------------------------------------------------------
    def _run_with_entry(
        self,
        case_id: str,
        tool: str,
        params: dict[str, Any] | None = None,
        *,
        allow_network: bool = False,
        max_safety: str = "READ_ONLY",
        audit: Any = None,
        caller: str | None = None,
    ) -> tuple[Observation, dict]:
        """Run and persist one capability, returning its exact manifest entry.

        This internal helper keeps sequence allocation, artifact persistence and the
        returned run metadata inside one case lock. It avoids the ambiguity of
        rereading ``runs[-1]`` after another process may have appended a run.
        """
        # Validate existence before creating/opening the lock file so an invalid or
        # missing case id cannot leave behind an empty case directory. Reload the
        # manifest after acquiring the lock to observe the latest committed state.
        self._manifest(case_id)
        case_dir = self._case_dir(case_id)
        lock_path = case_dir / ".case.lock"
        # `audit` may be a path/str (from the CLI or a test) or a ready
        # ToolAuditLog. registry.run expects the latter, so wrap a path here and
        # keep the original reference for persisting the ledger location.
        audit_log = (
            audit
            if isinstance(audit, ToolAuditLog)
            else (ToolAuditLog(audit) if audit else None)
        )
        with self._run_lock:
            with _exclusive_file_lock(lock_path):
                manifest = self._manifest(case_id)
                policy = SafetyPolicy(
                    max_level=SafetyLevel[max_safety],
                    allow_network=allow_network,
                )
                obs = registry.run(
                    tool,
                    params or {},
                    policy,
                    audit=audit_log,
                    caller=caller or f"case:{case_id}",
                )
                seq = len(manifest["runs"]) + 1
                filename = f"{seq:03d}_{tool.replace('.', '_')}.json"
                artifact_path = case_dir / "artifacts" / filename
                _atomic_write_text(
                    artifact_path,
                    json.dumps(obs.to_dict(), ensure_ascii=False, indent=2),
                )
                entry = {
                    "seq": seq,
                    "tool": tool,
                    "params": params or {},
                    "artifact": f"artifacts/{filename}",
                    "status": obs.status.value,
                    "ran_at": _now(),
                }
                manifest["runs"].append(entry)
                if audit:
                    # Remember which ledger the case writes to so the exported
                    # report can attest to its own chain of custody. Store the
                    # resolved path string, not the ToolAuditLog object repr.
                    manifest["audit_ledger"] = str(audit_log.path)
                self._save_manifest(case_id, manifest)
                return obs, dict(entry)

    def run(
        self,
        case_id: str,
        tool: str,
        params: dict[str, Any] | None = None,
        *,
        allow_network: bool = False,
        max_safety: str = "READ_ONLY",
        audit: Any = None,
        caller: str | None = None,
    ) -> Observation:
        obs, _entry = self._run_with_entry(
            case_id,
            tool,
            params,
            allow_network=allow_network,
            max_safety=max_safety,
            audit=audit,
            caller=caller,
        )
        return obs

    def timeline(self, case_id: str, *, limit: int = 200_000) -> Observation:
        manifest = self._manifest(case_id)
        sources = []
        for run in manifest.get("runs", []):
            artifact_path = self._run_artifact_path(case_id, run)
            if artifact_path.exists() and artifact_path.is_file():
                sources.append({"file": str(artifact_path)})
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
            "case.timeline",
            status,
            summary,
            facts=facts,
            warnings=warnings,
        )

    def entity_graph(self, case_id: str, *, limit: int = 5000) -> Observation:
        """Correlate source-linked entities across all persisted case Observations."""
        from .entity_graph import correlate_files

        manifest = self._manifest(case_id)
        files: list[str] = []
        for run in manifest.get("runs", []):
            artifact = self._run_artifact_path(case_id, run)
            if artifact.is_file():
                files.append(str(artifact))
        result = correlate_files(files, limit=limit, tool="case.entity_graph")
        result.facts["case_id"] = case_id
        return result

    def next_actions(self, case_id: str, *, limit: int = 12) -> dict[str, Any]:
        """Return a compact, deterministic next-action queue for an Agent.

        This deliberately recommends only known DFTK calls derived from persisted
        evidence intake and Case state. It does not infer findings or invent shell
        commands from artifact content.
        """
        manifest = self._manifest(case_id)
        runs = list(manifest.get("runs", []))
        executed = {(str(run.get("tool")), json.dumps(run.get("params", {}), sort_keys=True, ensure_ascii=False)) for run in runs}
        actions: list[dict[str, Any]] = []
        intake: dict[str, Any] | None = None
        for run in reversed(runs):
            if run.get("tool") != "evidence.intake":
                continue
            artifact = self._run_artifact_path(case_id, run)
            try:
                intake = json.loads(artifact.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                pass
            break
        if intake is None:
            actions.append({
                "action": "run", "tool": "evidence.intake", "params": {"path": "<evidence path>"},
                "reason": "No persisted evidence intake exists. Start with a bounded manifest before selecting specialist tools.",
                "requires_user_value": ["path"],
            })
        else:
            for step in (intake.get("facts", {}) or {}).get("next_steps", []):
                tool = step.get("tool")
                params = step.get("params")
                if not isinstance(tool, str) or not isinstance(params, dict):
                    continue
                key = (tool, json.dumps(params, sort_keys=True, ensure_ascii=False))
                if key in executed:
                    continue
                actions.append({"action": "run", "tool": tool, "params": params, "reason": step.get("reason", "evidence-intake route")})
                if len(actions) >= limit:
                    break
        executed_tools = {str(run.get("tool")) for run in runs}
        if len(runs) >= 2 and "case.entity_graph" not in executed_tools:
            actions.append({"action": "case", "operation": "graph", "reason": "Multiple persisted Observations can now be correlated into source-linked entities."})
        if len(runs) >= 2 and "case.timeline" not in executed_tools:
            actions.append({"action": "case", "operation": "timeline", "reason": "Multiple persisted Observations may contain time-bearing events."})
        return {"case_id": case_id, "run_count": len(runs), "actions": actions[:limit], "guidance": "Run only actions that answer the authorized investigation question; recommendations are triage steps, not findings."}

    def guided_intake(self, case_id: str, path: str, *, objective: str | None = None, max_steps: int = 2) -> dict[str, Any]:
        """Persist an Agent first response as individual, recoverable Case runs.

        Unlike the convenience recipe, this Case-native form persists the intake
        and each selected child separately. Agents can therefore page, correlate,
        audit, and resume every action after a context reset.
        """
        if not 0 <= int(max_steps) <= 5:
            raise CaseError("max_steps must be between 0 and 5")
        self._manifest(case_id)
        intake = self.run(case_id, "evidence.intake", {"path": path})
        raw_steps = intake.facts.get("next_steps", []) if isinstance(intake.facts, dict) else []
        steps = [step for step in raw_steps if isinstance(step, dict) and isinstance(step.get("tool"), str) and isinstance(step.get("params"), dict)]
        words = set((objective or "").lower().replace("_", " ").split())
        steps.sort(key=lambda step: (-sum(word in (step["tool"] + " " + str(step.get("reason", ""))).lower() for word in words), step["tool"], json.dumps(step["params"], sort_keys=True)))
        executed: list[dict[str, Any]] = []
        deferred: list[dict[str, Any]] = []
        for step in steps:
            if len(executed) >= int(max_steps):
                deferred.append(step); continue
            try:
                spec = registry.get(step["tool"])
            except KeyError:
                deferred.append({**step, "deferred_reason": "capability unavailable"}); continue
            if spec.safety != SafetyLevel.READ_ONLY or spec.network:
                deferred.append({**step, "deferred_reason": "not eligible for automatic read-only first response"}); continue
            observation = self.run(case_id, step["tool"], step["params"])
            executed.append({"tool": step["tool"], "params": step["params"], "reason": step.get("reason", "evidence-intake route"), "status": observation.status.value})
        return {"case_id": case_id, "intake_status": intake.status.value, "executed_actions": executed, "deferred_actions": deferred, "next_actions": self.next_actions(case_id), "guidance": "Each executed action is persisted as its own Case run. Review results before running deferred actions."}

    def brief(self, case_id: str, *, highlight_limit: int = 20) -> dict[str, Any]:
        """Return a bounded, Agent-context-friendly Case checkpoint."""
        manifest = self._manifest(case_id)
        runs: list[dict[str, Any]] = []
        highlights: list[dict[str, Any]] = []
        for run in manifest.get("runs", []):
            artifact = self._run_artifact_path(case_id, run)
            try:
                observation = json.loads(artifact.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                runs.append({"seq": run.get("seq"), "tool": run.get("tool"), "status": "missing_artifact"})
                continue
            facts = observation.get("facts") if isinstance(observation.get("facts"), dict) else {}
            runs.append({
                "seq": run.get("seq"), "tool": observation.get("tool", run.get("tool")),
                "status": observation.get("status", run.get("status")), "summary": observation.get("summary", ""),
                "warnings": (observation.get("warnings") or [])[:3], "errors": (observation.get("errors") or [])[:3],
            })
            for key, label in (("hunt_hits", "hunt_hit"), ("leads", "web_code_lead"), ("matches", "yara_match")):
                value = facts.get(key)
                if not isinstance(value, list):
                    continue
                for item in value[:5]:
                    highlights.append({"run_seq": run.get("seq"), "tool": observation.get("tool"), "kind": label, "value": item})
                    if len(highlights) >= highlight_limit:
                        break
                if len(highlights) >= highlight_limit:
                    break
            if len(highlights) >= highlight_limit:
                break
        graph = self.entity_graph(case_id, limit=500)
        shared_entities = [node for node in graph.facts.get("nodes", []) if len(node.get("occurrences", [])) >= 2][:highlight_limit]
        timeline = self.timeline(case_id, limit=10_000)
        return {
            "schema": "dftk.case.brief/1", "case_id": case_id, "name": manifest.get("name"),
            "run_count": len(runs), "runs": runs, "highlights": highlights,
            "shared_entities": shared_entities, "timeline_span": timeline.facts.get("span"),
            "next_actions": self.next_actions(case_id),
            "guidance": "This is a bounded checkpoint, not a final finding. Read the referenced Case run before relying on any highlight.",
        }

    def export(self, case_id: str, fmt: str = "json", *, limit: int = 200_000) -> str:
        manifest = self._manifest(case_id)
        timeline = self.timeline(case_id, limit=limit)
        report = {
            "schema": "dftk.case.report/1",
            "case": {
                key: manifest.get(key)
                for key in ("case_id", "name", "created_at", "runs")
            },
            "timeline": timeline.to_dict(),
            "entity_graph": self.entity_graph(case_id).to_dict(),
        }
        if manifest.get("audit_ledger"):
            report["audit"] = _audit_section(manifest["audit_ledger"])
        findings = self.findings_report(case_id)
        if findings["findings"]:
            report["conclusions"] = findings
        if fmt == "md":
            return _render_markdown(report)
        return json.dumps(report, ensure_ascii=False, indent=2)

    # -- conclusions ------------------------------------------------------
    def add_finding(
        self,
        case_id: str,
        claim: str,
        status: str,
        citations: list[dict[str, Any]],
        *,
        need_verify: str = "",
        analyst: str = "",
    ) -> dict[str, Any]:
        """Register a conclusion tied to persisted Case evidence (STATEFUL).

        A finding is only accepted when every citation resolves to a real run and
        a real evidence item inside that run's artifact. The referenced
        evidence ``source_sha256`` is captured at registration so a later
        ``export``/``answers`` can flag citations whose underlying evidence
        changed (``stale_citation``), instead of letting conclusions silently
        drift from the evidence they rest on.
        """
        if not claim or not str(claim).strip():
            raise CaseError("finding claim must be a non-empty string")
        if status not in FINDING_STATUSES:
            raise CaseError(
                f"finding status must be one of {FINDING_STATUSES}, got {status!r}"
            )
        if not isinstance(citations, list) or not citations:
            raise CaseError("finding must carry at least one citation")
        validated = self._validate_citations(case_id, citations)
        manifest = self._manifest(case_id)
        findings = manifest.setdefault("findings", [])
        fid = f"F{len(findings) + 1:03d}"
        finding = {
            "id": fid,
            "claim": str(claim),
            "status": status,
            "citations": validated,
            "need_verify": str(need_verify or ""),
            "analyst": str(analyst or ""),
            "created_at": _now(),
        }
        findings.append(finding)
        self._save_manifest(case_id, manifest)
        return finding

    def _validate_citations(
        self, case_id: str, citations: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Resolve citations against persisted runs; capture evidence hashes."""
        resolved: list[dict[str, Any]] = []
        for index, citation in enumerate(citations):
            if not isinstance(citation, dict):
                raise CaseError(f"citation #{index} must be an object")
            run_seq = citation.get("run_seq")
            evidence_index = citation.get("evidence_index")
            try:
                _entry, observation = self.read_run(case_id, int(run_seq))
            except (CaseError, TypeError, ValueError) as exc:
                raise CaseError(
                    f"citation #{index} references unknown run seq {run_seq}: {exc}"
                ) from exc
            evidence = (observation.get("evidence") or [])
            if not isinstance(evidence_index, int) or not (
                0 <= evidence_index < len(evidence)
            ):
                raise CaseError(
                    f"citation #{index} references evidence index {evidence_index} "
                    f"out of range for run seq {run_seq} (have {len(evidence)} items)"
                )
            item = evidence[evidence_index]
            resolved.append(
                {
                    "run_seq": int(run_seq),
                    "evidence_index": int(evidence_index),
                    "evidence_sha256": item.get("source_sha256") or "",
                    "kind": item.get("kind", ""),
                }
            )
        return resolved

    def list_findings(self, case_id: str) -> list[dict[str, Any]]:
        """Return the raw finding records stored for a case."""
        return list(self._manifest(case_id).get("findings", []))

    def findings_report(self, case_id: str) -> dict[str, Any]:
        """Resolve findings with live citation state and stale-citation flags.

        Each citation is re-read from its run artifact so the report shows the
        *current* evidence hash next to the hash captured at registration. A
        mismatch (or a missing run/evidence item) marks ``stale`` so reviewers
        can see exactly which conclusions no longer sit on the evidence they
        cited.
        """
        manifest = self._manifest(case_id)
        findings = manifest.get("findings", [])
        out_findings: list[dict[str, Any]] = []
        stale_total = 0
        for finding in findings:
            resolved_citations: list[dict[str, Any]] = []
            stale = 0
            for citation in finding.get("citations", []):
                entry: dict[str, Any] = {
                    "run_seq": citation["run_seq"],
                    "evidence_index": citation["evidence_index"],
                    "registered_sha256": citation.get("evidence_sha256", ""),
                }
                try:
                    _run_entry, observation = self.read_run(
                        case_id, citation["run_seq"]
                    )
                    evidence = observation.get("evidence") or []
                    item = (
                        evidence[citation["evidence_index"]]
                        if 0 <= citation["evidence_index"] < len(evidence)
                        else None
                    )
                except CaseError:
                    item = None
                if item is None:
                    entry["resolved"] = False
                    entry["stale"] = True
                    entry["current_value"] = None
                    stale += 1
                else:
                    current_sha = item.get("source_sha256") or ""
                    entry["resolved"] = True
                    entry["current_sha256"] = current_sha
                    entry["kind"] = item.get("kind", "")
                    entry["current_value"] = item.get("value")
                    entry["locator"] = item.get("locator", "")
                    entry["stale"] = bool(
                        citation.get("evidence_sha256")
                        and citation["evidence_sha256"] != current_sha
                    )
                    if entry["stale"]:
                        stale += 1
                resolved_citations.append(entry)
            stale_total += stale
            out_findings.append(
                {
                    "id": finding["id"],
                    "claim": finding["claim"],
                    "status": finding["status"],
                    "need_verify": finding.get("need_verify", ""),
                    "analyst": finding.get("analyst", ""),
                    "created_at": finding.get("created_at"),
                    "citations": resolved_citations,
                    "stale_citations": stale,
                }
            )
        return {
            "schema": "dftk.case.findings/1",
            "case_id": case_id,
            "findings": out_findings,
            "finding_count": len(out_findings),
            "stale_citation_count": stale_total,
        }

    def answers(self, case_id: str, out: str | None = None) -> dict[str, Any]:
        """Produce an answer_slots.json-shaped payload for the skill scorer.

        Each finding becomes a slot keyed by its finding id. Citations map to the
        ``evidence`` array with the *current* evidence hash; ``answer`` is the
        first resolved evidence value (or null). The payload is also written to
        ``out`` when given, so it drops straight into the question-workspace
        ``answers/`` directory the skill expects.
        """
        report = self.findings_report(case_id)
        slots: dict[str, Any] = {}
        for finding in report["findings"]:
            evidence: list[dict[str, Any]] = []
            for citation in finding["citations"]:
                if not citation.get("resolved"):
                    continue
                evidence.append(
                    {
                        "path": f"cases/{case_id}/artifacts/{self._run_artifact_filename(case_id, citation['run_seq'])}",
                        "locator": f"evidence[{citation['evidence_index']}]",
                        "field": citation.get("kind", ""),
                        "value": citation.get("current_value"),
                        "hash": citation.get("current_sha256")
                        or citation.get("registered_sha256", ""),
                    }
                )
            slots[finding["id"]] = {
                "question": finding["claim"],
                "status": finding["status"],
                "answer": evidence[0]["value"] if evidence else None,
                "evidence": evidence,
                "need_verify": finding["need_verify"] or None,
            }
        payload: dict[str, Any] = {
            "schema": "dftk.case.answers/1",
            "case_id": case_id,
            "slots": slots,
        }
        if out:
            path = Path(out)
            _atomic_write_text(
                path, json.dumps(payload, ensure_ascii=False, indent=2)
            )
        return payload

    def _run_artifact_filename(self, case_id: str, run_seq: int) -> str:
        """Return the stored artifact filename for a run seq (best effort)."""
        manifest = self._manifest(case_id)
        for run in manifest.get("runs", []):
            if int(run.get("seq", -1)) == int(run_seq):
                return run.get("artifact", "").split("/")[-1]
        return f"{int(run_seq):03d}.json"


def _audit_section(ledger: str) -> dict[str, Any]:
    """Verify the case ledger and return the digest embedded in the report.

    A report that cites its own chain of custody can be checked by a reviewer
    without trusting the case directory: recompute the ledger and compare.
    """
    from .audit import verify_ledger

    report = verify_ledger(ledger)
    return {
        "ledger": report["ledger"],
        "verdict": report["verdict"],
        "ok": report["ok"],
        "records": report["records"],
        "chained_records": report["chained_records"],
        "legacy_records": report["legacy_records"],
        "last_seq": report["last_seq"],
        "last_record_hash": report["last_record_hash"],
        "file_sha256": report["file_sha256"],
        "tools": report["tools"],
        "defects": report["defects"],
        "warnings": report["warnings"],
        "verified_at": _now(),
    }


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
    timeline = report["timeline"]["facts"]
    span = timeline.get("span")
    if span:
        lines.append(
            f"## Timeline ({timeline['source_count']} source(s), "
            f"{len(timeline['events'])} events)"
        )
        lines.append(f"- Span: {span['earliest']} → {span['latest']}")
        lines.append("")
        for event in timeline["events"][:500]:
            line = (
                f"- `{event['time']}` [{event['source']}] "
                f"{event['kind']} {event['path']}"
            ).rstrip()
            lines.append(line)
    else:
        lines.append("## Timeline: no time-bearing events captured")
    lines.append("")
    audit = report.get("audit")
    if audit:
        lines.append(f"## Audit ledger: {audit['verdict']}")
        lines.append("")
        lines.append(f"- Ledger: `{audit['ledger']}`")
        lines.append(
            f"- Records: {audit['records']} ({audit['chained_records']} chained, "
            f"{audit['legacy_records']} legacy)"
        )
        lines.append(f"- Last sequence: {audit['last_seq']}")
        lines.append(f"- Ledger SHA-256: `{audit['file_sha256']}`")
        lines.append(f"- Verified at: {audit['verified_at']}")
        for defect in audit["defects"]:
            lines.append(f"- DEFECT: {defect}")
        for warning in audit["warnings"]:
            lines.append(f"- Warning: {warning}")
    else:
        lines.append("## Audit ledger: not recorded for this case")
    lines.append("")
    conclusions = report.get("conclusions")
    if conclusions and conclusions.get("findings"):
        lines.append(
            f"## Conclusions & traceability "
            f"({conclusions['finding_count']} finding(s), "
            f"{conclusions['stale_citation_count']} stale citation(s))"
        )
        lines.append("")
        for finding in conclusions["findings"]:
            flag = " [STALE]" if finding["stale_citations"] else ""
            lines.append(
                f"### {finding['id']} — {finding['status']}{flag}"
            )
            lines.append("")
            lines.append(f"- Claim: {finding['claim']}")
            if finding["need_verify"]:
                lines.append(f"- Needs verification: {finding['need_verify']}")
            if finding["analyst"]:
                lines.append(f"- Analyst: {finding['analyst']}")
            lines.append("")
            lines.append("| run | evidence# | kind | current value | hash | state |")
            lines.append("|---|---|---|---|---|---|")
            for citation in finding["citations"]:
                state = "stale" if citation.get("stale") else ("resolved" if citation.get("resolved") else "missing")
                value = citation.get("current_value")
                value = "" if value is None else str(value)
                sha = citation.get("current_sha256") or citation.get("registered_sha256", "")
                kind = citation.get("kind", "")
                lines.append(
                    f"| {citation['run_seq']} | {citation['evidence_index']} | "
                    f"{kind} | {value} | `{sha[:12]}` | {state} |"
                )
            lines.append("")
    else:
        lines.append("## Conclusions: none registered yet")
    return "\n".join(lines)
