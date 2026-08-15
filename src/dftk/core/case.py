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
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .models import Observation, SafetyLevel, Status
from .registry import registry
from .safety import SafetyPolicy
from .timeline_core import merge_events

DEFAULT_WORKSPACE = ".dftk"


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


@contextmanager
def _exclusive_file_lock(path: Path) -> Iterator[None]:
    """Cross-platform advisory lock released automatically on process exit."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as fh:
        fh.seek(0, os.SEEK_END)
        if fh.tell() == 0:
            fh.write(b"0")
            fh.flush()
        fh.seek(0)
        if os.name == "nt":
            import msvcrt

            # LK_LOCK itself retries only for a bounded period on Windows. Use
            # non-blocking acquisition in a loop so a legitimate long-running
            # forensic parser does not make a concurrent CaseSession caller fail
            # merely because the case is busy. The OS releases the byte-range lock
            # automatically if the owning process exits.
            while True:
                try:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    time.sleep(0.05)
                finally:
                    fh.seek(0)
            try:
                yield
            finally:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


class CaseSession:
    def __init__(self, workspace: str | Path = DEFAULT_WORKSPACE):
        self.workspace = Path(workspace)
        self.cases_dir = self.workspace / "cases"

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
                audit=audit,
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
    return "\n".join(lines)
