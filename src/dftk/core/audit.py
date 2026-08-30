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

"""Append-only audit ledger for tool invocations (chain of custody).

Every `registry.run` call can emit one JSONL record describing *what* ran,
*who/what* invoked it, the resolved parameters (secrets redacted), the outcome,
and the evidence hashes produced. The ledger never touches evidence: it is a
side record used to reconstruct the provenance of an analysis.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Observation, ToolSpec

# Parameter keys whose values are treated as secrets and masked in the ledger.
_SECRET_KEY_RE = re.compile(
    r"(?:^|_)(?:password|passwd|pwd|token|secret|api[_-]?key|apikey|"
    r"private[_-]?key|credential|auth|authorization)(?:$|_)",
    re.I,
)

_MAX_PARAM_STR = 4096
_MAX_PARAM_DEPTH = 6
_GENESIS = "genesis"  # previous_hash of the first record in a ledger


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class ToolAuditLog:
    """Append-only JSONL log of tool invocations.

    Thread-safe. Construction creates the parent directory if needed. A single
    ``record`` call appends exactly one line; failures are swallowed so the
    forensic tool run is never disrupted by ledger I/O problems.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        *,
        tool: str,
        params: dict[str, Any],
        observation: Observation,
        spec: ToolSpec | None = None,
        caller: str = "cli",
    ) -> None:
        try:
            # Collect distinct evidence hashes. The same SHA-256 can legitimately
            # appear both as an evidence item's source_sha256 and as a derived
            # artifact's sha256 (e.g. the auto-stamped source node in
            # registry._stamp_provenance mirrors the evidence it came from), so we
            # de-duplicate to keep the ledger a true set, not a multiset.
            seen: set[str] = set()
            evidence_hashes: list[str] = []
            for e in observation.evidence:
                if e.source_sha256 and e.source_sha256 not in seen:
                    seen.add(e.source_sha256)
                    evidence_hashes.append(e.source_sha256)
            for d in getattr(observation, "derived_artifacts", []):
                s = getattr(d, "sha256", "")
                if s and s not in seen:
                    seen.add(s)
                    evidence_hashes.append(s)
            params_digest = _sha256(json.dumps(self._redact(params), ensure_ascii=False, sort_keys=True, default=str))
            result_digest = _sha256(json.dumps({
                "status": observation.status.value,
                "summary": observation.summary,
                "errors": list(observation.errors),
            }, ensure_ascii=False, default=str))
            evidence_digest = _sha256(json.dumps(sorted(evidence_hashes), ensure_ascii=False))
        except Exception:
            # Never let ledger serialization break the tool run.
            return
        try:
            with self._lock:
                prev = self._last_record_hash()
                seq = self._next_sequence()
                rec = {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "tool": tool,
                    "caller": caller,
                    "sequence": seq,
                    "status": observation.status.value,
                    "summary": observation.summary,
                    "safety": spec.safety.name if spec is not None else None,
                    "network": spec.network if spec is not None else None,
                    "tags": list(spec.tags) if spec is not None else None,
                    "requires": list(spec.requires) if spec is not None else None,
                    "params": self._redact(params),
                    "evidence_hashes": evidence_hashes,
                    "errors": list(observation.errors),
                    "params_digest": params_digest,
                    "result_digest": result_digest,
                    "evidence_digest": evidence_digest,
                }
                rec["previous_hash"] = prev
                body = json.dumps(rec, ensure_ascii=False, sort_keys=True, default=str)
                rec["record_hash"] = _sha256(prev + "|" + body)
                line = json.dumps(rec, ensure_ascii=False, sort_keys=True, default=str)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
        except OSError:
            # Ledger I/O failure must not surface to the forensic caller.
            return

    # -- hash chain helpers ------------------------------------------------
    def _last_record_hash(self) -> str:
        try:
            last = None
            with self.path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        last = line
            if last is None:
                return _GENESIS
            return json.loads(last).get("record_hash", _GENESIS)
        except (OSError, json.JSONDecodeError):
            return _GENESIS

    def _next_sequence(self) -> int:
        try:
            n = 0
            with self.path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        n += 1
            return n + 1
        except OSError:
            return 1

    @classmethod
    def verify(cls, path: str | os.PathLike[str]) -> dict[str, Any]:
        """Replay the ledger and confirm the hash chain is intact.

        Returns ``{"valid": True, "records": N, "reason": "chain intact"}`` or
        ``{"valid": False, "broken_at": <seq>, "line": <n>, "reason": <str>}``.
        """
        p = Path(path)
        if not p.exists():
            return {"valid": False, "broken_at": 0, "reason": "ledger file not found"}
        prev = _GENESIS
        seq = 0
        try:
            with p.open("r", encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    rec = json.loads(line)
                    stored_prev = rec.get("previous_hash", _GENESIS)
                    if stored_prev != prev:
                        return {
                            "valid": False, "broken_at": seq + 1, "line": lineno,
                            "reason": f"previous_hash mismatch: expected {prev}, got {stored_prev}",
                        }
                    body = {k: v for k, v in rec.items() if k != "record_hash"}
                    body_str = json.dumps(body, ensure_ascii=False, sort_keys=True, default=str)
                    expected_hash = _sha256(prev + "|" + body_str)
                    if rec.get("record_hash") != expected_hash:
                        return {
                            "valid": False, "broken_at": seq + 1, "line": lineno,
                            "reason": "record_hash mismatch (content tampered)",
                        }
                    prev = rec["record_hash"]
                    seq += 1
        except json.JSONDecodeError as e:
            return {"valid": False, "broken_at": seq + 1, "reason": f"malformed JSON at line {lineno}: {e}"}
        return {"valid": True, "records": seq, "reason": "chain intact"}

    @staticmethod
    def _redact(value: Any, depth: int = 0) -> Any:
        if depth > _MAX_PARAM_DEPTH:
            return "<omitted:too-deep>"
        if isinstance(value, dict):
            return {
                k: ("<redacted>" if _SECRET_KEY_RE.search(str(k)) else ToolAuditLog._redact(v, depth + 1))
                for k, v in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [ToolAuditLog._redact(v, depth + 1) for v in value]
        if isinstance(value, str) and len(value) > _MAX_PARAM_STR:
            return value[:_MAX_PARAM_STR] + f"<omitted:{len(value) - _MAX_PARAM_STR} chars>"
        return value


_DEFAULT_AUDIT_LOG: ToolAuditLog | None = None
_DEFAULT_AUDIT_LOG_RESOLVED = False


def _get_default_audit_log() -> ToolAuditLog | None:
    """Return the process-wide audit log from ``DFTK_AUDIT_LOG`` (or None).

    When the environment variable names a path, every ``registry.run`` call logs
    to it automatically — this is the "always-on chain-of-custody" mode. The
    resolution is cached so the file handle/decision is stable per process.
    """
    global _DEFAULT_AUDIT_LOG, _DEFAULT_AUDIT_LOG_RESOLVED
    if _DEFAULT_AUDIT_LOG_RESOLVED:
        return _DEFAULT_AUDIT_LOG
    path = os.environ.get("DFTK_AUDIT_LOG")
    if path:
        try:
            _DEFAULT_AUDIT_LOG = ToolAuditLog(path)
        except OSError:
            _DEFAULT_AUDIT_LOG = None
    _DEFAULT_AUDIT_LOG_RESOLVED = True
    return _DEFAULT_AUDIT_LOG
