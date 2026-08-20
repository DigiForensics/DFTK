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

# Value-level secret patterns that must be masked even when the surrounding
# parameter key does not match _SECRET_KEY_RE (e.g. a DSN/connection string or
# URL stored under "url"/"dsn"/"connectionString"/...).
_SECRET_VALUE_RES = [
    # user:password@host inside URLs / connection strings
    re.compile(r"(?i)([a-z][a-z0-9+.\-]*://)([^:/?#\s]+):([^@/?#\s]+)@"),
    # password=/pwd=/secret=/token=/... assignments embedded in a value.
    # Capture the key name and separator so the redaction keeps the key but
    # masks only the credential value (e.g. "Password=<redacted>").
    re.compile(
        r"(?i)(?<![a-z0-9])(?P<key>password|passwd|pwd|secret|token|api[_-]?key|"
        r"apikey|credential|authorization)\s*(?P<sep>[:=])\s*(?P<val>[^\s;\"']+)"
    ),
]


def _redact_string(value: str) -> str:
    """Mask embedded credentials inside an arbitrary string value."""
    value = _SECRET_VALUE_RES[0].sub(r"\1\2:<redacted>@", value)
    value = _SECRET_VALUE_RES[1].sub(r"\g<key>\g<sep><redacted>", value)
    return value


_MAX_PARAM_STR = 4096
_MAX_PARAM_DEPTH = 6


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
            rec = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "tool": tool,
                "caller": caller,
                "status": observation.status.value,
                "summary": _redact_string(observation.summary) if isinstance(observation.summary, str) else observation.summary,
                "safety": spec.safety.name if spec is not None else None,
                "network": spec.network if spec is not None else None,
                "tags": list(spec.tags) if spec is not None else None,
                "requires": list(spec.requires) if spec is not None else None,
                "params": self._redact(params),
                "evidence_hashes": [
                    e.source_sha256 for e in observation.evidence if e.source_sha256
                ],
                "errors": [_redact_string(e) if isinstance(e, str) else e for e in observation.errors],
            }
            line = json.dumps(rec, ensure_ascii=False, default=str)
        except Exception:
            # Never let ledger serialization break the tool run.
            return
        try:
            with self._lock:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
        except OSError:
            # Ledger I/O failure must not surface to the forensic caller.
            return

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
        if isinstance(value, str):
            value = _redact_string(value)
            if len(value) > _MAX_PARAM_STR:
                return value[:_MAX_PARAM_STR] + f"<omitted:{len(value) - _MAX_PARAM_STR} chars>"
            return value
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
