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

Records written by this version also carry a hash chain (``seq``/``prev_hash``/
``record_hash``) and can be verified offline with :func:`verify_ledger`, so an
edited, deleted, reordered or downgraded record is detectable instead of being
trusted on the strength of the file merely existing. Verification never writes
to the ledger.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .filelock import exclusive_file_lock
from .models import Observation, ToolSpec

# Hash-chain format. ``seq`` is the 0-based position of the record inside the
# chain, ``prev_hash`` the previous record's ``record_hash`` (the genesis marker
# for the first chained record) and ``record_hash`` the SHA-256 over the
# canonical JSON of the record without that field. The written line keeps a
# human-readable key order; only hashing uses the canonical form.
LEDGER_SCHEMA_VERSION = "dftk.audit.ledger/2"
LEDGER_GENESIS_HASH = "0" * 64
DEFAULT_LEDGER_MAX_BYTES = 1 << 30


def _canonical_json(payload: dict[str, Any]) -> bytes:
    """Return the stable byte serialization used for record hashing."""
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")


def compute_record_hash(record: dict[str, Any]) -> str:
    """Return the SHA-256 of ``record``, excluding its own ``record_hash``."""
    body = {k: v for k, v in record.items() if k != "record_hash"}
    return hashlib.sha256(_canonical_json(body)).hexdigest()

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
        # Dedicated lock file: the chain position is read from the ledger and the
        # new record written under this lock, so appends from other processes
        # cannot claim the same sequence number.
        self._lock_path = self.path.with_name(self.path.name + ".lock")
        # Failure counters so a silently-dropped ledger becomes observable:
        # callers (e.g. dftk doctor) can read health() instead of trusting a
        # ledger that stopped writing without anyone noticing.
        self.dropped = 0
        self.last_error: str | None = None
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _chain_position(self) -> tuple[int, str]:
        """Return ``(seq, prev_hash)`` for the record about to be appended.

        Read from the ledger itself (rather than cached) so appends from another
        process, or to a ledger written by an earlier run, continue the same
        chain. Must be called with the exclusive lock held.
        """
        last = _read_last_record(self.path)
        if last is not None and isinstance(last.get("seq"), int) and last.get("record_hash"):
            return last["seq"] + 1, str(last["record_hash"])
        # First chained record, or a legacy ledger with no chain yet.
        return 0, LEDGER_GENESIS_HASH

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
        except Exception as exc:
            # Never let ledger serialization break the tool run, but make the
            # drop observable so a dead ledger is not mistaken for a clean one.
            self.last_error = f"serialize: {type(exc).__name__}: {exc}"
            self.dropped += 1
            return
        try:
            with self._lock:
                # Chain position and the append itself share one cross-process
                # lock, so two writers cannot claim the same sequence number.
                with exclusive_file_lock(self._lock_path):
                    try:
                        seq, prev_hash = self._chain_position()
                        rec["seq"] = seq
                        rec["prev_hash"] = prev_hash
                        rec["record_hash"] = compute_record_hash(rec)
                        line = json.dumps(rec, ensure_ascii=False, default=str)
                    except Exception as exc:
                        self.last_error = f"serialize: {type(exc).__name__}: {exc}"
                        self.dropped += 1
                        return
                    try:
                        with self.path.open("a", encoding="utf-8") as fh:
                            fh.write(line + "\n")
                    except OSError as exc:
                        # Ledger I/O failure must not surface to the forensic
                        # caller, but it must not be invisible either: a dropped
                        # record still counts.
                        self.last_error = f"write: {type(exc).__name__}: {exc}"
                        self.dropped += 1
                        return
        except OSError as exc:
            # The lock file could not be taken or released: the record was not
            # appended, so report it as dropped rather than leaving the caller
            # believing the ledger is complete.
            self.last_error = f"lock: {type(exc).__name__}: {exc}"
            self.dropped += 1
            return

    def health(self) -> dict[str, Any]:
        """Return ledger liveness so a silently-failing ledger is detectable.

        ``ok`` is False once any record has been dropped; ``dropped`` and
        ``last_error`` give the operator enough to act on (e.g. full disk,
        unwritable path, removed directory).
        """
        return {
            "ok": self.dropped == 0,
            "path": str(self.path),
            "dropped": self.dropped,
            "last_error": self.last_error,
        }

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
_DEFAULT_AUDIT_LOG_ERROR: str | None = None


def _get_default_audit_log() -> ToolAuditLog | None:
    """Return the process-wide audit log from ``DFTK_AUDIT_LOG`` (or None).

    When the environment variable names a path, every ``registry.run`` call logs
    to it automatically — this is the "always-on chain-of-custody" mode. The
    resolution is cached so the file handle/decision is stable per process.

    If the path cannot be opened (unwritable, parent missing, etc.) the ledger is
    left disabled and ``_DEFAULT_AUDIT_LOG_ERROR`` records why, so ``dftk doctor``
    can warn instead of the failure staying silent.
    """
    global _DEFAULT_AUDIT_LOG, _DEFAULT_AUDIT_LOG_RESOLVED, _DEFAULT_AUDIT_LOG_ERROR
    if _DEFAULT_AUDIT_LOG_RESOLVED:
        return _DEFAULT_AUDIT_LOG
    path = os.environ.get("DFTK_AUDIT_LOG")
    if path:
        try:
            _DEFAULT_AUDIT_LOG = ToolAuditLog(path)
        except OSError as exc:
            _DEFAULT_AUDIT_LOG = None
            _DEFAULT_AUDIT_LOG_ERROR = f"cannot open audit ledger at {path!r}: {exc}"
    _DEFAULT_AUDIT_LOG_RESOLVED = True
    return _DEFAULT_AUDIT_LOG


def _read_last_record(
    path: Path, *, tail_bytes: int = 1 << 20, max_lines: int = 8
) -> dict[str, Any] | None:
    """Return the last parseable JSON object of ``path`` from a bounded tail read.

    Used to resume the chain across processes without reading a large ledger.
    Unparseable lines are skipped (a tail read can start mid-line, and a corrupt
    line is reported by :func:`verify_ledger` rather than blocking new appends).
    Returns ``None`` when the file is empty or unreadable, in which case the next
    append starts a fresh chain.
    """
    try:
        if path.stat().st_size <= 0:
            return None
        with path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - tail_bytes), os.SEEK_SET)
            data = fh.read()
    except OSError:
        return None
    for index, raw in enumerate(reversed(data.decode("utf-8", "ignore").splitlines())):
        if index >= max_lines:
            break
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict):
            return rec
    return None


def _compare_seal(seal_path: Path, report: dict[str, Any], defects: list[str]) -> dict[str, Any]:
    """Compare a ledger report against a seal written by :func:`seal_ledger`."""
    comparison: dict[str, Any] = {
        "path": str(seal_path),
        "loaded": False,
        "matches": False,
        "mismatches": [],
    }
    try:
        sealed = json.loads(seal_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        comparison["error"] = f"{type(exc).__name__}: {exc}"
        defects.append(f"seal file could not be read: {seal_path}")
        return comparison
    if not isinstance(sealed, dict):
        comparison["error"] = "seal is not a JSON object"
        defects.append(f"seal file is not a DFTK seal: {seal_path}")
        return comparison
    comparison["loaded"] = True
    comparison["sealed_at"] = sealed.get("sealed_at")
    checks = (
        ("file_sha256", "ledger bytes differ from the seal (edited, truncated or extended)"),
        ("records", "record count differs from the seal (records added or removed)"),
        ("last_record_hash", "last record hash differs from the seal"),
    )
    for key, message in checks:
        if key in sealed and sealed.get(key) != report.get(key):
            comparison["mismatches"].append(
                f"{message}: sealed {sealed.get(key)!r} vs present {report.get(key)!r}"
            )
    comparison["matches"] = not comparison["mismatches"]
    if not comparison["matches"]:
        defects.append(f"seal mismatch at {seal_path}: {comparison['mismatches'][0]}")
    return comparison


def verify_ledger(
    path: str | os.PathLike[str],
    *,
    seal: str | os.PathLike[str] | None = None,
    max_bytes: int = DEFAULT_LEDGER_MAX_BYTES,
) -> dict[str, Any]:
    """Recompute a ledger's hash chain and report every integrity problem found.

    Returns a plain dict (not an ``Observation``) so the CLI and the
    ``custody.ledger_verify`` capability share one implementation. ``verdict`` is:

    - ``intact`` — every record is chained and reproduces its own hash;
    - ``legacy`` — some records predate the chain format and cannot be verified;
    - ``partial`` — the file ends mid-append;
    - ``defective`` — a hash, chain link, sequence or sealing check failed;
    - ``unreadable`` — missing, unreadable or larger than ``max_bytes``.

    Verification is read-only and never modifies the ledger.
    """
    target = Path(path)
    report: dict[str, Any] = {
        "schema": LEDGER_SCHEMA_VERSION,
        "ledger": str(target),
        "ok": False,
        "verdict": "unreadable",
        "records": 0,
        "chained_records": 0,
        "legacy_records": 0,
        "chain_starts": 0,
        "first_ts": None,
        "last_ts": None,
        "last_seq": None,
        "last_record_hash": None,
        "tools": {},
        "bytes_read": 0,
        "file_sha256": None,
        "defects": [],
        "warnings": [],
        "seal": None,
    }
    defects: list[str] = report["defects"]
    warnings: list[str] = report["warnings"]
    if not target.is_file():
        defects.append(f"ledger file not found: {target}")
        return report
    try:
        size = target.stat().st_size
        handle = target.open("rb")
    except OSError as exc:
        defects.append(f"cannot read ledger: {type(exc).__name__}: {exc}")
        return report
    if max_bytes and size > max_bytes:
        defects.append(
            f"ledger is {size} bytes, above max_bytes={max_bytes}; "
            "verification requires reading the whole ledger"
        )
        return report

    tools: Counter[str] = Counter()
    hasher = hashlib.sha256()
    total = chained = legacy = chain_starts = 0
    seq_expected: int | None = None
    prev_hash: str | None = None
    last_hash: str | None = None
    last_seq: int | None = None
    first_ts: str | None = None
    last_ts: str | None = None
    malformed: list[int] = []
    partial_tail = False

    with handle:
        for lineno, raw in enumerate(handle, 1):
            total += len(raw)
            hasher.update(raw)
            text = raw.decode("utf-8", "ignore").strip()
            if not text:
                continue
            try:
                rec = json.loads(text)
            except json.JSONDecodeError:
                if raw.endswith(b"\n"):
                    malformed.append(lineno)
                else:
                    partial_tail = True
                continue
            if not isinstance(rec, dict):
                malformed.append(lineno)
                continue
            report["records"] += 1
            tool = rec.get("tool")
            if isinstance(tool, str):
                tools[tool] += 1
            ts = rec.get("ts")
            if isinstance(ts, str):
                if first_ts is None:
                    first_ts = ts
                last_ts = ts
            if isinstance(rec.get("seq"), int) and rec.get("record_hash"):
                chained += 1
                seq = rec["seq"]
                computed = compute_record_hash(rec)
                if computed != rec["record_hash"]:
                    defects.append(
                        f"line {lineno} (seq {seq}): record_hash mismatch — "
                        "the record was modified after it was written"
                    )
                if prev_hash is None:
                    chain_starts += 1
                    if rec.get("prev_hash") != LEDGER_GENESIS_HASH:
                        defects.append(
                            f"line {lineno} (seq {seq}): first chained record does not "
                            "start from the genesis hash"
                        )
                elif rec.get("prev_hash") != prev_hash:
                    defects.append(
                        f"line {lineno} (seq {seq}): chain break — prev_hash does not match "
                        "the previous record (a record was inserted, removed or reordered)"
                    )
                if seq_expected is not None and seq != seq_expected:
                    defects.append(
                        f"line {lineno}: sequence gap — expected seq {seq_expected}, found {seq}"
                    )
                seq_expected = seq + 1
                last_seq = seq
                # The next record must link to what this record *hashes to*, not
                # to the hash it claims: an edited record then breaks the link
                # too, so a naive edit is reported as both a bad hash and a
                # chain break instead of slipping through on a single defect.
                last_hash = str(rec["record_hash"])
                prev_hash = computed
            else:
                legacy += 1
                if chained:
                    defects.append(
                        f"line {lineno}: unchained record appended after chained records "
                        "(ledger downgraded)"
                    )

    report["bytes_read"] = total
    report["file_sha256"] = hasher.hexdigest()
    report["chained_records"] = chained
    report["legacy_records"] = legacy
    report["chain_starts"] = chain_starts
    report["first_ts"] = first_ts
    report["last_ts"] = last_ts
    report["last_seq"] = last_seq
    report["last_record_hash"] = last_hash
    report["tools"] = dict(sorted(tools.items()))
    if malformed:
        defects.append(f"{len(malformed)} unparsable line(s) at {malformed[:10]}")
    if partial_tail:
        warnings.append(
            "ledger ends with a partial line; it may be mid-append, or truncated mid-record"
        )
    if legacy:
        warnings.append(f"{legacy} legacy record(s) carry no hash chain and cannot be verified")
    if chain_starts > 1:
        warnings.append(f"{chain_starts} chain start(s) found; a new chain began after legacy records")
    if report["records"] and not chained:
        warnings.append("no chained records: this ledger predates the hash-chain format")
    if seal is not None:
        report["seal"] = _compare_seal(Path(seal), report, defects)

    if defects:
        verdict = "defective"
    elif legacy:
        verdict = "legacy"
    elif partial_tail:
        verdict = "partial"
    else:
        verdict = "intact"
    report["verdict"] = verdict
    report["ok"] = verdict == "intact"
    return report


def seal_ledger(path: str | os.PathLike[str], *, max_bytes: int = DEFAULT_LEDGER_MAX_BYTES) -> dict[str, Any]:
    """Return a seal for a ledger: record count, last hash and whole-file digest.

    A seal is the external anchor that makes deletion from the *end* of a ledger
    detectable — the file alone cannot prove its own tail was not removed.
    Store the seal outside the ledger (e.g. with the case report) and pass it to
    ``dftk audit verify --seal`` to re-check the ledger later.
    """
    report = verify_ledger(path, max_bytes=max_bytes)
    return {
        "schema": "dftk.audit.seal/1",
        "ledger": report["ledger"],
        "sealed_at": datetime.now(timezone.utc).isoformat(),
        "verdict_at_seal": report["verdict"],
        "records": report["records"],
        "chained_records": report["chained_records"],
        "legacy_records": report["legacy_records"],
        "last_seq": report["last_seq"],
        "last_record_hash": report["last_record_hash"],
        "file_sha256": report["file_sha256"],
        "defects_at_seal": report["defects"],
    }
