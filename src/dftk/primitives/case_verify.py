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

"""Audit-ledger 2.0 verification (`case.verify`) — DFTK 3.5.0.

Chain of custody is only meaningful if it can be *checked independently*. This
tool replays an audit ledger and reports a single verdict:

    VALID
    BROKEN  record: 128  reason: previous_hash mismatch

It validates the hash chain (previous_hash → record_hash), re-derives the
per-record result / evidence digests, and — when observations or a manifest are
supplied — cross-checks that the ledger actually describes the work performed.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from dftk.core.audit import ToolAuditLog
from dftk.core.helpers import sha256_file
from dftk.core.registry import registry
from dftk.core.models import Observation, Evidence, Status, SafetyLevel


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@registry.tool(
    name="case.verify",
    description=(
        "Verify an audit ledger's integrity and cross-check it against observations / a "
        "manifest. Validates the previous_hash → record_hash chain and re-derives each "
        "record's result and evidence digests. Reports VALID or BROKEN with the failing "
        "record number and reason."
    ),
    parameters={
        "type": "object",
        "properties": {
            "audit_log": {"type": "string", "description": "path to the JSONL audit ledger"},
            "observations": {"type": "array", "items": {"type": "object"},
                             "description": "optional Observation.to_dict() list to cross-check against the ledger"},
            "manifest": {"type": "object", "description": "optional case manifest (may declare record_count)"},
        },
        "required": ["audit_log"],
    },
    safety=SafetyLevel.READ_ONLY,
    tags=("case", "verify", "audit"),
    produces=("verification_report",),
    path_roles={"audit_log": "WORKSPACE_INPUT"},
)
def case_verify(audit_log: str, observations: list[dict] | None = None,
                manifest: dict | None = None) -> Observation:
    if not audit_log:
        return Observation("case.verify", Status.BLOCKED, "audit_log path is required",
                           errors=["no ledger supplied"])
    p = Path(audit_log)
    if not p.exists():
        return Observation("case.verify", Status.ERROR, "ledger file not found",
                           errors=[f"no such file: {audit_log}"],
                           facts={"verdict": "BROKEN", "reason": "ledger file not found"})

    ledger_sha = sha256_file(p)
    chain = ToolAuditLog.verify(p)
    checks: list[dict] = []
    mismatches: list[str] = []

    checks.append({
        "name": "previous_hash_chain",
        "ok": bool(chain.get("valid")),
        "detail": chain.get("reason", "chain intact"),
    })
    if not chain.get("valid"):
        mismatches.append(f"record {chain.get('broken_at')}: {chain.get('reason')}")

    # Re-derive per-record digests (independent of the chain link itself).
    records: list[dict] = []
    rd_ok = True
    ed_ok = True
    try:
        with p.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as e:
                    rd_ok = False
                    mismatches.append(f"line {lineno}: malformed JSON ({e})")
                    continue
                records.append(rec)
                try:
                    rd = _sha(json.dumps({
                        "status": rec.get("status"),
                        "summary": rec.get("summary"),
                        "errors": list(rec.get("errors") or []),
                    }, ensure_ascii=False, default=str))
                    if rec.get("result_digest") and rec["result_digest"] != rd:
                        rd_ok = False
                        mismatches.append(
                            f"record {rec.get('sequence', lineno)}: result_digest mismatch (content tampered)")
                    ed = _sha(json.dumps(sorted(rec.get("evidence_hashes") or []), ensure_ascii=False))
                    if rec.get("evidence_digest") and rec["evidence_digest"] != ed:
                        ed_ok = False
                        mismatches.append(
                            f"record {rec.get('sequence', lineno)}: evidence_digest mismatch")
                except (TypeError, ValueError) as e:
                    mismatches.append(f"line {lineno}: digest re-derivation failed ({e})")
    except OSError as e:
        return Observation("case.verify", Status.ERROR, "cannot read ledger",
                           errors=[str(e)], meta={"source_sha256": ledger_sha})

    checks.append({"name": "result_digest", "ok": rd_ok,
                   "detail": f"{len(records)} record(s) re-derived" if rd_ok else "see mismatches"})
    checks.append({"name": "evidence_digest", "ok": ed_ok,
                   "detail": f"{len(records)} record(s) re-derived" if ed_ok else "see mismatches"})

    # Cross-check observations against the ledger's recorded tool/status sequence.
    if observations:
        obs_seq = [(o.get("tool"), o.get("status")) for o in observations if isinstance(o, dict)]
        led_seq = [(r.get("tool"), r.get("status")) for r in records]
        ok = obs_seq == led_seq
        checks.append({"name": "observations_match", "ok": ok,
                       "detail": f"{len(obs_seq)} observation(s) vs {len(led_seq)} ledger record(s)"})
        if not ok:
            mismatches.append("observation sequence does not match the ledger record sequence")

    # Cross-check a manifest's declared record count.
    if isinstance(manifest, dict) and "record_count" in manifest:
        declared = manifest.get("record_count")
        ok = declared == len(records)
        checks.append({"name": "manifest_record_count", "ok": ok,
                       "detail": f"manifest declares {declared}, ledger has {len(records)}"})
        if not ok:
            mismatches.append(f"manifest record_count {declared} != ledger {len(records)}")

    verdict = "VALID" if all(c["ok"] for c in checks) else "BROKEN"
    broken_at = chain.get("broken_at") if not chain.get("valid") else None
    reason = chain.get("reason") if not chain.get("valid") else ("chain intact" if verdict == "VALID" else "; ".join(mismatches[:5]))

    return Observation(
        "case.verify",
        Status.OK if verdict == "VALID" else Status.PARTIAL,
        f"case verification: {verdict} ({len(records)} record(s))",
        facts={
            "verdict": verdict,
            "records": len(records),
            "broken_at": broken_at,
            "reason": reason,
            "checks": checks,
            "mismatches": mismatches,
        },
        evidence=[Evidence(str(p), "audit_ledger", f"{len(records)} records",
                           locator="ledger", source_sha256=ledger_sha,
                           method="hash-chain replay", state="LIVE",
                           confidence=1.0 if verdict == "VALID" else 0.2)],
        warnings=[] if verdict == "VALID" else mismatches[:20],
        meta={"source_sha256": ledger_sha, "ledger_path": str(p)},
    )
