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

"""Chain-of-custody verification.

The audit ledger records what ran; this module lets a reviewer check that the
record still says what it said when it was written. The verification itself is
read-only and produces ``Evidence`` for the ledger under review, so the verdict
can be cited like any other observation.
"""

from __future__ import annotations

from pathlib import Path

from dftk.core.audit import DEFAULT_LEDGER_MAX_BYTES, verify_ledger
from dftk.core.models import Evidence, Observation, SafetyLevel, Status
from dftk.core.registry import registry


@registry.tool(
    name="custody.ledger_verify",
    description=(
        "Verify a DFTK chain-of-custody audit ledger (JSONL). Recomputes the per-record "
        "SHA-256 hash chain and reports records that were edited, deleted, reordered, "
        "truncated or downgraded, plus optionally compares the ledger against a seal "
        "written by 'dftk audit seal'. Verification is read-only. A status of ok means "
        "verification completed: read facts.verdict "
        "('intact'/'legacy'/'partial'/'defective') and facts.chain_ok for the result — a "
        "negative integrity finding is an examination result, not a tool failure."
    ),
    safety=SafetyLevel.READ_ONLY,
    tags=("custody", "audit", "integrity", "triage"),
    produces=("ledger_verification",),
    cost_hint="medium",
    parameters={
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "seal": {"type": "string"},
            "max_bytes": {"type": "integer", "default": DEFAULT_LEDGER_MAX_BYTES},
        },
        "required": ["path"],
    },
)
def ledger_verify(path: str, seal: str | None = None, max_bytes: int = DEFAULT_LEDGER_MAX_BYTES) -> Observation:
    ledger = Path(path)
    if max_bytes <= 0:
        return Observation(
            "custody.ledger_verify",
            Status.ERROR,
            "max_bytes must be a positive integer",
            errors=[f"max_bytes={max_bytes}"],
        )
    report = verify_ledger(ledger, seal=seal, max_bytes=max_bytes)
    facts = {
        "verdict": report["verdict"],
        "chain_ok": report["verdict"] == "intact",
        "ledger": report["ledger"],
        "records": report["records"],
        "chained_records": report["chained_records"],
        "legacy_records": report["legacy_records"],
        "chain_starts": report["chain_starts"],
        "first_ts": report["first_ts"],
        "last_ts": report["last_ts"],
        "last_seq": report["last_seq"],
        "last_record_hash": report["last_record_hash"],
        "file_sha256": report["file_sha256"],
        "tools": report["tools"],
        "defects": report["defects"],
        "seal": report["seal"],
    }
    if report["verdict"] == "unreadable":
        return Observation(
            "custody.ledger_verify",
            Status.ERROR,
            f"Ledger could not be verified: {report['defects'][0] if report['defects'] else 'unreadable'}",
            facts=facts,
            errors=list(report["defects"]),
            warnings=list(report["warnings"]),
        )
    verdict = report["verdict"]
    summary = {
        "intact": f"Ledger intact: {report['chained_records']} chained record(s) verified",
        "legacy": (
            f"Ledger partly verifiable: {report['chained_records']} chained and "
            f"{report['legacy_records']} legacy record(s) without a hash chain"
        ),
        "partial": f"Ledger ends mid-append: {report['chained_records']} chained record(s) verified",
        "defective": f"Ledger DEFECTIVE: {len(report['defects'])} integrity defect(s) found",
    }[verdict]
    evidence = []
    if report["file_sha256"]:
        evidence.append(
            Evidence(
                report["ledger"],
                "audit_ledger",
                report["file_sha256"],
                locator=f"records:{report['records']}",
                note=f"hash chain verdict: {verdict}",
                source_sha256=report["file_sha256"],
                method="SHA-256 hash-chain recomputation",
            )
        )
    warnings = [f"LEDGER DEFECT: {d}" for d in report["defects"]] + list(report["warnings"])
    if not report["chained_records"]:
        warnings.append("no chained record verified; integrity of this ledger cannot be attested")
    return Observation(
        "custody.ledger_verify",
        Status.OK,
        summary,
        facts=facts,
        evidence=evidence,
        warnings=warnings,
        meta={"source_sha256": report["file_sha256"] or ""},
    )
