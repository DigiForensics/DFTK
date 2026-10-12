# Copyright 2026 DyNooob @ DigiForensics
# Licensed under the Apache License, Version 2.0.
"""Bounded, source-linked hunting for suspicious web-server code patterns."""
from __future__ import annotations

from pathlib import Path
import re

from dftk.core.helpers import bounded_files, safe_rel, sha256_file
from dftk.core.models import Evidence, Observation, SafetyLevel, Status
from dftk.core.registry import registry

_WEB_EXTENSIONS = {".php", ".phtml", ".php5", ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".py", ".js", ".ts"}
_PATTERNS = (
    ("dynamic_eval", re.compile(rb"\b(?:eval|assert)\s*\(", re.I), 3),
    ("shell_execution", re.compile(rb"\b(?:system|shell_exec|passthru|exec|popen|proc_open)\s*\(", re.I), 4),
    ("obfuscation_decode", re.compile(rb"\b(?:base64_decode|gzinflate|str_rot13|frombase64string|unescape)\s*\(", re.I), 2),
    ("java_process_execution", re.compile(rb"\b(?:Runtime\.getRuntime\s*\(\)\.exec|ProcessBuilder)\b", re.I), 4),
    ("dotnet_process_execution", re.compile(rb"\b(?:Process\.Start|cmd\.exe|powershell(?:\.exe)?)\b", re.I), 4),
    ("request_parameter", re.compile(rb"(?:\$_(?:GET|POST|REQUEST|COOKIE)|request\.(?:getparameter|form|querystring)|req\.(?:query|body))", re.I), 1),
    ("network_fetch", re.compile(rb"\b(?:curl_exec|file_get_contents\s*\(\s*['\"]https?://|WebClient|requests\.(?:get|post))", re.I), 2),
)


@registry.tool(
    name="web.webshell_hunt",
    description="Scan an extracted web/application tree for source-linked suspicious execution, request-input, obfuscation, and process-launch pattern combinations. Scores are triage leads, not malware verdicts.",
    safety=SafetyLevel.READ_ONLY,
    tags=("web", "webshell", "server", "malware", "hunt", "forensics"),
    produces=("webshell_leads", "code_indicators", "hash"),
    cost_hint="high",
    parameters={"type":"object","properties":{"root":{"type":"string"},"max_files":{"type":"integer","default":20000},"max_file_size":{"type":"integer","default":4194304},"hit_limit":{"type":"integer","default":1000},"min_score":{"type":"integer","default":4}},"required":["root"]},
)
def webshell_hunt(root: str, max_files: int = 20000, max_file_size: int = 4 * 1024 * 1024, hit_limit: int = 1000, min_score: int = 4) -> Observation:
    base = Path(root)
    if not base.is_dir():
        return Observation("web.webshell_hunt", Status.ERROR, "Web root directory not found", errors=[str(base)])
    hits=[]; evidence=[]; warnings=[]; scanned=skipped=traversed=0
    for item in bounded_files(base, max_files=max_files):
        traversed += 1
        if item.suffix.lower() not in _WEB_EXTENSIONS:
            continue
        try:
            if item.stat().st_size > max_file_size:
                skipped += 1; continue
            data = item.read_bytes(); scanned += 1
        except OSError as exc:
            warnings.append(f"could not read {item}: {exc}"); continue
        indicators=[]; score=0
        for name, pattern, weight in _PATTERNS:
            matches=list(pattern.finditer(data))[:20]
            if matches:
                score += weight
                indicators.append({"kind":name,"weight":weight,"offsets":[match.start() for match in matches]})
        if score < min_score:
            continue
        digest=sha256_file(item)
        row={"path":str(item),"relative_path":safe_rel(item,base),"sha256":digest,"score":score,"indicators":indicators}
        hits.append(row)
        evidence.append(Evidence(str(item),"webshell_lead",f"score:{score}",locator="offsets:"+",".join(str(offset) for indicator in indicators for offset in indicator['offsets'][:3]),source_sha256=digest,method="DFTK bounded web-code pattern hunt"))
        if len(hits)>=hit_limit:
            warnings.append(f"hit output limited to {hit_limit}"); break
    if traversed >= max_files:
        warnings.append(f"file traversal limited to {max_files}")
    if skipped: warnings.append(f"skipped {skipped} web file(s) larger than max_file_size")
    hits.sort(key=lambda row:(-row['score'],row['relative_path']))
    facts={"root":str(base),"scanned_web_files":scanned,"skipped_large_files":skipped,"lead_count":len(hits),"leads":hits,"minimum_score":min_score,"disclaimer":"Scores identify pattern combinations for review; they do not establish a web shell or malicious intent."}
    return Observation("web.webshell_hunt",Status.PARTIAL if warnings else Status.OK,f'Found {len(hits)} suspicious web-code lead(s) across {scanned} scanned web file(s)',facts=facts,evidence=evidence[:300],warnings=warnings,meta={"read_only":True,"source_evidence_modified":False})
