from __future__ import annotations
from .models import Observation, Evidence, Status

def aggregate(tool: str, children: list[Observation], summary: str) -> Observation:
    if any(c.status == Status.ERROR for c in children): status = Status.PARTIAL
    elif any(c.status in (Status.PARTIAL, Status.UNSUPPORTED, Status.BLOCKED) for c in children): status = Status.PARTIAL
    else: status = Status.OK
    facts = {c.tool: c.facts for c in children}
    evidence = [e for c in children for e in c.evidence]
    warnings = [f"{c.tool}: {w}" for c in children for w in c.warnings]
    errors = [f"{c.tool}: {e}" for c in children for e in c.errors]
    return Observation(tool, status, summary, facts=facts, evidence=evidence, warnings=warnings, errors=errors,
                       meta={"children": [c.to_dict() for c in children]})
