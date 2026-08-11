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
