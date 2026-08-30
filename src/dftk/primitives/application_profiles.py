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

"""Application Profile tools — DFTK 3.5.0.

Exposes the declarative profile model as two fixed capabilities:

* ``application.profile_list``  — enumerate registered profiles;
* ``application.profile_apply`` — detect / apply a profile to a SQLite artifact
  and normalise rows into a canonical shape (timestamp / sender / body / thread).

Databases are always opened **read-only** (``file:...?mode=ro``), so a profile
run can never modify evidence.
"""

from __future__ import annotations

from pathlib import Path

from dftk.core.helpers import sha256_file
from dftk.core.registry import registry
from dftk.core.models import Observation, Evidence, Status, SafetyLevel
from dftk.profiles import (
    get_profile_registry,
    match_profile,
    extract_records,
)


@registry.tool(
    name="application.profile_list",
    description=(
        "List registered application artifact profiles (detection conditions, database "
        "locations, table/field mapping, time format, encoding, attachment relations)."
    ),
    parameters={"type": "object", "properties": {}, "required": []},
    safety=SafetyLevel.READ_ONLY,
    tags=("application", "profile"),
    produces=("profile_list",),
)
def profile_list() -> Observation:
    profs = get_profile_registry().all()
    return Observation(
        "application.profile_list",
        Status.OK,
        f"{len(profs)} registered application profile(s)",
        facts={"profile_count": len(profs), "profiles": [p.to_dict() for p in profs]},
        warnings=[] if profs else ["no profiles registered"],
    )


@registry.tool(
    name="application.profile_apply",
    description=(
        "Detect (or explicitly select) an application artifact profile for a SQLite database "
        "and normalise its rows into canonical fields. Opens the database read-only. "
        "When no profile matches, the tool reports that explicitly instead of guessing."
    ),
    parameters={
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "path to the application database (read-only evidence)"},
            "profile_id": {"type": "string", "default": "", "description": "explicit profile id; empty = auto-detect"},
            "limit": {"type": "integer", "default": 1000},
        },
        "required": ["path"],
    },
    safety=SafetyLevel.READ_ONLY,
    tags=("application", "profile", "sqlite"),
    produces=("profile_records",),
    path_roles={"path": "EVIDENCE_INPUT"},
)
def profile_apply(path: str, profile_id: str = "", limit: int = 1000) -> Observation:
    h = sha256_file(Path(path))
    notes: list[str] = []
    if profile_id:
        prof = get_profile_registry().get(profile_id)
        if prof is None:
            return Observation(
                "application.profile_apply",
                Status.PARTIAL,
                f"unknown profile: {profile_id}",
                warnings=[f"available: {[p.id for p in get_profile_registry().all()]}"],
                meta={"source_sha256": h},
            )
        schema: dict = {}
    else:
        prof, schema, notes = match_profile(path)
        if prof is None:
            return Observation(
                "application.profile_apply",
                Status.PARTIAL,
                "no application profile matched this database",
                facts={"schema": schema, "matched": False},
                warnings=notes or ["no profile matched"],
                meta={"source_sha256": h},
            )

    records, warn = extract_records(path, prof, limit)
    notes.extend(warn)
    if not records:
        notes.append("no rows extracted (empty table or all mapped fields absent)")
    return Observation(
        "application.profile_apply",
        Status.PARTIAL if (not records or warn) else Status.OK,
        f"profile '{prof.id}' extracted {len(records)} record(s)",
        facts={
            "matched": True,
            "profile": prof.to_dict(),
            "schema": schema,
            "record_count": len(records),
            "records": records,
        },
        evidence=[Evidence(str(path), "application_db", f"{prof.id}:{len(records)} rows",
                           locator=f"table:{prof.table}", source_sha256=h,
                           confidence=0.5 if prof.confidence == "low" else 0.8,
                           method="ArtifactProfile normalisation", state="LIVE")],
        warnings=notes,
        meta={"source_sha256": h, "profile_id": prof.id},
    )
