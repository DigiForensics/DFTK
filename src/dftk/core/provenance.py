# Copyright 2026 DyNoooob @ DigiForensics
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

"""DerivedArtifact & provenance chain — DFTK 3.5.0.

DFTK 3.3 modelled evidence only as ``file -> SHA256``. That is enough to prove a
*source* file is intact, but it cannot express the chain a real investigation
actually walks:

    phone.zip
      └─ Android/data/xxx/databases/msg.db        (extracted)
            └─ recovered WAL frame #412 row        (carved)

3.5.0 introduces ``DerivedArtifact`` to record each hop with the tool + version
that produced it, the locator inside its parent, and its own hash. A
``ProvenanceIndex`` collects these into a JSON-serialisable chain that the audit
ledger and case reports can render.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass
class ArtifactRef:
    """A pointer to an artifact (original evidence or a derived one)."""

    artifact_id: str
    sha256: str = ""
    locator: str = ""  # e.g. "archive_member:data/msg.db" or "wal_frame:412"


@dataclass
class Derivation:
    """How a derived artifact was produced."""

    tool: str
    version: str
    params: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"tool": self.tool, "version": self.version, "params": self.params}


@dataclass
class DerivedArtifact:
    artifact_id: str
    source_artifact: str  # parent ArtifactRef.artifact_id ("" for the original evidence)
    locator: str          # where inside the parent this artifact lives
    derivation: Derivation
    sha256: str = ""
    size: int = 0
    state: str = "LIVE"   # LIVE | DELETED_CANDIDATE | CARVED | PARTIAL | RECOVERED
    kind: str = "derived"
    note: str = ""
    path: str = ""             # concrete derived output; empty for virtual/source nodes

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DerivedArtifact":
        return cls(
            artifact_id=data["artifact_id"],
            source_artifact=data.get("source_artifact", ""),
            locator=data.get("locator", ""),
            derivation=Derivation(**data.get("derivation", {"tool": "?", "version": "?"})),
            sha256=data.get("sha256", ""),
            size=int(data.get("size", 0)),
            state=data.get("state", "LIVE"),
            kind=data.get("kind", "derived"),
            note=data.get("note", ""),
            path=data.get("path", ""),
        )


class ProvenanceIndex:
    """Append-only collection of derived artifacts for one case or session.

    Deterministic artifact ids keep the chain stable across runs: the same
    source + locator always maps to the same id, so a tool re-run does not
    create duplicate nodes.
    """

    def __init__(self) -> None:
        self._by_id: dict[str, DerivedArtifact] = {}
        self._seq = 0

    def _next_id(self, source_artifact: str, locator: str) -> str:
        # Deterministic id: stable across re-runs for the same (source, locator).
        key = f"{source_artifact}|{locator}"
        # Use a short stable suffix derived from the key so ids are human-readable
        # and reproducible without storing a counter that depends on order.
        suffix = uuid.uuid5(uuid.NAMESPACE_URL, key).hex[:8]
        return f"artifact-{suffix}"

    def add(
        self,
        *,
        source_artifact: str,
        locator: str,
        tool: str,
        version: str,
        sha256: str = "",
        size: int = 0,
        state: str = "LIVE",
        kind: str = "derived",
        note: str = "",
        params: dict[str, Any] | None = None,
        path: str = "",
    ) -> DerivedArtifact:
        # Different acquisitions can share a basename/locator. A known root
        # digest is part of source identity; persisted historical IDs still load.
        identity_locator = f'{sha256}|{locator}' if not source_artifact and sha256 else locator
        artifact_id = self._next_id(source_artifact, identity_locator)
        art = DerivedArtifact(
            artifact_id=artifact_id,
            source_artifact=source_artifact,
            locator=locator,
            derivation=Derivation(tool=tool, version=version, params=params or {}),
            sha256=sha256,
            size=size,
            state=state,
            kind=kind,
            note=note,
            path=path,
        )
        self._by_id[artifact_id] = art
        return art

    def get(self, artifact_id: str) -> DerivedArtifact | None:
        return self._by_id.get(artifact_id)

    def chain(self, artifact_id: str) -> list[DerivedArtifact]:
        """Return the lineage from the original evidence down to ``artifact_id``."""
        out: list[DerivedArtifact] = []
        cur = self._by_id.get(artifact_id)
        guard = 0
        while cur is not None and guard < 1000:
            out.append(cur)
            if not cur.source_artifact:
                break
            cur = self._by_id.get(cur.source_artifact)
            guard += 1
        out.reverse()
        return out

    def all(self) -> list[DerivedArtifact]:
        return list(self._by_id.values())

    def to_dict(self) -> dict[str, Any]:
        return {"schema": "dftk.provenance/1", "artifacts": [a.to_dict() for a in self._by_id.values()]}

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    @classmethod
    def from_json(cls, text: str) -> "ProvenanceIndex":
        data = json.loads(text)
        idx = cls()
        for item in data.get("artifacts", []):
            art = DerivedArtifact.from_dict(item)
            idx._by_id[art.artifact_id] = art
        return idx
