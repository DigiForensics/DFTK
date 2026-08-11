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
from dataclasses import dataclass, field, asdict
from enum import IntEnum, Enum
from typing import Any

class SafetyLevel(IntEnum):
    READ_ONLY = 0
    STATEFUL = 1
    DESTRUCTIVE = 2

class Status(str, Enum):
    OK = "ok"
    PARTIAL = "partial"
    ERROR = "error"
    UNSUPPORTED = "unsupported"
    BLOCKED = "blocked"

@dataclass
class Evidence:
    source: str
    kind: str
    value: Any
    locator: str = ""
    note: str = ""
    source_sha256: str = ""
    confidence: float = 1.0
    method: str = ""

@dataclass
class Observation:
    tool: str
    status: Status
    summary: str
    facts: dict[str, Any] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data

@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    safety: SafetyLevel
    parameters: dict[str, Any]
    network: bool = False
    tags: tuple[str, ...] = ()
    produces: tuple[str, ...] = ()
    requires: tuple[str, ...] = ()
    deterministic: bool = True
    cost_hint: str = "low"
