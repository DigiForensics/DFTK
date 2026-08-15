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
from collections.abc import Callable
from typing import Any
from dataclasses import replace
from .models import Observation, Status, ToolSpec, SafetyLevel
from .safety import SafetyPolicy, SafetyViolation
from .external_tools import external_tool_available, EXTERNAL_TOOL_NAMES
from .audit import ToolAuditLog, _get_default_audit_log

ToolFunc = Callable[..., Observation]

class ToolRegistry:
    def __init__(self) -> None:
        self._specs: dict[str, ToolSpec] = {}
        self._funcs: dict[str, ToolFunc] = {}

    def register(self, spec: ToolSpec, func: ToolFunc) -> None:
        if spec.name in self._specs:
            raise ValueError(f"duplicate tool: {spec.name}")
        if not spec.tags:
            parts=tuple(p for p in spec.name.split('.') if p and p != 'recipe')
            spec=replace(spec,tags=parts or ('forensics',))
        if not spec.produces:
            spec=replace(spec,produces=('observation',))
        self._specs[spec.name] = spec
        self._funcs[spec.name] = func

    def tool(self, *, name: str, description: str, parameters: dict[str, Any],
             safety: SafetyLevel = SafetyLevel.READ_ONLY, network: bool = False,
             tags: tuple[str, ...] | list[str] = (), produces: tuple[str, ...] | list[str] = (),
             requires: tuple[str, ...] | list[str] = (), deterministic: bool = True,
             cost_hint: str = "low"):
        def deco(func: ToolFunc):
            self.register(ToolSpec(name, description, safety, parameters, network,
                                   tuple(tags), tuple(produces), tuple(requires), deterministic, cost_hint), func)
            return func
        return deco

    def specs(self) -> list[ToolSpec]:
        return [self._specs[k] for k in sorted(self._specs)]

    def get(self, name: str) -> ToolSpec:
        if name not in self._specs:
            raise KeyError(name)
        return self._specs[name]

    def find(self, *, tags: list[str] | None = None, produces: str | None = None) -> list[ToolSpec]:
        specs = self.specs()
        if tags:
            wanted = set(tags)
            specs = [s for s in specs if wanted.issubset(set(s.tags))]
        if produces:
            specs = [s for s in specs if produces in s.produces]
        return specs

    def run(
        self,
        name: str,
        params: dict[str, Any],
        policy: SafetyPolicy | None = None,
        audit: ToolAuditLog | None = None,
        caller: str = "cli",
    ) -> Observation:
        policy = policy or SafetyPolicy()
        audit = audit or _get_default_audit_log()
        spec = self._specs.get(name)
        if spec is None:
            out = Observation(name, Status.ERROR, "Unknown tool", errors=[f"unknown tool: {name}"])
            self._audit(audit, name, params, None, out, caller)
            return out
        try:
            policy.check(level=spec.safety, network=spec.network)
        except SafetyViolation as e:
            out = Observation(name, Status.BLOCKED, "Blocked by safety policy", errors=[str(e)])
            self._audit(audit, name, params, spec, out, caller)
            return out
        for dep in spec.requires:
            if dep in EXTERNAL_TOOL_NAMES and not external_tool_available(dep):
                out = Observation(
                    name,
                    Status.UNSUPPORTED,
                    f"Required external tool not available: {dep}",
                    errors=[
                        f"tool '{name}' requires external binary '{dep}', which was not "
                        f"found on PATH or via its DFTK_*_TOOL_DIRS directory"
                    ],
                )
                self._audit(audit, name, params, spec, out, caller)
                return out
        func = self._funcs[name]
        try:
            try:
                out = func(**params)
            except TypeError as e:
                # A TypeError raised while *binding* the call (missing required
                # arg / unexpected keyword) means the caller supplied the wrong
                # parameters. Any TypeError raised *inside* the tool body is a
                # tool bug and must be reported as an execution failure, never
                # disguised as a caller mistake.
                msg = str(e)
                qual = getattr(func, "__qualname__", "")
                if msg.startswith(qual + "(") or msg.startswith(
                    getattr(func, "__name__", "") + "("
                ):
                    out = Observation(name, Status.ERROR, "Invalid parameters", errors=[msg])
                    self._audit(audit, name, params, spec, out, caller)
                    return out
                raise
            if not isinstance(out, Observation):
                raise TypeError("tool did not return Observation")
            out.meta.setdefault("tool_contract", {
                "safety": spec.safety.name,
                "network": spec.network,
                "tags": list(spec.tags),
                "produces": list(spec.produces),
                "deterministic": spec.deterministic,
            })
            known_hash=out.meta.get("source_sha256") or out.meta.get("container_sha256") or ""
            for evidence in out.evidence:
                if not evidence.source_sha256 and known_hash:
                    evidence.source_sha256=known_hash
                evidence.confidence=max(0.0,min(1.0,float(evidence.confidence)))
            self._audit(audit, name, params, spec, out, caller)
            return out
        except Exception as e:
            out = Observation(name, Status.ERROR, "Tool execution failed", errors=[f"{type(e).__name__}: {e}"])
            self._audit(audit, name, params, spec, out, caller)
            return out

    @staticmethod
    def _audit(
        audit: ToolAuditLog | None,
        name: str,
        params: dict[str, Any],
        spec: ToolSpec | None,
        out: Observation,
        caller: str,
    ) -> None:
        if audit is not None and isinstance(out, Observation):
            audit.record(tool=name, params=params, observation=out, spec=spec, caller=caller)

registry = ToolRegistry()
