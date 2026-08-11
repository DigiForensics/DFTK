from __future__ import annotations
from collections.abc import Callable
from typing import Any
from dataclasses import replace
from .models import Observation, Status, ToolSpec, SafetyLevel
from .safety import SafetyPolicy, SafetyViolation

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

    def run(self, name: str, params: dict[str, Any], policy: SafetyPolicy | None = None) -> Observation:
        policy = policy or SafetyPolicy()
        if name not in self._specs:
            return Observation(name, Status.ERROR, "Unknown tool", errors=[f"unknown tool: {name}"])
        spec = self._specs[name]
        try:
            policy.check(level=spec.safety, network=spec.network)
        except SafetyViolation as e:
            return Observation(name, Status.BLOCKED, "Blocked by safety policy", errors=[str(e)])
        try:
            out = self._funcs[name](**params)
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
            return out
        except TypeError as e:
            return Observation(name, Status.ERROR, "Invalid parameters or tool implementation error", errors=[str(e)])
        except Exception as e:
            return Observation(name, Status.ERROR, "Tool execution failed", errors=[f"{type(e).__name__}: {e}"])

registry = ToolRegistry()
