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
import importlib.metadata
from collections.abc import Callable
import inspect
from contextvars import ContextVar
from typing import Any
from dataclasses import replace
from .models import Observation, Status, ToolSpec, SafetyLevel
from .safety import SafetyPolicy, SafetyViolation
from .external_tools import external_tool_available, EXTERNAL_TOOL_NAMES
from .audit import ToolAuditLog, _get_default_audit_log
from .path_policy import validate_params as _validate_path_params, PathEscapeError
from .provenance import ProvenanceIndex
from .parameters import validate as validate_parameters, ParameterError
import copy

ToolFunc = Callable[..., Observation]
_ACTIVE_POLICY: ContextVar[SafetyPolicy | None] = ContextVar("dftk_policy", default=None)


def _dftk_version() -> str:
    """Toolkit version used to stamp provenance derivation nodes.

    We prefer ``dftk.__version__`` (the version of the *running* source tree)
    so auto-stamped provenance agrees with the manual modules, which do
    ``from dftk import __version__``. Importing ``dftk`` at module load time
    would be circular (``dftk/__init__`` imports this registry), but by the
    time a tool actually runs the package is fully initialised, so a lazy
    import here is safe. Falls back to installed-distribution metadata, then
    to ``"unknown"``.
    """
    try:
        from dftk import __version__ as v
        return v
    except Exception:
        pass
    try:
        return importlib.metadata.version("dftk")
    except Exception:
        return "unknown"

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
        schema = copy.deepcopy(spec.parameters)
        # Normalize legacy contracts centrally; explicit roles always win.
        roles = dict(schema.get("x-path-roles", {}))
        inputs = {"path", "root", "image", "system_hive", "evtx", "wal_path", "db_path",
                  "mft_path", "identity_file", "left", "right"}
        analysis = {"files", "extra_sources", "seal", "rule_file"}
        for key, prop in schema.get("properties", {}).items():
            if key in inputs and prop.get("type") == "string":
                roles.setdefault(key, "EVIDENCE_INPUT")
            if key in analysis:
                roles.setdefault(key, "ANALYSIS_INPUT")
            if key == "output_dir":
                roles.setdefault(key, "WORKSPACE_OUTPUT")
            if "default" in prop and prop["default"] is None and key not in schema.get("required", []):
                typ = prop.get("type")
                if isinstance(typ, str) and typ != "null":
                    prop["type"] = [typ, "null"]
        if spec.name == "custody.ledger_verify":
            roles["path"] = "ANALYSIS_INPUT"
        roles.update(spec.path_roles)
        spec = replace(spec, parameters=schema, path_roles=roles)
        self._specs[spec.name] = spec
        self._funcs[spec.name] = func

    def tool(self, *, name: str, description: str, parameters: dict[str, Any],
             safety: SafetyLevel = SafetyLevel.READ_ONLY, network: bool = False,
             tags: tuple[str, ...] | list[str] | str = (), produces: tuple[str, ...] | list[str] | str = (),
             requires: tuple[str, ...] | list[str] | str = (), deterministic: bool = True,
             cost_hint: str = "low", path_roles: dict[str, str] | None = None):
        def deco(func: ToolFunc):
            # Accept a single semantic value without splitting it into characters.
            def values(value):
                return (value,) if isinstance(value, str) else tuple(value)

            self.register(ToolSpec(
                name=name, description=description, safety=safety, parameters=parameters,
                network=network, tags=values(tags), produces=values(produces),
                requires=values(requires), deterministic=deterministic,
                path_roles=path_roles or {},
                cost_hint=cost_hint,
            ), func)
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
        parent_policy = _ACTIVE_POLICY.get()
        policy = policy or parent_policy or SafetyPolicy()
        if parent_policy is not None:
            policy = SafetyPolicy(
                max_level=min(policy.max_level, parent_policy.max_level),
                allow_network=policy.allow_network and parent_policy.allow_network,
                evidence_root=parent_policy.evidence_root or policy.evidence_root,
                workspace_root=parent_policy.workspace_root or policy.workspace_root,
            )
        params = dict(params) if isinstance(params, dict) else params
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
        try:
            validate_parameters(params, spec.parameters)
        except ParameterError as exc:
            out = Observation(name, Status.ERROR, "Invalid parameters", errors=[str(exc)])
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
        # 3.5.0: role-aware path validation. Only enforced when the tool declares
        # path roles AND the policy carries both roots (the MCP server always does;
        # a bare CLI leaves roots None and degrades to the weaker name-based guard).
        if spec.path_roles and (policy.evidence_root is not None or policy.workspace_root is not None):
            try:
                resolved = _validate_path_params(
                    params,
                    spec.path_roles,
                    evidence_root=policy.evidence_root,
                    workspace_root=policy.workspace_root,
                )
            except PathEscapeError as e:
                out = Observation(
                    name, Status.BLOCKED,
                    "Blocked by path policy",
                    errors=[f"path policy violation: {e}"],
                    warnings=[f"declared roles: {spec.path_roles}"],
                )
                self._audit(audit, name, params, spec, out, caller)
                return out
            # Hand the tool the validated, containment-checked absolute paths so a
            # STATEFUL tool can never act on a raw, attacker-controlled string.
            for pname, ppath in resolved.items():
                params[pname] = [str(item) for item in ppath] if isinstance(ppath, list) else str(ppath)
        func = self._funcs[name]
        token = _ACTIVE_POLICY.set(policy)
        try:
            # Validate the caller's parameters before invoking. A binding
            # failure (missing required arg / unexpected keyword) is a caller
            # mistake and is reported as such; any TypeError raised *inside*
            # the tool body is a tool bug and is reported as an execution
            # failure by the outer handler. This avoids relying on the
            # CPython-specific wording of TypeError messages.
            try:
                inspect.signature(func).bind(**params)
            except TypeError as e:
                out = Observation(
                    name, Status.ERROR, "Invalid parameters",
                    errors=[f"parameter binding failed: {e}"],
                )
                self._audit(audit, name, params, spec, out, caller)
                return out
            out = func(**params)
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
            self._stamp_provenance(out, name)
            self._audit(audit, name, params, spec, out, caller)
            return out
        except Exception as e:
            out = Observation(name, Status.ERROR, "Tool execution failed", errors=[f"{type(e).__name__}: {e}"])
            self._audit(audit, name, params, spec, out, caller)
            return out
        finally:
            _ACTIVE_POLICY.reset(token)

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

    def _stamp_provenance(self, out: Observation, name: str) -> None:
        """Attach a baseline provenance chain for evidence-bearing observations.

        DFTK's headline "evidence preservation" claim is only honest when *every*
        tool that touches evidence records where that evidence came from. Four
        privileged modules (files / filesystem / network / report) already build a
        rich :class:`ProvenanceIndex` and set ``meta['provenance']`` themselves;
        we must not clobber their hand-built chain, so we skip any observation
        that already carries one.

        For every other tool that returns evidence with a known SHA-256, we
        register each evidence item as a ``source`` artifact. Because
        :class:`ProvenanceIndex` derives deterministic ids from
        ``(source_artifact, locator)``, these auto-generated nodes never collide
        with the manual modules' nodes (different locator prefixes) and stay
        stable across re-runs. This turns the Chain-of-Custody from "present in 4
        modules" into "present everywhere", which is what the reports assert.
        """
        if out.meta.get("provenance") is not None:
            return
        version = _dftk_version()
        prov = ProvenanceIndex()
        sources: list = []
        for ev in out.evidence:
            sha = (
                ev.source_sha256
                or out.meta.get("source_sha256")
                or out.meta.get("container_sha256")
                or ""
            )
            if not sha:
                continue
            locator = f"evidence:{ev.locator or ev.source or name}"
            sources.append(
                prov.add(
                    source_artifact="",
                    locator=locator,
                    tool=name,
                    version=version,
                    sha256=sha,
                    kind="source",
                    state="LIVE",
                )
            )
        if not sources:
            return
        out.meta["provenance"] = prov.to_dict()
        # Surface the same source nodes in the report's "Recovered / Derived
        # Artifacts" section so the custody chain is visible, not just internal.
        existing = {d.artifact_id for d in out.derived_artifacts}
        for art in sources:
            if art.artifact_id not in existing:
                out.derived_artifacts.append(art)

registry = ToolRegistry()
