# Copyright 2026 DyNooob @ DigiForensics
# Licensed under the Apache License, Version 2.0.
"""Native local MCP adapter for DFTK.

This module intentionally remains a thin protocol layer over DFTK's Registry,
Observation and CaseSession abstractions. It is not an autonomous forensic Agent.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, Callable
import importlib.metadata
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading

from .catalog import load_builtin_tools
from .core.case import CaseError, CaseSession
from .core.models import SafetyLevel
from .core.registry import registry
from .doctor import _mcp_version_supported, doctor_report
from . import __version__ as _TOOLKIT_VERSION

_EXPECTED_MCP = "2.0.0"
_MAX_ARGUMENT_BYTES = 256 * 1024
_MAX_MODEL_RESULT_BYTES = 512 * 1024
_MAX_QUERY_CHARS = 4096
_DEFAULT_TIMEOUT = 180

_QUERY_ALIASES = {
    "通讯录": "contacts android mobile sqlite",
    "联系人": "contacts android mobile sqlite",
    "短信": "sms message android mobile sqlite",
    "通话": "call android mobile sqlite",
    "域名": "domain url endpoint network",
    "网址": "url endpoint network",
    "服务器": "server endpoint linux network",
    "登录": "login auth authentication",
    "数据库": "database sqlite sql",
    "流量": "pcap network dns http tls",
    "注册表": "registry windows",
    "浏览器": "browser chromium firefox",
    "时间": "time timestamp timeline",
    "哈希": "hash sha256 artifact",
    "邮件": "email mime dkim spf",
}

_PATH_KEY_RE = re.compile(
    r"(?:^|_)(?:path|root|file|files|dir|directory|database|db|hive|capture|pcap|archive|image|source|sources|input|inputs|output|dest|destination|identity)(?:$|_)",
    re.I,
)
_NON_PATH_TEXT_KEY_RE = re.compile(
    r"(?:^|_)(?:query|needle|pattern|regex|regexp|expression|text|value|contains|param|params|url|uri|endpoint|host|domain|keyword|term|sql)(?:$|_)",
    re.I,
)
_WINDOWS_ABS_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\)")


def _spec_dict(spec: Any) -> dict[str, Any]:
    return {
        "name": spec.name,
        "description": spec.description,
        "safety": spec.safety.name,
        "network": bool(spec.network),
        "parameters": spec.parameters,
        "tags": list(spec.tags),
        "produces": list(spec.produces),
        "requires": list(spec.requires),
        "deterministic": bool(spec.deterministic),
        "cost_hint": spec.cost_hint,
    }


def _safe_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, default=str, separators=(",", ":")).encode("utf-8")


def _bounded(value: dict[str, Any], *, guidance: str = "Use a DFTK case and dftk_read_case_run for paged access to large Observations.") -> dict[str, Any]:
    raw = _safe_json_bytes(value)
    if len(raw) <= _MAX_MODEL_RESULT_BYTES:
        return value
    preview = raw[: _MAX_MODEL_RESULT_BYTES // 2].decode("utf-8", errors="replace")
    return {
        "ok": True,
        "truncated": True,
        "original_bytes": len(raw),
        "preview_json": preview,
        "guidance": guidance,
    }


def _bounded_run_result(result: dict[str, Any]) -> dict[str, Any]:
    raw = _safe_json_bytes(result)
    if len(raw) <= _MAX_MODEL_RESULT_BYTES:
        return result
    obs = result.get("observation") or {}
    evidence = list(obs.get("evidence") or []) if isinstance(obs, dict) else []
    facts = obs.get("facts") or {} if isinstance(obs, dict) else {}
    compact = {
        "ok": True,
        "case_id": result.get("case_id"),
        "case_run": result.get("case_run"),
        "truncated": True,
        "original_bytes": len(raw),
        "observation": {
            "tool": obs.get("tool") if isinstance(obs, dict) else None,
            "status": obs.get("status") if isinstance(obs, dict) else None,
            "summary": obs.get("summary") if isinstance(obs, dict) else None,
            "warnings": (obs.get("warnings") or [])[:20] if isinstance(obs, dict) else [],
            "errors": (obs.get("errors") or [])[:20] if isinstance(obs, dict) else [],
            "evidence_total": len(evidence),
            "evidence_preview": evidence[:10],
            "fact_keys": sorted(facts.keys()) if isinstance(facts, dict) else [],
        },
        "guidance": (
            "The full case-scoped Observation is persisted. Use dftk_read_case_run with "
            "case_id and case_run.seq to page evidence/facts. For a direct run, rerun with "
            "a DFTK case or narrow the parameters if full detail is required."
        ),
    }
    return compact


def _structured_error(tool: str, exc: Exception) -> dict[str, Any]:
    return {
        "ok": False,
        "tool": tool,
        "status": "error",
        "error_type": type(exc).__name__,
        "error": str(exc),
    }


def _is_probably_absolute_path(value: str) -> bool:
    return value.startswith("/") or bool(_WINDOWS_ABS_RE.match(value))


def _is_url(value: str) -> bool:
    low = value.lower()
    return low.startswith(("http://", "https://", "ftp://", "ws://", "wss://", "mailto:"))


def _within(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _validate_path_value(value: str, *, root: Path, key: str) -> None:
    if "\x00" in value:
        raise ValueError(f"NUL byte in path parameter {key!r}")
    if _is_url(value):
        return
    # On the host platform, normalize the path relative to the server-owned root.
    # Windows absolute syntax is also rejected when the server is not Windows so
    # a cross-platform test/Agent cannot smuggle an out-of-root path string.
    if _WINDOWS_ABS_RE.match(value) and os.name != "nt":
        raise ValueError(f"path parameter {key!r} is outside the local evidence-root model")
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = candidate.resolve(strict=False)
    if not _within(candidate, root):
        raise ValueError(f"path parameter {key!r} escapes MCP evidence root: {value!r}")


def _validate_params(value: Any, *, root: Path, key: str = "") -> None:
    if isinstance(value, dict):
        for k, v in value.items():
            _validate_params(v, root=root, key=str(k))
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _validate_params(item, root=root, key=key)
        return
    if not isinstance(value, str) or not value:
        return
    path_key = bool(_PATH_KEY_RE.search(key))
    non_path_key = bool(_NON_PATH_TEXT_KEY_RE.search(key))
    if non_path_key or _is_url(value):
        return

    # Known path-like parameter names are always constrained. For unknown string
    # parameters, conservatively treat path-shaped values as filesystem paths.
    # This closes the gap where a future primitive introduces a parameter such
    # as ``apk`` or ``evidence`` without matching the path-key vocabulary.
    looks_relative_path = (
        value.startswith(("./", ".\\", "../", "..\\"))
        or "/" in value
        or "\\" in value
        or (root / value).exists()
    )
    if path_key or _is_probably_absolute_path(value) or looks_relative_path:
        _validate_path_value(value, root=root, key=key or "<value>")


def _case_ids(session: CaseSession) -> set[str]:
    return {str(item.get("case_id")) for item in session.list() if item.get("case_id")}


def _require_case(session: CaseSession, case_id: str) -> None:
    if case_id not in _case_ids(session):
        raise CaseError(f"no such case: {case_id}")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _fact_path(value: Any, path: str) -> Any:
    current = value
    if not path:
        return current
    for part in path.split("."):
        if isinstance(current, dict):
            if part not in current:
                raise KeyError(f"fact path not found: {path}")
            current = current[part]
        elif isinstance(current, list) and part.isdigit():
            current = current[int(part)]
        else:
            raise KeyError(f"fact path not found: {path}")
    return current


def _page_value(value: Any, offset: int, limit: int) -> dict[str, Any]:
    offset = max(0, int(offset))
    limit = min(max(1, int(limit)), 200)
    if isinstance(value, list):
        return {"type": "list", "total": len(value), "offset": offset, "limit": limit, "items": value[offset : offset + limit]}
    if isinstance(value, dict):
        items = list(value.items())
        return {"type": "object", "total": len(items), "offset": offset, "limit": limit, "items": dict(items[offset : offset + limit])}
    if isinstance(value, str):
        char_limit = min(limit * 200, 20_000)
        return {"type": "string", "total_chars": len(value), "offset": offset, "limit_chars": char_limit, "value": value[offset : offset + char_limit]}
    return {"type": type(value).__name__, "value": value}


class DFTKMCPGateway:
    """Server-owned safety/root policy around the existing DFTK public runtime."""

    def __init__(
        self,
        *,
        root: str | Path = ".",
        workspace: str | Path = ".dftk",
        max_safety: str = "READ_ONLY",
        allow_network: bool = False,
        timeout_seconds: int = _DEFAULT_TIMEOUT,
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self.workspace = Path(workspace).expanduser()
        if not self.workspace.is_absolute():
            self.workspace = self.root / self.workspace
        self.workspace = self.workspace.resolve(strict=False)
        if not _within(self.workspace, self.root):
            raise ValueError("MCP workspace must be inside --root")
        max_safety = str(max_safety).upper()
        if max_safety not in {"READ_ONLY", "STATEFUL"}:
            raise ValueError("MCP max safety must be READ_ONLY or STATEFUL")
        self.max_safety = max_safety
        self.allow_network = bool(allow_network)
        self.timeout_seconds = min(max(1, int(timeout_seconds)), 3600)
        self._lock = threading.RLock()

    def preflight(self) -> dict[str, Any]:
        if not self.root.exists() or not self.root.is_dir():
            raise ValueError(f"MCP evidence root is not a directory: {self.root}")
        self.workspace.mkdir(parents=True, exist_ok=True)
        load_builtin_tools()
        if not list(registry.specs()):
            raise RuntimeError("DFTK capability registry is empty")
        return self.doctor()

    def doctor(self) -> dict[str, Any]:
        report = doctor_report()
        report["mcp_policy"] = {
            "transport": "stdio",
            "root": str(self.root),
            "workspace": str(self.workspace),
            "max_safety": self.max_safety,
            "allow_network": self.allow_network,
            "timeout_seconds": self.timeout_seconds,
            "destructive_allowed": False,
        }
        return report

    def search(self, query: str = "", tags: list[str] | None = None, produces: str | None = None, limit: int = 12) -> dict[str, Any]:
        query = (query or "").strip()
        expanded = [query]
        for key, replacement in _QUERY_ALIASES.items():
            if key in query:
                expanded.append(replacement)
        query = " ".join(part for part in expanded if part).strip()
        if len(query) > _MAX_QUERY_CHARS:
            raise ValueError("query is too long")
        limit = min(max(1, int(limit)), 50)
        specs = list(registry.find(tags=tags, produces=produces))
        if query:
            words = [w for w in re.findall(r"[a-zA-Z0-9_.:-]+", query.lower()) if w]
            ranked: list[tuple[int, str, Any]] = []
            for spec in specs:
                hay = " ".join([
                    spec.name,
                    spec.description,
                    " ".join(spec.tags),
                    " ".join(spec.produces),
                    " ".join(spec.requires),
                ]).lower()
                score = sum(4 if w in spec.name.lower() else 1 for w in words if w in hay)
                if not words or score:
                    ranked.append((score, spec.name, spec))
            ranked.sort(key=lambda x: (-x[0], x[1]))
            specs = [x[2] for x in ranked]
        else:
            specs.sort(key=lambda x: x.name)
        return {"ok": True, "count": min(len(specs), limit), "results": [_spec_dict(s) for s in specs[:limit]]}

    def describe(self, name: str) -> dict[str, Any]:
        try:
            spec = registry.get(name)
        except KeyError:
            return {"ok": False, "status": "unknown", "error": f"unknown DFTK capability: {name}"}
        return {"ok": True, "capability": _spec_dict(spec)}

    def _worker(self, request: dict[str, Any]) -> dict[str, Any]:
        raw = _safe_json_bytes(request)
        if len(raw) > _MAX_ARGUMENT_BYTES:
            raise ValueError(f"MCP run request exceeds {_MAX_ARGUMENT_BYTES} bytes")
        with tempfile.TemporaryDirectory(prefix="dftk-mcp-") as td:
            req = Path(td) / "request.json"
            resp = Path(td) / "response.json"
            req.write_bytes(raw)
            cmd = [sys.executable, "-m", "dftk.mcp_worker", str(req), str(resp)]
            kwargs: dict[str, Any] = {
                "cwd": str(self.root),
                "stdin": subprocess.DEVNULL,
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
            }
            if os.name == "nt":
                kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            else:
                kwargs["start_new_session"] = True
            proc = subprocess.Popen(cmd, **kwargs)
            try:
                proc.wait(timeout=self.timeout_seconds)
            except subprocess.TimeoutExpired:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                else:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                proc.wait(timeout=10)
                raise TimeoutError(f"DFTK capability exceeded MCP timeout ({self.timeout_seconds}s)")
            if not resp.exists():
                raise RuntimeError(f"DFTK worker exited {proc.returncode} without a response")
            data = _read_json(resp)
            if not data.get("ok"):
                raise RuntimeError(f"DFTK worker {data.get('error_type', 'error')}: {data.get('error', 'unknown error')}")
            return data

    def run(self, name: str, params: dict[str, Any] | None = None, case_id: str | None = None) -> dict[str, Any]:
        params = dict(params or {})
        _validate_params(params, root=self.root)
        try:
            spec = registry.get(name)
        except KeyError:
            return {"ok": False, "status": "unknown", "error": f"unknown DFTK capability: {name}"}
        if spec.safety > SafetyLevel[self.max_safety]:
            return {"ok": False, "status": "blocked", "error": f"capability safety {spec.safety.name} exceeds MCP ceiling {self.max_safety}"}
        if spec.network and not self.allow_network:
            return {"ok": False, "status": "blocked", "error": "network capability is disabled by MCP server policy"}

        request: dict[str, Any] = {
            "action": "run",
            "name": name,
            "params": params,
            "max_safety": self.max_safety,
            "allow_network": self.allow_network,
        }
        if case_id:
            session = CaseSession(self.workspace)
            _require_case(session, case_id)
            request.update({"action": "case_run", "workspace": str(self.workspace), "case_id": case_id})

        # Serializing here protects CaseSession's read/seq/write manifest sequence
        # and also keeps stdio Agent behavior deterministic across concurrent calls.
        with self._lock:
            data = self._worker(request)
        observation = dict(data["observation"])
        result = {
            "ok": True,
            "case_id": case_id,
            "observation": observation,
        }
        if case_id:
            result["case_run"] = data.get("case_run")
        return _bounded_run_result(result)

    def case(self, action: str, case_id: str | None = None, name: str | None = None, format: str = "json") -> dict[str, Any]:
        session = CaseSession(self.workspace)
        action = str(action or "").lower()
        with self._lock:
            if action == "new":
                return {"ok": True, "case": session.new(name)}
            if action == "list":
                return {"ok": True, "cases": session.list()}
            if not case_id:
                raise ValueError("case_id is required for this action")
            _require_case(session, case_id)
            if action == "show":
                return _bounded({"ok": True, "case": session.show(case_id)})
            if action == "timeline":
                return _bounded({"ok": True, "observation": session.timeline(case_id).to_dict()})
            if action == "export":
                if format not in {"json", "md"}:
                    raise ValueError("format must be 'json' or 'md'")
                text = session.export(case_id, fmt=format)
                return _bounded({"ok": True, "format": format, "report": text})
        raise ValueError("case action must be one of: new, list, show, timeline, export")

    def read_case_run(
        self,
        case_id: str,
        seq: int,
        *,
        evidence_offset: int = 0,
        evidence_limit: int = 20,
        fact_path: str = "",
        value_offset: int = 0,
        value_limit: int = 50,
    ) -> dict[str, Any]:
        session = CaseSession(self.workspace)
        _require_case(session, case_id)
        target, obs = session.read_run(case_id, seq)
        evidence = list(obs.get("evidence") or [])
        evidence_offset = max(0, int(evidence_offset))
        evidence_limit = min(max(1, int(evidence_limit)), 100)
        result: dict[str, Any] = {
            "ok": True,
            "case_id": case_id,
            "run": target,
            "observation": {
                "tool": obs.get("tool"),
                "status": obs.get("status"),
                "summary": obs.get("summary"),
                "warnings": obs.get("warnings") or [],
                "errors": obs.get("errors") or [],
                "evidence_total": len(evidence),
                "evidence_offset": evidence_offset,
                "evidence": evidence[evidence_offset : evidence_offset + evidence_limit],
                "fact_keys": sorted((obs.get("facts") or {}).keys()) if isinstance(obs.get("facts"), dict) else [],
                "meta": obs.get("meta") or {},
            },
        }
        if fact_path:
            value = _fact_path(obs.get("facts") or {}, fact_path)
            result["fact"] = {"path": fact_path, **_page_value(value, value_offset, value_limit)}
        return _bounded(result, guidance="Use evidence_offset/evidence_limit or fact_path/value_offset/value_limit to page this persisted Observation.")


def _safe(tool: str, fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return _bounded(fn())
    except Exception as exc:
        return _structured_error(tool, exc)


def create_server(gateway: DFTKMCPGateway):
    try:
        installed = importlib.metadata.version("mcp")
        from mcp.server import MCPServer
    except (ImportError, importlib.metadata.PackageNotFoundError) as exc:
        raise RuntimeError('DFTK MCP requires the optional dependency: pip install "dftk[mcp]"') from exc
    if not _mcp_version_supported(installed):
        raise RuntimeError(
            f"unsupported MCP SDK version {installed!r}; DFTK {_TOOLKIT_VERSION} "
            f"requires mcp >=2.0.0,<3 (validated with {_EXPECTED_MCP})"
        )

    server = MCPServer("DFTK")

    @server.tool()
    def dftk_doctor() -> dict[str, Any]:
        """Return DFTK capability health and the server-owned MCP safety/root policy."""
        return _safe("dftk_doctor", gateway.doctor)

    @server.tool()
    def dftk_search_capabilities(query: str = "", tags: list[str] | None = None, produces: str | None = None, limit: int = 12) -> dict[str, Any]:
        """Discover DFTK capabilities by evidence intent, tags, or produced evidence type."""
        return _safe("dftk_search_capabilities", lambda: gateway.search(query=query, tags=tags, produces=produces, limit=limit))

    @server.tool()
    def dftk_describe(name: str) -> dict[str, Any]:
        """Return the exact parameter, safety, dependency, tag and evidence contract for one DFTK capability."""
        return _safe("dftk_describe", lambda: gateway.describe(name))

    @server.tool()
    def dftk_run(name: str, params: dict[str, Any] | None = None, case_id: str | None = None) -> dict[str, Any]:
        """Execute one DFTK capability under server-owned safety/network/root policy; optionally persist it in an existing DFTK case."""
        return _safe("dftk_run", lambda: gateway.run(name=name, params=params, case_id=case_id))

    @server.tool()
    def dftk_case(action: str, case_id: str | None = None, name: str | None = None, format: str = "json") -> dict[str, Any]:
        """Manage the existing DFTK CaseSession: new, list, show, timeline, or export. Tool execution uses dftk_run with case_id."""
        return _safe("dftk_case", lambda: gateway.case(action=action, case_id=case_id, name=name, format=format))

    @server.tool()
    def dftk_read_case_run(
        case_id: str,
        seq: int,
        evidence_offset: int = 0,
        evidence_limit: int = 20,
        fact_path: str = "",
        value_offset: int = 0,
        value_limit: int = 50,
    ) -> dict[str, Any]:
        """Read/page one Observation already persisted by DFTK CaseSession without rerunning the forensic capability."""
        return _safe("dftk_read_case_run", lambda: gateway.read_case_run(
            case_id, seq,
            evidence_offset=evidence_offset,
            evidence_limit=evidence_limit,
            fact_path=fact_path,
            value_offset=value_offset,
            value_limit=value_limit,
        ))

    return server


def run_mcp_server(
    *,
    root: str | Path = ".",
    workspace: str | Path = ".dftk",
    max_safety: str = "READ_ONLY",
    allow_network: bool = False,
    timeout_seconds: int = _DEFAULT_TIMEOUT,
) -> None:
    """Run the local stdio MCP server. stdout is reserved for MCP framing."""
    gateway = DFTKMCPGateway(
        root=root,
        workspace=workspace,
        max_safety=max_safety,
        allow_network=allow_network,
        timeout_seconds=timeout_seconds,
    )
    # Any import-time noise from optional parsers is redirected away from stdio.
    with redirect_stdout(sys.stderr):
        gateway.preflight()
    server = create_server(gateway)
    server.run(transport="stdio")
