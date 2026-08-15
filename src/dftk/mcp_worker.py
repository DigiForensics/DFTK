# Copyright 2026 DyNooob @ DigiForensics
# Licensed under the Apache License, Version 2.0.
"""Isolated worker used by the native DFTK MCP server.

The worker owns primitive stdout/stderr so noisy third-party parsers cannot corrupt
stdio MCP framing in the parent server. Policy is supplied only by the parent.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any
import io
import json
import os
import traceback

_CAPTURE_CHARS = 20_000
_MAX_RESPONSE_BYTES = 64 * 1024 * 1024


class _TailCapture(io.TextIOBase):
    def __init__(self, limit: int = _CAPTURE_CHARS) -> None:
        self.limit = max(1024, int(limit))
        self._text = ""
        self.truncated = False

    @property
    def encoding(self) -> str:
        return "utf-8"

    def writable(self) -> bool:
        return True

    def write(self, value: str) -> int:
        value = str(value)
        combined = self._text + value
        if len(combined) > self.limit:
            self.truncated = True
        self._text = combined[-self.limit :]
        return len(value)

    def flush(self) -> None:
        return None

    def getvalue(self) -> str:
        return self._text


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    raw = (json.dumps(payload, ensure_ascii=False, indent=2, default=str) + "\n").encode("utf-8")
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise ValueError(f"worker response exceeds {_MAX_RESPONSE_BYTES} bytes")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".tmp-{os.getpid()}")
    with tmp.open("wb") as fh:
        fh.write(raw)
        fh.flush()
        try:
            os.fsync(fh.fileno())
        except OSError:
            pass
    os.replace(tmp, path)


def _execute(request: dict[str, Any]) -> dict[str, Any]:
    from .catalog import load_builtin_tools
    from .core.case import CaseSession
    from .core.models import SafetyLevel
    from .core.registry import registry
    from .core.safety import SafetyPolicy

    load_builtin_tools()
    action = request.get("action")
    if action == "ping":
        from . import __version__
        return {"ok": True, "version": __version__, "tools": len(list(registry.specs()))}

    name = str(request.get("name") or "")
    params = dict(request.get("params") or {})
    max_safety = str(request.get("max_safety") or "READ_ONLY").upper()
    if max_safety not in {"READ_ONLY", "STATEFUL"}:
        raise ValueError("MCP worker refuses safety above STATEFUL")
    allow_network = bool(request.get("allow_network", False))

    from .core.audit import ToolAuditLog

    audit_path = request.get("audit")
    audit = ToolAuditLog(audit_path) if audit_path else None
    caller = "mcp"

    if action == "run":
        policy = SafetyPolicy(
            max_level=SafetyLevel[max_safety],
            allow_network=allow_network,
        )
        obs = registry.run(name, params, policy, audit=audit, caller=caller)
        return {"ok": True, "observation": obs.to_dict()}

    if action == "case_run":
        workspace = Path(str(request["workspace"]))
        case_id = str(request["case_id"])
        session = CaseSession(workspace)
        obs, entry = session._run_with_entry(
            case_id,
            name,
            params,
            allow_network=allow_network,
            max_safety=max_safety,
            audit=audit,
            caller=f"mcp:case:{case_id}",
        )
        return {"ok": True, "observation": obs.to_dict(), "case_run": entry}

    raise ValueError(f"unknown worker action: {action!r}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m dftk.mcp_worker")
    parser.add_argument("request")
    parser.add_argument("response")
    args = parser.parse_args(argv)

    request_path = Path(args.request)
    response_path = Path(args.response)
    out = _TailCapture()
    err = _TailCapture()
    try:
        request = json.loads(request_path.read_text(encoding="utf-8"))
        with redirect_stdout(out), redirect_stderr(err):
            result = _execute(request)
        result["captured_stdout"] = out.getvalue()
        result["captured_stderr"] = err.getvalue()
        result["capture_truncated"] = bool(out.truncated or err.truncated)
        try:
            _atomic_json(response_path, result)
        except ValueError as exc:
            _atomic_json(
                response_path,
                {
                    "ok": False,
                    "error_type": "ResponseTooLarge",
                    "error": str(exc),
                    "captured_stdout": out.getvalue()[-4000:],
                    "captured_stderr": err.getvalue()[-4000:],
                },
            )
            return 3
        return 0
    except BaseException as exc:
        try:
            _atomic_json(
                response_path,
                {
                    "ok": False,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "traceback": traceback.format_exc(limit=12),
                    "captured_stdout": out.getvalue(),
                    "captured_stderr": err.getvalue(),
                },
            )
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
