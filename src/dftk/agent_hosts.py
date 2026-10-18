# Copyright 2026 DyNooob @ DigiForensics
# Licensed under the Apache License, Version 2.0.
"""Shared host detection and install locations for bootstrap and diagnostics."""
from pathlib import Path
import os

AGENT_SKILL_DIRS = {
    "workbuddy": ".workbuddy/skills",
    "codebuddy": ".codebuddy/skills",
    "kimi": ".kimi-code/skills",
    "claude": ".claude/skills",
    "codex": ".codex/skills",
    "hermes": ".hermes/skills",
    "agents": ".agents/skills",
    "cursor": ".cursor/skills",
    "gemini": ".gemini/skills",
}

HOST_MARKERS = [
    ("workbuddy", "WORKBUDDY_PRODUCT_NAME", "workbuddy"),
    ("workbuddy", "CODEBUDDY_HOST", "workbuddy"),
    ("codebuddy", "CODEBUDDY_HOST", "codebuddy"),
    ("kimi", "KIMI_CODE_HOST", "kimi"),
    ("claude", "CLAUDE_CODE", None),
    ("claude", "CLAUDECODE", None),
    ("codex", "CODEX_HOME", None),
    ("hermes", "HERMES_HOST", None),
    ("agents", "AGENTS_HOST", None),
    ("cursor", "CURSOR_TRACE_ID", None),
    ("gemini", "GEMINI_CLI", None),
]


def current_agent_host() -> str | None:
    for host, name, substring in HOST_MARKERS:
        value = os.environ.get(name)
        if value and (substring is None or substring in value.lower()):
            return host
    return None


def skill_base(target: str, home: Path | None = None) -> Path:
    if target == "codex" and os.environ.get("CODEX_HOME"):
        return Path(os.environ["CODEX_HOME"]).expanduser().absolute() / "skills"
    return (home or Path.home()) / AGENT_SKILL_DIRS[target]
