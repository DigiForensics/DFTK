# Copyright 2026 DyNooob @ DigiForensics
# Licensed under the Apache License, Version 2.0.
from pathlib import Path
import io
import tarfile

import pytest

from dftk.skill_bundle import _safe_extract_tar, install_from_repo_root
from dftk.cli import AGENT_SKILL_DIRS, _resolve_targets


# Env vars that _resolve_targets consults for host detection. Cleared between
# cases so each test controls exactly one marker.
_HOST_ENV_VARS = (
    "WORKBUDDY_PRODUCT_NAME", "CODEBUDDY_HOST", "CODEX_HOME",
    "CLAUDE_CODE", "CLAUDECODE", "CURSOR_TRACE_ID", "GEMINI_CLI",
)


def _clear_host_env(monkeypatch):
    for var in _HOST_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def test_resolve_targets_auto_prefers_workbuddy_product_name(monkeypatch):
    _clear_host_env(monkeypatch)
    monkeypatch.setenv("WORKBUDDY_PRODUCT_NAME", "WorkBuddy")
    assert _resolve_targets("auto") == ["workbuddy"]


def test_resolve_targets_auto_prefers_workbuddy_host(monkeypatch):
    _clear_host_env(monkeypatch)
    monkeypatch.setenv("CODEBUDDY_HOST", "workbuddy-desktop")
    assert _resolve_targets("auto") == ["workbuddy"]


def test_resolve_targets_auto_codebuddy_host(monkeypatch):
    _clear_host_env(monkeypatch)
    monkeypatch.setenv("CODEBUDDY_HOST", "codebuddy-desktop")
    assert _resolve_targets("auto") == ["codebuddy"]


def test_resolve_targets_auto_workbuddy_never_resolves_to_codebuddy(monkeypatch):
    # Guard against substring confusion: a workbuddy host must not match codebuddy.
    _clear_host_env(monkeypatch)
    monkeypatch.setenv("CODEBUDDY_HOST", "workbuddy-desktop")
    assert _resolve_targets("auto") == ["workbuddy"]


def test_resolve_targets_auto_existing_markers_unchanged(monkeypatch):
    _clear_host_env(monkeypatch)
    monkeypatch.setenv("CODEX_HOME", "/x")
    assert _resolve_targets("auto") == ["codex"]
    _clear_host_env(monkeypatch)
    monkeypatch.setenv("CLAUDE_CODE", "1")
    assert _resolve_targets("auto") == ["claude"]


def test_resolve_targets_explicit_target_passthrough(monkeypatch):
    assert _resolve_targets("workbuddy") == ["workbuddy"]
    assert _resolve_targets("all") == list(AGENT_SKILL_DIRS.keys())


def _make_fake_repo(root: Path) -> None:
    (root / "SKILL.md").write_text("# dftk\n", encoding="utf-8")
    refs = root / "references"
    refs.mkdir(parents=True)
    (refs / "claim-patterns.md").write_text("x\n", encoding="utf-8")
    (refs / "domains").mkdir()
    (refs / "domains" / "android.md").write_text("x\n", encoding="utf-8")
    tmpl = root / "templates"
    tmpl.mkdir()
    (tmpl / "answer-card.md").write_text("x\n", encoding="utf-8")

    skills = root / "skills"
    skills.mkdir()
    for name in ("apk", "pcap", "reverse-exe", "server-forensics"):
        d = skills / name
        d.mkdir()
        (d / "SKILL.md").write_text(f"# {name}\n", encoding="utf-8")


def test_install_from_repo_root(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _make_fake_repo(repo)

    base = tmp_path / "skills_base"
    installed = install_from_repo_root(repo, base)

    names = {p.name for p in installed}
    assert names == {"dftk", "apk", "pcap", "reverse-exe", "server-forensics"}

    # main skill lands under <base>/dftk with its references/templates
    assert (base / "dftk" / "SKILL.md").is_file()
    assert (base / "dftk" / "references" / "domains" / "android.md").is_file()
    assert (base / "dftk" / "templates" / "answer-card.md").is_file()

    # each standalone analysis skill lands under its own name
    assert (base / "apk" / "SKILL.md").is_file()
    assert (base / "server-forensics" / "SKILL.md").is_file()

    # standalone skills must NOT be nested under the main dftk skill
    assert not (base / "dftk" / "skills").exists()


def test_install_excludes_vcs_metadata(tmp_path: Path):
    # Simulate a git-cloned repo root: real skill content plus .git + .github.
    repo = tmp_path / "repo"
    repo.mkdir()
    _make_fake_repo(repo)
    (repo / ".git").mkdir()
    (repo / ".git" / "config").write_text("[core]\n", encoding="utf-8")
    (repo / ".gitignore").write_text("*.log\n", encoding="utf-8")
    (repo / ".github").mkdir()
    (repo / ".github" / "workflows").mkdir()
    (repo / ".github" / "workflows" / "ci.yml").write_text("on: push\n", encoding="utf-8")

    base = tmp_path / "skills_base"
    install_from_repo_root(repo, base)

    # VCS / CI metadata must never leak into the installed skill directory.
    assert not (base / "dftk" / ".git").exists()
    assert not (base / "dftk" / ".gitignore").exists()
    assert not (base / "dftk" / ".github").exists()
    # Real content is still present.
    assert (base / "dftk" / "SKILL.md").is_file()


def test_safe_tar_extraction_rejects_path_escape(tmp_path: Path):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as tf:
        member = tarfile.TarInfo("../outside.txt")
        member.size = 1
        tf.addfile(member, io.BytesIO(b"x"))
    data.seek(0)
    with tarfile.open(fileobj=data, mode="r") as tf:
        with pytest.raises(ValueError, match="escapes destination"):
            _safe_extract_tar(tf, tmp_path / "destination")
