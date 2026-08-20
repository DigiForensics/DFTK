# Copyright 2026 DyNooob @ DigiForensics
# Licensed under the Apache License, Version 2.0.
from __future__ import annotations

import io
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from urllib.request import urlopen

from . import __version__ as TOOLKIT_VERSION

# Canonical source for the DFTK Agent Skill: the main "how to use dftk tools"
# skill plus the standalone analysis skills (android / pcap / reverse-exe / ...).
# The skill text lives in the dedicated DFTK-skill repository, NOT in this pip
# package, so install fetches it from GitHub.
SKILL_REPO_URL = "https://github.com/DigiForensics/DFTK-skill.git"
SKILL_REPO_WEB = "https://github.com/DigiForensics/DFTK-skill"

# Name of the main dftk skill once installed into an Agent skills directory.
MAIN_SKILL_NAME = "dftk"


def default_ref() -> str:
    """Default DFTK-skill ref: the tag matching this dftk release (vX.Y.Z)."""
    return f"v{TOOLKIT_VERSION}"


def _safe_extract_tar(tf: tarfile.TarFile, destination: Path) -> None:
    """Extract a repository archive without accepting escaping paths or links."""
    root = destination.resolve()
    members: list[tarfile.TarInfo] = []
    for member in tf.getmembers():
        target = (root / member.name).resolve()
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"skill archive member escapes destination: {member.name!r}") from exc
        if member.issym() or member.islnk() or member.isdev():
            raise ValueError(f"skill archive contains unsupported special member: {member.name!r}")
        members.append(member)
    tf.extractall(root, members=members)


def fetch_skill_repo(ref: str | None = None, dest: Path | None = None) -> Path:
    """Fetch the DFTK-skill repository at ``ref`` into a local directory.

    Uses ``git clone`` when available, otherwise downloads the GitHub source
    tarball. Requires network access. Returns the repository root.

    ``ref`` defaults to the tag matching this dftk version. Pass a branch, tag,
    or commit sha to override (``dftk skill --install --ref <ref>``).
    """
    ref = ref or default_ref()
    dest = Path(dest) if dest else Path(tempfile.mkdtemp(prefix="dftk-skill-"))
    dest.mkdir(parents=True, exist_ok=True)

    if shutil.which("git"):
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", ref, SKILL_REPO_URL, str(dest)],
            check=True,
            capture_output=True,
        )
        return dest

    # Fallback: GitHub source tarball for the ref.
    url = (
        "https://github.com/DigiForensics/DFTK-skill/archive/refs/tags/"
        f"{ref}.tar.gz"
    )
    with urlopen(url) as resp:
        data = resp.read()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        _safe_extract_tar(tf, dest)
    nested = next((p for p in dest.iterdir() if p.is_dir()), None)
    return nested if nested is not None else dest


# VCS / CI / metadata that must never be copied into an installed skill dir.
_SKIP_NAMES = {".git", ".gitignore", ".github"}


def _copy_tree(src: Path, dst: Path, exclude_top: set[str] | None = None) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for child in src.iterdir():
        if child.name in _SKIP_NAMES:
            continue
        if exclude_top and child.name in exclude_top:
            continue
        target = dst / child.name
        if child.is_dir():
            _copy_tree(child, target)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(child.read_bytes())


def install_from_repo_root(repo_root: str | Path, destination: str | Path) -> list[Path]:
    """Install the main dftk skill and the standalone analysis skills/*.

    ``destination`` is an Agent skills base directory (e.g. ``~/.workbuddy/skills``).
    The main skill installs to ``<destination>/dftk``; each entry under
    ``<repo_root>/skills/`` installs to ``<destination>/<name>``.

    Returns the list of installed skill directories.
    """
    repo_root = Path(repo_root)
    base = Path(destination).expanduser()
    installed: list[Path] = []

    main_dest = base / MAIN_SKILL_NAME
    _copy_tree(repo_root, main_dest, exclude_top={"skills"})
    installed.append(main_dest)

    skills_dir = repo_root / "skills"
    if skills_dir.is_dir():
        for child in sorted(skills_dir.iterdir()):
            if child.is_dir() and not child.name.startswith("."):
                target = base / child.name
                _copy_tree(child, target)
                installed.append(target)
    return installed


def install_skill(ref: str | None, destination: str | Path) -> list[Path]:
    """Fetch DFTK-skill at ``ref`` and install it into ``destination`` (skills base)."""
    repo_root = fetch_skill_repo(ref)
    try:
        return install_from_repo_root(repo_root, destination)
    finally:
        shutil.rmtree(repo_root, ignore_errors=True)
