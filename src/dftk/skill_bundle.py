# Copyright 2026 DyNooob @ DigiForensics
# Licensed under the Apache License, Version 2.0.
from __future__ import annotations

from importlib.resources import files as package_files
from pathlib import Path


def bundled_skill_root():
    return package_files("dftk") / "skill"


def _copy_tree(src, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for child in src.iterdir():
        target = dst / child.name
        if child.is_dir():
            _copy_tree(child, target)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(child.read_bytes())


def install_bundled_skill(destination: str | Path) -> Path:
    """Install the entire progressive-disclosure DFTK Skill bundle."""
    dest = Path(destination).expanduser()
    if dest.name.lower() != "dftk":
        dest = dest / "dftk"
    _copy_tree(bundled_skill_root(), dest)
    return dest
