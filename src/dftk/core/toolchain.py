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

"""Environment preparation: turn an extracted forensic-toolkit directory into a
DFTK-managed, agent-readable toolchain.

This folds the win-tool-launcher workflow into DFTK. After a recipient extracts
the toolkit zip, running ``dftk prepare <root>``:

* records the toolkit root + a DFTK-managed shim directory in
  ``~/.dftk/toolchain.json`` (always under the user home => always readable by
  the agent, even when the toolkit lives on an exotic / non-PATH drive);
* generates two-layer shims (a ``.bat`` for real Windows terminals and an
  extensionless wrapper for the agent Bash) into that shim dir;
* emits ``set_path.bat`` / ``set_path.sh`` so the bare tool names also work in a
  plain terminal session without modifying persistent PATH;
* optionally rewrites a stale hardcoded root left inside launcher scripts
  of the bundle (``--rewrite-from``) so they point at the real location. Only
  ``.bat``/``.cmd``/``.ps1`` launchers are touched and every rewritten file is
  backed up first, so the step is reversible and never mangles data/config.

The binary resolver in ``core.external_tools`` then searches the shim dir and
toolkit root automatically, so the tools are found on subsequent ``dftk`` calls
without any manual PATH edit -- which is the whole point of the exercise.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from .external_tools import _EXTERNAL_TOOLS, _looks_runnable

_DEFAULT_BIN_SUBDIR = "bin"
_CONFIG_NAME = "toolchain.json"
# Only launcher scripts are ever rewritten. Other text files (data, configs,
# READMEs, source) are deliberately excluded: a stale-path substring can appear
# in evidence-like content, and rewriting it in place would both corrupt that
# content and change the toolkit's hashes with no easy recovery.
_REWRITE_EXTS = (".bat", ".cmd", ".ps1")


def toolchain_config_path(base: Path | None = None) -> Path:
    """Where the persistent toolchain config is stored.

    ``base`` overrides the search root (used by tests). Otherwise: explicit
    ``$DFTK_TOOLCHAIN_CONFIG`` wins, then ``~/.dftk/toolchain.json`` (the
    persistent, agent-readable default written by ``prepare``).
    """
    if base is not None:
        return Path(base).expanduser() / ".dftk" / _CONFIG_NAME
    env = os.environ.get("DFTK_TOOLCHAIN_CONFIG")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".dftk" / _CONFIG_NAME


def load_toolchain(base: Path | None = None) -> dict[str, Any]:
    p = toolchain_config_path(base)
    try:
        if p.is_file():
            data = json.loads(p.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        pass
    return {}


def save_toolchain(cfg: dict[str, Any], base: Path | None = None) -> Path:
    p = toolchain_config_path(base)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return p


def _find_real_binary(root: Path, entry: dict[str, Any]) -> str | None:
    """Locate the first real binary for a tool somewhere under ``root``.

    Bounded scan: the root itself, ``<root>/bin``, ``<root>/<name>``,
    ``<root>/<category>``, and one level of immediate subdirectories (plus their
    ``bin``). Never walks arbitrarily deep, so a large toolkit is safe.
    """
    exts = (".exe", ".bat", ".cmd", ".ps1")
    candidate_dirs = [root, root / "bin", root / entry["name"], root / entry["category"]]
    try:
        for child in sorted(root.iterdir()):
            if child.is_dir():
                candidate_dirs.append(child)
                candidate_dirs.append(child / "bin")
    except OSError:
        pass
    for d in candidate_dirs:
        if not isinstance(d, Path) or not d.is_dir():
            continue
        for cand in entry["binaries"]:
            names = [cand] + [cand + e for e in exts if not cand.lower().endswith(e)]
            for n in names:
                fp = d / n
                if fp.is_file() and _looks_runnable(fp):
                    return str(fp)
    return None


def _emit_shims(shim_dir: Path, name: str, real_exe: str) -> list[str]:
    """Write a .bat and an extensionless wrapper for ``name`` pointing at the real exe."""
    out: list[str] = []
    bat = f'@echo off\r\n"{real_exe}" %*\r\n'
    bat_path = shim_dir / f"{name}.bat"
    bat_path.write_text(bat, encoding="utf-8", newline="")
    out.append(str(bat_path))

    real_posix = real_exe.replace("\\", "/")
    if real_exe.lower().endswith((".bat", ".cmd")):
        body = f'#!/bin/sh\n# generated by dftk prepare\n exec cmd //c "{real_posix}" "$@"\n'
    else:
        body = f'#!/bin/sh\n# generated by dftk prepare\n exec "{real_posix}" "$@"\n'
    wpath = shim_dir / name
    wpath.write_text(body, encoding="utf-8", newline="")
    try:
        os.chmod(wpath, 0o755)
    except OSError:
        pass
    out.append(str(wpath))
    return out


def _emit_set_path(shim_dir: Path) -> None:
    shim_posix = str(shim_dir).replace("\\", "/")
    bat = (
        f'@echo off\r\nset "PATH={shim_dir};%PATH%"\r\n'
        f'echo DFTK toolchain shims active for THIS terminal session.\r\n'
    )
    (shim_dir / "set_path.bat").write_text(bat, encoding="utf-8", newline="")
    sh = (
        f'export PATH="{shim_posix}:$PATH"\n'
        f'# source this file to enable bare tool names in this session:\n'
        f'#   . "{shim_posix}/set_path.sh"\n'
        f'echo DFTK toolchain shims active for this session.\n'
    )
    (shim_dir / "set_path.sh").write_text(sh, encoding="utf-8", newline="")


def _rewrite_hardcoded_paths(
    root: Path, old: str, new: str, backup_dir: Path | None = None
) -> tuple[int, list[str]]:
    """Replace a stale hardcoded root inside launcher scripts of the bundle.

    Off by default; only runs when the caller passes ``--rewrite-from``.

    Safety:
    * Only launcher scripts (``.bat``/``.cmd``/``.ps1``) are touched. Other text
      files are left alone (see ``_REWRITE_EXTS``).
    * Every file that is about to be changed is copied verbatim into
      ``backup_dir`` first, so the rewrite is fully reversible. ``backup_dir``
      lives under the DFTK-managed shim dir (outside the toolkit) to avoid
      polluting the forensic image.

    Returns ``(count, backed_up_paths)``.
    """
    old_n = old.replace("\\", "/")
    new_n = new.replace("\\", "/")
    count = 0
    backed_up: list[str] = []
    for dp, _, fns in os.walk(root):
        for fn in fns:
            if not fn.lower().endswith(_REWRITE_EXTS):
                continue
            p = Path(dp) / fn
            try:
                t = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if old in t or old_n in t:
                nw = t.replace(old, new).replace(old_n, new_n)
                if nw != t:
                    if backup_dir is not None:
                        rel = p.relative_to(root)
                        bkp = backup_dir / rel
                        try:
                            bkp.parent.mkdir(parents=True, exist_ok=True)
                            bkp.write_text(t, encoding="utf-8")
                            backed_up.append(str(bkp))
                        except OSError:
                            pass
                    p.write_text(nw, encoding="utf-8")
                    count += 1
    return count, backed_up


def prepare(
    toolkit_root: str | Path,
    bin_dir: str | Path | None = None,
    rewrite_from: str | None = None,
    make_shims: bool = True,
) -> dict[str, Any]:
    """Prepare an extracted forensic-toolkit directory for DFTK.

    Parameters
    ----------
    toolkit_root:
        The directory the recipient extracted the toolkit zip into. Drive
        letters are never hardcoded -- the real location is derived here.
    bin_dir:
        Where shims are written. Defaults to ``~/.dftk/bin`` (user home, so the
        agent can always read it).
    rewrite_from:
        Optional stale absolute root to rewrite inside launcher scripts of the
        bundle to ``toolkit_root`` (mirrors win-tool-launcher's path-fix step).
        Only ``.bat``/``.cmd``/``.ps1`` launchers are affected, and each is
        backed up under the DFTK-managed shim dir before being changed.
    make_shims:
        When False, only records the toolkit root (no shim generation).
    """
    root = Path(toolkit_root).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"toolkit root is not a directory: {root}")

    shim_dir = (
        Path(bin_dir).expanduser().resolve()
        if bin_dir
        else (Path.home() / ".dftk" / _DEFAULT_BIN_SUBDIR)
    )
    shim_dir.mkdir(parents=True, exist_ok=True)

    found: list[dict[str, Any]] = []
    missing: list[str] = []
    shims: list[str] = []

    for entry in _EXTERNAL_TOOLS:
        real = _find_real_binary(root, entry)
        if not real:
            missing.append(entry["name"])
            continue
        found.append({"name": entry["name"], "path": real})
        if make_shims:
            shims.extend(_emit_shims(shim_dir, entry["name"], real))

    rewritten = 0
    rewrite_backup_dir: str | None = None
    if rewrite_from:
        resolved_old = Path(rewrite_from).expanduser().resolve()
        if resolved_old != root:
            ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
            backup_dir = shim_dir / "rewrite-backups" / ts
            try:
                backup_dir.mkdir(parents=True, exist_ok=True)
            except OSError:
                # A working backup location is required for the rewrite to be
                # reversible. If we cannot create it, do NOT rewrite (fail-closed):
                # silently rewriting launchers with no backup would be irreversible.
                backup_dir = None
            if backup_dir is not None:
                rewritten, _ = _rewrite_hardcoded_paths(
                    root, rewrite_from, str(root), backup_dir
                )
                if rewritten:
                    rewrite_backup_dir = str(backup_dir)

    if make_shims:
        _emit_set_path(shim_dir)

    cfg = {
        "toolkit_root": str(root),
        "bin_dir": str(shim_dir),
        "prepared_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    save_toolchain(cfg)

    return {
        "ok": True,
        "toolkit_root": str(root),
        "bin_dir": str(shim_dir),
        "found": found,
        "missing": missing,
        "shims": shims,
        "rewritten_files": rewritten,
        "rewrite_backup_dir": rewrite_backup_dir,
        "config": str(toolchain_config_path()),
    }
