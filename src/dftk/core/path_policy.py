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

"""Role-aware path policy — the foundation of DFTK 3.5.0 provenance.

The old model inferred a tool's safety from its ``ToolSpec`` but let the *kind*
of path a parameter carried be guessed from its name (``path`` / ``output`` /
``dest``). That made the read-only Evidence Root / writable Workspace separation
implicit and easy to violate: a STATEFUL tool could be handed an ``output_dir``
pointing anywhere, and ``archive.extract_safe`` guarded only ``../`` traversal.

3.5.0 replaces name-guessing with an explicit ``PathRole`` declared on every
path parameter. The ``PathPolicy`` validator resolves each path (following
symlinks / junctions / reparse points), rejects UNC and out-of-root escapes, and
returns a containment-checked ``Path`` the tool must use. This is the bedrock
the DerivedArtifact / Audit Ledger 2.0 chain is built on.
"""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Any


class PathRole(str, Enum):
    """What a path parameter is allowed to mean."""

    EVIDENCE_INPUT = "EVIDENCE_INPUT"      # read-only source; must resolve under evidence_root
    WORKSPACE_OUTPUT = "WORKSPACE_OUTPUT"  # writable derived product; must resolve under workspace_root
    ANALYSIS_INPUT = "ANALYSIS_INPUT"  # read from evidence or derived workspace
    WORKSPACE_INPUT = "WORKSPACE_INPUT"    # readable input already inside the workspace


class PathEscapeError(ValueError):
    """Raised when a path parameter would escape its authorised root."""


# Windows drive-letter absolute path, e.g. ``C:\evidence`` or ``c:/x``.
_WINDOWS_ABS_RE = None


def _is_unc(value: str) -> bool:
    # \\server\share or \\?\... — DFTK does not follow UNC in 3.5.0.
    return value.startswith("\\\\") or value.startswith("//") and value[1:3] in ("?\\", "\\")


def _is_windows_abs(value: str) -> bool:
    # Python regex import kept lazy to avoid a module-level dependency on re
    # for the common (non-Windows) path.
    if len(value) >= 2 and value[1] == ":" and value[0].isalpha():
        return True
    return value.startswith("\\\\")


def _resolve(p: Path) -> Path:
    # Follow symlinks/junctions/reparse points. ``strict=False`` so a not-yet-
    # created output target still resolves its parent chain.
    try:
        return p.resolve(strict=False)
    except OSError:
        return p.resolve(strict=False)


def _contained(resolved: Path, root: Path) -> bool:
    """True iff ``resolved`` is ``root`` or inside it (cross-platform, after
    realpath resolution so symlink/junction escapes are caught)."""
    root_r = root.resolve(strict=False)
    try:
        common = os.path.commonpath([str(root_r), str(resolved)])
    except ValueError:
        # Different drives on Windows => never contained.
        return False
    return common == str(root_r)


def validate_path(
    raw: str,
    role: PathRole,
    *,
    evidence_root: Path | None = None,
    workspace_root: Path | None = None,
    derived_inputs: dict[str, str] | None = None,
) -> Path:
    """Resolve and containment-check one path parameter.

    When the relevant root is not configured the validator degrades to a
    best-effort check (NUL bytes, UNC rejection, lexical traversal) so the tool
    still runs under a bare CLI, but the *strong* guarantee only holds when both
    roots are supplied (the MCP server always does).
    """
    if not isinstance(raw, str) or not raw:
        raise PathEscapeError(f"path parameter must be a non-empty string, got {raw!r}")
    if "\x00" in raw:
        raise PathEscapeError("NUL byte in path parameter")
    if _is_unc(raw):
        raise PathEscapeError(f"UNC paths are not permitted: {raw!r}")

    if _is_windows_abs(raw) and os.name != "nt":
        raise PathEscapeError(f"Windows path is outside the local root model: {raw!r}")
    base = workspace_root if role in (PathRole.WORKSPACE_INPUT, PathRole.WORKSPACE_OUTPUT) else evidence_root
    candidate = Path(raw)
    if base is not None and not candidate.is_absolute():
        candidate = Path(base) / candidate
    resolved = _resolve(candidate)
    if role == PathRole.ANALYSIS_INPUT:
        roots = [Path(root) for root in (evidence_root, workspace_root) if root is not None]
        if roots and not any(_contained(resolved, root) for root in roots):
            raise PathEscapeError(f"analysis input escapes evidence and workspace roots: {raw!r}")
        if roots and not resolved.exists():
            raise PathEscapeError(f"path does not exist: {raw!r}")
        return resolved

    if role == PathRole.EVIDENCE_INPUT:
        root, must_exist, writable = evidence_root, True, False
    elif role == PathRole.WORKSPACE_OUTPUT:
        root, must_exist, writable = workspace_root, False, True
    else:  # WORKSPACE_INPUT
        root, must_exist, writable = workspace_root, True, False

    if root is None:
        # No root configured: reject literal traversal that is detectable
        # lexically, but do not pretend to enforce containment.
        if ".." in Path(raw).parts:
            raise PathEscapeError(
                f"path traversal ('..') rejected without a configured root: {raw!r}"
            )
        return resolved

    if not _contained(resolved, Path(root)):
        if (role == PathRole.EVIDENCE_INPUT and workspace_root is not None
                and _contained(resolved, Path(workspace_root))
                and (expected := (derived_inputs or {}).get(str(resolved)))):
            from .helpers import sha256_file
            if not resolved.is_file() or sha256_file(resolved) != expected:
                raise PathEscapeError(f"registered derived evidence changed or is missing: {raw!r}")
            return resolved
        raise PathEscapeError(
            f"path {raw!r} ({role.value}) escapes authorised root {Path(root)}"
        )
    if must_exist and not resolved.exists():
        raise PathEscapeError(f"path does not exist: {raw!r}")
    # A WORKSPACE_OUTPUT may be created; we only ensure it does not point at a
    # read-only evidence file. Existence is the caller's responsibility.
    _ = writable
    return resolved


def validate_params(
    params: dict[str, Any],
    path_roles: dict[str, str],
    *,
    evidence_root: Path | None = None,
    workspace_root: Path | None = None,
    derived_inputs: dict[str, str] | None = None,
) -> dict[str, Path | list[Path]]:
    """Validate every declared path parameter.

    Returns a mapping ``param_name -> resolved Path`` so the tool can use the
    pre-checked path directly instead of re-resolving user input.
    """
    resolved: dict[str, Path | list[Path]] = {}
    for name, role_str in path_roles.items():
        if name not in params:
            continue
        value = params[name]
        if value is None or value == "":
            continue  # optional path omitted by the caller
        if isinstance(value, list):
            resolved[name] = [validate_path(item, PathRole(role_str), evidence_root=evidence_root,
                                           workspace_root=workspace_root, derived_inputs=derived_inputs) for item in value]
            continue
        if not isinstance(value, str):
            raise PathEscapeError(f"path parameter {name!r} must be a string, got {type(value).__name__}")
        role = PathRole(role_str)
        resolved[name] = validate_path(
            value,
            role,
            evidence_root=evidence_root,
            workspace_root=workspace_root,
            derived_inputs=derived_inputs,
        )
    return resolved
