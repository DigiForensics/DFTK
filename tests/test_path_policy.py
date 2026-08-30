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

import os
import tempfile
from pathlib import Path

import pytest

from dftk.core.path_policy import PathRole, PathEscapeError, validate_path, validate_params


def _roots():
    base = Path(tempfile.mkdtemp())
    evidence = base / "evidence"
    workspace = base / "workspace"
    evidence.mkdir()
    workspace.mkdir()
    (evidence / "x.db").write_bytes(b"hello")
    return evidence, workspace


def test_evidence_input_ok_under_root():
    evidence, workspace = _roots()
    p = validate_path(str(evidence / "x.db"), PathRole.EVIDENCE_INPUT,
                      evidence_root=evidence, workspace_root=workspace)
    assert p == (evidence / "x.db").resolve()


def test_evidence_input_missing_is_rejected():
    evidence, workspace = _roots()
    with pytest.raises(PathEscapeError):
        validate_path(str(evidence / "nope.db"), PathRole.EVIDENCE_INPUT,
                      evidence_root=evidence, workspace_root=workspace)


def test_traversal_escape_rejected():
    evidence, workspace = _roots()
    with pytest.raises(PathEscapeError):
        validate_path("../etc/passwd", PathRole.EVIDENCE_INPUT,
                      evidence_root=evidence, workspace_root=workspace)


def test_workspace_output_must_stay_in_workspace():
    evidence, workspace = _roots()
    p = validate_path(str(workspace / "out"), PathRole.WORKSPACE_OUTPUT,
                      evidence_root=evidence, workspace_root=workspace)
    assert str(p).startswith(str(workspace.resolve()))


def test_workspace_output_escape_rejected():
    evidence, workspace = _roots()
    with pytest.raises(PathEscapeError):
        validate_path(str(evidence / "escape"), PathRole.WORKSPACE_OUTPUT,
                      evidence_root=evidence, workspace_root=workspace)


def test_unc_rejected():
    evidence, workspace = _roots()
    with pytest.raises(PathEscapeError):
        validate_path("\\\\server\\share\\x", PathRole.EVIDENCE_INPUT,
                      evidence_root=evidence, workspace_root=workspace)


def test_symlink_escape_rejected():
    evidence, workspace = _roots()
    outside = evidence.parent / "outside"
    outside.mkdir()
    link = workspace / "link"
    # symlink inside workspace pointing outside the evidence root (still must be
    # under evidence root for EVIDENCE_INPUT).
    try:
        os.symlink(outside, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlink not supported on this platform")
    with pytest.raises(PathEscapeError):
        validate_path(str(link / "x"), PathRole.EVIDENCE_INPUT,
                      evidence_root=evidence, workspace_root=workspace)


def test_no_root_degrades_to_traversal_check():
    # Without configured roots, only literal traversal is rejected (best-effort).
    p = validate_path("/tmp/foo", PathRole.EVIDENCE_INPUT)
    assert p == Path("/tmp/foo").resolve()
    with pytest.raises(PathEscapeError):
        validate_path("../foo", PathRole.EVIDENCE_INPUT)


def test_validate_params_returns_resolved_map():
    evidence, workspace = _roots()
    resolved = validate_params(
        {"path": str(evidence / "x.db"), "output_dir": str(workspace / "o")},
        {"path": "EVIDENCE_INPUT", "output_dir": "WORKSPACE_OUTPUT"},
        evidence_root=evidence, workspace_root=workspace,
    )
    assert "path" in resolved and "output_dir" in resolved
    assert str(resolved["output_dir"]).startswith(str(workspace.resolve()))
