# Copyright 2026 DyNooob @ DigiForensics
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in the License.
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

import io
import zipfile
from pathlib import Path

import pytest

from dftk.core.registry import registry
from dftk.core.safety import SafetyPolicy
from dftk.core.models import SafetyLevel
from dftk import get_registry

# Register built-in capabilities (archive.extract_safe, ...) before use.
get_registry()


def _make_zip(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("data/msg.db", b"sqlite-bytes")
        z.writestr("readme.txt", b"notes")


def test_extract_safe_emits_derived_artifacts(tmp_path: Path):
    archive = tmp_path / "phone.zip"
    _make_zip(archive)
    out = tmp_path / "ws"
    obs = registry.run("archive.extract_safe", {"path": str(archive), "output_dir": str(out)},
                        SafetyPolicy(SafetyLevel.STATEFUL))
    assert obs.status.value in ("ok", "partial")
    assert obs.derived_artifacts, "extracted members must be registered as DerivedArtifact"
    # original evidence + 2 members
    kinds = {d.kind for d in obs.derived_artifacts}
    assert "evidence" in kinds
    # provenance meta present and round-trips
    prov = obs.meta["provenance"]
    assert prov["schema"] == "dftk.provenance/1"
    assert len(prov["artifacts"]) == len(obs.derived_artifacts)
    # each member locator references the archive member
    locators = {d.locator for d in obs.derived_artifacts if d.kind == "derived"}
    assert "archive_member:data/msg.db" in locators


def test_registry_blocks_path_escape_with_roots(tmp_path: Path):
    evidence = tmp_path / "evidence"
    workspace = tmp_path / "workspace"
    evidence.mkdir()
    workspace.mkdir()
    archive = evidence / "phone.zip"
    _make_zip(archive)
    # attacker tries to write extracted files outside the workspace
    policy = SafetyPolicy(SafetyLevel.STATEFUL, evidence_root=evidence, workspace_root=workspace)
    obs = registry.run("archive.extract_safe",
                       {"path": str(archive), "output_dir": str(tmp_path / "evil")},
                       policy)
    assert obs.status.value == "blocked"
    assert "path policy" in obs.summary.lower()


def test_registry_allows_inside_workspace(tmp_path: Path):
    evidence = tmp_path / "evidence"
    workspace = tmp_path / "workspace"
    evidence.mkdir()
    workspace.mkdir()
    archive = evidence / "phone.zip"
    _make_zip(archive)
    policy = SafetyPolicy(SafetyLevel.STATEFUL, evidence_root=evidence, workspace_root=workspace)
    obs = registry.run("archive.extract_safe",
                       {"path": str(archive), "output_dir": str(workspace / "out")},
                       policy)
    assert obs.status.value in ("ok", "partial")
    assert (workspace / "out" / "data" / "msg.db").exists()
