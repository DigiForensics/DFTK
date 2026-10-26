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

from dftk.core.provenance import ProvenanceIndex, DerivedArtifact


def test_add_original_and_derived():
    idx = ProvenanceIndex()
    root = idx.add(source_artifact="", locator="file:phone.zip", tool="archive.extract_safe",
                   version="3.5.0", sha256="a" * 64, size=100, kind="evidence")
    assert root.source_artifact == ""
    child = idx.add(source_artifact=root.artifact_id, locator="archive_member:data/msg.db",
                    tool="archive.extract_safe", version="3.5.0", sha256="b" * 64, size=50)
    assert child.source_artifact == root.artifact_id


def test_deterministic_ids():
    idx1 = ProvenanceIndex()
    a = idx1.add(source_artifact="", locator="file:phone.zip", tool="t", version="3.5.0")
    idx2 = ProvenanceIndex()
    b = idx2.add(source_artifact="", locator="file:phone.zip", tool="t", version="3.5.0")
    assert a.artifact_id == b.artifact_id


def test_same_named_acquisitions_have_distinct_root_and_child_identities():
    idx = ProvenanceIndex()
    first = idx.add(source_artifact='', locator='file:phone.zip', tool='t', version='test', sha256='a' * 64)
    second = idx.add(source_artifact='', locator='file:phone.zip', tool='t', version='test', sha256='b' * 64)
    assert first.artifact_id != second.artifact_id
    left = idx.add(source_artifact=first.artifact_id, locator='archive_member:photo.png', tool='t', version='test')
    right = idx.add(source_artifact=second.artifact_id, locator='archive_member:photo.png', tool='t', version='test')
    assert left.artifact_id != right.artifact_id


def test_chain_walks_lineage():
    idx = ProvenanceIndex()
    root = idx.add(source_artifact="", locator="file:phone.zip", tool="t", version="3.5.0")
    mid = idx.add(source_artifact=root.artifact_id, locator="archive_member:data/msg.db", tool="t", version="3.5.0")
    leaf = idx.add(source_artifact=mid.artifact_id, locator="wal_frame:412", tool="sqlite.recover", version="3.5.0")
    chain = idx.chain(leaf.artifact_id)
    assert [c.artifact_id for c in chain] == [root.artifact_id, mid.artifact_id, leaf.artifact_id]


def test_roundtrip_json():
    idx = ProvenanceIndex()
    root = idx.add(source_artifact="", locator="file:phone.zip", tool="t", version="3.5.0", sha256="c" * 64)
    idx.add(source_artifact=root.artifact_id, locator="m", tool="t", version="3.5.0", state="RECOVERED")
    text = idx.to_json()
    back = ProvenanceIndex.from_json(text)
    assert len(back.all()) == 2
    assert back.get(root.artifact_id).sha256 == "c" * 64


def test_derived_artifact_to_from_dict():
    art = DerivedArtifact(
        artifact_id="artifact-1", source_artifact="", locator="file:x",
        derivation={"tool": "t", "version": "3.5.0", "params": {"a": 1}},
        sha256="d" * 64, size=9, state="LIVE",
    )
    d = art.to_dict()
    assert d["derivation"]["tool"] == "t"
    assert DerivedArtifact.from_dict(d).artifact_id == "artifact-1"
