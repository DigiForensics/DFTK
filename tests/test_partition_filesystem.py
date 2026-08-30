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

import struct
import tempfile
from pathlib import Path

from dftk import get_registry
from dftk.core.registry import registry
from dftk.core.models import SafetyLevel
from dftk.core.safety import SafetyPolicy

get_registry()  # register image.partitions + filesystem.*

_STATEFUL = SafetyPolicy(max_level=SafetyLevel.STATEFUL)


def _build_mbr(image: Path, *, gpt_protective: bool = False) -> None:
    data = bytearray(10 * 1024 * 1024)
    if gpt_protective:
        # Protective MBR: one 0xEE partition spanning the disk.
        entry = bytearray(16)
        entry[4] = 0xEE
        struct.pack_into("<I", entry, 8, 1)
        struct.pack_into("<I", entry, 12, (len(data) // 512) - 1)
        data[446:446 + 16] = entry
    else:
        entry = bytearray(16)
        entry[0] = 0x00
        entry[4] = 0x83  # Linux
        struct.pack_into("<I", entry, 8, 2048)            # start LBA
        struct.pack_into("<I", entry, 12, 4096)           # sectors
        data[446:446 + 16] = entry
    data[510] = 0x55
    data[511] = 0xAA
    image.write_bytes(bytes(data))


def _build_gpt(image: Path) -> None:
    data = bytearray(10 * 1024 * 1024)
    # Protective MBR
    pentry = bytearray(16)
    pentry[4] = 0xEE
    struct.pack_into("<I", pentry, 8, 1)
    struct.pack_into("<I", pentry, 12, (len(data) // 512) - 1)
    data[446:446 + 16] = pentry
    data[510] = 0x55
    data[511] = 0xAA
    # GPT header at LBA1 (ignoring CRC; parser does not verify it)
    hdr = bytearray(512)
    hdr[0:8] = b"EFI PART"
    struct.pack_into("<I", hdr, 8, 0x00010000)   # revision
    struct.pack_into("<I", hdr, 80, 1)           # num entries
    struct.pack_into("<I", hdr, 84, 128)         # entry size
    struct.pack_into("<Q", hdr, 72, 2)           # partition entries LBA
    data[512:512 + 512] = hdr
    # One partition entry at LBA2
    entry = bytearray(128)
    # type GUID: arbitrary
    entry[0:16] = b"\x00" * 16
    entry[0] = 0x01
    struct.pack_into("<Q", entry, 32, 2048)      # first LBA
    struct.pack_into("<Q", entry, 40, 6143)      # last LBA
    name = "TestGPT".encode("utf-16-le")
    entry[56:56 + len(name)] = name
    data[1024:1024 + 128] = entry
    image.write_bytes(bytes(data))


def test_image_partitions_mbr(tmp_path: Path):
    img = tmp_path / "disk.img"
    _build_mbr(img)
    from dftk.core.registry import registry
    obs = registry.run("image.partitions", {"path": str(img)})
    assert obs.status.value == "ok", obs.summary
    assert len(obs.facts["partitions"]) == 1
    p = obs.facts["partitions"][0]
    assert p["scheme"] == "MBR"
    assert p["type"] == "Linux"
    assert p["start_lba"] == 2048
    assert p["start_byte"] == 2048 * 512


def test_image_partitions_gpt(tmp_path: Path):
    img = tmp_path / "disk.img"
    _build_gpt(img)
    from dftk.core.registry import registry
    obs = registry.run("image.partitions", {"path": str(img)})
    assert obs.status.value == "ok", obs.summary
    gpt = [p for p in obs.facts["partitions"] if p["scheme"] == "GPT"]
    assert gpt, "no GPT partition parsed"
    assert gpt[0]["name"] == "TestGPT"
    assert gpt[0]["start_lba"] == 2048


def test_filesystem_raw_read_and_extract(tmp_path: Path):
    img = tmp_path / "disk.img"
    _build_mbr(img)
    blob = b"FORENSIC_MARKER-" + bytes(range(256)) * 4
    # Write the blob at partition offset 0 (image offset 2048*512).
    with img.open("r+b") as fh:
        fh.seek(2048 * 512)
        fh.write(blob)

    from dftk.core.registry import registry
    # Raw offset read (no pytsk3 required).
    obs = registry.run("filesystem.read", {"path": str(img), "partition": 1,
                                           "offset": 0, "length": len(blob)})
    assert obs.status.value == "ok", obs.summary
    assert bytes.fromhex(obs.facts["hex_preview"][: len(blob) * 2])[:20] == blob[:20]

    # Extract to workspace -> DerivedArtifact.
    ws = tmp_path / "workspace"
    ws.mkdir()
    obs2 = registry.run("filesystem.extract", {"path": str(img), "output_dir": str(ws),
                                               "partition": 1, "offset": 0,
                                               "length": len(blob), "name": "blob.bin"},
                        policy=_STATEFUL)
    assert obs2.status.value == "ok", obs2.summary
    out = ws / "blob.bin"
    assert out.read_bytes() == blob
    # provenance: 1 evidence source + 1 derived
    arts = obs2.derived_artifacts
    assert len(arts) == 2, [a.to_dict() for a in arts]
    kinds = {a.kind for a in arts}
    assert kinds == {"evidence", "derived"}


def test_filesystem_tsk_ops_unsupported_without_pytsk3(tmp_path: Path):
    # When pytsk3 is unavailable the deep traversal tools must degrade to
    # UNSUPPORTED rather than crash.
    try:
        import pytsk3  # noqa: F401
        have_tsk = True
    except ImportError:
        have_tsk = False
    if have_tsk:
        return  # cannot assert UNSUPPORTED in this environment
    img = tmp_path / "disk.img"
    _build_mbr(img)
    from dftk.core.registry import registry
    for tool in ("filesystem.list", "filesystem.walk", "filesystem.stat", "filesystem.deleted"):
        params = {"path": str(img), "path_in_fs": "/"} if tool != "filesystem.deleted" \
            else {"path": str(img)}
        obs = registry.run(tool, params)
        assert obs.status.value == "unsupported", (tool, obs.summary)
