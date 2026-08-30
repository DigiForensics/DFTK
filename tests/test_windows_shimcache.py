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

"""Tests for windows.shimcache parser."""

from __future__ import annotations

import datetime
import struct

from dftk.core.registry import registry
from dftk.primitives import windows_shimcache as sc


def _make_entry(path_str: str, dt: datetime.datetime) -> bytes:
    epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    ft = int((dt - epoch).total_seconds() * 10_000_000)
    assert sc._plausible_ft(ft), "test fixture must use a 2000-2050 FILETIME"
    entry = bytearray(0x80)
    pb = path_str.encode("utf-16-le")
    entry[0x10 : 0x10 + len(pb)] = pb
    struct.pack_into("<Q", entry, 0x60, ft)
    return bytes(entry)


def test_registered():
    assert registry.get("windows.shimcache") is not None


def test_parse_win7_layout():
    e1 = _make_entry(r"C:\Windows\System32\evil.exe", datetime.datetime(2020, 6, 15, tzinfo=datetime.timezone.utc))
    e2 = _make_entry(r"C:\Program Files\app\loader.dll", datetime.datetime(2019, 3, 2, tzinfo=datetime.timezone.utc))
    blob = e1 + e2
    layout, entries = sc._parse_entries(blob)
    assert layout == "win7_8_10_pre1511"
    assert len(entries) == 2
    paths = {e["path"] for e in entries}
    assert r"C:\Windows\System32\evil.exe" in paths
    assert r"C:\Program Files\app\loader.dll" in paths
    for e in entries:
        assert e["execution_inference"] == "unsupported"
        assert e["last_modified"] is not None
        assert e["confidence"] == "low"


def test_tool_runs_on_blob(tmp_path):
    e1 = _make_entry(r"C:\Users\victim\runme.exe", datetime.datetime(2021, 1, 1, tzinfo=datetime.timezone.utc))
    p = tmp_path / "shim.bin"
    p.write_bytes(e1)
    obs = registry.run("windows.shimcache", {"path": str(p)})
    assert obs.status.value in ("ok", "partial")
    assert obs.facts["entry_count"] >= 1
    assert any("execution_inference" in w or "not" in w.lower() for w in obs.warnings)
