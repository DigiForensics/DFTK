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

import os

from dftk.doctor import detect_external_tools, doctor_report, _resolve_binary


def test_detect_external_tools_includes_catalog():
    tools = detect_external_tools()
    names = {t["name"] for t in tools}
    assert "jadx" in names and "tshark" in names and "ghidra" in names
    for t in tools:
        assert set(t) == {"name", "category", "purpose", "available", "path"}
        assert isinstance(t["available"], bool)
        if t["available"]:
            assert t["path"]
        else:
            assert t["path"] is None


def test_doctor_report_carries_external_section():
    report = doctor_report()
    ext = report["external"]
    assert ext["total"] == len(ext["tools"])
    assert ext["available"] <= ext["total"]


def test_resolve_binary_finds_on_path(monkeypatch):
    monkeypatch.setattr(
        "dftk.core.external_tools.shutil.which",
        lambda c: r"C:\tools\jadx.bat" if c == "jadx" else None,
    )
    assert _resolve_binary(["jadx"], []) == r"C:\tools\jadx.bat"
    assert _resolve_binary(["apktool"], []) is None


def test_resolve_binary_falls_back_to_extra_dir(monkeypatch, tmp_path):
    monkeypatch.setattr("dftk.core.external_tools.shutil.which", lambda c: None)
    monkeypatch.setattr(os.path, "isfile", lambda p: str(tmp_path) in p)
    monkeypatch.setattr(os, "access", lambda p, mode: True)
    d = str(tmp_path / "bin")
    os.makedirs(d, exist_ok=True)
    got = _resolve_binary(["radare2"], [d])
    assert got is not None and d in got


def test_resolve_binary_extra_dir_ignores_missing(monkeypatch, tmp_path):
    monkeypatch.setattr("dftk.core.external_tools.shutil.which", lambda c: None)
    monkeypatch.setattr(os.path, "isfile", lambda p: False)
    assert _resolve_binary(["radare2"], [str(tmp_path)]) is None
