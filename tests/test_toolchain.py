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
from pathlib import Path

from dftk.core import toolchain
from dftk.core.external_tools import (
    detect_external_tools,
    external_tool_available,
    resolve_external_tool,
    toolchain_roots,
)


def _fake_toolkit(root: object, names: list[str]) -> None:
    bindir = root / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    for n in names:
        (bindir / f"{n}.bat").write_text("@echo off\r\n", encoding="utf-8", newline="")


def test_prepare_makes_tools_discoverable_without_path(tmp_path, monkeypatch):
    # Redirect the persistent config into tmp so we never touch the real home.
    monkeypatch.setenv("DFTK_TOOLCHAIN_CONFIG", str(tmp_path / "tc.json"))
    # Disable PATH-based discovery so the test proves config-driven resolution.
    monkeypatch.setattr("dftk.core.external_tools.shutil.which", lambda c: None)

    root = tmp_path / "toolkit"
    _fake_toolkit(root, ["jadx", "apktool", "tshark"])

    report = toolchain.prepare(root, bin_dir=str(tmp_path / "shims"))
    assert report["ok"]
    assert {f["name"] for f in report["found"]} >= {"jadx", "apktool", "tshark"}
    assert report["missing"]  # not every catalogued tool is present in the fake kit

    # Shims are generated into the DFTK-managed, agent-readable dir.
    assert (tmp_path / "shims" / "jadx.bat").is_file()
    assert (tmp_path / "shims" / "jadx").is_file()
    assert (tmp_path / "shims" / "set_path.bat").is_file()
    assert (tmp_path / "shims" / "set_path.sh").is_file()

    # Config records both the root and the shim dir.
    assert toolchain_roots()["toolkit_root"] == str(root)
    assert toolchain_roots()["bin_dir"] == str(tmp_path / "shims")

    # Now discovery works purely through the config, with no PATH involvement.
    det = {t["name"]: t for t in detect_external_tools()}
    assert det["jadx"]["available"] is True
    assert det["jadx"]["source"] == "DFTK_TOOLS / dftk prepare root"
    assert det["jadx"]["path"] == str(root / "bin" / "jadx.bat")
    assert external_tool_available("jadx") is True
    assert resolve_external_tool("jadx") == str(root / "bin" / "jadx.bat")


def test_prepare_records_root_only_with_no_shims(tmp_path, monkeypatch):
    monkeypatch.setenv("DFTK_TOOLCHAIN_CONFIG", str(tmp_path / "tc.json"))
    monkeypatch.setattr("dftk.core.external_tools.shutil.which", lambda c: None)

    root = tmp_path / "toolkit"
    _fake_toolkit(root, ["jadx"])

    report = toolchain.prepare(root, bin_dir=str(tmp_path / "shims"), make_shims=False)
    assert report["shims"] == []
    # No launcher files were emitted, only the (empty) shim directory itself.
    emitted = [p for p in (tmp_path / "shims").iterdir()] if (tmp_path / "shims").is_dir() else []
    assert all(p.is_dir() for p in emitted)
    # Root is still recorded, so detection still finds the real binary.
    assert external_tool_available("jadx") is True


def test_prepare_rewrites_hardcoded_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("DFTK_TOOLCHAIN_CONFIG", str(tmp_path / "tc.json"))
    monkeypatch.setattr("dftk.core.external_tools.shutil.which", lambda c: None)

    root = tmp_path / "toolkit"
    _fake_toolkit(root, ["jadx"])
    stale = r"D:\StaleToolkit"
    launcher = root / "bin" / "jadx.bat"
    launcher.write_text(f'@echo off\r\n"{stale}\\bin\\jadx.exe" %*\r\n', encoding="utf-8", newline="")
    # A non-launcher file that happens to contain the stale path must NOT be
    # rewritten -- it could be evidence-like content.
    notes = root / "notes.txt"
    notes.write_text(f"original location was {stale}\n", encoding="utf-8")

    report = toolchain.prepare(root, rewrite_from=stale)
    assert report["rewritten_files"] >= 1
    assert stale not in launcher.read_text(encoding="utf-8")
    assert str(root).replace("\\", "/") in launcher.read_text(encoding="utf-8").replace("\\", "/")

    # Non-launcher content is preserved verbatim.
    assert notes.read_text(encoding="utf-8") == f"original location was {stale}\n"

    # The rewrite is reversible: an untouched copy was backed up first.
    assert report["rewrite_backup_dir"]
    backups = list((Path(report["rewrite_backup_dir"])).rglob("*.bat"))
    assert backups
    assert stale in backups[0].read_text(encoding="utf-8")


def test_prepare_rewrite_is_noop_when_old_equals_root(tmp_path, monkeypatch):
    monkeypatch.setenv("DFTK_TOOLCHAIN_CONFIG", str(tmp_path / "tc.json"))
    monkeypatch.setattr("dftk.core.external_tools.shutil.which", lambda c: None)

    root = tmp_path / "toolkit"
    _fake_toolkit(root, ["jadx"])
    launcher = root / "bin" / "jadx.bat"
    launcher.write_text('@echo off\r\n"C:\\X\\bin\\jadx.exe" %*\r\n', encoding="utf-8", newline="")

    # Passing the toolkit's own location as --rewrite-from must not churn files.
    report = toolchain.prepare(root, rewrite_from=str(root))
    assert report["rewritten_files"] == 0
    assert report["rewrite_backup_dir"] is None


def test_load_save_toolchain_roundtrip(tmp_path):
    cfg = {"toolkit_root": "E:/TOOLKIT", "bin_dir": "C:/Users/x/.dftk/bin"}
    p = toolchain.save_toolchain(cfg, base=tmp_path)
    assert p.is_file()
    assert toolchain.load_toolchain(base=tmp_path) == cfg
