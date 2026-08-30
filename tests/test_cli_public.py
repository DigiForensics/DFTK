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

import json

import pytest

from dftk import __version__
from dftk.cli import main


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"dftk {__version__}"


def test_run_positional_path(capsys, tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"DFTK positional shortcut test\n")
    rc = main(["run", "file.hash", str(f)])
    out = capsys.readouterr().out
    assert rc == 0
    assert '"status": "ok"' in out
    assert '"sha256"' in out


def test_run_explicit_params_still_works(capsys, tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"explicit params blob\n")
    rc = main(["run", "file.hash", "--params", f'{{"path": "{f}"}}'])
    out = capsys.readouterr().out
    assert rc == 0
    assert '"status": "ok"' in out


def test_run_report_one_click(capsys, tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"report one-click\n")
    rdir = tmp_path / "report"
    rc = main(["run", "file.hash", str(f), "--report", str(rdir)])
    out = capsys.readouterr().out
    assert rc == 0
    report = rdir / "dftk_report.html"
    assert report.exists(), "HTML report should be written"
    assert "Report written to" in out
    # report is a self-contained HTML document
    assert "<html" in report.read_text(encoding="utf-8", errors="ignore").lower()


def test_list_grouped(capsys):
    rc = main(["list", "--group"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert "groups" in data
    assert isinstance(data["groups"], dict)
    assert len(data["groups"]) > 0
