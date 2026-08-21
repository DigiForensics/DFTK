# Copyright 2026 DyNooob @ DigiForensics
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
from pathlib import Path

import pytest

from dftk import doctor


_HOST_ENV_VARS = tuple(sorted({var for _, var, _ in doctor._HOST_MARKERS}))


def _clear_host_env(monkeypatch):
    for var in _HOST_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def _make_skill(base: Path, host: str) -> None:
    skill = base / doctor._AGENT_SKILL_DIRS[host] / "dftk"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("# dftk skill\n")


# --- ok derivation (was a hardcoded constant before this fix) ---

def test_ok_true_when_tools_loaded_and_mcp_absent():
    # Default environment: registry loads, mcp not installed -> ok True.
    report = doctor.doctor_report()
    assert report["ok"] is True


def test_ok_false_when_mcp_version_unsupported(monkeypatch):
    monkeypatch.setattr(
        doctor, "_dist_version", lambda name: "1.0.0" if name == "mcp" else None
    )
    assert doctor.doctor_report()["ok"] is False


def test_ok_true_when_mcp_version_supported(monkeypatch):
    monkeypatch.setattr(
        doctor, "_dist_version", lambda name: "2.1.0" if name == "mcp" else None
    )
    assert doctor.doctor_report()["ok"] is True


# --- warnings content ---

def test_warnings_includes_mcp_not_installed():
    codes = [w["code"] for w in doctor.doctor_report()["warnings"]]
    assert "mcp-not-installed" in codes


def test_warnings_include_optional_and_external_missing():
    codes = [w["code"] for w in doctor.doctor_report()["warnings"]]
    assert "optional-missing" in codes
    assert "external-missing" in codes


# --- skill_install self-check (prevents the host-misdetect bug from recurring) ---

def test_skill_install_detects_workbuddy_location(tmp_path, monkeypatch):
    _clear_host_env(monkeypatch)
    monkeypatch.setenv("WORKBUDDY_PRODUCT_NAME", "WorkBuddy")
    _make_skill(tmp_path, "workbuddy")
    status = doctor._skill_install_status(home=tmp_path)
    assert status["expected_host"] == "workbuddy"
    assert status["installed"] is True
    assert status["misplaced"] is False
    assert status["found_at"] == ["workbuddy"]


def test_skill_install_detects_misplaced(tmp_path, monkeypatch):
    _clear_host_env(monkeypatch)
    monkeypatch.setenv("WORKBUDDY_PRODUCT_NAME", "WorkBuddy")
    _make_skill(tmp_path, "agents")  # installed in the wrong host dir
    status = doctor._skill_install_status(home=tmp_path)
    assert status["expected_host"] == "workbuddy"
    assert status["installed"] is False
    assert status["misplaced"] is True
    assert status["found_at"] == ["agents"]


def test_skill_install_not_installed_anywhere(tmp_path, monkeypatch):
    _clear_host_env(monkeypatch)
    monkeypatch.setenv("WORKBUDDY_PRODUCT_NAME", "WorkBuddy")
    status = doctor._skill_install_status(home=tmp_path)
    assert status["expected_host"] == "workbuddy"
    assert status["installed"] is False
    assert status["misplaced"] is False
    assert status["found_at"] == []


def test_skill_misplaced_warning_in_report(tmp_path, monkeypatch):
    _clear_host_env(monkeypatch)
    monkeypatch.setenv("WORKBUDDY_PRODUCT_NAME", "WorkBuddy")
    # Isolate Path.home so doctor_report's skill check uses the fake home.
    monkeypatch.setattr(doctor.Path, "home", lambda: tmp_path)
    _make_skill(tmp_path, "agents")
    report = doctor.doctor_report()
    codes = [w["code"] for w in report["warnings"]]
    assert "skill-misplaced" in codes
