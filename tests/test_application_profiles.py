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

"""Tests for the Application Profile architecture."""

from __future__ import annotations

import sqlite3

from dftk.core.registry import registry
from dftk.primitives import application_profiles as ap
from dftk.profiles import get_profile_registry


def _make_msg_db(path) -> None:
    conn = sqlite3.connect(str(path))
    conn.execute(
        "CREATE TABLE messages (id INTEGER PRIMARY KEY, thread_id INTEGER, "
        "address TEXT, body TEXT, date INTEGER)"
    )
    conn.execute(
        "INSERT INTO messages (thread_id, address, body, date) VALUES "
        "(1, '+15550001', 'hello world', 1588593600000), "
        "(1, '+15550002', 'second message', 1588593700000)"
    )
    conn.commit()
    conn.close()


def test_demo_profile_registered():
    ids = [p.id for p in get_profile_registry().all()]
    assert "android.generic_messaging" in ids


def test_profile_list_tool():
    out = registry.run("application.profile_list", {})
    assert out.status.value == "ok"
    assert out.facts["profile_count"] >= 1
    assert any(p["id"] == "android.generic_messaging" for p in out.facts["profiles"])


def test_profile_apply_autodetect(tmp_path):
    db = tmp_path / "msg.db"
    _make_msg_db(db)
    out = registry.run("application.profile_apply", {"path": str(db)})
    assert out.facts.get("matched") is True, out.warnings
    assert out.facts["record_count"] == 2
    recs = out.facts["records"]
    bodies = {r["body"] for r in recs}
    assert "hello world" in bodies
    # epoch-ms converted to ISO
    ts = [r["timestamp"] for r in recs]
    assert all(t and t.startswith("2020-05-04") for t in ts), ts


def test_profile_apply_explicit(tmp_path):
    db = tmp_path / "msg.db"
    _make_msg_db(db)
    out = registry.run("application.profile_apply",
                       {"path": str(db), "profile_id": "android.generic_messaging"})
    assert out.facts["profile"]["id"] == "android.generic_messaging"
    assert out.facts["record_count"] == 2


def test_profile_unknown_id(tmp_path):
    db = tmp_path / "msg.db"
    _make_msg_db(db)
    out = registry.run("application.profile_apply", {"path": str(db), "profile_id": "nope"})
    assert out.status.value == "partial"


def test_no_profile_matches(tmp_path):
    db = tmp_path / "other.db"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE foo (a INTEGER)")
    conn.commit()
    conn.close()
    out = registry.run("application.profile_apply", {"path": str(db)})
    assert out.facts.get("matched") is False
    assert any("profile matched" in w.lower() for w in out.warnings), out.warnings


def test_unknown_profile_id_reports_available(tmp_path):
    db = tmp_path / "msg.db"
    _make_msg_db(db)
    out = ap.profile_apply(str(db), "does.not.exist")
    assert out.status.value == "partial"
    assert "does.not.exist" in out.summary
    assert any("available" in w for w in out.warnings)
