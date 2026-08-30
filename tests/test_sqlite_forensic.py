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

import shutil
import sqlite3
import tempfile
from pathlib import Path

from dftk import get_registry
from dftk.core.registry import registry
from dftk.core.sqlite_forensic import read_varint, parse_record

get_registry()  # ensure built-ins (database.sqlite_*) are registered


def _make_db(path: Path, *, wal: bool = False) -> Path | None:
    con = sqlite3.connect(str(path))
    if wal:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA wal_autocheckpoint=0")
    con.execute("CREATE TABLE chat(id INTEGER PRIMARY KEY, who TEXT, msg TEXT)")
    rows = [(i, f"user{i}", f"hello world number {i}") for i in range(1, 11)]
    con.executemany("INSERT INTO chat(id,who,msg) VALUES(?,?,?)", rows)
    con.commit()
    # Delete three rows WITHOUT vacuuming so their cell bytes persist.
    con.execute("DELETE FROM chat WHERE id IN (3,4,5)")
    con.commit()
    wal_copy = None
    if wal:
        wp = Path(str(path) + "-wal")
        wal_copy = path.parent / (path.name + ".walcopy")
        shutil.copy(wp, wal_copy)
    con.close()
    return wal_copy


def test_varint_and_record_roundtrip():
    v, n = read_varint(b"\x7f", 0)
    assert v == 127 and n == 1
    v, n = read_varint(b"\x81\x01", 0)
    assert v == 129 and n == 2
    # Record: header_len=3, serial [23 (text len5), 53 (text len20)], body = "user3"+"hello..."
    rec = bytes([3, 23, 53]) + b"user3" + b"hello world number 3"
    cols = parse_record(rec, 1)
    assert cols == ["user3", "hello world number 3"], cols


def test_forensic_inventory_and_pages(tmp_path: Path):
    db = tmp_path / "chat.db"
    _make_db(db)
    obs = registry.run("database.sqlite_forensic_inventory", {"path": str(db)})
    assert obs.status.value == "ok", obs.summary
    assert obs.facts["header"]["magic"] == "SQLite format 3"
    assert obs.facts["header"]["page_size"] in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)
    assert "leaf_table" in obs.facts["page_distribution"]

    obs2 = registry.run("database.sqlite_pages", {"path": str(db)})
    assert obs2.status.value == "ok"
    assert any(p["type"] == "leaf_table" for p in obs2.facts["pages"])


def test_freelist_reports(tmp_path: Path):
    db = tmp_path / "chat.db"
    _make_db(db)
    obs = registry.run("database.sqlite_freelist", {"path": str(db)})
    assert obs.status.value == "ok"
    assert "freelist_total" in obs.facts


def test_deleted_records_recovered(tmp_path: Path):
    db = tmp_path / "chat.db"
    _make_db(db)
    obs = registry.run("database.sqlite_deleted_records", {"path": str(db)})
    assert obs.status.value in ("ok", "partial"), obs.summary
    # 7 live rows remain; 3 were deleted and should be recoverable.
    # NOTE: id is INTEGER PRIMARY KEY (rowid alias) so records have 2 columns.
    per = {r["table"]: r["recovered"] for r in obs.facts["per_table"]}
    total = per.get("chat", 0)
    samples = {r["table"]: r["records"] for r in obs.facts["samples"]}
    candidates = sum(1 for c in samples.get("chat", []) if c["state"] == "DELETED_CANDIDATE")
    assert total >= 3, f"expected >=3 recovered, got {total}"
    assert candidates >= 3, f"expected >=3 deleted candidates, got {candidates}"
    recovered_cols = [tuple(c["columns"]) for c in samples.get("chat", [])]
    assert ("user3", "hello world number 3") in recovered_cols, \
        "deleted row not found among recovered records"


def test_wal_parses_and_recover_runs(tmp_path: Path):
    db = tmp_path / "chat.db"
    wal_copy = _make_db(db, wal=True)
    assert wal_copy is not None and wal_copy.is_file()
    obs = registry.run("database.sqlite_wal", {"wal_path": str(wal_copy)})
    assert obs.status.value in ("ok", "partial"), obs.summary
    assert obs.facts["frame_count"] >= 1
    assert obs.facts["valid_frames"] >= 1

    obs2 = registry.run("database.sqlite_recover", {"path": str(db), "wal_path": str(wal_copy)})
    assert obs2.status.value in ("ok", "partial"), obs2.summary
    assert "live_total" in obs2.facts


# --- regression: 48/64-bit integer serial types ------------------------------ #

def test_serial_type_5_and_6_are_six_and_eight_bytes():
    """SQLite serial types 5 and 6 are 6- and 8-byte integers, not 5 and 6.

    Mis-sizing them corrupts live record decoding *and* makes freeblock-clobbered
    records fail the exact-fit check, so larger deleted rows were silently never
    recovered at all.
    """
    from dftk.core.sqlite_forensic import serial_content_size, serial_type_value

    assert serial_content_size(5) == 6
    assert serial_content_size(6) == 8
    assert serial_content_size(4) == 4   # unchanged neighbours
    assert serial_content_size(7) == 8

    assert serial_type_value(5, (1234567890123).to_bytes(6, "big", signed=True), 0, 1) == 1234567890123
    assert serial_type_value(6, (1588593600000).to_bytes(8, "big", signed=True), 0, 1) == 1588593600000


def test_live_rows_with_wide_integers_decode_correctly(tmp_path: Path):
    """A 6/8-byte integer column must not shift the columns that follow it."""
    db = tmp_path / "wide.db"
    con = sqlite3.connect(str(db))
    con.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, ts INTEGER, who TEXT, msg TEXT)")
    con.executemany("INSERT INTO t(id,ts,who,msg) VALUES(?,?,?,?)",
                    [(1, 1588593600000, "alice", "first message"),
                     (2, 1588593700000, "bob", "second message")])
    con.commit()
    con.close()

    obs = registry.run("database.sqlite_query", {"path": str(db), "sql": "SELECT * FROM t"})
    assert obs.status.value in ("ok", "partial"), obs.summary
    rows = obs.facts.get("rows") or []
    assert [r[0] for r in rows] == [1, 2]
    assert rows[0][1] == 1588593600000      # 8-byte integer survived
    assert rows[0][3] == "first message"    # and did not shift the text columns


def test_deleted_wide_row_is_recovered(tmp_path: Path):
    """Larger deleted rows must be recovered, not silently skipped."""
    db = tmp_path / "del.db"
    con = sqlite3.connect(str(db))
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, thread_id INTEGER, "
                "address TEXT, body TEXT, date INTEGER)")
    con.executemany("INSERT INTO t VALUES(?,?,?,?,?)",
                    [(1, 1, "+15550001", "meet me at the usual place", 1588593600000),
                     (2, 1, "+15550002", "DELETED: wire transfer confirmed", 1588593700000),
                     (3, 1, "+15550001", "ok, moving to another channel", 1588593800000)])
    con.commit()
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    con.execute("DELETE FROM t WHERE id=2")
    con.commit()
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")   # residue lands in the DB page
    con.close()

    obs = registry.run("database.sqlite_deleted_records", {"path": str(db)})
    assert obs.status.value in ("ok", "partial"), obs.summary
    recovered = sum(t["recovered"] for t in obs.facts.get("per_table", []))
    assert recovered >= 1, obs.facts.get("per_table")
    texts = " ".join(str(c) for s in obs.facts.get("samples", [])
                     for r in s["records"] for c in r["columns"])
    assert "wire transfer confirmed" in texts
