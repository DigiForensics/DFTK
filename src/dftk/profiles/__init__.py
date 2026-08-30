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

"""Application Profile architecture — DFTK 3.5.0.

Rather than hard-coding one parser per messaging app (WeChat / QQ / WeCom /
DingTalk / Lark …), 3.5.0 introduces a **declarative** profile model. A profile
describes *how* an application stores its artifacts so one generic engine can
read many apps:

    detection conditions · database location · table structure · field mapping
    · time format · encoding · attachment relations

3.5.0 ships one validated demo profile (generic Android messaging) to prove the
model. 3.6 can then add the high-value Chinese IM apps as *data*, not as bespoke
parser code.
"""

from __future__ import annotations

import sqlite3
import urllib.parse
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class ArtifactProfile:
    """Declarative description of one application's on-disk artifacts."""

    id: str
    platform: str                      # android | windows | browser
    app_name: str
    description: str = ""
    db_globs: tuple[str, ...] = ()     # where the artifacts live (evidence-side)
    detect_tables: tuple[str, ...] = ()   # at least one must exist
    detect_columns: tuple[str, ...] = ()  # at least one must exist in that table
    table: str = ""                    # primary table to normalise
    field_map: dict[str, str] = field(default_factory=dict)   # canonical -> source column
    time_format: str = "epoch_ms"      # epoch_ms | epoch_s | iso | filetime
    time_fields: tuple[str, ...] = ()  # canonical field names holding a timestamp
    encoding: str = "utf-8"
    attachments: str = ""              # how attachments relate (free-form, honest)
    confidence: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for k in ("db_globs", "detect_tables", "detect_columns", "time_fields"):
            d[k] = list(d[k])
        return d


class ProfileRegistry:
    def __init__(self) -> None:
        self._by_id: dict[str, ArtifactProfile] = {}

    def register(self, profile: ArtifactProfile) -> None:
        if profile.id in self._by_id:
            raise ValueError(f"duplicate profile: {profile.id}")
        self._by_id[profile.id] = profile

    def all(self) -> list[ArtifactProfile]:
        return [self._by_id[k] for k in sorted(self._by_id)]

    def get(self, profile_id: str) -> ArtifactProfile | None:
        return self._by_id.get(profile_id)


_REGISTRY = ProfileRegistry()


def get_profile_registry() -> ProfileRegistry:
    return _REGISTRY


def _ro_connect(path: str) -> sqlite3.Connection:
    p = str(Path(path).resolve())
    uri = f"file:{urllib.parse.quote(p)}?mode=ro"
    return sqlite3.connect(uri, uri=True)


def _schema(conn: sqlite3.Connection) -> dict[str, list[str]]:
    """Return {table_name: [column_names]} for a SQLite database."""
    tables: dict[str, list[str]] = {}
    try:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table','view')"
        ).fetchall()
    except sqlite3.DatabaseError:
        return tables
    for (tname,) in rows:
        try:
            cols = [r[1] for r in conn.execute(f'PRAGMA table_info("{tname}")').fetchall()]
        except sqlite3.DatabaseError:
            cols = []
        tables[tname] = cols
    return tables


def match_profile(path: str) -> tuple[ArtifactProfile | None, dict[str, list[str]], list[str]]:
    """Auto-detect which registered profile matches ``path``.

    Returns ``(profile, schema, notes)``. Opens the database read-only.
    """
    notes: list[str] = []
    if not Path(path).exists():
        return None, {}, [f"database not found: {path}"]
    try:
        conn = _ro_connect(path)
    except sqlite3.Error as e:
        return None, {}, [f"cannot open database: {e}"]
    try:
        schema = _schema(conn)
    finally:
        conn.close()
    if not schema:
        return None, {}, ["no tables found (not a SQLite database?)"]
    best: ArtifactProfile | None = None
    for prof in _REGISTRY.all():
        for tname in prof.detect_tables:
            cols = schema.get(tname)
            if cols is None:
                continue
            if not prof.detect_columns or any(c in cols for c in prof.detect_columns):
                best = prof
                break
        if best is not None:
            break
    if best is None:
        notes.append("no registered profile matched the detected schema")
    return best, schema, notes


def _convert_time(value: Any, time_format: str) -> str | None:
    try:
        if value is None:
            return None
        if time_format == "epoch_ms":
            return datetime.fromtimestamp(int(value) / 1000, tz=timezone.utc).isoformat()
        if time_format == "epoch_s":
            return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat()
        if time_format == "filetime":
            return _ft(int(value))
        return str(value)
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _ft(v: int) -> str | None:
    from dftk.core.regf import filetime_to_iso

    return filetime_to_iso(v)


def extract_records(
    path: str,
    profile: ArtifactProfile,
    limit: int = 1000,
) -> tuple[list[dict], list[str]]:
    """Normalise rows from ``profile.table`` using the profile's field mapping."""
    warnings: list[str] = []
    try:
        conn = _ro_connect(path)
    except sqlite3.Error as e:
        return [], [f"cannot open database: {e}"]
    try:
        schema = _schema(conn)
        cols = schema.get(profile.table)
        if cols is None:
            return [], [f"table '{profile.table}' not present in database"]
        missing = [c for c in profile.field_map.values() if c not in cols]
        if missing:
            warnings.append(f"field(s) not present in table, left null: {missing}")
        selected = [c for c in profile.field_map.values() if c in cols]
        if not selected:
            return [], ["none of the mapped fields exist in the table"]
        order = {c: i for i, c in enumerate(cols)}
        selected.sort(key=lambda c: order[c])
        sql = f'SELECT {", ".join(f"[{c}]" for c in selected)} FROM "{profile.table}" LIMIT ?'
        rows = conn.execute(sql, (min(limit, 50000),)).fetchall()
    except sqlite3.DatabaseError as e:
        return [], [f"query failed: {e}"]
    finally:
        conn.close()

    out: list[dict] = []
    for row in rows:
        rec: dict[str, Any] = {"profile": profile.id}
        for canonical, col in profile.field_map.items():
            val = row[selected.index(col)] if col in selected else None
            if canonical in profile.time_fields:
                rec[canonical] = _convert_time(val, profile.time_format)
                rec[f"{canonical}_raw"] = val
            else:
                if isinstance(val, bytes):
                    try:
                        val = val.decode(profile.encoding, "replace")
                    except (LookupError, UnicodeDecodeError):
                        val = val.hex()
                rec[canonical] = val
        out.append(rec)
    return out, warnings


# Import bundled profiles for side effects (registration).
from . import android, windows, browser  # noqa: E402,F401
