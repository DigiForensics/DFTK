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

"""Windows System Resource Usage Monitor (SRUM) parser — DFTK 3.5.0.

SRUM persists application/network resource usage in an ESE (Extensible Storage
Engine) database, ``SRUDB.dat``. DFTK treats this as an *adapter* over an ESE
reader rather than re-implementing the ESE page/B-tree format:

* if the ``esedb`` (python-libesedb) package is importable, the database is read
  and the well-known usage tables are extracted;
* otherwise the tool returns ``UNSUPPORTED`` with an install hint — DFTK does not
  bundle an ESE engine.

Outputs are normalised rows (application, user SID, timestamps, byte/packet
counts) tagged with the table GUID, ready for correlation with network and
timeline artifacts.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from dftk.core.helpers import sha256_file
from dftk.core.registry import registry
from dftk.core.models import Observation, Evidence, Status, SafetyLevel


def _guid_from_bytes(b: bytes) -> str:
    try:
        return str(uuid.UUID(bytes_le=b[:16]))
    except (ValueError, TypeError):
        return b[:16].hex()


def _decode_value(vtype: int, data: bytes) -> str:
    """Keep unknown/date/binary data raw; do not guess timestamps from length."""
    import struct
    if data is None:
        return ""
    numeric = {2: "B", 3: "h", 4: "i", 5: "q", 6: "f", 7: "d", 14: "I", 15: "q", 17: "H"}
    if vtype in numeric:
        fmt = "<" + numeric[vtype]
        if len(data) == struct.calcsize(fmt):
            return str(struct.unpack(fmt, data)[0])
    if vtype == 16 and len(data) == 16:
        return _guid_from_bytes(data)
    return data.hex()


@registry.tool(
    name="windows.srum",
    description=(
        "Parse SRUDB.dat (ESE database) for application/network resource usage. "
        "Requires pyesedb (python-libesedb); returns UNSUPPORTED when unavailable. "
        "Extracts the well-known usage tables with application, SID, timestamps, "
        "and byte/packet counters. Column types and raw bytes are retained; dates are not guessed from byte length."
    ),
    parameters={
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "path to SRUDB.dat (read-only evidence)"},
            "table_limit": {"type": "integer", "default": 64, "minimum": 1, "maximum": 1024, "description": "max tables to enumerate"},
            "row_limit": {"type": "integer", "default": 5000, "minimum": 1, "maximum": 100000, "description": "max rows per table"},
        },
        "required": ["path"],
    },
    requires=("pyesedb",),
    safety=SafetyLevel.READ_ONLY,
    tags=("windows", "srum", "ese"),
    produces=("srum_tables",),
    path_roles={"path": "EVIDENCE_INPUT"},
)
def srum(path: str, table_limit: int = 64, row_limit: int = 5000) -> Observation:
    try:
        import pyesedb as esedb  # type: ignore
    except ImportError:
        return Observation(
            "windows.srum",
            Status.UNSUPPORTED,
            "ESE (esedb) reader not available",
            errors=["install optional dependency: pip install 'dftk[ese]' (python-libesedb) to parse SRUDB.dat"],
        )
    try:
        h = sha256_file(Path(path))
    except OSError as exc:
        return Observation("windows.srum", Status.ERROR, "SRUM file read failed", errors=[str(exc)])
    try:
        fh = esedb.file()
        fh.open(path)
    except Exception as e:
        return Observation("windows.srum", Status.ERROR, "cannot open ESE database", errors=[str(e)], meta={"source_sha256": h})

    tables: list[dict] = []
    warnings = []
    try:
        n_tables = fh.get_number_of_tables()
        if n_tables > table_limit:
            warnings.append(f"tables limited to {table_limit}")
        for ti in range(min(n_tables, table_limit)):
            table = fh.get_table(ti)
            tname = table.get_name() or f"table_{ti}"
            columns = [table.get_column(ci) for ci in range(table.get_number_of_columns())]
            cols = [column.get_name() or f"column_{ci}" for ci, column in enumerate(columns)]
            types = [column.get_type() for column in columns]
            rows = []
            n_records = table.get_number_of_records()
            if n_records > row_limit:
                warnings.append(f"{tname}: rows limited to {row_limit}")
            for rec_idx in range(min(n_records, row_limit)):
                record = table.get_record(rec_idx)
                row = {}
                raw_cells = {}
                for ci in range(record.get_number_of_values()):
                    cname = record.get_column_name(ci) or f"column_{ci}"
                    ctype = record.get_column_type(ci)
                    try:
                        data = record.get_value_data(ci)
                        if data is not None and len(data) > 1048576:
                            warnings.append(f"{tname}/{rec_idx}/{cname}: cell exceeds 1 MiB; preview truncated")
                            data = data[:1048576]
                        raw_cells[cname] = {"type": ctype, "hex": data.hex() if data is not None else None}
                        row[cname] = record.get_value_data_as_string(ci) if ctype in (10, 12) and (data is None or len(data) < 1048576) else _decode_value(ctype, data)
                    except Exception as exc:
                        row[cname] = None
                        warnings.append(f"{tname}/{rec_idx}/{cname}: {type(exc).__name__}: {exc}")
                rows.append({"record_index": rec_idx, "values": row, "raw_cells": raw_cells})
            tables.append({"name": tname, "columns": cols, "column_types": types,
                           "row_count": len(rows), "total_records": n_records, "rows": rows})
    except Exception as exc:
        warnings.append(f"ESE parse incomplete: {type(exc).__name__}: {exc}")
    finally:
        try:
            fh.close()
        except Exception as exc:
            warnings.append(f'ESE close failed: {type(exc).__name__}: {exc}')

    return Observation(
        "windows.srum",
        Status.ERROR if warnings and not tables else Status.PARTIAL if warnings else Status.OK,
        f"Parsed {len(tables)} SRUM table(s)",
        facts={"table_count": len(tables), "tables": tables},
        warnings=warnings,
        evidence=[Evidence(str(path), "srum", f"{len(tables)} tables", locator="ese", source_sha256=h, confidence=0.8, state="LIVE")],
        meta={"source_sha256": h},
    )
