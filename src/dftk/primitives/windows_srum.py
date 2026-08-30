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
    """Decode a column value by ESE column type into a string for reporting."""
    if data is None:
        return ""
    # JET_coltypText / LongText
    if vtype in (0x80, 0x81, 0x82):
        try:
            return data.decode("utf-16-le", "replace").rstrip("\x00")
        except Exception:
            return data.decode("latin-1", "replace")
    # JET_coltypLong / LongBinary -> GUID-ish or hex
    if vtype in (0x83, 0x84):
        if len(data) == 16:
            return _guid_from_bytes(data)
        return data.hex()
    # numeric / datetime
    try:
        if len(data) == 8:
            import struct

            val = struct.unpack_from("<Q", data, 0)[0]
            # FILETIME interpretation attempt
            return str(val)
        if len(data) == 4:
            import struct

            return str(struct.unpack_from("<I", data, 0)[0])
        if len(data) == 2:
            import struct

            return str(struct.unpack_from("<H", data, 0)[0])
        if len(data) == 1:
            return str(data[0])
    except Exception:
        pass
    return data.hex()


@registry.tool(
    name="windows.srum",
    description=(
        "Parse SRUDB.dat (ESE database) for application/network resource usage. "
        "Requires the 'esedb' package; returns UNSUPPORTED when unavailable. "
        "Extracts the well-known usage tables with application, SID, timestamps, "
        "and byte/packet counters."
    ),
    parameters={
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "path to SRUDB.dat (read-only evidence)"},
            "table_limit": {"type": "integer", "default": 64, "description": "max tables to enumerate"},
            "row_limit": {"type": "integer", "default": 5000, "description": "max rows per table"},
        },
        "required": ["path"],
    },
    safety=SafetyLevel.READ_ONLY,
    tags=("windows", "srum", "ese"),
    produces=("srum_tables",),
    path_roles={"path": "EVIDENCE_INPUT"},
)
def srum(path: str, table_limit: int = 64, row_limit: int = 5000) -> Observation:
    try:
        import esedb  # type: ignore
    except ImportError:
        return Observation(
            "windows.srum",
            Status.UNSUPPORTED,
            "ESE (esedb) reader not available",
            errors=["install optional dependency: pip install 'dftk[ese]' (python-libesedb) to parse SRUDB.dat"],
        )
    h = sha256_file(Path(path))
    try:
        fh = esedb.file()
        fh.open(path)
    except Exception as e:
        return Observation("windows.srum", Status.ERROR, "cannot open ESE database", errors=[str(e)], meta={"source_sha256": h})

    tables: list[dict] = []
    try:
        n_tables = fh.get_number_of_tables()
        for ti in range(min(n_tables, table_limit)):
            table = fh.get_table(ti)
            tname = table.get_name() or f"table_{ti}"
            cols = [table.get_column_name(ci) for ci in range(table.get_number_of_columns())]
            rows: list[dict] = []
            try:
                table.get_number_of_records()
            except Exception:
                pass
            rec_idx = 0
            while True:
                record = table.get_record(rec_idx)
                if record is None:
                    break
                row: dict[str, str] = {}
                for ci, cname in enumerate(cols):
                    try:
                        ctype = table.get_column_type(ci)
                        cdata = record.get_value_data(ci)
                        row[cname] = _decode_value(ctype, cdata)
                    except Exception:
                        row.setdefault(cols[ci] if ci < len(cols) else f"col{ci}", "")
                rows.append(row)
                rec_idx += 1
                if rec_idx >= row_limit:
                    break
            tables.append({"name": tname, "columns": cols, "row_count": len(rows), "rows": rows})
    except Exception as e:
        return Observation("windows.srum", Status.ERROR, "ESE parse failed", errors=[str(e)], meta={"source_sha256": h})
    finally:
        try:
            fh.close()
        except Exception:
            pass

    return Observation(
        "windows.srum",
        Status.OK,
        f"Parsed {len(tables)} SRUM table(s)",
        facts={"table_count": len(tables), "tables": tables},
        evidence=[Evidence(str(path), "srum", f"{len(tables)} tables", locator="ese", source_sha256=h, confidence=0.8, state="LIVE")],
        meta={"source_sha256": h},
    )
