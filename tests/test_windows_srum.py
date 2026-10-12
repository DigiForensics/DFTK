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

"""Tests for the SRUM (ESE) adapter — graceful degradation when esedb is absent."""

from __future__ import annotations

from dftk.core.registry import registry


def test_srum_registered():
    assert registry.get("windows.srum") is not None


def test_srum_unsupported_without_esedb(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "pyesedb", None)
    # python-libesedb is not installed in this environment.
    obs = registry.run("windows.srum", {"path": "/no/such/SRUDB.dat"})
    assert obs.status.value == "unsupported"
    assert any("esedb" in e or "libesedb" in e.lower() for e in obs.errors + obs.warnings)


def test_srum_uses_pyesedb_column_api_and_reports_truncation(tmp_path, monkeypatch):
    import sys
    import struct
    from types import SimpleNamespace
    from dftk.primitives.windows_srum import srum, _decode_value
    class Column:
        def get_name(self):return 'counter'
        def get_type(self):return 4
    class Record:
        def get_number_of_values(self):return 1
        def get_column_name(self,index):return 'counter'
        def get_column_type(self,index):return 4
        def get_value_data(self, index):return struct.pack('<i', -7)
    class Table:
        def get_name(self):return 'Usage'
        def get_number_of_columns(self):return 1
        def get_column(self,index):return Column()
        def get_number_of_records(self):return 2
        def get_record(self,index):
            assert index < 2
            return Record()
    class Reader:
        closed=False
        def open(self,path):pass
        def get_number_of_tables(self):return 1
        def get_table(self,index):return Table()
        def close(self):self.closed=True
    reader=Reader()
    monkeypatch.setitem(sys.modules,'pyesedb',SimpleNamespace(file=lambda:reader))
    source=tmp_path/'SRUDB.dat';source.write_bytes(b'synthetic ESE binding input')
    obs=srum(str(source),row_limit=1)
    assert obs.status.value=='partial'
    table=obs.facts['tables'][0]
    assert table['total_records']==2
    assert table['rows'][0]['values']['counter']=='-7'
    assert table['rows'][0]['raw_cells']['counter']['type']==4
    assert reader.closed
    assert _decode_value(8,struct.pack('<d',45000.0))==struct.pack('<d',45000.0).hex()
