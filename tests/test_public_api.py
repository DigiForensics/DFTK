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

import sqlite3

import dftk


def test_public_registry_and_run_tool(tmp_path):
    reg=dftk.get_registry()
    # Phase 2 registered SQLite forensic (database.sqlite_*) + filesystem.*,
    # Phase 3 added pure-Python Registry (windows.registry_tree /
    # windows.registry_deleted_keys), 3.5.0 Network Forensics 2.0 added the
    # flow / reassembly / session layer, Windows USN Journal (windows.usnjrnl)
    # plus deep binary forensics (binary.pe_* / binary.elf_dynamic), and the
    # remaining depth work: the Volatility 3 adapter (memory.*), Windows Amcache /
    # Shimcache / SRUM, the HTML report layer (case.report_html), the Application
    # Profile architecture (application.profile_*), and audit verification
    # (case.verify).
    # The full registry (primitives + recipes) is 113 tools.
    assert len(reg.specs()) == 113
    assert reg.get('artifact.inspect').safety.name == 'READ_ONLY'

    db=tmp_path/'public-api.db'
    con=sqlite3.connect(db)
    con.execute('create table demo(id integer, note text)')
    con.execute("insert into demo values(1,'needle-value')")
    con.commit(); con.close()

    obs=dftk.run_tool('database.sqlite_search', {'path':str(db),'query':'needle'})
    assert obs.status.value == 'ok'
    assert obs.evidence
