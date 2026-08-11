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
from pathlib import Path
from dftk.primitives.database import sqlite_inventory

def test_sqlite_readonly_inventory(tmp_path):
    p=tmp_path/'x.db'; con=sqlite3.connect(p); con.execute('create table t(id integer, name text)'); con.executemany('insert into t values(?,?)',[(1,'a'),(2,'b')]); con.commit(); con.close()
    before=set(tmp_path.iterdir()); obs=sqlite_inventory(str(p)); after=set(tmp_path.iterdir())
    assert obs.status.value=='ok'; assert any(x['name']=='t' and x.get('row_count')==2 for x in obs.facts['objects'])
    assert before==after
