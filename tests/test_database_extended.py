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
from dftk.primitives.database import sqlite_query,sql_dump_inventory
from dftk.core.models import Status


def test_sqlite_query_read_only(tmp_path):
    p=tmp_path/'x.db'; con=sqlite3.connect(p); con.execute('create table users(id integer,name text)'); con.executemany('insert into users values(?,?)',[(1,'a'),(2,'b')]); con.commit(); con.close()
    obs=sqlite_query(str(p),'select name from users order by id')
    assert obs.status==Status.OK and obs.facts['rows']==[['a'],['b']]
    blocked=sqlite_query(str(p),'delete from users')
    assert blocked.status==Status.BLOCKED


def test_sql_dump_inventory(tmp_path):
    p=tmp_path/'dump.sql'; p.write_text('USE app;\nCREATE TABLE `users` (id INT, name TEXT);\nINSERT INTO `users` VALUES (1,"a");\nINSERT INTO `users` VALUES (2,"b");\nCREATE TABLE posts(id INT);\n',encoding='utf-8')
    obs=sql_dump_inventory(str(p)); tables={x['table']:x for x in obs.facts['tables']}
    assert obs.facts['databases']==['app']; assert tables['users']['insert_statements']==2; assert 'posts' in tables


def test_sql_dump_inventory_bounds_an_overlong_line(tmp_path):
    p=tmp_path/'long.sql'
    p.write_bytes(b'A' * 64 + b';\nCREATE TABLE later(id INT);\n')
    obs=sql_dump_inventory(str(p),max_line_bytes=32)
    assert obs.status==Status.PARTIAL
    assert obs.facts['tables']==[]
    assert 'line exceeded 32 bytes' in obs.warnings[0]

from dftk.primitives.database import sqlite_search

def test_sqlite_search_across_tables(tmp_path):
    p=tmp_path/'search.db'; con=sqlite3.connect(p); con.execute('create table users(name text,note text)'); con.execute('insert into users values(?,?)',('Qingyi','hello')); con.commit(); con.close()
    obs=sqlite_search(str(p),'qingyi')
    assert obs.facts['matches'][0]['table']=='users'; assert obs.facts['matches'][0]['column']=='name'
