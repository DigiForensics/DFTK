import sqlite3
from pathlib import Path
from dftk.primitives.database import sqlite_inventory

def test_sqlite_readonly_inventory(tmp_path):
    p=tmp_path/'x.db'; con=sqlite3.connect(p); con.execute('create table t(id integer, name text)'); con.executemany('insert into t values(?,?)',[(1,'a'),(2,'b')]); con.commit(); con.close()
    before=set(tmp_path.iterdir()); obs=sqlite_inventory(str(p)); after=set(tmp_path.iterdir())
    assert obs.status.value=='ok'; assert any(x['name']=='t' and x.get('row_count')==2 for x in obs.facts['objects'])
    assert before==after
