import sqlite3

import dftk


def test_public_registry_and_run_tool(tmp_path):
    reg=dftk.get_registry()
    assert len(reg.specs()) == 66
    assert reg.get('artifact.inspect').safety.name == 'READ_ONLY'

    db=tmp_path/'public-api.db'
    con=sqlite3.connect(db)
    con.execute('create table demo(id integer, note text)')
    con.execute("insert into demo values(1,'needle-value')")
    con.commit(); con.close()

    obs=dftk.run_tool('database.sqlite_search', {'path':str(db),'query':'needle'})
    assert obs.status.value == 'ok'
    assert obs.evidence
