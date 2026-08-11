import sqlite3
from dftk.primitives.android import appdata_inventory


def test_android_appdata_inventory(tmp_path):
    root=tmp_path/'com.example'; (root/'shared_prefs').mkdir(parents=True); (root/'databases').mkdir()
    (root/'shared_prefs/settings.xml').write_text('<map><string name="server">https://api.example</string><boolean name="enabled" value="true" /></map>',encoding='utf-8')
    db=root/'databases/app.db'; con=sqlite3.connect(db); con.execute('create table t(x)'); con.commit(); con.close()
    obs=appdata_inventory(str(root)); assert obs.facts['shared_preferences'][0]['entries']['server']['value']=='https://api.example'; assert len(obs.facts['database_candidates'])==1
