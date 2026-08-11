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
from dftk.primitives.android import appdata_inventory


def test_android_appdata_inventory(tmp_path):
    root=tmp_path/'com.example'; (root/'shared_prefs').mkdir(parents=True); (root/'databases').mkdir()
    (root/'shared_prefs/settings.xml').write_text('<map><string name="server">https://api.example</string><boolean name="enabled" value="true" /></map>',encoding='utf-8')
    db=root/'databases/app.db'; con=sqlite3.connect(db); con.execute('create table t(x)'); con.commit(); con.close()
    obs=appdata_inventory(str(root)); assert obs.facts['shared_preferences'][0]['entries']['server']['value']=='https://api.example'; assert len(obs.facts['database_candidates'])==1
