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
from datetime import datetime,timezone
from dftk.primitives.browser import chromium_history,chromium_downloads,firefox_history


def test_chromium_history_and_downloads(tmp_path):
    p=tmp_path/'History'; con=sqlite3.connect(p)
    con.execute('create table urls(id integer primary key,url text,title text,visit_count integer,typed_count integer,last_visit_time integer)')
    con.execute('create table visits(id integer primary key,url integer,visit_time integer,from_visit integer,transition integer)')
    con.execute('create table downloads(id integer primary key,current_path text,target_path text,start_time integer,end_time integer,received_bytes integer,total_bytes integer,state integer)')
    con.execute('create table downloads_url_chains(id integer,chain_index integer,url text)')
    ts=13300000000000000
    con.execute('insert into urls values(1,?,?,?,?,?)',('https://example.com','Example',1,1,ts))
    con.execute('insert into visits values(1,1,?,0,0)',(ts,))
    con.execute('insert into downloads values(1,?,?,?,?,?,?,?)',('/tmp/a','/home/a',ts,ts+10,10,10,1))
    con.execute('insert into downloads_url_chains values(1,0,?)',('https://example.com/a',)); con.commit(); con.close()
    h=chromium_history(str(p)); assert h.facts['visits'][0]['url']=='https://example.com'
    d=chromium_downloads(str(p)); assert d.facts['downloads'][0]['url_chain']==['https://example.com/a']


def test_firefox_history(tmp_path):
    p=tmp_path/'places.sqlite'; con=sqlite3.connect(p)
    con.execute('create table moz_places(id integer primary key,url text,title text,visit_count integer)')
    con.execute('create table moz_historyvisits(id integer primary key,place_id integer,visit_date integer,from_visit integer,visit_type integer)')
    con.execute('insert into moz_places values(1,?,?,?)',('https://mozilla.org','Mozilla',1)); con.execute('insert into moz_historyvisits values(1,1,1700000000000000,0,1)'); con.commit(); con.close()
    obs=firefox_history(str(p)); assert obs.facts['visits'][0]['url']=='https://mozilla.org'

from dftk.primitives.browser import chromium_cookies

def test_chromium_cookie_inventory_redacts_value_by_default(tmp_path):
    p=tmp_path/'Cookies'; con=sqlite3.connect(p); con.execute('create table cookies(host_key text,name text,path text,expires_utc integer,is_secure integer,is_httponly integer,value text,encrypted_value blob)'); con.execute('insert into cookies values(?,?,?,?,?,?,?,?)',('.example.com','sid','/',13300000000000000,1,1,'plaintext',b'v10encrypted')); con.commit(); con.close()
    obs=chromium_cookies(str(p)); row=obs.facts['cookies'][0]
    assert row['host_key']=='.example.com'; assert 'value' not in row; assert row['value_present'] is True; assert row['encrypted_value_length']>0


def test_chromium_downloads_unsupported_result_keeps_source_hash(tmp_path):
    p=tmp_path/'History'; con=sqlite3.connect(p)
    con.execute('create table downloads(unrecognized_column text)'); con.commit(); con.close()
    obs=chromium_downloads(str(p))
    assert obs.status.value=='unsupported'
    assert obs.meta['source_sha256']
