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

from __future__ import annotations
from pathlib import Path
import sqlite3
from dftk.core.registry import registry
from dftk.core.models import Observation,Evidence,Status,SafetyLevel
from dftk.core.helpers import sha256_file

@registry.tool(name="database.sqlite_inventory",description="Open SQLite in read-only URI mode and report objects, schemas and optional row counts.",safety=SafetyLevel.READ_ONLY,
 parameters={"type":"object","properties":{"path":{"type":"string"},"count_rows":{"type":"boolean","default":True},"table_limit":{"type":"integer","default":500}},"required":["path"]})
def sqlite_inventory(path:str,count_rows:bool=True,table_limit:int=500)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation("database.sqlite_inventory",Status.ERROR,"SQLite file not found",errors=[str(p)])
    uri=f"file:{p.resolve().as_posix()}?mode=ro&immutable=1"
    try:
        con=sqlite3.connect(uri,uri=True); con.execute('PRAGMA query_only=ON')
        rows=con.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE type IN ('table','view','index','trigger') ORDER BY type,name LIMIT ?",(table_limit,)).fetchall()
        objects=[]; ev=[]
        for typ,name,tbl,sql in rows:
            row={"type":typ,"name":name,"table":tbl,"sql":sql}
            if count_rows and typ=='table' and not name.startswith('sqlite_'):
                try: row['row_count']=con.execute(f'SELECT COUNT(*) FROM "{name.replace(chr(34),chr(34)*2)}"').fetchone()[0]
                except sqlite3.DatabaseError as e: row['row_count_error']=str(e)
            objects.append(row); ev.append(Evidence(str(p),'sqlite_schema',sql or name,locator=f"sqlite_master:{typ}:{name}"))
        qc=con.execute('PRAGMA quick_check').fetchone()[0]
        con.close()
    except sqlite3.DatabaseError as e:
        return Observation("database.sqlite_inventory",Status.UNSUPPORTED,"SQLite parsing failed",errors=[str(e)],meta={"source_sha256":sha256_file(p)})
    return Observation("database.sqlite_inventory",Status.OK,f"SQLite inventory complete: {len(objects)} object(s)",facts={"quick_check":qc,"objects":objects},evidence=ev[:300],meta={"source_sha256":sha256_file(p)})

@registry.tool(name='database.sqlite_query',description='Execute one bounded read-only SELECT/WITH query against SQLite with SQLite authorizer write operations denied.',
 safety=SafetyLevel.READ_ONLY,tags=('database','sqlite','query'),produces=('query_rows',),
 parameters={'type':'object','properties':{'path':{'type':'string'},'sql':{'type':'string'},'params':{'type':'array','default':[]},'limit':{'type':'integer','default':1000}},'required':['path','sql']})
def sqlite_query(path:str,sql:str,params:list|None=None,limit:int=1000)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('database.sqlite_query',Status.ERROR,'SQLite file not found',errors=[str(p)])
    stripped=sql.strip().rstrip(';').strip()
    if ';' in stripped: return Observation('database.sqlite_query',Status.BLOCKED,'Only one SQL statement is allowed',errors=['multiple statements are not permitted'])
    first=stripped.split(None,1)[0].lower() if stripped else ''
    if first not in ('select','with'): return Observation('database.sqlite_query',Status.BLOCKED,'Only SELECT/WITH statements are allowed',errors=[f'first token: {first or "<empty>"}'])
    uri=f"file:{p.resolve().as_posix()}?mode=ro&immutable=1"
    allowed={sqlite3.SQLITE_SELECT,sqlite3.SQLITE_READ,sqlite3.SQLITE_FUNCTION}
    if hasattr(sqlite3,'SQLITE_RECURSIVE'): allowed.add(sqlite3.SQLITE_RECURSIVE)
    def auth(action,arg1,arg2,db,trigger):
        return sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY
    try:
        con=sqlite3.connect(uri,uri=True); con.execute('PRAGMA query_only=ON'); con.set_authorizer(auth)
        cur=con.execute(stripped,params or []); cols=[d[0] for d in cur.description or []]
        rows=[]
        for row in cur.fetchmany(limit+1):
            rows.append([x.hex() if isinstance(x,bytes) else x for x in row])
        con.close()
    except sqlite3.DatabaseError as e:
        return Observation('database.sqlite_query',Status.ERROR,'Read-only SQLite query failed',errors=[str(e)],meta={'source_sha256':sha256_file(p)})
    truncated=len(rows)>limit
    if truncated: rows=rows[:limit]
    return Observation('database.sqlite_query',Status.OK,f'Returned {len(rows)} row(s)',facts={'columns':cols,'rows':rows,'row_count':len(rows)},evidence=[Evidence(str(p),'sqlite_query',stripped,locator='read-only connection',method='SQLite authorizer')],warnings=[f'rows limited to {limit}'] if truncated else [],meta={'source_sha256':sha256_file(p)})

import re

_CREATE_RX=re.compile(r'(?is)\bCREATE\s+(?:TEMP(?:ORARY)?\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?P<name>`[^`]+`|"[^"]+"|\[[^\]]+\]|[A-Za-z_][\w.$-]*)\s*\(')
_INSERT_RX=re.compile(r'(?is)^\s*INSERT\s+INTO\s+(?P<name>`[^`]+`|"[^"]+"|\[[^\]]+\]|[A-Za-z_][\w.$-]*)')
_USE_RX=re.compile(r'(?is)^\s*USE\s+(?P<name>`[^`]+`|[A-Za-z_][\w.$-]*)')

def _sql_ident(name:str)->str:
    if len(name)>=2 and ((name[0]==name[-1]=='`') or (name[0]==name[-1]=='"') or (name[0]=='[' and name[-1]==']')): return name[1:-1]
    return name

@registry.tool(name='database.sql_dump_inventory',description='Inventory generic SQL text dumps (MySQL/PostgreSQL/SQLite-style) for databases, CREATE TABLE statements and INSERT counts without importing the dump.',
 safety=SafetyLevel.READ_ONLY,tags=('database','sql_dump','triage'),produces=('sql_schema','table_activity'),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'max_bytes':{'type':'integer','default':268435456},'statement_limit':{'type':'integer','default':200000}},'required':['path']})
def sql_dump_inventory(path:str,max_bytes:int=256*1024*1024,statement_limit:int=200000)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('database.sql_dump_inventory',Status.ERROR,'SQL dump not found',errors=[str(p)])
    tables={}; databases=[]; inserts={}; scanned=0; statements=0; buf=''; warnings=[]
    try:
        with p.open('rb') as f:
            while scanned<max_bytes and statements<statement_limit:
                raw=f.readline()
                if not raw: break
                scanned+=len(raw)
                line=raw.decode('utf-8','replace')
                if not buf and line.lstrip().startswith(('--','#')): continue
                buf+=line
                # Process complete-ish statements at semicolon boundaries. This is intentionally a schema/activity inventory, not a full SQL parser.
                while ';' in buf and statements<statement_limit:
                    stmt,buf=buf.split(';',1); statements+=1
                    text=stmt.strip()
                    if not text: continue
                    m=_USE_RX.match(text)
                    if m:
                        name=_sql_ident(m.group('name'))
                        if name not in databases: databases.append(name)
                    m=_CREATE_RX.search(text)
                    if m:
                        name=_sql_ident(m.group('name')); tables.setdefault(name,{'create_statement':(text+';')[:20000],'insert_statements':0})
                    m=_INSERT_RX.match(text)
                    if m:
                        name=_sql_ident(m.group('name')); inserts[name]=inserts.get(name,0)+1; tables.setdefault(name,{'create_statement':None,'insert_statements':0})['insert_statements']=inserts[name]
                if scanned>=max_bytes: break
    except OSError as e:
        return Observation('database.sql_dump_inventory',Status.ERROR,'SQL dump read failed',errors=[str(e)],meta={'source_sha256':sha256_file(p)})
    if scanned>=max_bytes and p.stat().st_size>scanned: warnings.append(f'input scan limited to {max_bytes} bytes')
    if statements>=statement_limit: warnings.append(f'statement parsing limited to {statement_limit}')
    rows=[{'table':name,**v} for name,v in sorted(tables.items())]
    ev=[Evidence(str(p),'sql_table',r['table'],locator='SQL text',method='bounded SQL statement inventory') for r in rows[:300]]
    return Observation('database.sql_dump_inventory',Status.OK,f'Found {len(rows)} table name(s) across {statements} SQL statement(s)',facts={'databases':databases,'tables':rows,'bytes_scanned':scanned,'statements_scanned':statements},evidence=ev,warnings=warnings,meta={'source_sha256':sha256_file(p)})

@registry.tool(name='database.sqlite_search',description='Search bounded SQLite tables/columns for a literal value using immutable read-only access; avoids requiring the Agent to construct schema-specific SQL first.',
 safety=SafetyLevel.READ_ONLY,tags=('database','sqlite','search'),produces=('database_matches',),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'query':{'type':'string'},'case_sensitive':{'type':'boolean','default':False},'table_limit':{'type':'integer','default':200},'column_limit':{'type':'integer','default':2000},'result_limit':{'type':'integer','default':1000}},'required':['path','query']})
def sqlite_search(path:str,query:str,case_sensitive:bool=False,table_limit:int=200,column_limit:int=2000,result_limit:int=1000)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('database.sqlite_search',Status.ERROR,'SQLite file not found',errors=[str(p)])
    uri=f"file:{p.resolve().as_posix()}?mode=ro&immutable=1"; hits=[]; warnings=[]; scanned_cols=0
    try:
        con=sqlite3.connect(uri,uri=True); con.execute('PRAGMA query_only=ON')
        tables=[r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT ?",(table_limit,))]
        for table in tables:
            tq='"'+table.replace('"','""')+'"'
            try: info=con.execute(f'PRAGMA table_info({tq})').fetchall()
            except sqlite3.DatabaseError as e: warnings.append(f'{table}: table_info failed: {e}'); continue
            for col in info:
                if scanned_cols>=column_limit or len(hits)>=result_limit: break
                name=col[1]; cq='"'+name.replace('"','""')+'"'; scanned_cols+=1
                expr=f'instr(CAST({cq} AS TEXT), ?) > 0' if case_sensitive else f'instr(lower(CAST({cq} AS TEXT)), lower(?)) > 0'
                remaining=result_limit-len(hits)
                try:
                    try:
                        rows=con.execute(f'SELECT rowid,{cq} FROM {tq} WHERE {expr} LIMIT ?',(query,remaining)).fetchall(); has_rowid=True
                    except sqlite3.DatabaseError:
                        rows=con.execute(f'SELECT {cq} FROM {tq} WHERE {expr} LIMIT ?',(query,remaining)).fetchall(); has_rowid=False
                    for row in rows:
                        rid=row[0] if has_rowid else None; value=row[1] if has_rowid else row[0]
                        if isinstance(value,bytes): value={'bytes_hex':value[:256].hex(),'length':len(value)}
                        hits.append({'table':table,'column':name,'rowid':rid,'value':value})
                except sqlite3.DatabaseError as e: warnings.append(f'{table}.{name}: search failed: {e}')
            if scanned_cols>=column_limit or len(hits)>=result_limit: break
        con.close()
    except sqlite3.DatabaseError as e:
        return Observation('database.sqlite_search',Status.UNSUPPORTED,'SQLite search failed',errors=[str(e)],meta={'source_sha256':sha256_file(p)})
    if scanned_cols>=column_limit: warnings.append(f'column scan limited to {column_limit}')
    if len(hits)>=result_limit: warnings.append(f'results limited to {result_limit}')
    ev=[Evidence(str(p),'sqlite_match',h['value'],locator=f"table:{h['table']};column:{h['column']};rowid:{h['rowid']}",method='read-only SQLite literal search') for h in hits[:300]]
    return Observation('database.sqlite_search',Status.PARTIAL if warnings else Status.OK,f'Found {len(hits)} SQLite match(es)',facts={'query':query,'matches':hits,'tables_scanned':len(tables),'columns_scanned':scanned_cols},evidence=ev,warnings=warnings,meta={'source_sha256':sha256_file(p)})
