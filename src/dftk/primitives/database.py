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
from dftk.core.sqlite_forensic import (
    parse_sqlite_header, parse_wal, reconstruct_logical_pages, walk_table_leaves,
    parse_schema, recover_deleted, PAGE_TYPE_NAMES, read_varint,
)


def _load_bytes(path: str, max_bytes: int = 256 * 1024 * 1024) -> bytes:
    """Read an evidence file fully, bounded. Returns bytes."""
    p = Path(path)
    size = p.stat().st_size
    if size > max_bytes:
        raise ValueError(f"file too large for forensic load: {size} > {max_bytes}")
    return p.read_bytes()

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
                try: row['row_count']=con.execute(f'SELECT COUNT(*) FROM "{name.replace(chr(34), chr(34)*2)}"').fetchone()[0]
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
                if line.lstrip().startswith(('--','#')): continue
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

# --------------------------------------------------------------------------- #
# DFTK 3.5.0 — SQLite forensic depth (own bounded parser, no sqlite3 reliance)
# --------------------------------------------------------------------------- #

@registry.tool(name='database.sqlite_forensic_inventory',description='Forensic inventory of a SQLite database: 100-byte header fields (page size, change counter, freelist, schema cookie, autovacuum, encoding, page count) plus a page-type distribution. Uses a direct byte parser, not the SQLite engine.',safety=SafetyLevel.READ_ONLY,tags=('database','sqlite','forensic'),produces=('sqlite_header','page_distribution'),
 parameters={'type':'object','properties':{'path':{'type':'string'},'max_bytes':{'type':'integer','default':268435456}},'required':['path'],'x-path-roles':{'path':'EVIDENCE_INPUT'}})
def sqlite_forensic_inventory(path:str,max_bytes:int=256*1024*1024)->Observation:
    try: data=_load_bytes(path,max_bytes)
    except (OSError,ValueError) as e: return Observation('database.sqlite_forensic_inventory',Status.ERROR,'Cannot read SQLite evidence',errors=[str(e)])
    try: hdr=parse_sqlite_header(data)
    except ValueError as e: return Observation('database.sqlite_forensic_inventory',Status.UNSUPPORTED,'Not a SQLite database',errors=[str(e)],meta={'source_sha256':sha256_file(path)})
    page_size=hdr['page_size']; num_pages=len(data)//page_size
    in_hdr=hdr['in_header_db_size_pages']
    dist:dict[str,int]={}
    for pn in range(1,num_pages+1):
        start=(pn-1)*page_size; pt=data[start] if start<len(data) else 0
        dist[PAGE_TYPE_NAMES.get(pt, f'type_{pt}')]=dist.get(PAGE_TYPE_NAMES.get(pt, f'type_{pt}'),0)+1
    facts={'header':hdr,'page_size':page_size,'page_count_file':num_pages,'page_count_header':in_hdr,
           'page_distribution':dist,'freelist_total_header':hdr['total_freelist_pages'],
           'wal_present':Path(path+'-wal').is_file()}
    ev=[Evidence(str(path),'sqlite_header',page_size,locator='byte 0..100',note='direct byte parse')]
    return Observation('database.sqlite_forensic_inventory',Status.OK,'SQLite forensic inventory complete',facts=facts,evidence=ev,meta={'source_sha256':sha256_file(path)})

@registry.tool(name='database.sqlite_pages',description='Enumerate every page in a SQLite database with its type, cell count, freeblock and fragmented-byte metadata. Low-level structural map.',safety=SafetyLevel.READ_ONLY,tags=('database','sqlite','forensic'),produces=('page_map'),
 parameters={'type':'object','properties':{'path':{'type':'string'},'max_bytes':{'type':'integer','default':268435456},'page_limit':{'type':'integer','default':100000}},'required':['path'],'x-path-roles':{'path':'EVIDENCE_INPUT'}})
def sqlite_pages(path:str,max_bytes:int=256*1024*1024,page_limit:int=100000)->Observation:
    try: data=_load_bytes(path,max_bytes)
    except (OSError,ValueError) as e: return Observation('database.sqlite_pages',Status.ERROR,'Cannot read SQLite evidence',errors=[str(e)])
    try: hdr=parse_sqlite_header(data)
    except ValueError as e: return Observation('database.sqlite_pages',Status.UNSUPPORTED,'Not a SQLite database',errors=[str(e)],meta={'source_sha256':sha256_file(path)})
    page_size=hdr['page_size']; num_pages=len(data)//page_size; pages=[]
    for pn in range(1,min(num_pages,page_limit)+1):
        start=(pn-1)*page_size; page=data[start:start+page_size]
        if len(page)<8: continue
        ptype=page[0]; name=PAGE_TYPE_NAMES.get(ptype,f'type_{ptype}')
        num_cells=int.from_bytes(page[3:5],'big')
        frag=int(page[7]) if ptype in (10,13) else 0
        first_fb=int.from_bytes(page[1:3],'big') if ptype in (10,13) else 0
        pages.append({'page':pn,'type':name,'cells':num_cells,'freeblocks':first_fb,'fragmented_bytes':frag})
    return Observation('database.sqlite_pages',Status.OK,f'Mapped {len(pages)} page(s)',facts={'page_size':page_size,'page_count':num_pages,'pages':pages},meta={'source_sha256':sha256_file(path)})

@registry.tool(name='database.sqlite_wal',description='Parse a SQLite WAL (-wal) file: header (magic, salts, checksums), and every frame with page number, commit flag, salt match and native-order checksum validity.',safety=SafetyLevel.READ_ONLY,tags=('database','sqlite','wal'),produces=('wal_frames'),
 parameters={'type':'object','properties':{'wal_path':{'type':'string'},'db_path':{'type':'string'}},'required':['wal_path']})
def sqlite_wal(wal_path:str,db_path:str='')->Observation:
    wp=Path(wal_path)
    if not wp.is_file(): return Observation('database.sqlite_wal',Status.ERROR,'WAL file not found',errors=[str(wp)])
    try: wb=wp.read_bytes()
    except OSError as e: return Observation('database.sqlite_wal',Status.ERROR,'WAL read failed',errors=[str(e)])
    try: wal=parse_wal(wb)
    except ValueError as e: return Observation('database.sqlite_wal',Status.UNSUPPORTED,'Not a WAL file',errors=[str(e)],meta={'source_sha256':sha256_file(wp)})
    valid=sum(1 for f in wal['frames'] if f['valid'])
    facts={'header':wal['header'],'frame_count':wal['frame_count'],'valid_frames':valid,
           'committed_frames':sum(1 for f in wal['frames'] if f['commit'])}
    if db_path: facts['db_sha256']=sha256_file(Path(db_path))
    ev=[Evidence(str(wp),'wal_frame',f['page_number'],locator=f"frame:{f['index']}",state='LIVE' if f['valid'] else 'PARTIAL') for f in wal['frames'][:300]]
    return Observation('database.sqlite_wal',Status.OK if valid else Status.PARTIAL,f'Parsed {wal["frame_count"]} WAL frame(s), {valid} valid',facts=facts,evidence=ev,meta={'source_sha256':sha256_file(wp)})

@registry.tool(name='database.sqlite_freelist',description='Enumerate the SQLite freelist: the trunk chain and every freelist leaf page, comparing against the header total. Freelist pages hold dropped table/record data.',safety=SafetyLevel.READ_ONLY,tags=('database','sqlite','freelist'),produces=('freelist'),
 parameters={'type':'object','properties':{'path':{'type':'string'},'max_bytes':{'type':'integer','default':268435456}},'required':['path'],'x-path-roles':{'path':'EVIDENCE_INPUT'}})
def sqlite_freelist(path:str,max_bytes:int=256*1024*1024)->Observation:
    try: data=_load_bytes(path,max_bytes)
    except (OSError,ValueError) as e: return Observation('database.sqlite_freelist',Status.ERROR,'Cannot read SQLite evidence',errors=[str(e)])
    try: hdr=parse_sqlite_header(data)
    except ValueError as e: return Observation('database.sqlite_freelist',Status.UNSUPPORTED,'Not a SQLite database',errors=[str(e)],meta={'source_sha256':sha256_file(path)})
    page_size=hdr['page_size']; num_pages=len(data)//page_size
    pages={pn:data[(pn-1)*page_size:pn*page_size] for pn in range(1,num_pages+1)}
    # Walk trunk chain.
    trunk=int.from_bytes(pages.get(1,b'\x00'*100)[32:36],'big')
    leaf_pages=[]; trunk_pages=[]; seen=set(); guard=0
    while trunk and trunk in pages and trunk not in seen and guard<100000:
        seen.add(trunk); trunk_pages.append(trunk)
        t=pages[trunk]; n_leaf=int.from_bytes(t[4:8],'big')
        for i in range(n_leaf):
            off=8+i*4
            if off+4>len(t): break
            leaf_pages.append(int.from_bytes(t[off:off+4],'big'))
        nxt=int.from_bytes(t[0:4],'big'); trunk=nxt; guard+=1
    facts={'header_total_freelist':hdr['total_freelist_pages'],'freelist_trunk_pages':trunk_pages,
           'freelist_leaf_pages':leaf_pages,'freelist_total':len(trunk_pages)+len(leaf_pages)}
    return Observation('database.sqlite_freelist',Status.OK,f'Freelist: {len(trunk_pages)} trunk + {len(leaf_pages)} leaf page(s)',facts=facts,meta={'source_sha256':sha256_file(path)})

@registry.tool(name='database.sqlite_deleted_records',description='Carve deleted/candidate records from SQLite unallocated page space, freeblocks and freelist pages. Classifies each as DELETED_CANDIDATE (column count matches the live schema) or CARVED (record-shaped but unmatched).',safety=SafetyLevel.READ_ONLY,tags=('database','sqlite','recovery'),produces=('deleted_records'),
 parameters={'type':'object','properties':{'path':{'type':'string'},'max_bytes':{'type':'integer','default':268435456},'limit_per_table':{'type':'integer','default':200}},'required':['path'],'x-path-roles':{'path':'EVIDENCE_INPUT'}})
def sqlite_deleted_records(path:str,max_bytes:int=256*1024*1024,limit_per_table:int=200)->Observation:
    try: data=_load_bytes(path,max_bytes)
    except (OSError,ValueError) as e: return Observation('database.sqlite_deleted_records',Status.ERROR,'Cannot read SQLite evidence',errors=[str(e)])
    try: hdr=parse_sqlite_header(data)
    except ValueError as e: return Observation('database.sqlite_deleted_records',Status.UNSUPPORTED,'Not a SQLite database',errors=[str(e)],meta={'source_sha256':sha256_file(path)})
    page_size=hdr['page_size']; reserved=hdr['reserved_bytes_per_page']; enc=hdr['text_encoding']
    num_pages=len(data)//page_size
    pages={pn:data[(pn-1)*page_size:pn*page_size] for pn in range(1,num_pages+1)}
    schema=parse_schema(pages,page_size,reserved,enc)
    recovered=recover_deleted(pages,schema,page_size,reserved,enc,limit_per_table)
    total=sum(len(r['recovered']) for r in recovered)
    candidates=sum(1 for r in recovered for c in r['recovered'] if c['state']=='DELETED_CANDIDATE')
    ev=[Evidence(str(path),'sqlite_deleted_record',c['columns'],locator=f"table:{r['table']};page:{c['page']};offset:{c['offset']}",state=c['state'],method='byte carving (no sqlite3)') for r in recovered for c in r['recovered'][:200]]
    return Observation('database.sqlite_deleted_records',Status.PARTIAL if total else Status.OK,f'Recovered {total} deleted/carved record(s) ({candidates} candidate(s))',facts={'tables':len(schema),'per_table':[{'table':r['table'],'live_rows':r['live_rows'],'recovered':len(r['recovered'])} for r in recovered],'samples':[{'table':r['table'],'records':r['recovered'][:20]} for r in recovered]},evidence=ev,warnings=['Carved records are heuristic; not all are genuine deleted rows.'],meta={'source_sha256':sha256_file(path)})

@registry.tool(name='database.sqlite_recover',description='Reconstruct the logical current database by overlaying valid WAL frames onto DB pages, then recover live + deleted records across all tables. The deepest SQLite recovery path.',safety=SafetyLevel.READ_ONLY,tags=('database','sqlite','recovery','wal'),produces=('recovered_records'),
 parameters={'type':'object','properties':{'path':{'type':'string'},'wal_path':{'type':'string'},'max_bytes':{'type':'integer','default':268435456},'limit_per_table':{'type':'integer','default':200}},'required':['path'],'x-path-roles':{'path':'EVIDENCE_INPUT'}})
def sqlite_recover(path:str,wal_path:str='',max_bytes:int=256*1024*1024,limit_per_table:int=200)->Observation:
    try: data=_load_bytes(path,max_bytes)
    except (OSError,ValueError) as e: return Observation('database.sqlite_recover',Status.ERROR,'Cannot read SQLite evidence',errors=[str(e)])
    try: hdr=parse_sqlite_header(data)
    except ValueError as e: return Observation('database.sqlite_recover',Status.UNSUPPORTED,'Not a SQLite database',errors=[str(e)],meta={'source_sha256':sha256_file(path)})
    page_size=hdr['page_size']; reserved=hdr['reserved_bytes_per_page']; enc=hdr['text_encoding']
    wal_bytes=None
    if wal_path:
        wp=Path(wal_path)
        if wp.is_file(): wal_bytes=wp.read_bytes()
    elif Path(path+'-wal').is_file():
        wal_bytes=Path(path+'-wal').read_bytes()
    pages=reconstruct_logical_pages(data,wal_bytes,page_size)
    schema=parse_schema(pages,page_size,reserved,enc)
    recovered=recover_deleted(pages,schema,page_size,reserved,enc,limit_per_table)
    live_total=sum(r['live_rows'] for r in recovered)
    del_total=sum(len(r['recovered']) for r in recovered)
    facts={'wal_applied':wal_bytes is not None,'tables':[{'table':r['table'],'live_rows':r['live_rows'],'recovered':len(r['recovered'])} for r in recovered],
           'live_total':live_total,'recovered_total':del_total,
           'samples':[{'table':r['table'],'records':r['recovered'][:20]} for r in recovered]}
    ev=[Evidence(str(path),'sqlite_recovered',c['columns'],locator=f"table:{r['table']};page:{c['page']};offset:{c['offset']}",state=c['state'],method='WAL overlay + carving') for r in recovered for c in r['recovered'][:200]]
    return Observation('database.sqlite_recover',Status.PARTIAL if del_total else Status.OK,f'Recovered: {live_total} live + {del_total} deleted/carved record(s)',facts=facts,evidence=ev,warnings=['Carved records are heuristic.'],meta={'source_sha256':sha256_file(path),'wal_sha256':sha256_file(Path(wal_path)) if wal_path and Path(wal_path).is_file() else ''})
