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
import hashlib
import sqlite3
from dftk.core.registry import registry
from dftk.core.models import Observation,Evidence,Status,SafetyLevel
from dftk.core.helpers import sha256_file, read_file_bounded, sqlite_immutable_warnings
from dftk.core.sqlite_forensic import (
    parse_sqlite_header, parse_wal, reconstruct_logical_pages, walk_table_leaves,
    parse_schema, recover_deleted, PAGE_TYPE_NAMES, read_varint,
)


def _load_bytes(path: str, max_bytes: int = 256 * 1024 * 1024) -> bytes:
    """Read an evidence file fully, bounded. Returns bytes."""
    data, err = read_file_bounded(path, max_bytes)
    if err:
        raise ValueError(f"forensic read failed: {err}")
    return data


def _json_records(value):
    if isinstance(value, bytes):
        return {"type": "blob", "hex": value.hex(), "length": len(value)}
    if isinstance(value, list):
        return [_json_records(item) for item in value]
    if isinstance(value, dict):
        return {key: _json_records(item) for key, item in value.items()}
    return value


def _supported_recovery_tables(schema, pages):
    supported, unsupported = [], []
    for table in schema:
        page = pages.get(table["rootpage"], b"")
        offset = 100 if table["rootpage"] == 1 else 0
        if len(page) <= offset or page[offset] not in (5, 13):
            unsupported.append({"table": table["name"], "reason": "not an available rowid table B-tree (WITHOUT ROWID, virtual, missing, or damaged root)"})
        else:
            supported.append(table)
    return supported, unsupported

@registry.tool(name="database.sqlite_inventory",description="Open SQLite in read-only URI mode and report objects, schemas and optional row counts.",safety=SafetyLevel.READ_ONLY,
 parameters={"type":"object","properties":{"path":{"type":"string"},"count_rows":{"type":"boolean","default":True},"table_limit":{"type":"integer","default":500}},"required":["path"]})
def sqlite_inventory(path:str,count_rows:bool=True,table_limit:int=500)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation("database.sqlite_inventory",Status.ERROR,"SQLite file not found",errors=[str(p)])
    uri=p.resolve().as_uri() + "?mode=ro&immutable=1"
    con = None
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
    finally:
        if con is not None:
            con.close()
    warnings = sqlite_immutable_warnings(p)
    if qc != "ok": warnings.append(f"SQLite quick_check: {qc}")
    if any("row_count_error" in obj for obj in objects): warnings.append("some table counts failed; inspect row_count_error")
    if len(objects) >= table_limit: warnings.append(f"schema inventory limited to {table_limit} objects")
    return Observation("database.sqlite_inventory",Status.PARTIAL if warnings else Status.OK,f"SQLite inventory complete: {len(objects)} object(s)",facts={"quick_check":qc,"objects":objects},evidence=ev[:300],warnings=warnings,meta={"source_sha256":sha256_file(p)})

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
    uri=p.resolve().as_uri() + "?mode=ro&immutable=1"
    allowed={sqlite3.SQLITE_SELECT,sqlite3.SQLITE_READ,sqlite3.SQLITE_FUNCTION}
    if hasattr(sqlite3,'SQLITE_RECURSIVE'): allowed.add(sqlite3.SQLITE_RECURSIVE)
    def auth(action,arg1,arg2,db,trigger):
        return sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY
    con = None
    try:
        con=sqlite3.connect(uri,uri=True); con.execute('PRAGMA query_only=ON'); con.set_authorizer(auth)
        cur=con.execute(stripped,params or []); cols=[d[0] for d in cur.description or []]
        rows=[]
        for row in cur.fetchmany(limit+1):
            rows.append([x.hex() if isinstance(x,bytes) else x for x in row])
        con.close()
    except sqlite3.DatabaseError as e:
        return Observation('database.sqlite_query',Status.ERROR,'Read-only SQLite query failed',errors=[str(e)],meta={'source_sha256':sha256_file(p)})
    finally:
        if con is not None:
            con.close()
    truncated=len(rows)>limit
    if truncated: rows=rows[:limit]
    warnings = sqlite_immutable_warnings(p) + ([f'rows limited to {limit}'] if truncated else [])
    return Observation('database.sqlite_query',Status.PARTIAL if warnings else Status.OK,f'Returned {len(rows)} row(s)',facts={'columns':cols,'rows':rows,'row_count':len(rows)},evidence=[Evidence(str(p),'sqlite_query',stripped,locator='read-only connection',method='SQLite authorizer')],warnings=warnings,meta={'source_sha256':sha256_file(p)})

import re

_CREATE_RX=re.compile(r'(?is)\bCREATE\s+(?:TEMP(?:ORARY)?\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?P<name>`[^`]+`|"[^"]+"|\[[^\]]+\]|[A-Za-z_][\w.$-]*)\s*\(')
_INSERT_RX=re.compile(r'(?is)^\s*INSERT\s+INTO\s+(?P<name>`[^`]+`|"[^"]+"|\[[^\]]+\]|[A-Za-z_][\w.$-]*)')
_USE_RX=re.compile(r'(?is)^\s*USE\s+(?P<name>`[^`]+`|[A-Za-z_][\w.$-]*)')

def _sql_ident(name:str)->str:
    if len(name)>=2 and ((name[0]==name[-1]=='`') or (name[0]==name[-1]=='"') or (name[0]=='[' and name[-1]==']')): return name[1:-1]
    return name

@registry.tool(name='database.sql_dump_inventory',description='Inventory generic SQL text dumps (MySQL/PostgreSQL/SQLite-style) for databases, CREATE TABLE statements and INSERT counts without importing the dump.',
 safety=SafetyLevel.READ_ONLY,tags=('database','sql_dump','triage'),produces=('sql_schema','table_activity'),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'max_bytes':{'type':'integer','default':268435456},'statement_limit':{'type':'integer','default':200000},'max_line_bytes':{'type':'integer','default':1048576}},'required':['path']})
def sql_dump_inventory(path:str,max_bytes:int=256*1024*1024,statement_limit:int=200000,max_line_bytes:int=1024*1024)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('database.sql_dump_inventory',Status.ERROR,'SQL dump not found',errors=[str(p)])
    if max_bytes <= 0 or statement_limit <= 0 or max_line_bytes <= 0:
        return Observation('database.sql_dump_inventory',Status.ERROR,'SQL dump limits must be positive')
    tables={}; databases=[]; inserts={}; scanned=0; statements=0; buf=''; warnings=[]; line_limited=False
    try:
        with p.open('rb') as f:
            while scanned<max_bytes and statements<statement_limit:
                raw=f.readline(max_line_bytes+1)
                if not raw: break
                scanned+=len(raw)
                if len(raw)>max_line_bytes:
                    line_limited=True
                    warnings.append(f'line exceeded {max_line_bytes} bytes; parsing stopped before the remaining line content')
                    break
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
    status=Status.PARTIAL if warnings or line_limited else Status.OK
    return Observation('database.sql_dump_inventory',status,f'Found {len(rows)} table name(s) across {statements} SQL statement(s)',facts={'databases':databases,'tables':rows,'bytes_scanned':scanned,'statements_scanned':statements},evidence=ev,warnings=warnings,meta={'source_sha256':sha256_file(p)})

@registry.tool(name='database.sqlite_search',description='Search bounded SQLite tables/columns for a literal value using immutable read-only access; avoids requiring the Agent to construct schema-specific SQL first.',
 safety=SafetyLevel.READ_ONLY,tags=('database','sqlite','search'),produces=('database_matches',),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'query':{'type':'string'},'case_sensitive':{'type':'boolean','default':False},'table_limit':{'type':'integer','default':200},'column_limit':{'type':'integer','default':2000},'result_limit':{'type':'integer','default':1000}},'required':['path','query']})
def sqlite_search(path:str,query:str,case_sensitive:bool=False,table_limit:int=200,column_limit:int=2000,result_limit:int=1000)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('database.sqlite_search',Status.ERROR,'SQLite file not found',errors=[str(p)])
    uri=p.resolve().as_uri() + "?mode=ro&immutable=1"; hits=[]; warnings=sqlite_immutable_warnings(p); scanned_cols=0
    con = None
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
    finally:
        if con is not None:
            con.close()
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
    try: wb=_load_bytes(str(wp))
    except (OSError,ValueError) as exc:
        return Observation('database.sqlite_wal',Status.ERROR,'WAL read failed',errors=[str(exc)])
    digest=hashlib.sha256(wb).hexdigest()
    try: wal=parse_wal(wb)
    except ValueError as exc:
        return Observation('database.sqlite_wal',Status.UNSUPPORTED,'Not a supported WAL file',errors=[str(exc)],meta={'source_sha256':digest})
    valid=wal['valid_frames']; committed=wal['committed_frame_count']
    warnings=[]
    if not wal['header']['header_checksum_valid']: warnings.append('WAL header checksum is invalid')
    if valid < wal['frame_count']: warnings.append('WAL validation chain failed; frames at/after the first failure are not current evidence')
    if wal['trailing_bytes']: warnings.append('truncated WAL tail was not parsed')
    if valid > committed: warnings.append('valid but uncommitted WAL tail is excluded from the current snapshot')
    if wal['frame_count']>300: warnings.append('frame evidence limited to 300; summary counts cover the bounded input')
    facts={'header':wal['header'],'frame_count':wal['frame_count'],'valid_frames':valid,
           'committed_frames':sum(1 for f in wal['frames'] if f['commit'] and f['valid']),
           'committed_frame_count':committed,'last_commit_index':wal['last_commit_index'],
           'trailing_bytes':wal['trailing_bytes']}
    if db_path: facts['db_sha256']=sha256_file(Path(db_path))
    ev=[Evidence(str(wp),'wal_frame',f['page_number'],locator=f"frame:{f['index']}",
                 state='LIVE' if f['valid'] and f['index']<committed else 'PARTIAL',
                 note='committed snapshot frame' if f['valid'] and f['index']<committed else 'uncommitted or invalid frame')
        for f in wal['frames'][:300]]
    return Observation('database.sqlite_wal',Status.PARTIAL if warnings or not valid else Status.OK,
                       f'Parsed {wal["frame_count"]} WAL frame(s), {valid} valid',facts=facts,evidence=ev,warnings=warnings,meta={'source_sha256':digest})

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
 parameters={'type':'object','properties':{'path':{'type':'string'},'max_bytes':{'type':'integer','default':268435456},'limit_per_table':{'type':'integer','default':200,'minimum':1,'maximum':10000}},'required':['path'],'x-path-roles':{'path':'EVIDENCE_INPUT'}})
def sqlite_deleted_records(path:str,max_bytes:int=256*1024*1024,limit_per_table:int=200)->Observation:
    try: data=_load_bytes(path,max_bytes)
    except (OSError,ValueError) as e: return Observation('database.sqlite_deleted_records',Status.ERROR,'Cannot read SQLite evidence',errors=[str(e)])
    try: hdr=parse_sqlite_header(data)
    except ValueError as e: return Observation('database.sqlite_deleted_records',Status.UNSUPPORTED,'Not a SQLite database',errors=[str(e)],meta={'source_sha256':sha256_file(path)})
    page_size=hdr['page_size']; reserved=hdr['reserved_bytes_per_page']; enc=hdr['text_encoding']
    num_pages=len(data)//page_size
    pages={pn:data[(pn-1)*page_size:pn*page_size] for pn in range(1,num_pages+1)}
    schema=parse_schema(pages,page_size,reserved,enc)
    schema,unsupported_tables=_supported_recovery_tables(schema,pages)
    recovered=_json_records(recover_deleted(pages,schema,page_size,reserved,enc,limit_per_table))
    total=sum(len(r['recovered']) for r in recovered)
    candidates=sum(1 for r in recovered for c in r['recovered'] if c['state']=='DELETED_CANDIDATE')
    ev=[Evidence(str(path),'sqlite_deleted_record',c['columns'],locator=f"table:{r['table']};page:{c['page']};offset:{c['offset']}",state=c['state'],method='byte carving (no sqlite3)') for r in recovered for c in r['recovered'][:200]]
    return Observation('database.sqlite_deleted_records',Status.PARTIAL if total else Status.OK,f'Recovered {total} deleted/carved record(s) ({candidates} candidate(s))',facts={'tables':len(schema),'unsupported_tables':unsupported_tables,'per_table':[{'table':r['table'],'live_rows':r['live_rows'],'recovered':len(r['recovered'])} for r in recovered],'samples':[{'table':r['table'],'records':r['recovered'][:20]} for r in recovered]},evidence=ev,warnings=['Carved records are heuristic; not all are genuine deleted rows.']+([f'{len(unsupported_tables)} unsupported table(s) excluded from recovery'] if unsupported_tables else []),meta={'source_sha256':sha256_file(path)})

@registry.tool(name='database.sqlite_recover',description='Reconstruct only the last committed valid WAL snapshot; return bounded live storage records, heuristic deleted candidates, WAL diagnostics, and unsupported-table coverage. Source DB/WAL remain unchanged.',safety=SafetyLevel.READ_ONLY,tags=('database','sqlite','recovery','wal'),produces=('recovered_records'),
 parameters={'type':'object','properties':{'path':{'type':'string'},'wal_path':{'type':'string'},'max_bytes':{'type':'integer','default':268435456},'limit_per_table':{'type':'integer','default':200,'minimum':1,'maximum':10000}},'required':['path'],'x-path-roles':{'path':'EVIDENCE_INPUT'}})
def sqlite_recover(path:str,wal_path:str='',max_bytes:int=256*1024*1024,limit_per_table:int=200)->Observation:
    try: data=_load_bytes(path,max_bytes)
    except (OSError,ValueError) as e: return Observation('database.sqlite_recover',Status.ERROR,'Cannot read SQLite evidence',errors=[str(e)])
    try: hdr=parse_sqlite_header(data)
    except ValueError as e: return Observation('database.sqlite_recover',Status.UNSUPPORTED,'Not a SQLite database',errors=[str(e)],meta={'source_sha256':sha256_file(path)})
    page_size=hdr['page_size']; reserved=hdr['reserved_bytes_per_page']; enc=hdr['text_encoding']
    wal_bytes=None
    wp=Path(wal_path) if wal_path else Path(path+'-wal')
    warnings=[]
    if wal_path or wp.exists() or wp.is_symlink():
        if not wal_path and wp.is_symlink():
            warnings.append('automatic WAL sidecar is a symlink; not read. Supply an authorized explicit wal_path instead')
        else:
            try: wal_bytes=_load_bytes(str(wp),max_bytes)
            except (OSError,ValueError) as exc:
                return Observation('database.sqlite_recover',Status.ERROR,'Cannot read requested SQLite WAL',errors=[str(exc)])
    diagnostics={}
    pages=reconstruct_logical_pages(data,wal_bytes,page_size,diagnostics=diagnostics)
    warnings.extend(diagnostics['warnings'])
    schema=parse_schema(pages,page_size,reserved,enc)
    schema,unsupported_tables=_supported_recovery_tables(schema,pages)
    recovered=_json_records(recover_deleted(pages,schema,page_size,reserved,enc,limit_per_table))
    live_total=sum(r['live_rows'] for r in recovered)
    del_total=sum(len(r['recovered']) for r in recovered)
    db_digest=hashlib.sha256(data).hexdigest()
    wal_digest=hashlib.sha256(wal_bytes).hexdigest() if wal_bytes is not None else ''
    facts={'wal_applied':diagnostics['applied_frames']>0,'wal_applied_frames':diagnostics['applied_frames'],
           'wal_diagnostics':{key:value for key,value in diagnostics.items() if key!='page_sources'},
           'tables':[{'table':r['table'],'live_rows':r['live_rows'],'recovered':len(r['recovered'])} for r in recovered],
           'live_total':live_total,'recovered_total':del_total,
           'samples':[{'table':r['table'],'records':r['recovered'][:20]} for r in recovered],
           'live_samples':[{'table':r['table'],'records':r['live_records']} for r in recovered],
           'unsupported_tables':unsupported_tables,'live_total_scope':'supported rowid-table B-trees only'}
    ev=[]
    for result in recovered:
        for record in result['live_records'] + result['recovered'][:200]:
            wal_ref=diagnostics['page_sources'].get(record['page'])
            locator=f"table:{result['table']};page:{record['page']};"+(f"offset:{record['offset']}" if 'offset' in record else f"rowid:{record['rowid']}")
            if wal_ref: locator=f"frame:{wal_ref['frame_index']};"+locator
            ev.append(Evidence(str(wp) if wal_ref else str(path),'sqlite_live_record' if record['state']=='LIVE' else 'sqlite_recovered',record['columns'],
                               source_sha256=wal_digest if wal_ref else db_digest,
                               locator=locator,state=record['state'],method='committed WAL overlay + carving',
                               note='record start page attribution; database and WAL hashes identify reconstruction inputs'))
    if unsupported_tables: warnings.append(f'{len(unsupported_tables)} unsupported table(s) excluded; counts do not cover them')
    if any(r['live_rows']>len(r['live_records']) for r in recovered):
        warnings.append(f'live record samples limited to {limit_per_table} per table; live_total counts all decoded supported rows')
    warnings.append('Carved records are heuristic; a zero result does not prove deleted data is absent. Recovery samples show at most 20 candidates per table.')
    if any(len(r['recovered'])>=limit_per_table for r in recovered):
        warnings.append(f'recovery candidate limit reached ({limit_per_table} per table)')
    return Observation('database.sqlite_recover',Status.PARTIAL,
                       f'Recovered: {live_total} live + {del_total} deleted/carved record(s)',
                       facts=facts,evidence=ev,warnings=warnings,
                       meta={'source_sha256':db_digest,'wal_sha256':wal_digest,'wal_path':str(wp) if wal_bytes is not None else ''})
