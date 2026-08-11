from __future__ import annotations
from datetime import datetime,timezone,timedelta
from pathlib import Path
import sqlite3
from dftk.core.registry import registry
from dftk.core.models import Observation,Evidence,Status,SafetyLevel
from dftk.core.helpers import sha256_file

_CHROME_EPOCH=datetime(1601,1,1,tzinfo=timezone.utc)

def _chrome_time(v):
    try:
        n=int(v)
        if n<=0: return None
        return (_CHROME_EPOCH+timedelta(microseconds=n)).isoformat()
    except (TypeError,ValueError,OverflowError): return None

def _unix_micro_time(v):
    try:
        n=int(v)
        if n<=0: return None
        return datetime.fromtimestamp(n/1_000_000,tz=timezone.utc).isoformat()
    except (TypeError,ValueError,OverflowError,OSError): return None

def _open_ro(p:Path):
    con=sqlite3.connect(f"file:{p.resolve().as_posix()}?mode=ro&immutable=1",uri=True)
    con.execute('PRAGMA query_only=ON')
    return con

def _tables(con):
    return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}

@registry.tool(name='browser.chromium_history',description='Read Chromium/Chrome/Edge History SQLite visits and URLs in immutable read-only mode.',
 safety=SafetyLevel.READ_ONLY,tags=('browser','chromium','history','timeline'),produces=('browser_history','timeline'),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'limit':{'type':'integer','default':5000}},'required':['path']})
def chromium_history(path:str,limit:int=5000)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('browser.chromium_history',Status.ERROR,'History database not found',errors=[str(p)])
    try:
        con=_open_ro(p); tabs=_tables(con)
        if 'urls' not in tabs: con.close(); return Observation('browser.chromium_history',Status.UNSUPPORTED,'Chromium urls table not found',meta={'source_sha256':sha256_file(p)})
        rows=[]
        if 'visits' in tabs:
            sql='''SELECT v.id,u.url,u.title,u.visit_count,u.typed_count,v.visit_time,v.from_visit,v.transition FROM visits v JOIN urls u ON u.id=v.url ORDER BY v.visit_time DESC LIMIT ?'''
            for rid,url,title,vc,tc,vt,frm,tr in con.execute(sql,(limit,)):
                rows.append({'visit_id':rid,'url':url,'title':title,'visit_count':vc,'typed_count':tc,'visit_time':_chrome_time(vt),'visit_time_raw':vt,'from_visit':frm,'transition':tr})
        else:
            sql='SELECT id,url,title,visit_count,typed_count,last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT ?'
            for rid,url,title,vc,tc,vt in con.execute(sql,(limit,)):
                rows.append({'url_id':rid,'url':url,'title':title,'visit_count':vc,'typed_count':tc,'visit_time':_chrome_time(vt),'visit_time_raw':vt})
        con.close()
    except sqlite3.DatabaseError as e:
        return Observation('browser.chromium_history',Status.UNSUPPORTED,'Chromium History parsing failed',errors=[str(e)],meta={'source_sha256':sha256_file(p)})
    ev=[Evidence(str(p),'browser_visit',r['url'],locator=f"visit:{r.get('visit_id',r.get('url_id'))}",method='Chromium History SQLite') for r in rows[:300]]
    return Observation('browser.chromium_history',Status.OK,f'Recovered {len(rows)} Chromium history row(s)',facts={'visits':rows},evidence=ev,warnings=[f'results limited to {limit}'] if len(rows)>=limit else [],meta={'source_sha256':sha256_file(p)})

@registry.tool(name='browser.chromium_downloads',description='Read Chromium/Chrome/Edge download records and URL chains from History SQLite in immutable read-only mode.',
 safety=SafetyLevel.READ_ONLY,tags=('browser','chromium','downloads','timeline'),produces=('browser_downloads','timeline'),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'limit':{'type':'integer','default':5000}},'required':['path']})
def chromium_downloads(path:str,limit:int=5000)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('browser.chromium_downloads',Status.ERROR,'History database not found',errors=[str(p)])
    try:
        con=_open_ro(p); tabs=_tables(con)
        if 'downloads' not in tabs: con.close(); return Observation('browser.chromium_downloads',Status.UNSUPPORTED,'Chromium downloads table not found',meta={'source_sha256':sha256_file(p)})
        cols={r[1] for r in con.execute('PRAGMA table_info(downloads)')}
        wanted=['id','current_path','target_path','start_time','end_time','received_bytes','total_bytes','state','danger_type','interrupt_reason','tab_url','referrer','site_url','url']
        selected=[c for c in wanted if c in cols]
        if not selected: con.close(); return Observation('browser.chromium_downloads',Status.UNSUPPORTED,'No known Chromium download columns found')
        query='SELECT '+','.join('"'+c+'"' for c in selected)+' FROM downloads ORDER BY '+('start_time' if 'start_time' in selected else selected[0])+' DESC LIMIT ?'
        rows=[]
        chains={}
        if 'downloads_url_chains' in tabs:
            for did,idx,url in con.execute('SELECT id,chain_index,url FROM downloads_url_chains ORDER BY id,chain_index'):
                chains.setdefault(did,[]).append(url)
        for values in con.execute(query,(limit,)):
            row=dict(zip(selected,values)); did=row.get('id')
            for key in ('start_time','end_time'):
                if key in row: row[key+'_iso']=_chrome_time(row.get(key))
            if did in chains: row['url_chain']=chains[did]
            rows.append(row)
        con.close()
    except sqlite3.DatabaseError as e:
        return Observation('browser.chromium_downloads',Status.UNSUPPORTED,'Chromium download parsing failed',errors=[str(e)],meta={'source_sha256':sha256_file(p)})
    ev=[Evidence(str(p),'browser_download',r.get('target_path') or r.get('current_path') or r.get('url_chain') or r.get('url'),locator=f"download:{r.get('id','')}",method='Chromium History SQLite') for r in rows[:300]]
    return Observation('browser.chromium_downloads',Status.OK,f'Recovered {len(rows)} Chromium download row(s)',facts={'downloads':rows},evidence=ev,warnings=[f'results limited to {limit}'] if len(rows)>=limit else [],meta={'source_sha256':sha256_file(p)})

@registry.tool(name='browser.firefox_history',description='Read Firefox places.sqlite history visits in immutable read-only mode.',
 safety=SafetyLevel.READ_ONLY,tags=('browser','firefox','history','timeline'),produces=('browser_history','timeline'),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'limit':{'type':'integer','default':5000}},'required':['path']})
def firefox_history(path:str,limit:int=5000)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('browser.firefox_history',Status.ERROR,'places.sqlite not found',errors=[str(p)])
    try:
        con=_open_ro(p); tabs=_tables(con)
        if not {'moz_places','moz_historyvisits'}.issubset(tabs): con.close(); return Observation('browser.firefox_history',Status.UNSUPPORTED,'Firefox history tables not found',meta={'source_sha256':sha256_file(p)})
        sql='''SELECT h.id,p.url,p.title,p.visit_count,h.visit_date,h.from_visit,h.visit_type FROM moz_historyvisits h JOIN moz_places p ON p.id=h.place_id ORDER BY h.visit_date DESC LIMIT ?'''
        rows=[{'visit_id':rid,'url':url,'title':title,'visit_count':vc,'visit_time':_unix_micro_time(vd),'visit_time_raw':vd,'from_visit':frm,'visit_type':vt} for rid,url,title,vc,vd,frm,vt in con.execute(sql,(limit,))]
        con.close()
    except sqlite3.DatabaseError as e:
        return Observation('browser.firefox_history',Status.UNSUPPORTED,'Firefox History parsing failed',errors=[str(e)],meta={'source_sha256':sha256_file(p)})
    ev=[Evidence(str(p),'browser_visit',r['url'],locator=f"visit:{r['visit_id']}",method='Firefox places.sqlite') for r in rows[:300]]
    return Observation('browser.firefox_history',Status.OK,f'Recovered {len(rows)} Firefox history row(s)',facts={'visits':rows},evidence=ev,warnings=[f'results limited to {limit}'] if len(rows)>=limit else [],meta={'source_sha256':sha256_file(p)})

@registry.tool(name='browser.chromium_cookies',description='Inventory Chromium/Chrome/Edge Cookies SQLite metadata in immutable read-only mode. Plaintext values are omitted unless include_values=true; encrypted blobs are never decrypted.',
 safety=SafetyLevel.READ_ONLY,tags=('browser','chromium','cookies'),produces=('browser_cookies',),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'include_values':{'type':'boolean','default':False},'limit':{'type':'integer','default':5000}},'required':['path']})
def chromium_cookies(path:str,include_values:bool=False,limit:int=5000)->Observation:
    import hashlib
    p=Path(path)
    if not p.is_file(): return Observation('browser.chromium_cookies',Status.ERROR,'Cookies database not found',errors=[str(p)])
    try:
        con=_open_ro(p); tabs=_tables(con)
        if 'cookies' not in tabs: con.close(); return Observation('browser.chromium_cookies',Status.UNSUPPORTED,'Chromium cookies table not found',meta={'source_sha256':sha256_file(p)})
        cols={r[1] for r in con.execute('PRAGMA table_info(cookies)')}
        wanted=['host_key','name','path','creation_utc','expires_utc','last_access_utc','is_secure','is_httponly','samesite','source_scheme','value','encrypted_value']
        selected=[c for c in wanted if c in cols]
        query='SELECT '+','.join('"'+c+'"' for c in selected)+' FROM cookies LIMIT ?'
        rows=[]
        for values in con.execute(query,(limit,)):
            row=dict(zip(selected,values))
            for key in ('creation_utc','expires_utc','last_access_utc'):
                if key in row: row[key+'_iso']=_chrome_time(row.get(key))
            plain=row.pop('value',None) if 'value' in row else None
            enc=row.pop('encrypted_value',None) if 'encrypted_value' in row else None
            if include_values and plain: row['value']=plain
            elif plain: row['value_present']=True; row['value_length']=len(plain)
            if isinstance(enc,bytes) and enc:
                row['encrypted_value_length']=len(enc); row['encrypted_value_sha256']=hashlib.sha256(enc).hexdigest()
            rows.append(row)
        con.close()
    except sqlite3.DatabaseError as e:
        return Observation('browser.chromium_cookies',Status.UNSUPPORTED,'Chromium Cookies parsing failed',errors=[str(e)],meta={'source_sha256':sha256_file(p)})
    ev=[Evidence(str(p),'browser_cookie',f"{r.get('host_key','')} {r.get('name','')}",locator=f"cookie:{i}",method='Chromium Cookies SQLite') for i,r in enumerate(rows[:300])]
    return Observation('browser.chromium_cookies',Status.OK,f'Recovered {len(rows)} Chromium cookie row(s)',facts={'cookies':rows,'include_values':include_values},evidence=ev,warnings=[f'results limited to {limit}'] if len(rows)>=limit else [],meta={'source_sha256':sha256_file(p)})
