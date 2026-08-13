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
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import os,re,struct,zipfile
from dftk.core.registry import registry
from dftk.core.models import Observation,Evidence,Status,SafetyLevel
from dftk.core.helpers import sha256_file,bounded_files,safe_rel


def _kind_from_header(p:Path, head:bytes)->tuple[str,float,list[str]]:
    notes=[]
    if head.startswith(b'PK\x03\x04') or head.startswith(b'PK\x05\x06'):
        kind='zip'; conf=0.98
        try:
            with zipfile.ZipFile(p) as z:
                names=set(z.namelist())
                if 'AndroidManifest.xml' in names and any(re.fullmatch(r'classes(?:\d+)?\.dex',n) for n in names): return 'apk',1.0,notes
                if 'META-INF/MANIFEST.MF' in names: return 'jar_or_zip',0.92,notes
        except (OSError,zipfile.BadZipFile): notes.append('ZIP signature present but central directory could not be read')
        return kind,conf,notes
    if head.startswith(b'dex\n'): return 'dex',1.0,notes
    if head.startswith(b'\x7fELF'): return 'elf',1.0,notes
    if head.startswith(b'SQLite format 3\x00'): return 'sqlite',1.0,notes
    if head.startswith(b'regf'): return 'windows_registry_hive',1.0,notes
    if head.startswith((b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'M<\xb2\xa1',b'\xa1\xb2<M')): return 'pcap',1.0,notes
    if head.startswith(b'\x0a\x0d\x0d\x0a'): return 'pcapng',1.0,notes
    if head.startswith(b'MZ'): return 'pe',0.98,notes
    if head.startswith(b'%PDF-'): return 'pdf',1.0,notes
    if head.startswith(b'\x89PNG\r\n\x1a\n'): return 'png',1.0,notes
    if head.startswith(b'\xff\xd8\xff'): return 'jpeg',0.99,notes
    if head.startswith(b'\x1f\x8b'): return 'gzip',1.0,notes
    # EWF/Expert Witness Format segment signature: EVF + tab/CR/LF + FF 00
    if head.startswith(b'EVF\x09\x0d\x0a\xff\x00'): return 'ewf_e01',1.0,notes
    return 'unknown',0.0,notes

@registry.tool(name='artifact.inspect',description='Identify an artifact from magic bytes and container structure, with size and SHA-256.',
 safety=SafetyLevel.READ_ONLY,tags=('artifact','triage'),produces=('artifact_type','hash'),
 parameters={'type':'object','properties':{'path':{'type':'string'}},'required':['path']})
def artifact_inspect(path:str)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('artifact.inspect',Status.ERROR,'Input is not a file',errors=[str(p)])
    with p.open('rb') as f: head=f.read(4096)
    kind,confidence,notes=_kind_from_header(p,head)
    h=sha256_file(p)
    facts={'path':str(p),'size':p.stat().st_size,'kind':kind,'confidence':confidence,'sha256':h,'extension':p.suffix.lower()}
    ev=[Evidence(str(p),'artifact_magic',kind,locator='bytes:0-4095',source_sha256=h,confidence=confidence,method='magic/container inspection')]
    return Observation('artifact.inspect',Status.OK,f'Artifact identified as {kind}',facts=facts,evidence=ev,warnings=notes,meta={'source_sha256':h})

@registry.tool(name='tree.inventory',description='Bounded inventory of an extracted evidence directory: file counts, extensions, total size and largest files.',
 safety=SafetyLevel.READ_ONLY,tags=('filesystem','triage'),produces=('file_inventory',),cost_hint='medium',
 parameters={'type':'object','properties':{'root':{'type':'string'},'max_files':{'type':'integer','default':50000},'largest':{'type':'integer','default':100}},'required':['root']})
def tree_inventory(root:str,max_files:int=50000,largest:int=100)->Observation:
    r=Path(root)
    if not r.is_dir(): return Observation('tree.inventory',Status.ERROR,'Directory not found',errors=[str(r)])
    exts=Counter(); rows=[]; total=0; n=0
    for f in bounded_files(r,max_files=max_files):
        try: st=f.stat()
        except OSError: continue
        n+=1; total+=st.st_size; exts[f.suffix.lower() or '<none>']+=1
        rows.append((st.st_size,safe_rel(f,r)))
    rows.sort(reverse=True)
    warnings=[f'file inventory limited to {max_files}'] if n>=max_files else []
    facts={'file_count':n,'total_size':total,'extensions':dict(exts.most_common()),'largest_files':[{'path':p,'size':s} for s,p in rows[:largest]]}
    return Observation('tree.inventory',Status.OK,f'Inventoried {n} file(s)',facts=facts,evidence=[Evidence(str(r),'directory_inventory',n,locator='recursive')],warnings=warnings)

@registry.tool(name='file.search_tree',description='Search a file or directory tree for text/byte patterns with bounded results and source locators.',
 safety=SafetyLevel.READ_ONLY,tags=('filesystem','search'),produces=('search_matches',),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'query':{'type':'string'},'regex':{'type':'boolean','default':False},'case_sensitive':{'type':'boolean','default':False},'max_files':{'type':'integer','default':20000},'max_file_size':{'type':'integer','default':16777216},'limit':{'type':'integer','default':1000}},'required':['path','query']})
def search_tree(path:str,query:str,regex:bool=False,case_sensitive:bool=False,max_files:int=20000,max_file_size:int=16*1024*1024,limit:int=1000)->Observation:
    root=Path(path)
    if not root.exists(): return Observation('file.search_tree',Status.ERROR,'Path not found',errors=[str(root)])
    files=[root] if root.is_file() else bounded_files(root,max_files=max_files)
    flags=0 if case_sensitive else re.IGNORECASE
    try: rx=re.compile(query.encode('utf-8'),flags) if regex else None
    except re.error as e: return Observation('file.search_tree',Status.ERROR,'Invalid regular expression',errors=[str(e)])
    needle=query.encode('utf-8') if case_sensitive else query.lower().encode('utf-8')
    matches=[]; ev=[]; scanned=0; skipped=0
    for f in files:
        try:
            if not f.is_file(): continue
            if f.stat().st_size>max_file_size: skipped+=1; continue
            data=f.read_bytes(); scanned+=1
        except OSError: continue
        if regex:
            iterator=((m.start(),m.group()) for m in rx.finditer(data))
        else:
            hay=data if case_sensitive else data.lower()
            def _iter():
                pos=0
                while True:
                    i=hay.find(needle,pos)
                    if i<0: break
                    yield i,data[i:i+len(needle)]
                    pos=i+max(1,len(needle))
            iterator=_iter()
        for off,val in iterator:
            rel=safe_rel(f,root) if root.is_dir() else f.name
            preview=data[max(0,off-80):min(len(data),off+len(val)+120)].decode('utf-8','replace')
            row={'path':str(f),'relative':rel,'offset':off,'match':val.decode('utf-8','replace'),'preview':preview}
            matches.append(row); ev.append(Evidence(str(f),'search_match',row['match'],locator=f'offset:{off}',method='regex' if regex else 'literal'))
            if len(matches)>=limit: break
        if len(matches)>=limit: break
    warnings=[]
    if skipped: warnings.append(f'skipped {skipped} file(s) larger than max_file_size')
    if len(matches)>=limit: warnings.append(f'results limited to {limit}')
    return Observation('file.search_tree',Status.OK,f'Found {len(matches)} match(es) across {scanned} scanned file(s)',facts={'matches':matches,'scanned_files':scanned,'skipped_large_files':skipped},evidence=ev[:300],warnings=warnings)

@registry.tool(name='timeline.file_metadata',description='Create a bounded filesystem metadata timeline from an extracted evidence tree.',
 safety=SafetyLevel.READ_ONLY,tags=('timeline','filesystem'),produces=('timeline',),cost_hint='medium',
 parameters={'type':'object','properties':{'root':{'type':'string'},'max_files':{'type':'integer','default':50000},'limit':{'type':'integer','default':100000}},'required':['root']})
def metadata_timeline(root:str,max_files:int=50000,limit:int=100000)->Observation:
    r=Path(root)
    if not r.is_dir(): return Observation('timeline.file_metadata',Status.ERROR,'Directory not found',errors=[str(r)])
    events=[]; n=0
    def iso(ts:float)->str: return datetime.fromtimestamp(ts,tz=timezone.utc).isoformat()
    for f in bounded_files(r,max_files=max_files):
        try: st=f.stat()
        except OSError: continue
        n+=1; rel=safe_rel(f,r)
        for kind,ts in [('mtime',st.st_mtime),('ctime',st.st_ctime),('atime',st.st_atime)]:
            events.append({'time':iso(ts),'epoch':ts,'kind':kind,'path':rel,'size':st.st_size})
            if len(events)>=limit: break
        if len(events)>=limit: break
    events.sort(key=lambda x:(x['epoch'],x['path'],x['kind']))
    warnings=[]
    if n>=max_files: warnings.append(f'file traversal limited to {max_files}')
    if len(events)>=limit: warnings.append(f'timeline limited to {limit} events')
    return Observation('timeline.file_metadata',Status.OK,f'Built {len(events)} filesystem metadata event(s)',facts={'events':events,'file_count':n},evidence=[Evidence(str(r),'timeline',len(events),locator='filesystem metadata')],warnings=warnings)
