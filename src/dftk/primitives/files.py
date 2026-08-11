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
import tarfile, zipfile, os
from dftk.core.registry import registry
from dftk.core.models import Observation, Evidence, Status, SafetyLevel
from dftk.core.helpers import hash_file, sha256_file, printable_strings

@registry.tool(
    name="file.hash",
    description="Compute cryptographic hashes of one file without modifying it.",
    safety=SafetyLevel.READ_ONLY,
    parameters={
        "type":"object","properties":{
            "path":{"type":"string"},
            "algorithms":{"type":"array","items":{"type":"string"},"default":["sha256"]}
        },"required":["path"]
    },
)
def file_hash(path: str, algorithms: list[str] | None = None) -> Observation:
    p=Path(path)
    if not p.is_file():
        return Observation("file.hash", Status.ERROR, "Input is not a file", errors=[str(p)])
    algorithms=algorithms or ["sha256"]
    hashes=hash_file(p, algorithms)
    return Observation("file.hash", Status.OK, f"Computed {len(hashes)} hash value(s)",
        facts={"path":str(p),"size":p.stat().st_size,"hashes":hashes},
        evidence=[Evidence(str(p),"file",hashes,locator="bytes:0-")])

@registry.tool(
    name="file.strings",
    description="Extract bounded printable ASCII strings with byte offsets.",
    safety=SafetyLevel.READ_ONLY,
    parameters={"type":"object","properties":{
        "path":{"type":"string"},"min_length":{"type":"integer","minimum":1,"default":4},
        "limit":{"type":"integer","minimum":1,"default":5000}
    },"required":["path"]},
)
def file_strings(path: str, min_length: int = 4, limit: int = 5000) -> Observation:
    p=Path(path)
    if not p.is_file(): return Observation("file.strings",Status.ERROR,"Input is not a file",errors=[str(p)])
    data=p.read_bytes()
    rows=printable_strings(data,min_length)[:limit]
    ev=[Evidence(str(p),"string",s,locator=f"offset:{off}") for off,s in rows[:200]]
    warnings=[]
    if len(rows)>=limit: warnings.append(f"result limited to {limit} strings")
    return Observation("file.strings",Status.OK,f"Extracted {len(rows)} printable strings",
        facts={"count":len(rows),"strings":[{"offset":o,"value":s} for o,s in rows]}, evidence=ev,
        warnings=warnings, meta={"source_sha256":sha256_file(p)})

@registry.tool(
    name="archive.inventory",
    description="Inventory ZIP/TAR archive members and metadata without extraction.",
    safety=SafetyLevel.READ_ONLY,
    parameters={"type":"object","properties":{"path":{"type":"string"},"limit":{"type":"integer","default":10000}},"required":["path"]},
)
def archive_inventory(path: str, limit: int = 10000) -> Observation:
    p=Path(path)
    if not p.is_file(): return Observation("archive.inventory",Status.ERROR,"Input is not a file",errors=[str(p)])
    members=[]
    kind=""
    try:
        if zipfile.is_zipfile(p):
            kind="zip"
            with zipfile.ZipFile(p) as z:
                for zi in z.infolist()[:limit]:
                    members.append({"name":zi.filename,"size":zi.file_size,"compressed_size":zi.compress_size,"crc32":f"{zi.CRC:08x}","is_dir":zi.is_dir()})
        elif tarfile.is_tarfile(p):
            kind="tar"
            with tarfile.open(p,"r:*") as t:
                for ti in t.getmembers()[:limit]:
                    members.append({"name":ti.name,"size":ti.size,"type":ti.type.decode("latin1") if isinstance(ti.type,bytes) else str(ti.type),"is_dir":ti.isdir()})
        else:
            return Observation("archive.inventory",Status.UNSUPPORTED,"Unsupported archive format",meta={"source_sha256":sha256_file(p)})
    except Exception as e:
        return Observation("archive.inventory",Status.ERROR,"Archive parsing failed",errors=[f"{type(e).__name__}: {e}"],meta={"source_sha256":sha256_file(p)})
    return Observation("archive.inventory",Status.OK,f"Inventoried {len(members)} {kind} member(s)",facts={"format":kind,"members":members,"member_count":len(members)},
        evidence=[Evidence(str(p),"archive_inventory",f"{len(members)} members",locator="central-directory" if kind=="zip" else "member-table")],meta={"source_sha256":sha256_file(p)})

@registry.tool(name='archive.extract_safe',description='Extract ZIP/TAR members into a separate workspace with path-traversal, member-count and total-size limits. Source archive is never modified.',
 safety=SafetyLevel.STATEFUL,tags=('archive','workspace','extract'),produces=('extracted_files',),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'output_dir':{'type':'string'},'member_limit':{'type':'integer','default':20000},'total_size_limit':{'type':'integer','default':2147483648},'overwrite':{'type':'boolean','default':False}},'required':['path','output_dir']})
def archive_extract_safe(path:str,output_dir:str,member_limit:int=20000,total_size_limit:int=2*1024*1024*1024,overwrite:bool=False)->Observation:
    src=Path(path); out=Path(output_dir)
    if not src.is_file(): return Observation('archive.extract_safe',Status.ERROR,'Archive not found',errors=[str(src)])
    out.mkdir(parents=True,exist_ok=True)
    root=out.resolve(); extracted=[]; total=0; warnings=[]
    def target(name:str)->Path:
        nonlocal root
        dest=(root/name).resolve()
        try: dest.relative_to(root)
        except ValueError: raise ValueError(f'path traversal rejected: {name}')
        return dest
    try:
        if zipfile.is_zipfile(src):
            with zipfile.ZipFile(src) as z:
                infos=z.infolist()
                if len(infos)>member_limit: return Observation('archive.extract_safe',Status.BLOCKED,'Archive member limit exceeded',errors=[f'{len(infos)} > {member_limit}'])
                if sum(i.file_size for i in infos)>total_size_limit: return Observation('archive.extract_safe',Status.BLOCKED,'Archive expanded-size limit exceeded')
                for info in infos:
                    dest=target(info.filename)
                    if info.is_dir(): dest.mkdir(parents=True,exist_ok=True); continue
                    if dest.exists() and not overwrite: warnings.append(f'skipped existing: {dest}'); continue
                    dest.parent.mkdir(parents=True,exist_ok=True)
                    with z.open(info) as rf,dest.open('wb') as wf:
                        while True:
                            chunk=rf.read(1024*1024)
                            if not chunk: break
                            total+=len(chunk)
                            if total>total_size_limit: raise ValueError('expanded-size limit exceeded during extraction')
                            wf.write(chunk)
                    extracted.append({'path':str(dest),'relative':str(dest.relative_to(root)),'size':dest.stat().st_size,'sha256':sha256_file(dest)})
        elif tarfile.is_tarfile(src):
            with tarfile.open(src,'r:*') as t:
                infos=t.getmembers()
                if len(infos)>member_limit: return Observation('archive.extract_safe',Status.BLOCKED,'Archive member limit exceeded',errors=[f'{len(infos)} > {member_limit}'])
                regular=[i for i in infos if i.isfile()]
                if sum(i.size for i in regular)>total_size_limit: return Observation('archive.extract_safe',Status.BLOCKED,'Archive expanded-size limit exceeded')
                for info in infos:
                    if info.issym() or info.islnk(): warnings.append(f'skipped link member: {info.name}'); continue
                    dest=target(info.name)
                    if info.isdir(): dest.mkdir(parents=True,exist_ok=True); continue
                    if not info.isfile(): warnings.append(f'skipped special member: {info.name}'); continue
                    if dest.exists() and not overwrite: warnings.append(f'skipped existing: {dest}'); continue
                    dest.parent.mkdir(parents=True,exist_ok=True); rf=t.extractfile(info)
                    if rf is None: continue
                    with rf,dest.open('wb') as wf:
                        while True:
                            chunk=rf.read(1024*1024)
                            if not chunk: break
                            total+=len(chunk)
                            if total>total_size_limit: raise ValueError('expanded-size limit exceeded during extraction')
                            wf.write(chunk)
                    extracted.append({'path':str(dest),'relative':str(dest.relative_to(root)),'size':dest.stat().st_size,'sha256':sha256_file(dest)})
        else: return Observation('archive.extract_safe',Status.UNSUPPORTED,'Unsupported archive format')
    except (OSError,ValueError,zipfile.BadZipFile,tarfile.TarError) as e:
        return Observation('archive.extract_safe',Status.ERROR,'Safe extraction failed',errors=[str(e)],facts={'extracted':extracted},warnings=warnings)
    return Observation('archive.extract_safe',Status.PARTIAL if warnings else Status.OK,f'Extracted {len(extracted)} file(s) into workspace',facts={'output_dir':str(root),'extracted':extracted,'total_bytes':total},evidence=[Evidence(str(src),'workspace_extract',str(root),locator='archive members',note='stateful workspace operation; source unchanged')],warnings=warnings,meta={'source_sha256':sha256_file(src)})

@registry.tool(name='file.strings_unicode',description='Extract bounded UTF-16LE/UTF-16BE printable strings with byte offsets; useful for Windows/native artifacts that ASCII strings miss.',
 safety=SafetyLevel.READ_ONLY,tags=('file','strings','unicode'),produces=('strings',),
 parameters={'type':'object','properties':{'path':{'type':'string'},'min_length':{'type':'integer','default':4},'limit':{'type':'integer','default':5000}},'required':['path']})
def file_strings_unicode(path:str,min_length:int=4,limit:int=5000)->Observation:
    import re
    p=Path(path)
    if not p.is_file(): return Observation('file.strings_unicode',Status.ERROR,'Input is not a file',errors=[str(p)])
    data=p.read_bytes(); rows=[]
    ml=max(1,min_length)
    le=re.compile(rb'(?:[\x20-\x7e]\x00){%d,}'%ml)
    be=re.compile(rb'(?:\x00[\x20-\x7e]){%d,}'%ml)
    for enc,rx in [('utf-16le',le),('utf-16be',be)]:
        for m in rx.finditer(data):
            rows.append({'offset':m.start(),'encoding':enc,'value':m.group().decode(enc,'replace')})
            if len(rows)>=limit: break
        if len(rows)>=limit: break
    rows.sort(key=lambda x:(x['offset'],x['encoding']))
    ev=[Evidence(str(p),'unicode_string',r['value'],locator=f"offset:{r['offset']};encoding:{r['encoding']}") for r in rows[:300]]
    return Observation('file.strings_unicode',Status.OK,f'Extracted {len(rows)} UTF-16 string(s)',facts={'strings':rows},evidence=ev,warnings=[f'results limited to {limit}'] if len(rows)>=limit else [],meta={'source_sha256':sha256_file(p)})
