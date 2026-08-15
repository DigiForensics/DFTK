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
import struct, tarfile, zipfile, os
from dftk.core.registry import registry
from dftk.core.models import Observation, Evidence, Status, SafetyLevel
from dftk.core.helpers import hash_file, sha256_file, printable_strings, read_file_bounded_observation

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
    # Bound the in-memory read so very large evidence cannot exhaust RAM
    # (DEFAULT_MAX_READ caps the whole-file load). On oversize input the
    # helper returns an UNSUPPORTED Observation carrying the source hash.
    data, err = read_file_bounded_observation("file.strings", p)
    if err is not None:
        return err
    rows=printable_strings(data,min_length)[:limit]
    ev=[Evidence(str(p),"string",s,locator=f"offset:{off}") for off,s in rows[:200]]
    warnings=[]
    if len(rows)>=limit: warnings.append(f"result limited to {limit} strings")
    return Observation("file.strings",Status.OK,f"Extracted {len(rows)} printable strings",
        facts={"count":len(rows),"strings":[{"offset":o,"value":s} for o,s in rows]}, evidence=ev,
        warnings=warnings, meta={"source_sha256":sha256_file(p)})

_CDFH_SIG = b"PK\x01\x02"  # central directory file header
_EOCD_SIG = b"PK\x05\x06"   # end of central directory


def _zip_central_dir_offset(path: str):
    """Locate the central directory start via the EOCD record.

    Returns ``(cd_offset, cd_size, comment_len)`` or ``None`` when the EOCD
    cannot be found (e.g. a truncated/Zip64-only archive). The caller then
    falls back to the stdlib reader.
    """
    size = os.path.getsize(path)
    max_scan = min(size, 22 + 0xFFFF)
    with open(path, "rb") as f:
        f.seek(size - max_scan)
        tail = f.read(max_scan)
    idx = tail.rfind(_EOCD_SIG)
    if idx == -1:
        return None
    # EOCD after the signature: disk(2) cd_disk(2) disk_entries(2)
    # total_entries(2) cd_size(4) cd_offset(4) comment_len(2)
    off = idx + 4
    if len(tail) - off < 18:
        return None
    (_disk, _cd_disk, _d_entries, _t_entries,
     cd_size, cd_offset, comment_len) = struct.unpack_from("<HHHHIIH", tail, off)
    return cd_offset, cd_size, comment_len


def _iter_zip_members(path: str, limit: int):
    """Stream ZIP central-directory members, stopping after ``limit``.

    Unlike ``ZipFile.infolist()``, this does NOT materialize the whole central
    directory up front, so peak memory stays O(limit) even for archives with
    millions of entries. The reader is intentionally minimal: it walks the
    central directory file headers sequentially and extracts only the fields
    inventory needs. If the EOCD/central directory cannot be read, it falls
    back to stdlib ``infolist`` (original behavior).
    """
    located = _zip_central_dir_offset(path)
    if located is None:
        with zipfile.ZipFile(path) as z:
            for zi in z.infolist()[:limit]:
                yield {"name": zi.filename, "size": zi.file_size,
                       "compressed_size": zi.compress_size,
                       "crc32": f"{zi.CRC:08x}", "is_dir": zi.is_dir()}
        return
    cd_offset, cd_size, _ = located
    with open(path, "rb") as f:
        f.seek(cd_offset)
        remaining = cd_size
        count = 0
        while count < limit and remaining >= 46:
            if f.read(4) != _CDFH_SIG:
                break
            header = f.read(42)  # remainder of the 46-byte fixed header
            if len(header) < 42:
                break
            (_ver_made, _ver_need, _flags, _method, _mod_time, _mod_date,
             crc32, comp_size, uncomp_size, fname_len, extra_len, comm_len,
             _disk_start, _int_attrs, _ext_attrs, _rel_offset) = struct.unpack(
                "<HHHHHHIIIHHHHHII", header)
            name = f.read(fname_len).decode("utf-8", "replace")
            f.read(extra_len + comm_len)
            remaining -= 46 + fname_len + extra_len + comm_len
            count += 1
            yield {"name": name, "size": uncomp_size,
                   "compressed_size": comp_size,
                   "crc32": f"{crc32:08x}", "is_dir": name.endswith("/")}


@registry.tool(
    name="archive.inventory",
    description="Inventory ZIP/TAR archive members and metadata without extraction. The member list is bounded by `limit` (peak memory stays proportional to `limit` even for very large archives).",
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
            for zi in _iter_zip_members(str(p), limit):
                members.append(zi)
        elif tarfile.is_tarfile(p):
            kind="tar"
            with tarfile.open(p,"r:*") as t:
                while len(members) < limit:
                    ti = t.next()
                    if ti is None:
                        break
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
    data, err = read_file_bounded_observation('file.strings_unicode', p)
    if err is not None:
        return err
    rows=[]
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
