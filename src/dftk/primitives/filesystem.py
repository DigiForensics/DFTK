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

"""Filesystem primitives — DFTK 3.5.0.

Exposes a partition table (`image.partitions`) and a filesystem API
(`filesystem.list/walk/stat/read/extract/deleted`).

  * ``read`` / ``extract`` work in raw offset mode (no FS parser) for any image,
    and also read a named file when a filesystem backend can resolve the path.
  * ``list`` / ``walk`` / ``stat`` / ``deleted`` require a filesystem parser.
    ``pytsk3`` provides the broadest coverage (NTFS / ext / HFS+ …); a pure-Python
    FAT reader (no external dependency) activates automatically for FAT volumes,
    so FAT evidence is fully usable even where pytsk3 is not installed.

All writes go to the workspace and are registered as DerivedArtifacts (Phase 1
provenance model). Evidence is never modified.
"""

from __future__ import annotations

from pathlib import Path

from dftk.core.registry import registry
from dftk.core.models import Observation, Evidence, Status, SafetyLevel
from dftk.core.helpers import sha256_file
from dftk.core.partition import open_block_source, parse_partitions, Partition
from dftk.core.fs_backend import open_filesystem, UnsupportedFilesystem
from dftk.core.provenance import ProvenanceIndex


def _resolve_partition_offset(src, partition: int, partition_offset: int | None) -> tuple[int, list[Partition]]:
    parts = parse_partitions(src)
    if partition_offset is not None:
        return partition_offset, parts
    if not parts:
        return 0, parts
    # Partition param is 1-based; MBR/GPT entries keep original index.
    idx = partition - 1
    if 0 <= idx < len(parts):
        return parts[idx].start_byte, parts
    return parts[0].start_byte, parts


@registry.tool(name='image.partitions',description='Parse the partition table (MBR and GPT) of a disk image (raw dd or E01) without mounting or modifying it. Pure-Python parser.',safety=SafetyLevel.READ_ONLY,tags=('image','partition'),produces=('partition_table'),
 parameters={'type':'object','properties':{'path':{'type':'string'},'sector_size':{'type':'integer','default':512}},'required':['path'],'x-path-roles':{'path':'EVIDENCE_INPUT'}})
def image_partitions(path:str,sector_size:int=512)->Observation:
    try: src=open_block_source(path,sector_size)
    except (OSError,RuntimeError) as e: return Observation('image.partitions',Status.ERROR,'Cannot open image',errors=[str(e)])
    try: parts=parse_partitions(src)
    except Exception as e: return Observation('image.partitions',Status.ERROR,'Partition parse failed',errors=[str(e)],meta={'source_sha256':sha256_file(Path(path))})
    rows=[{'index':p.index,'scheme':p.scheme,'type':p.type,'name':p.name,'guid':p.guid,
           'start_lba':p.start_lba,'num_sectors':p.num_sectors,'start_byte':p.start_byte,
           'size_byte':p.size_byte,'flags':p.flags} for p in parts]
    return Observation('image.partitions',Status.OK,f'Found {len(rows)} partition(s)',facts={'sector_size':sector_size,'partitions':rows},
                       evidence=[Evidence(str(path),'partition',f"{p.scheme}:{p.type}",locator=f"lba:{p.start_lba}") for p in parts[:300]],
                       meta={'source_sha256':sha256_file(Path(path))})


@registry.tool(name='filesystem.list',description='List the root (or given) directory of a filesystem inside a disk image. FAT volumes use the pure-Python reader (no external dependency); NTFS/ext/HFS+ still require pytsk3.',safety=SafetyLevel.READ_ONLY,tags=('filesystem','list'),produces=('directory_entries'),
 parameters={'type':'object','properties':{'path':{'type':'string'},'partition':{'type':'integer','default':1},'partition_offset':{'type':'integer','default':0},'path_in_fs':{'type':'string','default':'/'},'entry_limit':{'type':'integer','default':2000}},'required':['path'],'x-path-roles':{'path':'EVIDENCE_INPUT'}})
def filesystem_list(path:str,partition:int=1,partition_offset:int=0,path_in_fs:str='/',entry_limit:int=2000)->Observation:
    try: src=open_block_source(path)
    except (OSError,RuntimeError) as e: return Observation('filesystem.list',Status.ERROR,'Cannot open image',errors=[str(e)])
    off,parts=_resolve_partition_offset(src,partition,partition_offset or None)
    try: fs=open_filesystem(src,off,prefer_tsk=True)
    except Exception as e: return Observation('filesystem.list',Status.ERROR,'Filesystem open failed',errors=[str(e)],meta={'source_sha256':sha256_file(Path(path))})
    try: entries=fs.list_dir(path_in_fs,entry_limit)
    except UnsupportedFilesystem as e: return Observation('filesystem.list',Status.UNSUPPORTED,'FAT is supported natively; NTFS/ext/HFS+ listing needs pytsk3',errors=[str(e)],meta={'source_sha256':sha256_file(Path(path))})
    finally: fs.close()
    return Observation('filesystem.list',Status.PARTIAL if len(entries)>=entry_limit else Status.OK,f'Listed {len(entries)} entr(y/ies) at {path_in_fs}',facts={'path_in_fs':path_in_fs,'entries':entries},meta={'source_sha256':sha256_file(Path(path))})


@registry.tool(name='filesystem.walk',description='Recursively walk a filesystem inside a disk image with depth/entry limits and optional deleted-entry inclusion. FAT uses the pure-Python reader; NTFS/ext/HFS+ need pytsk3.',safety=SafetyLevel.READ_ONLY,tags=('filesystem','walk'),produces=('walk_entries'),
 parameters={'type':'object','properties':{'path':{'type':'string'},'partition':{'type':'integer','default':1},'partition_offset':{'type':'integer','default':0},'path_in_fs':{'type':'string','default':'/'},'max_depth':{'type':'integer','default':8},'max_entries':{'type':'integer','default':5000},'include_deleted':{'type':'boolean','default':False}},'required':['path'],'x-path-roles':{'path':'EVIDENCE_INPUT'}})
def filesystem_walk(path:str,partition:int=1,partition_offset:int=0,path_in_fs:str='/',max_depth:int=8,max_entries:int=5000,include_deleted:bool=False)->Observation:
    try: src=open_block_source(path)
    except (OSError,RuntimeError) as e: return Observation('filesystem.walk',Status.ERROR,'Cannot open image',errors=[str(e)])
    off,parts=_resolve_partition_offset(src,partition,partition_offset or None)
    try: fs=open_filesystem(src,off,prefer_tsk=True)
    except Exception as e: return Observation('filesystem.walk',Status.ERROR,'Filesystem open failed',errors=[str(e)],meta={'source_sha256':sha256_file(Path(path))})
    try: entries=fs.walk(path_in_fs,max_depth,max_entries,include_deleted)
    except UnsupportedFilesystem as e: return Observation('filesystem.walk',Status.UNSUPPORTED,'FAT is supported natively; NTFS/ext/HFS+ walk needs pytsk3',errors=[str(e)],meta={'source_sha256':sha256_file(Path(path))})
    finally: fs.close()
    return Observation('filesystem.walk',Status.PARTIAL if len(entries)>=max_entries else Status.OK,f'Walked {len(entries)} entr(y/ies)',facts={'path_in_fs':path_in_fs,'max_depth':max_depth,'include_deleted':include_deleted,'entries':entries},meta={'source_sha256':sha256_file(Path(path))})


@registry.tool(name='filesystem.stat',description='Return filesystem metadata (size, timestamps, type, attributes) for a file/dir inside a disk image. FAT uses the pure-Python reader; NTFS/ext/HFS+ need pytsk3.',safety=SafetyLevel.READ_ONLY,tags=('filesystem','stat'),produces=('file_stat'),
 parameters={'type':'object','properties':{'path':{'type':'string'},'partition':{'type':'integer','default':1},'partition_offset':{'type':'integer','default':0},'path_in_fs':{'type':'string','default':'/'}},'required':['path','path_in_fs'],'x-path-roles':{'path':'EVIDENCE_INPUT'}})
def filesystem_stat(path:str,partition:int=1,partition_offset:int=0,path_in_fs:str='/')->Observation:
    try: src=open_block_source(path)
    except (OSError,RuntimeError) as e: return Observation('filesystem.stat',Status.ERROR,'Cannot open image',errors=[str(e)])
    off,parts=_resolve_partition_offset(src,partition,partition_offset or None)
    try: fs=open_filesystem(src,off,prefer_tsk=True)
    except Exception as e: return Observation('filesystem.stat',Status.ERROR,'Filesystem open failed',errors=[str(e)],meta={'source_sha256':sha256_file(Path(path))})
    try: meta=fs.stat(path_in_fs)
    except UnsupportedFilesystem as e: return Observation('filesystem.stat',Status.UNSUPPORTED,'FAT is supported natively; NTFS/ext/HFS+ stat needs pytsk3',errors=[str(e)],meta={'source_sha256':sha256_file(Path(path))})
    finally: fs.close()
    return Observation('filesystem.stat',Status.OK,f'Stat {path_in_fs}',facts={'stat':meta},meta={'source_sha256':sha256_file(Path(path))})


@registry.tool(name='filesystem.read',description='Read a byte range from a filesystem. With a filesystem backend (pytsk3 for NTFS/ext/HFS+, or the pure-Python FAT reader) + path_in_fs, reads that file; otherwise reads partition_offset+offset raw bytes. Returns a bounded hex preview + SHA-256.',safety=SafetyLevel.READ_ONLY,tags=('filesystem','read'),produces=('bytes_preview'),
 parameters={'type':'object','properties':{'path':{'type':'string'},'partition':{'type':'integer','default':1},'partition_offset':{'type':'integer','default':0},'path_in_fs':{'type':'string','default':''},'offset':{'type':'integer','default':0},'length':{'type':'integer','default':4096},'preview_bytes':{'type':'integer','default':1024}},'required':['path','length'],'x-path-roles':{'path':'EVIDENCE_INPUT'}})
def filesystem_read(path:str,partition:int=1,partition_offset:int=0,path_in_fs:str='',offset:int=0,length:int=4096,preview_bytes:int=1024)->Observation:
    try: src=open_block_source(path)
    except (OSError,RuntimeError) as e: return Observation('filesystem.read',Status.ERROR,'Cannot open image',errors=[str(e)])
    off,parts=_resolve_partition_offset(src,partition,partition_offset or None)
    try: fs=open_filesystem(src,off,prefer_tsk=True)
    except Exception as e: return Observation('filesystem.read',Status.ERROR,'Filesystem open failed',errors=[str(e)],meta={'source_sha256':sha256_file(Path(path))})
    try:
        if path_in_fs and fs.kind in ('tsk','fat'):
            data=fs.read_file(path_in_fs,offset,length)
            mode='fs_file'
        else:
            data=fs.read(offset,length)
            mode='raw_offset'
    except UnsupportedFilesystem as e:
        return Observation('filesystem.read',Status.UNSUPPORTED,'Read needs pytsk3 for non-FAT filesystems, or a raw offset',errors=[str(e)],meta={'source_sha256':sha256_file(Path(path))})
    finally: fs.close()
    import hashlib
    return Observation('filesystem.read',Status.OK,f'Read {len(data)} byte(s) ({mode})',facts={'mode':mode,'length':len(data),'sha256':hashlib.sha256(data).hexdigest(),'hex_preview':data[:preview_bytes].hex()},meta={'source_sha256':sha256_file(Path(path))})


@registry.tool(name='filesystem.deleted',description='List deleted file entries recovered from a filesystem. FAT volumes are recovered by the pure-Python reader; NTFS/ext unallocated recovery still requires pytsk3.',safety=SafetyLevel.READ_ONLY,tags=('filesystem','deleted'),produces=('deleted_entries'),
 parameters={'type':'object','properties':{'path':{'type':'string'},'partition':{'type':'integer','default':1},'partition_offset':{'type':'integer','default':0},'entry_limit':{'type':'integer','default':2000}},'required':['path'],'x-path-roles':{'path':'EVIDENCE_INPUT'}})
def filesystem_deleted(path:str,partition:int=1,partition_offset:int=0,entry_limit:int=2000)->Observation:
    try: src=open_block_source(path)
    except (OSError,RuntimeError) as e: return Observation('filesystem.deleted',Status.ERROR,'Cannot open image',errors=[str(e)])
    off,parts=_resolve_partition_offset(src,partition,partition_offset or None)
    try: fs=open_filesystem(src,off,prefer_tsk=True)
    except Exception as e: return Observation('filesystem.deleted',Status.ERROR,'Filesystem open failed',errors=[str(e)],meta={'source_sha256':sha256_file(Path(path))})
    try: entries=fs.list_deleted(entry_limit)
    except UnsupportedFilesystem as e: return Observation('filesystem.deleted',Status.UNSUPPORTED,'FAT is recovered natively; NTFS/ext deleted recovery needs pytsk3',errors=[str(e)],meta={'source_sha256':sha256_file(Path(path))})
    finally: fs.close()
    return Observation('filesystem.deleted',Status.PARTIAL if len(entries)>=entry_limit else Status.OK,f'Found {len(entries)} deleted entr(y/ies)',facts={'deleted_entries':entries},meta={'source_sha256':sha256_file(Path(path))})


@registry.tool(name='filesystem.extract',description='Extract a byte range (raw offset or, with pytsk3, a file path) from a disk image into the workspace. The extracted file is registered as a DerivedArtifact (provenance). STATEFUL: writes only to workspace.',safety=SafetyLevel.STATEFUL,tags=('filesystem','extract'),produces=('extracted_file','derived_artifact'),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'output_dir':{'type':'string'},'partition':{'type':'integer','default':1},'partition_offset':{'type':'integer','default':0},'path_in_fs':{'type':'string','default':''},'offset':{'type':'integer','default':0},'length':{'type':'integer','default':0},'name':{'type':'string','default':''},'max_bytes':{'type':'integer','default':1073741824}},'required':['path','output_dir'],'x-path-roles':{'path':'EVIDENCE_INPUT','output_dir':'WORKSPACE_OUTPUT'}})
def filesystem_extract(path:str,output_dir:str,partition:int=1,partition_offset:int=0,path_in_fs:str='',offset:int=0,length:int=0,name:str='',max_bytes:int=1073741824)->Observation:
    if not output_dir: return Observation('filesystem.extract',Status.BLOCKED,'output_dir is required (workspace)',errors=['workspace output not specified'])
    try: src=open_block_source(path)
    except (OSError,RuntimeError) as e: return Observation('filesystem.extract',Status.ERROR,'Cannot open image',errors=[str(e)])
    off,parts=_resolve_partition_offset(src,partition,partition_offset or None)
    try: fs=open_filesystem(src,off,prefer_tsk=True)
    except Exception as e: return Observation('filesystem.extract',Status.ERROR,'Filesystem open failed',errors=[str(e)],meta={'source_sha256':sha256_file(Path(path))})
    try:
        if path_in_fs and fs.kind in ('tsk','fat'):
            if length<=0: return Observation('filesystem.extract',Status.BLOCKED,'length must be > 0 for raw extraction',errors=[])
            data=fs.read_file(path_in_fs,offset,min(length,max_bytes))
            base=name or Path(path_in_fs).name or 'extracted.bin'
            info={'path':str(Path(output_dir)/base),'size':len(data)}
        else:
            if length<=0: return Observation('filesystem.extract',Status.BLOCKED,'length must be > 0 for raw extraction',errors=[])
            data=fs.read(offset,min(length,max_bytes))
            base=name or f"part{partition}_off{offset}.bin"
            info={'path':str(Path(output_dir)/base),'size':len(data)}
    except UnsupportedFilesystem as e:
        return Observation('filesystem.extract',Status.UNSUPPORTED,'Extraction needs pytsk3 for non-FAT filesystems, or a raw offset',errors=[str(e)],meta={'source_sha256':sha256_file(Path(path))})
    finally: fs.close()
    import hashlib
    Path(info['path']).parent.mkdir(parents=True,exist_ok=True)
    Path(info['path']).write_bytes(data)
    sha=hashlib.sha256(data).hexdigest()
    # Provenance: register the source image and the extracted derived artifact.
    from dftk import __version__ as DFTK_VERSION_lazy  # noqa: lazy import inside fn
    prov=ProvenanceIndex()
    src_art=prov.add(source_artifact='',locator=f"file:{Path(path).name}",tool='filesystem.extract',version=DFTK_VERSION_lazy,sha256=sha256_file(Path(path)),size=Path(path).stat().st_size,kind='evidence',state='LIVE')
    der=prov.add(source_artifact=src_art.artifact_id,locator=f"partition:{partition};offset:{offset};path:{path_in_fs or '-'}",tool='filesystem.extract',version=DFTK_VERSION_lazy,sha256=sha,size=len(data),kind='derived',state='LIVE',params={'partition':partition,'offset':offset,'length':len(data),'path_in_fs':path_in_fs})
    ev=[Evidence(str(path),'extracted_file',info['path'],locator=f"partition:{partition};offset:{offset}",source_sha256=sha256_file(Path(path)),artifact_id=der.artifact_id,derivation=der.derivation.to_dict(),state='LIVE')]
    return Observation('filesystem.extract',Status.OK,f"Extracted {info['size']} byte(s) to workspace",facts={'extracted':info,'sha256':sha},evidence=ev,derived_artifacts=prov.all(),meta={'source_sha256':sha256_file(Path(path)),'provenance':prov.to_dict()})