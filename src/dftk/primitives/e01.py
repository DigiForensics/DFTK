from __future__ import annotations
from pathlib import Path
from dftk.core.registry import registry
from dftk.core.models import Observation,Evidence,Status,SafetyLevel
from dftk.core.helpers import sha256_file

@registry.tool(name="image.e01_inventory",description="Open an E01/EWF image read-only with pyewf and report segment/media metadata. Filesystem traversal is intentionally a separate future primitive.",safety=SafetyLevel.READ_ONLY,requires=('pyewf',),tags=('image','e01'),produces=('ewf_metadata',),
 parameters={"type":"object","properties":{"path":{"type":"string"}},"required":["path"]})
def e01_inventory(path:str)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation("image.e01_inventory",Status.ERROR,"E01 segment not found",errors=[str(p)])
    try: import pyewf
    except ImportError: return Observation("image.e01_inventory",Status.UNSUPPORTED,"pyewf is not installed",errors=["install an environment that provides pyewf/libewf Python bindings"],meta={"container_sha256":sha256_file(p)})
    h=None; warnings=[]
    try:
        names=pyewf.glob(str(p)); h=pyewf.handle(); h.open(names)
        facts={"segments":list(names),"media_size":h.get_media_size(),"header_values":{}}
        for key in ('case_number','description','examiner_name','evidence_number','notes','acquiry_date','system_date'):
            try:
                v=h.get_header_value(key)
                if v: facts['header_values'][key]=v
            except Exception as e:
                warnings.append(f"header {key} unreadable: {type(e).__name__}: {e}")
    except Exception as e:
        return Observation("image.e01_inventory",Status.ERROR,"E01 open failed",errors=[f"{type(e).__name__}: {e}"],meta={"container_sha256":sha256_file(p)})
    finally:
        if h is not None:
            try: h.close()
            except Exception as e: warnings.append(f"EWF handle close warning: {type(e).__name__}: {e}")
    return Observation("image.e01_inventory",Status.PARTIAL if warnings else Status.OK,"E01 metadata inventory complete",facts=facts,evidence=[Evidence(str(p),'ewf_media_size',facts['media_size'],locator='EWF metadata')],warnings=warnings,meta={"container_sha256":sha256_file(p)})

@registry.tool(name='image.e01_filesystem_inventory',description='Read E01/EWF through pyewf + pytsk3 and inventory volume partitions and bounded filesystem root entries without mounting or modifying evidence.',
 safety=SafetyLevel.READ_ONLY,tags=('image','e01','filesystem'),produces=('partition_table','filesystem_inventory'),requires=('pyewf','pytsk3'),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'entry_limit':{'type':'integer','default':2000}},'required':['path']})
def e01_filesystem_inventory(path:str,entry_limit:int=2000)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('image.e01_filesystem_inventory',Status.ERROR,'E01 segment not found',errors=[str(p)])
    try:
        import pyewf,pytsk3
    except ImportError as e:
        return Observation('image.e01_filesystem_inventory',Status.UNSUPPORTED,'pyewf and pytsk3 are required',errors=[f'missing dependency: {getattr(e,"name",str(e))}','install libewf/pyewf and pytsk3 in the forensic environment'],meta={'container_sha256':sha256_file(p)})

    class EwfImgInfo(pytsk3.Img_Info):
        def __init__(self,handle):
            self._handle=handle
            super().__init__(url='',type=pytsk3.TSK_IMG_TYPE_EXTERNAL)
        def close(self):
            return None
        def read(self,offset,size):
            self._handle.seek(offset); return self._handle.read(size)
        def get_size(self):
            return self._handle.get_media_size()

    handle=None
    try:
        names=pyewf.glob(str(p)); handle=pyewf.handle(); handle.open(names); img=EwfImgInfo(handle)
        sector=512; partitions=[]; fs_rows=[]; warnings=[]
        try:
            vol=pytsk3.Volume_Info(img)
            for part in vol:
                desc=part.desc.decode('utf-8','replace') if isinstance(part.desc,bytes) else str(part.desc)
                row={'addr':int(part.addr),'start_sector':int(part.start),'sector_count':int(part.len),'description':desc,'flags':int(part.flags)}
                partitions.append(row)
                if not (part.flags & pytsk3.TSK_VS_PART_FLAG_ALLOC): continue
                offset=int(part.start)*sector
                try:
                    fs=pytsk3.FS_Info(img,offset=offset); root=fs.open_dir(path='/'); count=0
                    entries=[]
                    for entry in root:
                        if count>=entry_limit: break
                        try:
                            name=entry.info.name.name
                            if isinstance(name,bytes): name=name.decode('utf-8','replace')
                            if name in ('.','..'): continue
                            meta=entry.info.meta
                            entries.append({'name':name,'meta_addr':int(meta.addr) if meta else None,'size':int(meta.size) if meta else None,'type':int(meta.type) if meta else None})
                            count+=1
                        except (AttributeError,TypeError,ValueError):
                            continue
                    fs_rows.append({'partition_addr':int(part.addr),'offset':offset,'fs_type':int(fs.info.ftype),'root_entries':entries})
                except (OSError,IOError,RuntimeError) as e:
                    warnings.append(f'partition {part.addr} filesystem open failed: {e}')
        except (OSError,IOError,RuntimeError):
            # Some images contain a filesystem directly without a volume system.
            partitions=[{'addr':0,'start_sector':0,'sector_count':handle.get_media_size()//sector,'description':'whole image','flags':None}]
            try:
                fs=pytsk3.FS_Info(img,offset=0); root=fs.open_dir(path='/'); entries=[]
                for entry in root:
                    if len(entries)>=entry_limit: break
                    try:
                        name=entry.info.name.name
                        if isinstance(name,bytes): name=name.decode('utf-8','replace')
                        if name in ('.','..'): continue
                        meta=entry.info.meta; entries.append({'name':name,'meta_addr':int(meta.addr) if meta else None,'size':int(meta.size) if meta else None,'type':int(meta.type) if meta else None})
                    except (AttributeError,TypeError,ValueError): continue
                fs_rows=[{'partition_addr':0,'offset':0,'fs_type':int(fs.info.ftype),'root_entries':entries}]
            except (OSError,IOError,RuntimeError) as e:
                return Observation('image.e01_filesystem_inventory',Status.UNSUPPORTED,'No supported volume system or filesystem found',errors=[str(e)],facts={'partitions':partitions},meta={'container_sha256':sha256_file(p)})
        return Observation('image.e01_filesystem_inventory',Status.PARTIAL if warnings else Status.OK,f'Inventoried {len(partitions)} partition(s) and {len(fs_rows)} filesystem(s)',facts={'segments':list(names),'partitions':partitions,'filesystems':fs_rows},evidence=[Evidence(str(p),'partition_table',len(partitions),locator='TSK volume/filesystem metadata',method='pyewf+pytsk3')],warnings=warnings,meta={'container_sha256':sha256_file(p)})
    except Exception as e:
        return Observation('image.e01_filesystem_inventory',Status.ERROR,'E01 filesystem inventory failed',errors=[f'{type(e).__name__}: {e}'],meta={'container_sha256':sha256_file(p)})
    finally:
        if handle is not None:
            try: handle.close()
            except Exception:
                # The observation has already been created; close failure does not alter evidence bytes.
                handle=None
