# Copyright 2026 DyNooob @ DigiForensics
# Licensed under the Apache License, Version 2.0.
"""Mach-O structural inventory using Apple's published loader/fat layouts."""
from __future__ import annotations
import struct
import uuid
from pathlib import Path
from dftk.core.helpers import read_file_bounded_observation
from dftk.core.models import Evidence, Observation, SafetyLevel, Status
from dftk.core.registry import registry

_THIN={b'\xce\xfa\xed\xfe':('<',32),b'\xfe\xed\xfa\xce':('>',32),
       b'\xcf\xfa\xed\xfe':('<',64),b'\xfe\xed\xfa\xcf':('>',64)}
_FAT={b'\xca\xfe\xba\xbe':('>',False),b'\xbe\xba\xfe\xca':('<',False),
      b'\xca\xfe\xba\xbf':('>',True),b'\xbf\xba\xfe\xca':('<',True)}
_CPUS={7:'x86',12:'ARM',18:'PowerPC',0x01000007:'x86-64',0x0100000c:'ARM64',0x01000012:'PowerPC64'}


def _cstring(data,start,end):
    if not 0<=start<end<=len(data):
        raise ValueError('Load-command string offset outside command')
    zero=data.find(b'\0',start,end)
    if zero<0: raise ValueError('Unterminated load-command string')
    return data[start:zero].decode('utf-8','replace')


def _thin(data,base,symbol_limit,command_limit):
    if data[:4] not in _THIN:
        raise ValueError('Slice lacks Mach-O magic')
    endian,bits=_THIN[data[:4]]; header=32 if bits==64 else 28
    if len(data)<header: raise ValueError('Truncated Mach-O header')
    _,cpu,subtype,kind,ncmds,cmdbytes,flags=struct.unpack_from(endian+'7I',data)
    if header+cmdbytes>len(data): raise ValueError('Load-command region exceeds slice')
    if ncmds>cmdbytes//8: raise ValueError('Load-command count exceeds command region')
    row={'offset':base,'size':len(data),'bitness':bits,'endian':'little' if endian=='<' else 'big',
         'cpu':_CPUS.get(cpu,f'0x{cpu:08x}'),'cpu_type':cpu,'cpu_subtype':subtype,'file_type':kind,
         'flags':flags,'pie':bool(flags&0x200000),'load_command_count':ncmds,
         'dylibs':[],'rpaths':[],'segments':[],'symbols':[],'uuid':None,'code_signature':None}
    warnings=[]; pos=header; symtab=None
    for index in range(min(ncmds,command_limit)):
        if pos+8>header+cmdbytes: raise ValueError('Truncated load-command header')
        cmd,size=struct.unpack_from(endian+'II',data,pos); bare=cmd&0x7fffffff
        if size<8 or size%(8 if bits==64 else 4) or pos+size>header+cmdbytes:
            raise ValueError('Invalid load-command size/alignment')
        if bare in {0xc,0xd,0x18,0x1f,0x20,0x23,0xe,0xf,0x1c}:
            minimum=24 if bare in {0xc,0xd,0x18,0x1f,0x20,0x23} else 12
            if size<minimum: raise ValueError('Truncated dylib/rpath command')
            start=struct.unpack_from(endian+'I',data,pos+8)[0]
            if start<minimum: raise ValueError('String overlaps load-command structure')
            value=_cstring(data,pos+start,pos+size)
            target='rpaths' if bare==0x1c else 'dylibs'
            row[target].append({'value':value,'command':cmd,'offset':base+pos})
        elif bare==0x1b:
            if size<24: raise ValueError('Truncated UUID command')
            row['uuid']=str(uuid.UUID(bytes=data[pos+8:pos+24]))
        elif bare==0x1d:
            if size<16: raise ValueError('Truncated code-signature command')
            off,count=struct.unpack_from(endian+'II',data,pos+8)
            if off+count>len(data): raise ValueError('Code-signature region exceeds slice')
            row['code_signature']={'offset':base+off,'size':count,'cryptographically_verified':False}
        elif bare==2:
            if size<24: raise ValueError('Truncated symbol-table command')
            symtab=struct.unpack_from(endian+'4I',data,pos+8)
        elif bare in (1,0x19):
            is64=bare==0x19; minimum=72 if is64 else 56
            if size<minimum: raise ValueError('Truncated segment command')
            name=data[pos+8:pos+24].split(b'\0')[0].decode('utf-8','replace')
            vmaddr,vmsize,fileoff,filesize=struct.unpack_from(endian+('4Q' if is64 else '4I'),data,pos+24)
            nsects=struct.unpack_from(endian+'I',data,pos+(64 if is64 else 48))[0]
            section_size=80 if is64 else 68
            if minimum+nsects*section_size>size: raise ValueError('Section table exceeds segment command')
            if fileoff+filesize>len(data): raise ValueError('Segment file range exceeds slice')
            row['segments'].append({'name':name,'vm_address':vmaddr,'vm_size':vmsize,'file_offset':base+fileoff,
                                    'file_size':filesize,'section_count':nsects})
        pos+=size
    if ncmds>command_limit:
        warnings.append(f'Load commands limited to {command_limit}')
    elif pos!=header+cmdbytes:
        warnings.append('Load-command sizes do not cover the declared command region')
    if symtab:
        off,count,strings,string_size=symtab; entry=16 if bits==64 else 12
        if off+count*entry>len(data) or strings+string_size>len(data):
            raise ValueError('Symbol/string table exceeds slice')
        row['symbol_count']=count
        for index in range(min(count,symbol_limit)):
            loc=off+index*entry
            name_index,typ,section,desc,value=struct.unpack_from(endian+('IBBHQ' if bits==64 else 'IBBHI'),data,loc)
            if name_index>=string_size: raise ValueError('Symbol name index exceeds string table')
            name=_cstring(data,strings+name_index,strings+string_size)
            row['symbols'].append({'name':name,'type':typ,'section':section,'description':desc,'value':value,'offset':base+loc})
        if count>symbol_limit: warnings.append(f'Symbols limited to {symbol_limit}')
    return row,warnings


@registry.tool(name='binary.macho_inventory',description='Inventory thin 32/64-bit and universal Mach-O headers, load commands, dylibs, rpaths, UUID, segments and bounded symbols without executing the sample. Code-signature presence is not cryptographic verification.',
 safety=SafetyLevel.READ_ONLY,tags=('binary','macho','macos','reverse','symbols'),produces=('macho_metadata','binary_symbols'),cost_hint='medium',
 path_roles={'path':'EVIDENCE_INPUT'},parameters={'type':'object','properties':{'path':{'type':'string'},
 'symbol_limit':{'type':'integer','default':2000,'minimum':1,'maximum':100000},
 'command_limit':{'type':'integer','default':4096,'minimum':1,'maximum':100000},
 'max_bytes':{'type':'integer','default':536870912,'minimum':1}},'required':['path']})
def macho_inventory(path:str,symbol_limit:int=2000,command_limit:int=4096,max_bytes:int=536870912)->Observation:
    tool='binary.macho_inventory'
    if any(isinstance(n,bool) or not isinstance(n,int) or n<1 for n in (symbol_limit,command_limit,max_bytes)):
        return Observation(tool,Status.ERROR,'Invalid Mach-O bounds',errors=['positive integer limits required'])
    data,error,digest=read_file_bounded_observation(tool,path,max_bytes)
    if error: return error
    if data[:4] not in _THIN and data[:4] not in _FAT:
        return Observation(tool,Status.UNSUPPORTED,'Not a Mach-O binary',meta={'source_sha256':digest})
    slices=[];warnings=[];errors=[]
    try:
        if data[:4] in _THIN:
            row,notes=_thin(data,0,symbol_limit,command_limit);slices.append(row);warnings.extend(notes)
        else:
            endian,is64=_FAT[data[:4]]
            if len(data)<8: raise ValueError('Truncated universal header')
            count=struct.unpack_from(endian+'I',data,4)[0];width=32 if is64 else 20
            if not 1<=count<=64 or 8+count*width>len(data): raise ValueError('Invalid/truncated universal architecture table')
            regions=[]
            for index in range(count):
                values=struct.unpack_from(endian+('IIQQII' if is64 else 'IIIII'),data,8+index*width)
                cpu,subtype,off,size,align=values[:5]
                if off<8+count*width or size<28 or off+size>len(data) or align>63 or off%(1<<align):
                    errors.append(f'Architecture {index}: invalid slice bounds/alignment');continue
                if any(off<other+length and other<off+size for other,length in regions):
                    errors.append(f'Architecture {index}: overlapping slice');continue
                regions.append((off,size))
                try:
                    row,notes=_thin(data[off:off+size],off,symbol_limit,command_limit)
                    if row['cpu_type']!=cpu or row['cpu_subtype']!=subtype:
                        notes.append(f'Architecture {index}: universal and slice CPU descriptors differ')
                    slices.append(row);warnings.extend(notes)
                except (ValueError,struct.error) as exc:
                    errors.append(f'Architecture {index}: {exc}')
    except (ValueError,struct.error) as exc:
        errors.append(str(exc))
    status=Status.ERROR if not slices else Status.PARTIAL if errors or warnings else Status.OK
    evidence=[Evidence(str(path),'macho_slice',row['cpu'],locator=f"offset:{row['offset']};size:{row['size']}",source_sha256=digest,method='Mach-O structural parser') for row in slices]
    return Observation(tool,status,f'Parsed {len(slices)} Mach-O slice(s)',facts={'universal':data[:4] in _FAT,'slices':slices},
                       evidence=evidence,warnings=warnings,errors=errors,meta={'source_sha256':digest})
