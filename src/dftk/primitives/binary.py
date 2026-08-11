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
import struct,re
from dftk.core.registry import registry
from dftk.core.models import Observation,Evidence,Status,SafetyLevel
from dftk.core.helpers import printable_strings,sha256_file

MACHINES={3:"x86",40:"ARM",62:"x86-64",183:"AArch64",243:"RISC-V"}

class ElfError(ValueError): pass

def parse_elf(data:bytes):
    if len(data)<52 or data[:4]!=b'\x7fELF': raise ElfError("not an ELF file")
    cls=data[4]; enc=data[5]
    if cls not in (1,2): raise ElfError("unsupported ELF class")
    if enc not in (1,2): raise ElfError("unsupported ELF encoding")
    endian='<' if enc==1 else '>'
    if cls==1:
        if len(data)<52: raise ElfError("truncated ELF32")
        e_machine=struct.unpack_from(endian+'H',data,18)[0]
        e_shoff=struct.unpack_from(endian+'I',data,32)[0]
        e_shentsize=struct.unpack_from(endian+'H',data,46)[0]; e_shnum=struct.unpack_from(endian+'H',data,48)[0]; e_shstrndx=struct.unpack_from(endian+'H',data,50)[0]
        fmt=endian+'IIIIIIIIII'; expected=40
    else:
        if len(data)<64: raise ElfError("truncated ELF64")
        e_machine=struct.unpack_from(endian+'H',data,18)[0]
        e_shoff=struct.unpack_from(endian+'Q',data,40)[0]
        e_shentsize=struct.unpack_from(endian+'H',data,58)[0]; e_shnum=struct.unpack_from(endian+'H',data,60)[0]; e_shstrndx=struct.unpack_from(endian+'H',data,62)[0]
        fmt=endian+'IIQQQQIIQQ'; expected=64
    if e_shentsize<expected or e_shoff+e_shentsize*e_shnum>len(data): raise ElfError("section header table outside file")
    raw=[]
    for i in range(e_shnum): raw.append(struct.unpack_from(fmt,data,e_shoff+i*e_shentsize))
    if e_shstrndx>=len(raw): raise ElfError("invalid section-name table index")
    shstr=raw[e_shstrndx]; str_off=str_shoff=shstr[4] if cls==2 else shstr[4]; str_size=shstr[5] if cls==2 else shstr[5]
    # layout keeps sh_offset/sh_size at tuple indexes 4/5 in both formats above
    if str_off+str_size>len(data): raise ElfError("section-name string table outside file")
    tab=data[str_off:str_off+str_size]
    def name_at(off):
        if off>=len(tab): return "<bad-name>"
        end=tab.find(b'\0',off); end=len(tab) if end<0 else end
        return tab[off:end].decode('utf-8','replace')
    sections=[]
    for i,sh in enumerate(raw):
        sec_off=sh[4]; sec_size=sh[5]
        sections.append({"index":i,"name":name_at(sh[0]),"type":sh[1],"offset":sec_off,"size":sec_size})
    return {"class":32 if cls==1 else 64,"endianness":"little" if enc==1 else "big","machine":MACHINES.get(e_machine,str(e_machine)),"machine_id":e_machine,"sections":sections}

@registry.tool(name="binary.elf_inventory",description="Parse ELF architecture and section metadata; optionally extract bounded printable strings.",safety=SafetyLevel.READ_ONLY,
 parameters={"type":"object","properties":{"path":{"type":"string"},"strings":{"type":"boolean","default":True},"string_limit":{"type":"integer","default":2000}},"required":["path"]})
def elf_inventory(path:str,strings:bool=True,string_limit:int=2000)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation("binary.elf_inventory",Status.ERROR,"ELF file not found",errors=[str(p)])
    data=p.read_bytes()
    try: info=parse_elf(data)
    except ElfError as e: return Observation("binary.elf_inventory",Status.UNSUPPORTED,"ELF parsing failed",errors=[str(e)],meta={"source_sha256":sha256_file(p)})
    rows=printable_strings(data,4)[:string_limit] if strings else []
    info["strings"]=[{"offset":o,"value":s} for o,s in rows]
    ev=[Evidence(str(p),"elf_section",s["name"],locator=f"offset:{s['offset']};size:{s['size']}") for s in info["sections"]]
    return Observation("binary.elf_inventory",Status.OK,f"Parsed ELF{info['class']} with {len(info['sections'])} sections",facts=info,evidence=ev,meta={"source_sha256":sha256_file(p)})

PE_MACHINES={0x014c:'x86',0x8664:'x86-64',0x01c0:'ARM',0xaa64:'ARM64'}

@registry.tool(name='binary.pe_inventory',description='Parse PE/COFF architecture, timestamp, characteristics and section table without executing the binary.',
 safety=SafetyLevel.READ_ONLY,tags=('binary','windows','pe'),produces=('pe_metadata',),
 parameters={'type':'object','properties':{'path':{'type':'string'},'strings':{'type':'boolean','default':False},'string_limit':{'type':'integer','default':2000}},'required':['path']})
def pe_inventory(path:str,strings:bool=False,string_limit:int=2000)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('binary.pe_inventory',Status.ERROR,'PE file not found',errors=[str(p)])
    data=p.read_bytes(); h=sha256_file(p)
    if len(data)<0x40 or data[:2]!=b'MZ': return Observation('binary.pe_inventory',Status.UNSUPPORTED,'Not an MZ/PE file',meta={'source_sha256':h})
    peoff=struct.unpack_from('<I',data,0x3c)[0]
    if peoff+24>len(data) or data[peoff:peoff+4]!=b'PE\0\0': return Observation('binary.pe_inventory',Status.UNSUPPORTED,'PE signature not found',meta={'source_sha256':h})
    machine,nsec,tstamp,_,_,opt_size,chars=struct.unpack_from('<HHIIIHH',data,peoff+4)
    sec_base=peoff+24+opt_size
    if sec_base+nsec*40>len(data): return Observation('binary.pe_inventory',Status.ERROR,'Section table outside file',meta={'source_sha256':h})
    magic=struct.unpack_from('<H',data,peoff+24)[0] if opt_size>=2 and peoff+26<=len(data) else 0
    sections=[]; ev=[]
    for i in range(nsec):
        off=sec_base+i*40; raw_name=data[off:off+8].split(b'\0',1)[0]; name=raw_name.decode('ascii','replace')
        vsize,vaddr,rsize,roff=struct.unpack_from('<IIII',data,off+8)
        schars=struct.unpack_from('<I',data,off+36)[0]
        row={'name':name,'virtual_size':vsize,'virtual_address':vaddr,'raw_size':rsize,'raw_offset':roff,'characteristics':f'0x{schars:08x}'}
        sections.append(row); ev.append(Evidence(str(p),'pe_section',name,locator=f'offset:{roff};size:{rsize}',source_sha256=h))
    facts={'machine':PE_MACHINES.get(machine,f'0x{machine:04x}'),'machine_id':machine,'sections':sections,'coff_timestamp':tstamp,'optional_magic':f'0x{magic:04x}','bitness':64 if magic==0x20b else 32 if magic==0x10b else None,'characteristics':f'0x{chars:04x}'}
    if strings:
        facts['strings']=[{'offset':o,'value':s} for o,s in printable_strings(data,4)[:string_limit]]
    return Observation('binary.pe_inventory',Status.OK,f'Parsed PE with {nsec} section(s)',facts=facts,evidence=ev,meta={'source_sha256':h})

@registry.tool(name='binary.native_indicator_scan',description='Heuristically scan a native binary for JNI names, crypto APIs, URLs and suspicious command/network indicators. Findings are indicators, not conclusions.',
 safety=SafetyLevel.READ_ONLY,tags=('binary','triage','native'),produces=('native_indicators',),
 parameters={'type':'object','properties':{'path':{'type':'string'},'limit':{'type':'integer','default':1000}},'required':['path']})
def native_indicator_scan(path:str,limit:int=1000)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('binary.native_indicator_scan',Status.ERROR,'Binary not found',errors=[str(p)])
    rows=printable_strings(p.read_bytes(),4); categories={
        'jni':re.compile(r'(?:Java_[A-Za-z0-9_]+|JNI_OnLoad|RegisterNatives)'),
        'crypto':re.compile(r'(?i)(?:AES|DES|RC4|ChaCha|EVP_|SHA(?:1|224|256|384|512)|MD5|Cipher|encrypt|decrypt)'),
        'url':re.compile(r'(?i)https?://[^\s"\']+'),
        'network':re.compile(r'\b(?:socket|connect|sendto|recvfrom|getaddrinfo|inet_addr)\b'),
        'command':re.compile(r'\b(?:system|popen|execve|/bin/sh|cmd\.exe|powershell)\b',re.I),
    }
    hits=[]; ev=[]
    for off,s in rows:
        cats=[name for name,rx in categories.items() if rx.search(s)]
        if not cats: continue
        hit={'offset':off,'value':s,'categories':cats}; hits.append(hit)
        ev.append(Evidence(str(p),'native_indicator',s,locator=f'offset:{off}',confidence=0.6,method='printable-string heuristic',note=','.join(cats)))
        if len(hits)>=limit: break
    warnings=['indicator scan is heuristic and must be corroborated with structural/disassembly evidence']
    if len(hits)>=limit: warnings.append(f'results limited to {limit}')
    return Observation('binary.native_indicator_scan',Status.OK,f'Found {len(hits)} native indicator string(s)',facts={'matches':hits},evidence=ev[:300],warnings=warnings,meta={'source_sha256':sha256_file(p)})
