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
from dataclasses import dataclass
from pathlib import Path
import struct, zipfile, hashlib, re
from dftk.core.registry import registry
from dftk.core.models import Observation, Evidence, Status, SafetyLevel
from dftk.core.helpers import sha256_file

class DexFormatError(ValueError): pass

@dataclass
class DexString:
    index:int; data_offset:int; utf16_size:int; value:str

def _read_uleb128(data: bytes, off: int) -> tuple[int,int]:
    result=0; shift=0
    for _ in range(5):
        if off>=len(data): raise DexFormatError("truncated ULEB128")
        b=data[off]; off+=1
        result |= (b & 0x7f) << shift
        if not (b & 0x80): return result,off
        shift += 7
    raise DexFormatError("ULEB128 too long")

def _decode_mutf8(raw: bytes) -> str:
    # DEX uses Java modified UTF-8. Decode to UTF-16 code units first, then combine surrogate pairs.
    units=[]; i=0
    while i < len(raw):
        b=raw[i]
        if b == 0: break
        if b < 0x80:
            units.append(b); i+=1; continue
        if (b & 0xE0)==0xC0 and i+1<len(raw):
            b2=raw[i+1]
            if (b2 & 0xC0)!=0x80: units.append(0xfffd); i+=1; continue
            units.append(((b & 0x1f)<<6)|(b2&0x3f)); i+=2; continue
        if (b & 0xF0)==0xE0 and i+2<len(raw):
            b2,b3=raw[i+1],raw[i+2]
            if (b2&0xC0)!=0x80 or (b3&0xC0)!=0x80: units.append(0xfffd); i+=1; continue
            units.append(((b&0x0f)<<12)|((b2&0x3f)<<6)|(b3&0x3f)); i+=3; continue
        units.append(0xfffd); i+=1
    out=[]; i=0
    while i<len(units):
        u=units[i]
        if 0xD800<=u<=0xDBFF and i+1<len(units) and 0xDC00<=units[i+1]<=0xDFFF:
            cp=0x10000+((u-0xD800)<<10)+(units[i+1]-0xDC00); out.append(chr(cp)); i+=2
        elif 0xD800<=u<=0xDFFF: out.append('\ufffd'); i+=1
        else: out.append(chr(u)); i+=1
    return ''.join(out)

def parse_dex_strings(data: bytes) -> list[DexString]:
    if len(data)<0x70: raise DexFormatError("file too small for DEX header")
    if data[:4] != b"dex\n":
        raise DexFormatError(f"unsupported DEX magic {data[:8]!r}")
    endian_tag=struct.unpack_from('<I',data,0x28)[0]
    if endian_tag != 0x12345678: raise DexFormatError("reverse-endian DEX is not supported")
    string_ids_size=struct.unpack_from('<I',data,0x38)[0]
    string_ids_off=struct.unpack_from('<I',data,0x3c)[0]
    if string_ids_off + string_ids_size*4 > len(data): raise DexFormatError("string_ids table outside file")
    rows=[]
    for idx in range(string_ids_size):
        data_off=struct.unpack_from('<I',data,string_ids_off+idx*4)[0]
        if data_off>=len(data): raise DexFormatError(f"string {idx} data offset outside file")
        utf16_size,pos=_read_uleb128(data,data_off)
        end=data.find(b'\x00',pos)
        if end<0: raise DexFormatError(f"unterminated string {idx}")
        rows.append(DexString(idx,data_off,utf16_size,_decode_mutf8(data[pos:end])))
    return rows

@registry.tool(name="android.dex_strings",description="Parse the DEX string table using ULEB128 string_data_item and modified UTF-8.",safety=SafetyLevel.READ_ONLY,
 parameters={"type":"object","properties":{"path":{"type":"string"},"contains":{"type":"string"},"regex":{"type":"string"},"limit":{"type":"integer","default":10000}},"required":["path"]})
def dex_strings(path:str, contains:str|None=None, regex:str|None=None, limit:int=10000)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation("android.dex_strings",Status.ERROR,"DEX file not found",errors=[str(p)])
    try: rows=parse_dex_strings(p.read_bytes())
    except DexFormatError as e: return Observation("android.dex_strings",Status.UNSUPPORTED,"DEX parsing failed",errors=[str(e)],meta={"source_sha256":sha256_file(p)})
    try: rx=re.compile(regex) if regex else None
    except re.error as e: return Observation("android.dex_strings",Status.ERROR,"Invalid regular expression",errors=[str(e)])
    filtered=[]
    for r in rows:
        if contains is not None and contains.lower() not in r.value.lower(): continue
        if rx is not None and not rx.search(r.value): continue
        filtered.append(r)
        if len(filtered)>=limit: break
    evidence=[Evidence(str(p),"dex_string",r.value,locator=f"string_id:{r.index};offset:{r.data_offset}") for r in filtered[:300]]
    return Observation("android.dex_strings",Status.OK,f"Parsed {len(rows)} DEX strings; returned {len(filtered)}",facts={"total":len(rows),"matches":[r.__dict__ for r in filtered]},evidence=evidence,
        warnings=[f"matches limited to {limit}"] if len(filtered)>=limit else [],meta={"source_sha256":sha256_file(p)})

@registry.tool(name="android.apk_inventory",description="Inventory APK ZIP members, DEX files, native libraries, certificates and manifest presence.",safety=SafetyLevel.READ_ONLY,
 parameters={"type":"object","properties":{"path":{"type":"string"}},"required":["path"]})
def apk_inventory(path:str)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation("android.apk_inventory",Status.ERROR,"APK not found",errors=[str(p)])
    if not zipfile.is_zipfile(p): return Observation("android.apk_inventory",Status.UNSUPPORTED,"Input is not a ZIP/APK",meta={"source_sha256":sha256_file(p)})
    with zipfile.ZipFile(p) as z:
        names=z.namelist()
        dex=sorted(n for n in names if re.fullmatch(r"classes(?:\d+)?\.dex",n))
        libs=sorted(n for n in names if n.startswith("lib/") and n.endswith(".so"))
        certs=sorted(n for n in names if n.upper().startswith("META-INF/") and n.upper().endswith((".RSA",".DSA",".EC",".SF")))
        manifest="AndroidManifest.xml" if "AndroidManifest.xml" in names else None
        assets=sum(1 for n in names if n.startswith("assets/") and not n.endswith('/'))
        res=sum(1 for n in names if n.startswith("res/") and not n.endswith('/'))
        dex_hashes={n:hashlib.sha256(z.read(n)).hexdigest() for n in dex}
    ev=[Evidence(str(p),"apk_entry",n,locator=f"zip:{n}") for n in (dex+libs+certs)[:300]]
    return Observation("android.apk_inventory",Status.OK,"APK inventory complete",facts={"entries":len(names),"dex":dex,"dex_sha256":dex_hashes,"native_libraries":libs,"signing_entries":certs,"manifest":manifest,"asset_files":assets,"resource_files":res},evidence=ev,meta={"source_sha256":sha256_file(p)})

@registry.tool(name="android.apk_search",description="Search parsed DEX string tables inside an APK for a literal or regular expression.",safety=SafetyLevel.READ_ONLY,
 parameters={"type":"object","properties":{"path":{"type":"string"},"query":{"type":"string"},"regex":{"type":"boolean","default":False},"limit":{"type":"integer","default":500}},"required":["path","query"]})
def apk_search(path:str,query:str,regex:bool=False,limit:int=500)->Observation:
    p=Path(path)
    if not zipfile.is_zipfile(p): return Observation("android.apk_search",Status.UNSUPPORTED,"Input is not a ZIP/APK")
    hits=[]; errors=[]
    try: rx=re.compile(query) if regex else None
    except re.error as e: return Observation("android.apk_search",Status.ERROR,"Invalid regular expression",errors=[str(e)])
    with zipfile.ZipFile(p) as z:
        for name in sorted(z.namelist()):
            if not re.fullmatch(r"classes(?:\d+)?\.dex",name): continue
            try: rows=parse_dex_strings(z.read(name))
            except DexFormatError as e: errors.append(f"{name}: {e}"); continue
            for r in rows:
                matched=bool(rx.search(r.value)) if rx else query.lower() in r.value.lower()
                if matched:
                    hits.append({"dex":name,"index":r.index,"offset":r.data_offset,"value":r.value})
                    if len(hits)>=limit: break
            if len(hits)>=limit: break
    status=Status.PARTIAL if errors else Status.OK
    ev=[Evidence(str(p),"apk_dex_string",h["value"],locator=f"zip:{h['dex']};string_id:{h['index']};offset:{h['offset']}") for h in hits[:300]]
    return Observation("android.apk_search",status,f"Found {len(hits)} matching DEX string(s)",facts={"matches":hits},evidence=ev,warnings=errors,
        meta={"source_sha256":sha256_file(p)})

# ---- Android binary XML (AXML) manifest support ----
RES_STRING_POOL_TYPE=0x0001
RES_XML_TYPE=0x0003
RES_XML_START_NAMESPACE_TYPE=0x0100
RES_XML_END_NAMESPACE_TYPE=0x0101
RES_XML_START_ELEMENT_TYPE=0x0102
RES_XML_END_ELEMENT_TYPE=0x0103
TYPE_REFERENCE=0x01
TYPE_STRING=0x03
TYPE_INT_DEC=0x10
TYPE_INT_HEX=0x11
TYPE_INT_BOOLEAN=0x12
UTF8_FLAG=0x00000100
NO_INDEX=0xffffffff
ANDROID_NS='http://schemas.android.com/apk/res/android'

class AxmlError(ValueError): pass

def _u16(data:bytes,off:int)->int:
    if off+2>len(data): raise AxmlError('truncated uint16')
    return struct.unpack_from('<H',data,off)[0]

def _u32(data:bytes,off:int)->int:
    if off+4>len(data): raise AxmlError('truncated uint32')
    return struct.unpack_from('<I',data,off)[0]

def _len8(data:bytes,off:int)->tuple[int,int]:
    if off>=len(data): raise AxmlError('truncated UTF-8 length')
    a=data[off]; off+=1
    if a&0x80:
        if off>=len(data): raise AxmlError('truncated UTF-8 length')
        return ((a&0x7f)<<8)|data[off],off+1
    return a,off

def _len16(data:bytes,off:int)->tuple[int,int]:
    a=_u16(data,off); off+=2
    if a&0x8000:
        b=_u16(data,off); off+=2
        return ((a&0x7fff)<<16)|b,off
    return a,off

def _parse_string_pool(data:bytes,start:int)->tuple[list[str],int]:
    if _u16(data,start)!=RES_STRING_POOL_TYPE: raise AxmlError('expected string pool')
    header_size=_u16(data,start+2); size=_u32(data,start+4)
    if header_size<28 or start+size>len(data): raise AxmlError('invalid string pool bounds')
    count=_u32(data,start+8); flags=_u32(data,start+16); strings_start=_u32(data,start+20)
    offsets_start=start+header_size
    if offsets_start+count*4>start+size: raise AxmlError('string offsets outside pool')
    out=[]; utf8=bool(flags&UTF8_FLAG)
    for i in range(count):
        rel=_u32(data,offsets_start+i*4); pos=start+strings_start+rel
        if pos>=start+size: raise AxmlError(f'string {i} outside pool')
        if utf8:
            _,pos=_len8(data,pos); byte_len,pos=_len8(data,pos)
            if pos+byte_len>start+size: raise AxmlError(f'string {i} truncated')
            out.append(data[pos:pos+byte_len].decode('utf-8','replace'))
        else:
            chars,pos=_len16(data,pos); byte_len=chars*2
            if pos+byte_len>start+size: raise AxmlError(f'string {i} truncated')
            out.append(data[pos:pos+byte_len].decode('utf-16le','replace'))
    return out,start+size

def _sp(strings:list[str],idx:int)->str|None:
    return None if idx==NO_INDEX or idx>=len(strings) else strings[idx]

def _typed_value(strings:list[str],dtype:int,data:int,raw:int)->object:
    if raw!=NO_INDEX:
        v=_sp(strings,raw)
        if v is not None: return v
    if dtype==TYPE_STRING: return _sp(strings,data) or ''
    if dtype==TYPE_INT_BOOLEAN: return bool(data)
    if dtype==TYPE_INT_DEC: return data
    if dtype==TYPE_INT_HEX: return f'0x{data:x}'
    if dtype==TYPE_REFERENCE: return f'@0x{data:08x}'
    return {'type':dtype,'data':data}

def parse_axml(data:bytes)->dict:
    if len(data)<8 or _u16(data,0)!=RES_XML_TYPE: raise AxmlError('not Android binary XML')
    total=_u32(data,4)
    if total>len(data): raise AxmlError('AXML declared size exceeds input')
    off=_u16(data,2)
    strings=[]; namespaces={}; elements=[]; stack=[]
    while off+8<=min(total,len(data)):
        typ=_u16(data,off); header=_u16(data,off+2); size=_u32(data,off+4)
        if size<8 or off+size>len(data): raise AxmlError(f'invalid chunk at {off}')
        if typ==RES_STRING_POOL_TYPE:
            strings,_=_parse_string_pool(data,off)
        elif typ==RES_XML_START_NAMESPACE_TYPE and header>=16:
            prefix=_sp(strings,_u32(data,off+16)); uri=_sp(strings,_u32(data,off+20))
            if uri is not None: namespaces[uri]=prefix or ''
        elif typ==RES_XML_START_ELEMENT_TYPE and header>=16:
            ns_idx=_u32(data,off+16); name_idx=_u32(data,off+20)
            attr_start=_u16(data,off+24); attr_size=_u16(data,off+26); attr_count=_u16(data,off+28)
            name=_sp(strings,name_idx) or f'<string:{name_idx}>'; ns=_sp(strings,ns_idx)
            attrs={}; base=off+16+attr_start
            if attr_size<20 and attr_count: raise AxmlError('invalid attribute size')
            for i in range(attr_count):
                a=base+i*attr_size
                if a+20>off+size: raise AxmlError('attribute outside element chunk')
                ans=_sp(strings,_u32(data,a)); aname=_sp(strings,_u32(data,a+4)) or f'<string:{_u32(data,a+4)}>'
                raw=_u32(data,a+8); dtype=data[a+15]; valdata=_u32(data,a+16)
                key=f'android:{aname}' if ans==ANDROID_NS else aname
                attrs[key]=_typed_value(strings,dtype,valdata,raw)
            row={'name':name,'namespace':ns,'attributes':attrs,'depth':len(stack),'offset':off}
            elements.append(row); stack.append(name)
        elif typ==RES_XML_END_ELEMENT_TYPE:
            if stack: stack.pop()
        off+=size
    return {'strings':strings,'namespaces':namespaces,'elements':elements}

def _manifest_summary(parsed:dict)->dict:
    elements=parsed['elements']; summary={'package':None,'version_code':None,'version_name':None,'permissions':[],'sdk':{},'application':{},'components':[],'intent_actions':[]}
    for e in elements:
        a=e['attributes']; name=e['name']
        if name=='manifest':
            summary['package']=a.get('package'); summary['version_code']=a.get('android:versionCode'); summary['version_name']=a.get('android:versionName')
        elif name=='uses-permission':
            v=a.get('android:name') or a.get('name')
            if v and v not in summary['permissions']: summary['permissions'].append(v)
        elif name=='uses-sdk':
            summary['sdk']={k:v for k,v in a.items() if k in ('android:minSdkVersion','android:targetSdkVersion','android:maxSdkVersion')}
        elif name=='application':
            summary['application']={k:v for k,v in a.items() if k in ('android:name','android:debuggable','android:allowBackup','android:usesCleartextTraffic','android:networkSecurityConfig')}
        elif name in ('activity','activity-alias','service','receiver','provider'):
            summary['components'].append({'type':name,'name':a.get('android:name'),'exported':a.get('android:exported'),'permission':a.get('android:permission'),'authorities':a.get('android:authorities')})
        elif name=='action':
            v=a.get('android:name')
            if v and v not in summary['intent_actions']: summary['intent_actions'].append(v)
    return summary

@registry.tool(name='android.apk_manifest',description='Parse AndroidManifest.xml from an APK, including binary AXML, and summarize package, permissions, SDK and components.',
 safety=SafetyLevel.READ_ONLY,tags=('android','apk','manifest'),produces=('android_manifest','permissions','components'),
 parameters={'type':'object','properties':{'path':{'type':'string'},'include_elements':{'type':'boolean','default':False}},'required':['path']})
def apk_manifest(path:str,include_elements:bool=False)->Observation:
    p=Path(path)
    if not p.is_file() or not zipfile.is_zipfile(p): return Observation('android.apk_manifest',Status.UNSUPPORTED,'Input is not an APK/ZIP')
    try:
        with zipfile.ZipFile(p) as z: raw=z.read('AndroidManifest.xml')
    except KeyError: return Observation('android.apk_manifest',Status.UNSUPPORTED,'AndroidManifest.xml is absent',meta={'source_sha256':sha256_file(p)})
    try:
        if raw.lstrip().startswith(b'<'):
            import xml.etree.ElementTree as ET
            root=ET.fromstring(raw)
            return Observation('android.apk_manifest',Status.PARTIAL,'Plain XML manifest detected; binary AXML structured summary is not required',facts={'root_tag':root.tag,'package':root.attrib.get('package')},evidence=[Evidence(str(p),'manifest','plain_xml',locator='zip:AndroidManifest.xml')],warnings=['plain XML manifest: only root metadata summarized'],meta={'source_sha256':sha256_file(p)})
        parsed=parse_axml(raw); summary=_manifest_summary(parsed)
        facts={'summary':summary,'element_count':len(parsed['elements']),'string_count':len(parsed['strings'])}
        if include_elements: facts['elements']=parsed['elements']
        ev=[Evidence(str(p),'manifest_field',v,locator='zip:AndroidManifest.xml') for v in ([summary['package']] if summary['package'] else [])]
        ev.extend(Evidence(str(p),'permission',v,locator='zip:AndroidManifest.xml') for v in summary['permissions'][:200])
        return Observation('android.apk_manifest',Status.OK,'Android manifest parsed',facts=facts,evidence=ev,meta={'source_sha256':sha256_file(p)})
    except (AxmlError,ValueError,struct.error) as e:
        return Observation('android.apk_manifest',Status.UNSUPPORTED,'Android manifest parsing failed',errors=[str(e)],meta={'source_sha256':sha256_file(p)})

APK_SIG_MAGIC=b'APK Sig Block 42'
APK_SIG_IDS={0x7109871a:'v2',0xf05368c0:'v3',0x1b93ad61:'v3.1',0x6dff800d:'source_stamp'}

def _apk_signing_block(data:bytes)->dict:
    # Find the last End of Central Directory and inspect the block immediately before central directory.
    pos=data.rfind(b'PK\x05\x06',max(0,len(data)-65557))
    if pos<0 or pos+22>len(data): return {'present':False,'schemes':[],'ids':[]}
    cd_off=struct.unpack_from('<I',data,pos+16)[0]
    if cd_off<24 or cd_off>len(data): return {'present':False,'schemes':[],'ids':[]}
    footer=cd_off-24
    if data[footer+8:footer+24]!=APK_SIG_MAGIC: return {'present':False,'schemes':[],'ids':[]}
    size=struct.unpack_from('<Q',data,footer)[0]; start=cd_off-(size+8)
    if start<0 or start+8>footer: return {'present':False,'schemes':[],'ids':[],'error':'invalid signing block size'}
    if struct.unpack_from('<Q',data,start)[0]!=size: return {'present':False,'schemes':[],'ids':[],'error':'signing block size mismatch'}
    ids=[]; cur=start+8
    while cur<footer:
        if cur+8>footer: break
        pair_len=struct.unpack_from('<Q',data,cur)[0]; cur+=8
        if pair_len<4 or cur+pair_len>footer: break
        ident=struct.unpack_from('<I',data,cur)[0]; ids.append(ident); cur+=pair_len
    schemes=[APK_SIG_IDS[i] for i in ids if i in APK_SIG_IDS]
    return {'present':True,'offset':start,'size':size+8,'ids':[f'0x{i:08x}' for i in ids],'schemes':schemes}

@registry.tool(name='android.apk_signing_inventory',description='Detect APK v1 signing entries and APK Signing Block scheme IDs (v2/v3/v3.1/source stamp) without modifying the APK.',
 safety=SafetyLevel.READ_ONLY,tags=('android','apk','signing'),produces=('apk_signing',),
 parameters={'type':'object','properties':{'path':{'type':'string'}},'required':['path']})
def apk_signing_inventory(path:str)->Observation:
    p=Path(path)
    if not p.is_file() or not zipfile.is_zipfile(p): return Observation('android.apk_signing_inventory',Status.UNSUPPORTED,'Input is not an APK/ZIP')
    data=p.read_bytes(); block=_apk_signing_block(data)
    with zipfile.ZipFile(p) as z:
        names=z.namelist(); v1=[n for n in names if n.upper().startswith('META-INF/') and n.upper().endswith(('.RSA','.DSA','.EC','.SF'))]
    schemes=[]
    if v1: schemes.append('v1')
    schemes.extend(s for s in block.get('schemes',[]) if s not in schemes)
    facts={'schemes_detected':schemes,'v1_entries':v1,'signing_block':block}
    ev=[Evidence(str(p),'apk_signing_scheme',s,locator='META-INF' if s=='v1' else f"offset:{block.get('offset','')}") for s in schemes]
    return Observation('android.apk_signing_inventory',Status.OK,f"Detected APK signing scheme marker(s): {', '.join(schemes) if schemes else 'none'}",facts=facts,evidence=ev,meta={'source_sha256':sha256_file(p)})

@registry.tool(name='android.appdata_inventory',description='Inventory an extracted Android app data directory (shared_prefs, databases, files, cache) without modifying it.',
 safety=SafetyLevel.READ_ONLY,tags=('android','appdata','filesystem'),produces=('android_appdata','database_candidates','shared_preferences'),cost_hint='medium',
 parameters={'type':'object','properties':{'root':{'type':'string'},'max_files':{'type':'integer','default':20000}},'required':['root']})
def appdata_inventory(root:str,max_files:int=20000)->Observation:
    import xml.etree.ElementTree as ET
    from dftk.core.helpers import bounded_files,safe_rel
    r=Path(root)
    if not r.is_dir(): return Observation('android.appdata_inventory',Status.ERROR,'App data directory not found',errors=[str(r)])
    dbs=[]; prefs=[]; files=[]; warnings=[]
    for f in bounded_files(r,max_files=max_files):
        try: size=f.stat().st_size
        except OSError: continue
        rel=safe_rel(f,r); low=rel.replace('\\','/').lower()
        row={'path':str(f),'relative':rel,'size':size}
        if '/databases/' in '/'+low or f.suffix.lower() in ('.db','.sqlite','.sqlite3'):
            dbs.append(row)
        if '/shared_prefs/' in '/'+low and f.suffix.lower()=='.xml':
            pref={'path':str(f),'relative':rel,'size':size,'entries':{}}
            if size<=4*1024*1024:
                try:
                    root_xml=ET.fromstring(f.read_bytes())
                    entries={}
                    for child in root_xml:
                        key=child.attrib.get('name')
                        if not key: continue
                        if child.tag=='string': val=child.text or ''
                        elif child.tag in ('int','long','float','boolean'): val=child.attrib.get('value')
                        elif child.tag=='set': val=[x.text or '' for x in child if x.tag=='string']
                        else: val=child.attrib.get('value') or child.text
                        entries[key]={'type':child.tag,'value':val}
                    pref['entries']=entries
                except (ET.ParseError,OSError) as e:
                    warnings.append(f'{f}: shared_prefs parse failed: {e}')
            prefs.append(pref)
        if len(files)<1000:
            files.append(row)
    ev=[]
    for p in prefs[:200]: ev.append(Evidence(p['path'],'shared_preferences',list(p.get('entries',{}).keys()),locator='XML map',method='Android SharedPreferences XML'))
    for d in dbs[:200]: ev.append(Evidence(d['path'],'database_candidate',d['relative'],locator='file'))
    return Observation('android.appdata_inventory',Status.PARTIAL if warnings else Status.OK,f'Inventoried Android app data: {len(prefs)} preference file(s), {len(dbs)} database candidate(s)',facts={'shared_preferences':prefs,'database_candidates':dbs,'sample_files':files},evidence=ev,warnings=warnings)

@registry.tool(name='android.apk_endpoints',description='Extract URL/domain/IP/content-URI endpoint candidates from parsed DEX strings across an APK with source DEX/string locators.',
 safety=SafetyLevel.READ_ONLY,tags=('android','apk','network'),produces=('endpoints','domains','urls'),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'limit':{'type':'integer','default':2000}},'required':['path']})
def apk_endpoints(path:str,limit:int=2000)->Observation:
    p=Path(path)
    if not p.is_file() or not zipfile.is_zipfile(p): return Observation('android.apk_endpoints',Status.UNSUPPORTED,'Input is not an APK/ZIP')
    url_rx=re.compile(r'https?://[^\s"\'<>]+',re.I)
    content_rx=re.compile(r'content://[^\s"\'<>]+',re.I)
    ip_rx=re.compile(r'(?<!\d)(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?::\d{1,5})?(?!\d)')
    domain_rx=re.compile(r'(?i)(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?::\d{1,5})?')
    found=[]; seen=set(); errors=[]
    def add(kind,value,dex,row):
        key=(kind,value.lower())
        if key in seen or len(found)>=limit: return
        seen.add(key); found.append({'kind':kind,'value':value,'dex':dex,'string_id':row.index,'offset':row.data_offset})
    with zipfile.ZipFile(p) as z:
        for name in sorted(z.namelist()):
            if not re.fullmatch(r'classes(?:\d+)?\.dex',name): continue
            try: rows=parse_dex_strings(z.read(name))
            except DexFormatError as e: errors.append(f'{name}: {e}'); continue
            for row in rows:
                for m in url_rx.finditer(row.value): add('url',m.group(0),name,row)
                for m in content_rx.finditer(row.value): add('content_uri',m.group(0),name,row)
                for m in ip_rx.finditer(row.value): add('ip',m.group(0),name,row)
                # Domain matches inside already-extracted URLs are still useful as a normalized host candidate.
                for m in domain_rx.finditer(row.value): add('domain',m.group(0),name,row)
                if len(found)>=limit: break
            if len(found)>=limit: break
    ev=[Evidence(str(p),f"apk_{x['kind']}",x['value'],locator=f"zip:{x['dex']};string_id:{x['string_id']};offset:{x['offset']}",confidence=0.8 if x['kind'] in ('url','content_uri') else 0.65,method='DEX string endpoint extraction') for x in found[:300]]
    warnings=list(errors)
    if len(found)>=limit: warnings.append(f'results limited to {limit}')
    return Observation('android.apk_endpoints',Status.PARTIAL if errors else Status.OK,f'Extracted {len(found)} endpoint candidate(s)',facts={'endpoints':found},evidence=ev,warnings=warnings,meta={'source_sha256':sha256_file(p)})
