import struct,zipfile
from dftk.primitives.android import parse_axml,apk_manifest,apk_signing_inventory,RES_STRING_POOL_TYPE,RES_XML_TYPE,RES_XML_START_NAMESPACE_TYPE,RES_XML_START_ELEMENT_TYPE,RES_XML_END_ELEMENT_TYPE,UTF8_FLAG,NO_INDEX,TYPE_STRING


def _chunk(typ,header,size_body,body=b''):
    return struct.pack('<HHI',typ,header,8+len(size_body)+len(body))+size_body+body


def _string_pool(strings):
    blobs=[]; offs=[]; pos=0
    for s in strings:
        b=s.encode('utf-8'); blob=bytes([len(s),len(b)])+b+b'\x00'; offs.append(pos); blobs.append(blob); pos+=len(blob)
    header_size=28; strings_start=header_size+4*len(strings)
    payload=struct.pack('<IIIII',len(strings),0,UTF8_FLAG,strings_start,0)+b''.join(struct.pack('<I',o) for o in offs)+b''.join(blobs)
    size=8+len(payload)
    return struct.pack('<HHI',RES_STRING_POOL_TYPE,header_size,size)+payload


def _node_header(typ,size,line=1):
    return struct.pack('<HHIII',typ,16,size,line,NO_INDEX)


def _start_ns(prefix_idx,uri_idx):
    return _node_header(RES_XML_START_NAMESPACE_TYPE,24)+struct.pack('<II',prefix_idx,uri_idx)


def _start_element(name_idx,attrs):
    # attrs: (ns_idx,name_idx,raw_idx,type,data)
    attr_bytes=b''
    for ns,name,raw,dtype,data in attrs:
        attr_bytes+=struct.pack('<IIIHBBI',ns,name,raw,8,0,dtype,data)
    ext=struct.pack('<IIHHHHHH',NO_INDEX,name_idx,20,20,len(attrs),0,0,0)
    size=16+len(ext)+len(attr_bytes)
    return _node_header(RES_XML_START_ELEMENT_TYPE,size)+ext+attr_bytes


def _end_element(name_idx):
    return _node_header(RES_XML_END_ELEMENT_TYPE,24)+struct.pack('<II',NO_INDEX,name_idx)


def _axml_bytes():
    strings=['manifest','package','com.example.app','android','http://schemas.android.com/apk/res/android','uses-permission','name','android.permission.INTERNET']
    idx={s:i for i,s in enumerate(strings)}
    chunks=[_string_pool(strings),_start_ns(idx['android'],idx['http://schemas.android.com/apk/res/android']),
            _start_element(idx['manifest'],[(NO_INDEX,idx['package'],idx['com.example.app'],TYPE_STRING,idx['com.example.app'])]),
            _start_element(idx['uses-permission'],[(idx['http://schemas.android.com/apk/res/android'],idx['name'],idx['android.permission.INTERNET'],TYPE_STRING,idx['android.permission.INTERNET'])]),
            _end_element(idx['uses-permission']),_end_element(idx['manifest'])]
    total=8+sum(len(c) for c in chunks)
    return struct.pack('<HHI',RES_XML_TYPE,8,total)+b''.join(chunks)


def test_parse_binary_axml_and_apk_manifest(tmp_path):
    raw=_axml_bytes(); parsed=parse_axml(raw)
    assert any(e['name']=='manifest' for e in parsed['elements'])
    p=tmp_path/'a.apk'
    with zipfile.ZipFile(p,'w') as z:
        z.writestr('AndroidManifest.xml',raw); z.writestr('classes.dex',b'dex\n035\x00'+b'\0'*104)
    obs=apk_manifest(str(p)); summary=obs.facts['summary']
    assert summary['package']=='com.example.app'; assert 'android.permission.INTERNET' in summary['permissions']


def test_apk_v1_signing_marker(tmp_path):
    p=tmp_path/'signed.apk'
    with zipfile.ZipFile(p,'w') as z:
        z.writestr('AndroidManifest.xml',_axml_bytes()); z.writestr('META-INF/CERT.RSA',b'x'); z.writestr('META-INF/CERT.SF',b'x')
    obs=apk_signing_inventory(str(p)); assert 'v1' in obs.facts['schemes_detected']

from dftk.primitives.android import apk_endpoints

def _simple_dex_with_strings(strings):
    # Minimal DEX string table sufficient for the toolkit parser tests.
    header=bytearray(0x70); header[:8]=b'dex\n035\x00'; struct.pack_into('<I',header,0x28,0x12345678)
    ids_off=0x70; data_off=ids_off+4*len(strings); ids=[]; payload=b''
    for s in strings:
        b=s.encode(); ids.append(data_off+len(payload)); payload+=bytes([len(s)])+b+b'\x00'
    struct.pack_into('<I',header,0x38,len(strings)); struct.pack_into('<I',header,0x3c,ids_off)
    return bytes(header)+b''.join(struct.pack('<I',x) for x in ids)+payload

def test_apk_endpoint_extraction(tmp_path):
    p=tmp_path/'e.apk'
    dex=_simple_dex_with_strings(['https://api.example.com/v1','content://com.example.provider/items','8.8.8.8:53'])
    with zipfile.ZipFile(p,'w') as z: z.writestr('AndroidManifest.xml',_axml_bytes()); z.writestr('classes.dex',dex)
    obs=apk_endpoints(str(p)); vals={x['value'] for x in obs.facts['endpoints']}
    assert 'https://api.example.com/v1' in vals; assert '8.8.8.8:53' in vals
