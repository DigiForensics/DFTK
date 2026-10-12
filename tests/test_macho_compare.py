"""Independent structural fixtures plus local native Mach-O compatibility."""
import hashlib
from pathlib import Path
import struct
import pytest
import dftk
from dftk.primitives.binary_compare import compare
from dftk.primitives.macho import macho_inventory


def _thin(endian='<',bits=64):
    dylib=b'/usr/lib/libSystem.B.dylib\0'
    size=((24+len(dylib)+7)//8)*8
    load=struct.pack(endian+'6I',0xc,size,24,0,0,0)+dylib
    load+=b'\0'*(size-len(load))
    uid=struct.pack(endian+'II',0x1b,24)+bytes.fromhex('00112233445566778899aabbccddeeff')
    header_size=32 if bits==64 else 28
    symbol_offset=header_size+len(load)+len(uid)+24
    name=b'\0_example\0';symbol_size=16 if bits==64 else 12
    sym=struct.pack(endian+'6I',2,24,symbol_offset,1,symbol_offset+symbol_size,len(name))
    header=struct.pack(endian+'7I',0xfeedfacf if bits==64 else 0xfeedface,0x0100000c if bits==64 else 7,0,2,3,len(load)+len(uid)+len(sym),0x200000)
    if bits==64:header+=b'\0'*4
    entry=struct.pack(endian+('IBBHQ' if bits==64 else 'IBBHI'),1,0xf,1,0,0x1000)
    return header+load+uid+sym+entry+name


@pytest.mark.parametrize('endian,bits',[('<',32),('>',32),('<',64),('>',64)])
def test_thin_macho_endianness_symbols_and_uuid(tmp_path,endian,bits):
    p=tmp_path/'sample';data=_thin(endian,bits);p.write_bytes(data)
    result=macho_inventory(str(p))
    assert result.status.value=='ok',result.errors
    row=result.facts['slices'][0]
    assert row['bitness']==bits and row['symbols'][0]['name']=='_example'
    assert row['uuid']=='00112233-4455-6677-8899-aabbccddeeff'
    assert row['dylibs'][0]['value']=='/usr/lib/libSystem.B.dylib'
    assert row['pie'] and result.evidence[0].source_sha256==hashlib.sha256(data).hexdigest()
    assert p.read_bytes()==data


@pytest.mark.parametrize('wide,endian',[(False,'>'),(False,'<'),(True,'>'),(True,'<')])
def test_universal_layouts(tmp_path,wide,endian):
    thin=_thin();offset=64
    header=struct.pack(endian+'II',0xcafebabf if wide else 0xcafebabe,1)
    entry=struct.pack(endian+('IIQQII' if wide else 'IIIII'),*(0x0100000c,0,offset,len(thin),0,*((0,) if wide else ())))
    p=tmp_path/'universal';p.write_bytes(header+entry+b'\0'*(offset-len(header)-len(entry))+thin)
    result=macho_inventory(str(p))
    assert result.status.value=='ok',result.errors
    assert result.facts['universal'] and result.facts['slices'][0]['offset']==offset


def test_macho_malformed_command_and_truncated_header(tmp_path):
    p=tmp_path/'sample';p.write_bytes(b'\xcf\xfa\xed\xfe')
    assert macho_inventory(str(p)).status.value=='error'
    data=bytearray(_thin());struct.pack_into('<I',data,36,4);p.write_bytes(data)
    assert macho_inventory(str(p)).status.value=='error'
    p.write_bytes(b'MZ');assert macho_inventory(str(p)).status.value=='unsupported'
    p.write_bytes(_thin());assert macho_inventory(str(p),command_limit=1).status.value=='partial'
    assert macho_inventory(str(p),max_bytes=2).status.value=='unsupported'


def test_invalid_universal_slice_does_not_discard_good_slice(tmp_path):
    thin=_thin();start=64
    header=struct.pack('>II',0xcafebabe,2)
    good=struct.pack('>5I',0x0100000c,0,start,len(thin),0)
    bad=struct.pack('>5I',7,0,999999,len(thin),0)
    p=tmp_path/'fat';p.write_bytes(header+good+bad+b'\0'*(start-48)+thin)
    result=macho_inventory(str(p))
    assert result.status.value=='partial' and len(result.facts['slices'])==1 and result.errors


def test_local_native_macho_when_available():
    p=Path('/usr/bin/true')
    if not p.is_file() or p.read_bytes()[:4] not in {b'\xca\xfe\xba\xbe',b'\xcf\xfa\xed\xfe'}:
        pytest.skip('local native Mach-O only on macOS')
    result=macho_inventory(str(p))
    assert result.status.value in {'ok','partial'},result.errors
    assert result.facts['slices']
    assert any(row['code_signature'] for row in result.facts['slices'])


def test_compare_exact_counts_sizes_and_per_source_hashes(tmp_path):
    a=tmp_path/'a';b=tmp_path/'b'
    a.write_bytes(b'abcdefgh');b.write_bytes(b'ab00efghXYZ')
    result=compare(str(a),str(b),block_size=2,limit=1)
    assert result.status.value=='partial'
    assert result.facts['changed_blocks']==3
    assert result.facts['differences'][0]['offset']==2
    assert result.facts['left']['sha256']==hashlib.sha256(a.read_bytes()).hexdigest()
    assert result.facts['right']['sha256']==hashlib.sha256(b.read_bytes()).hexdigest()
    assert len({item.source_sha256 for item in result.evidence})==2
    assert not result.facts['identical']


def test_compare_empty_identical_and_byte_limits(tmp_path):
    a=tmp_path/'a';b=tmp_path/'b';a.write_bytes(b'');b.write_bytes(b'')
    result=compare(str(a),str(b))
    assert result.status.value=='ok' and result.facts['identical']
    a.write_bytes(b'123');assert compare(str(a),str(b),max_bytes=2).status.value=='unsupported'
    assert compare(str(a),str(b),block_size=0).status.value=='error'
    assert compare(str(a),str(tmp_path/'absent')).status.value=='error'


def test_macho_identification_and_discovery(tmp_path):
    from dftk.suggest import suggest
    p=tmp_path/'carve';p.write_bytes(_thin())
    result=dftk.run_tool('artifact.inspect',{'path':str(p)})
    assert result.facts['kind']=='macho'
    assert suggest(str(p))['results'][0]['name']=='binary.macho_inventory'
