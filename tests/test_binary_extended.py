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

import struct
from dftk.primitives.binary import pe_inventory,native_indicator_scan


def _minimal_pe64():
    peoff=0x80; opt=bytearray(0xf0); struct.pack_into('<H',opt,0,0x20b)
    hdr=bytearray(peoff); hdr[:2]=b'MZ'; struct.pack_into('<I',hdr,0x3c,peoff)
    coff=struct.pack('<HHIIIHH',0x8664,1,123456,0,0,len(opt),0x2022)
    sec=bytearray(40); sec[:5]=b'.text'; struct.pack_into('<IIII',sec,8,0x100,0x1000,0x200,0x200); struct.pack_into('<I',sec,36,0x60000020)
    data=bytes(hdr)+b'PE\0\0'+coff+bytes(opt)+bytes(sec)
    return data+b'\0'*max(0,0x400-len(data))


def test_pe_inventory(tmp_path):
    p=tmp_path/'a.exe'; p.write_bytes(_minimal_pe64())
    obs=pe_inventory(str(p)); assert obs.facts['machine']=='x86-64'; assert obs.facts['bitness']==64; assert obs.facts['sections'][0]['name']=='.text'


def test_native_indicator_is_explicitly_heuristic(tmp_path):
    p=tmp_path/'lib.so'; p.write_bytes(b'xxxxJava_com_example_Test_nativeFoo\x00AES_encrypt\x00https://example.org/x\x00')
    obs=native_indicator_scan(str(p)); assert len(obs.facts['matches'])>=3; assert any('heuristic' in x for x in obs.warnings)
