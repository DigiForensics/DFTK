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
from dftk.primitives.android import parse_dex_strings

def make_dex(strings):
    header=bytearray(0x70); header[:8]=b'dex\n035\x00'; struct.pack_into('<I',header,0x28,0x12345678)
    string_ids_off=0x70; data_off=string_ids_off+4*len(strings)
    blob=bytearray(header)+bytearray(4*len(strings)); cursor=data_off
    for i,s in enumerate(strings):
        raw=s.encode('utf-8'); assert len(s)<0x80
        struct.pack_into('<I',blob,string_ids_off+i*4,cursor)
        blob.extend(bytes([len(s)])+raw+b'\x00'); cursor=len(blob)
    struct.pack_into('<I',blob,0x20,len(blob)); struct.pack_into('<I',blob,0x38,len(strings)); struct.pack_into('<I',blob,0x3c,string_ids_off)
    return bytes(blob)

def test_dex_string_data_skips_uleb_length():
    rows=parse_dex_strings(make_dex(['hello','world']))
    assert [r.value for r in rows]==['hello','world']
    assert rows[0].utf16_size==5

def test_dex_mutf8_null():
    data=bytearray(make_dex(['x']))
    off=struct.unpack_from('<I',data,0x70)[0]
    # utf16_size=3, modified UTF-8 for A\0B
    data[off:]=bytes([3])+b'A\xc0\x80B\x00'
    rows=parse_dex_strings(bytes(data))
    assert rows[0].value=='A\x00B'
