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

import struct,socket
from dftk.primitives.network import pcap_inventory

def test_simple_pcap(tmp_path):
    gh=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)
    eth=b'\x00'*12+struct.pack('!H',0x0800)
    ip=bytearray(20); ip[0]=0x45; ip[9]=6; ip[12:16]=socket.inet_aton('10.0.0.1'); ip[16:20]=socket.inet_aton('10.0.0.2')
    tcp=struct.pack('!HH',1234,80)+b'\x00'*16
    pkt=eth+bytes(ip)+tcp
    rec=struct.pack('<IIII',1,0,len(pkt),len(pkt))+pkt
    p=tmp_path/'x.pcap'; p.write_bytes(gh+rec)
    obs=pcap_inventory(str(p)); assert obs.facts['packet_count']==1; assert obs.facts['protocol_counts']['tcp']==1; assert obs.facts['samples'][0]['dst_port']==80
