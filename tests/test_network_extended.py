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
from dftk.primitives.network import pcapng_inventory,capture_protocols


def _ipv4_udp_dns():
    dns=struct.pack('!HHHHHH',0x1234,0x0100,1,0,0,0)+b'\x07example\x03com\x00'+struct.pack('!HH',1,1)
    udp=struct.pack('!HHHH',53000,53,8+len(dns),0)+dns
    src=socket.inet_aton('10.0.0.2'); dst=socket.inet_aton('8.8.8.8')
    ip=bytearray(20); ip[0]=0x45; struct.pack_into('!H',ip,2,20+len(udp)); ip[8]=64; ip[9]=17; ip[12:16]=src; ip[16:20]=dst
    eth=b'\xaa'*6+b'\xbb'*6+struct.pack('!H',0x0800)
    return eth+bytes(ip)+udp


def _ipv4_tcp_http():
    payload=b'GET /login HTTP/1.1\r\nHost: example.org\r\nUser-Agent: test\r\n\r\n'
    tcp=bytearray(20); struct.pack_into('!HH',tcp,0,12345,80); tcp[12]=0x50
    ip=bytearray(20); ip[0]=0x45; struct.pack_into('!H',ip,2,20+20+len(payload)); ip[8]=64; ip[9]=6; ip[12:16]=socket.inet_aton('1.2.3.4'); ip[16:20]=socket.inet_aton('5.6.7.8')
    eth=b'\xaa'*6+b'\xbb'*6+struct.pack('!H',0x0800)
    return eth+bytes(ip)+bytes(tcp)+payload


def _pcapng(pkt):
    shb=struct.pack('<II',0x0A0D0D0A,28)+struct.pack('<IHHq',0x1A2B3C4D,1,0,-1)+struct.pack('<I',28)
    idb=struct.pack('<IIHHI',1,20,1,0,65535)+struct.pack('<I',20)
    pad=(4-len(pkt)%4)%4; body=struct.pack('<IIIII',0,0,1000000,len(pkt),len(pkt))+pkt+b'\0'*pad; blen=8+len(body)+4
    epb=struct.pack('<II',6,blen)+body+struct.pack('<I',blen)
    return shb+idb+epb


def _pcap(pkt):
    gh=b'\xd4\xc3\xb2\xa1'+struct.pack('<HHIIII',2,4,0,0,65535,1)
    ph=struct.pack('<IIII',1,0,len(pkt),len(pkt))
    return gh+ph+pkt


def test_pcapng_and_dns(tmp_path):
    p=tmp_path/'a.pcapng'; p.write_bytes(_pcapng(_ipv4_udp_dns()))
    inv=pcapng_inventory(str(p)); assert inv.facts['packet_count']==1; assert inv.facts['protocol_counts']['udp']==1
    proto=capture_protocols(str(p)); assert proto.facts['dns_questions'][0]['name']=='example.com'


def test_http_from_classic_pcap(tmp_path):
    p=tmp_path/'a.pcap'; p.write_bytes(_pcap(_ipv4_tcp_http()))
    obs=capture_protocols(str(p)); req=obs.facts['http_requests'][0]
    assert req['host']=='example.org'; assert req['target']=='/login'
