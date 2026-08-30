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
from dftk.primitives.network import pcapng_inventory,capture_protocols,pcap_inventory
from dftk.primitives import network as net


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


# --- edge-case coverage previously missing from the suite ---------------------

def _dns_name(n):
    out=b""
    for part in n.split("."):
        out+=bytes([len(part)])+part.encode()
    return out+b"\x00"

def _dns_response_www_ptr():
    # question 'example.com'; answer name = literal 'www' + pointer(0xC00C) to
    # the question name -> resolves to 'www.example.com' (RFC 1035 compression).
    q=_dns_name("example.com")+struct.pack('>HH',1,1)
    www=bytes([3])+b"www"
    ans=www+struct.pack('>H',0xC00C)+struct.pack('>HHIH',1,1,60,4)+socket.inet_aton("9.9.9.9")
    return struct.pack('>HHHHHH',0x1111,0x8180,1,1,0,0)+q+ans

def test_dns_multilabel_pointer_compression(tmp_path):
    # build a UDP/DNS packet carrying the www+ptr response
    dns=_dns_response_www_ptr()
    udp=struct.pack('!HHHH',53000,53,8+len(dns),0)+dns
    src=socket.inet_aton('10.0.0.2'); dst=socket.inet_aton('8.8.8.8')
    ip=bytearray(20); ip[0]=0x45; struct.pack_into('!H',ip,2,20+len(udp)); ip[8]=64; ip[9]=17; ip[12:16]=src; ip[16:20]=dst
    eth=b'\xaa'*6+b'\xbb'*6+struct.pack('!H',0x0800)
    p=tmp_path/'c.pcap'; p.write_bytes(_pcap(eth+bytes(ip)+udp))
    obs=capture_protocols(str(p))
    ans=obs.facts['dns_answers']
    assert any(a['name']=='www.example.com' and a['address']=='9.9.9.9' for a in ans), ans

def test_http_chunked_body_decoded(tmp_path):
    # Full chunked HTTP response carried in one server->client segment.
    body=(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
          b"Transfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n")
    eth=b'\x00'*6+b'\x11'*6+b'\x08\x00'
    def tcp(sip,dip,sp,dp,seq,flags,payload=b""):
        total=20+20+len(payload)
        ip=struct.pack('!BBHHHBBHII',0x45,0,total,0x1234,0,64,6,0,
                       int.from_bytes(socket.inet_aton(sip),'big'),int.from_bytes(socket.inet_aton(dip),'big'))
        off_flags=(5<<12)|flags
        return eth+ip+struct.pack('!HHIIHHHH',sp,dp,seq,0,off_flags,65535,0,0)+payload
    C,S,CP,SP="10.0.0.1","10.0.0.2",1111,80
    pkts=[tcp(C,S,CP,SP,1000,0x02), tcp(S,C,SP,CP,5000,0x12),
          tcp(C,S,CP,SP,1001,0x10), tcp(S,C,SP,CP,5001,0x18,body)]
    p=tmp_path/'h.pcap'
    p.write_bytes(struct.pack('<IHHIIII',0xA1B2C3D4,2,4,0,0,65535,1)
                 + b"".join(struct.pack('<IIII',1700000000+i,0,len(d),len(d))+d for i,d in enumerate(pkts)))
    obs=net.tcp_reassemble(str(p))
    s2c=[s for s in obs.facts['streams'] if s['server_to_client']['length']>=len(body)][0]
    full=bytes.fromhex(s2c['server_to_client']['hex_preview'].rstrip('.'))
    meta,decoded=next(iter(net._iter_http_messages(full,False)))
    assert decoded==b"Wikipedia", decoded
    assert meta['content_type']=='text/plain'

def test_pcapng_big_endian_and_simple_block(tmp_path):
    def build(en, spb=False):
        shb=struct.pack(en+'II',0x0A0D0D0A,28)+struct.pack(en+'IHHq',0x1A2B3C4D,1,0,-1)+struct.pack(en+'I',28)
        idb=struct.pack(en+'IIHHI',1,20,1,0,65535)+struct.pack(en+'I',20)
        eth=b'\x00'*6+b'\x11'*6+struct.pack('!H',0x0800)
        ip=bytearray(20); ip[0]=0x45; struct.pack_into('!H',ip,2,20+20); ip[8]=64; ip[9]=6
        ip[12:16]=socket.inet_aton('10.0.0.1'); ip[16:20]=socket.inet_aton('10.0.0.2')
        tcp=struct.pack('!HH',1234,80)+b'\x00'*16
        pkt=eth+bytes(ip)+tcp
        if spb:
            body=struct.pack(en+'I',len(pkt))+pkt; blen=8+len(body)+4
            return shb+idb+struct.pack(en+'II',3,blen)+body+struct.pack(en+'I',blen)
        pad=(4-len(pkt)%4)%4
        body=struct.pack(en+'IIIII',0,0,1000000,len(pkt),len(pkt))+pkt+b'\0'*pad
        blen=8+len(body)+4
        return shb+idb+struct.pack(en+'II',6,blen)+body+struct.pack(en+'I',blen)
    for tag,data in [("LE_EPB",build('<')),("BE_EPB",build('>')),("SPB",build('<',spb=True))]:
        p=tmp_path/f"{tag}.pcapng"; p.write_bytes(data)
        obs=pcapng_inventory(str(p))
        assert obs.facts['packet_count']==1, (tag, obs.facts['packet_count'])
        assert obs.facts['protocol_counts']['tcp']==1, (tag, obs.facts['protocol_counts'])

def test_vlan_tag_passthrough(tmp_path):
    gh=struct.pack('<IHHIIII',0xA1B2C3D4,2,4,0,0,65535,1)
    eth=b'\x00'*6+b'\x11'*6+b'\x81\x00\x00\x64'+struct.pack('!H',0x0800)  # 802.1Q vlan 100
    ip=bytearray(20); ip[0]=0x45; struct.pack_into('!H',ip,2,20+20); ip[8]=64; ip[9]=6
    ip[12:16]=socket.inet_aton('10.1.1.1'); ip[16:20]=socket.inet_aton('10.1.1.2')
    tcp=struct.pack('!HH',5000,443)+b'\x00'*16
    pkt=eth+bytes(ip)+tcp
    rec=struct.pack('<IIII',1,0,len(pkt),len(pkt))+pkt
    p=tmp_path/'v.pcap'; p.write_bytes(gh+rec)
    obs=pcap_inventory(str(p))
    assert obs.facts['protocol_counts']['tcp']==1, obs.facts['protocol_counts']
    assert obs.facts['samples'][0]['src']=='10.1.1.1'
    assert obs.facts['samples'][0]['dst_port']==443

