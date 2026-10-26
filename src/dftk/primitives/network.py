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
import struct,socket,re,hashlib
from collections import Counter
from dftk.core.registry import registry
from dftk.core.models import Observation,Evidence,Status,SafetyLevel
from dftk.core.provenance import ProvenanceIndex
from dftk.core.helpers import sha256_file, read_file_bounded_observation

class PcapError(ValueError): pass

def _ip(b): return socket.inet_ntoa(b)

@registry.tool(name="network.pcap_inventory",description="Parse classic PCAP packet headers and summarize IPv4 TCP/UDP endpoint tuples without external libraries.",safety=SafetyLevel.READ_ONLY,
 parameters={"type":"object","properties":{"path":{"type":"string"},"packet_limit":{"type":"integer","default":200000},"sample_limit":{"type":"integer","default":200}},"required":["path"]})
def pcap_inventory(path:str,packet_limit:int=200000,sample_limit:int=200)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation("network.pcap_inventory",Status.ERROR,"PCAP not found",errors=[str(p)])
    data,err,src=read_file_bounded_observation('network.pcap_inventory',p,4*1024*1024*1024)
    if err: return err
    if len(data)<24: return Observation("network.pcap_inventory",Status.UNSUPPORTED,"PCAP too small",meta={"source_sha256":src})
    magic=data[:4]
    fmts={b'\xd4\xc3\xb2\xa1':('<',False),b'\xa1\xb2\xc3\xd4':('>',False),b'M<\xb2\xa1':('<',True),b'\xa1\xb2<M':('>',True)}
    if magic not in fmts:
        return Observation("network.pcap_inventory",Status.UNSUPPORTED,"Only classic PCAP is supported (not PCAPNG)",meta={"source_sha256":src})
    endian,nano=fmts[magic]; network=struct.unpack_from(endian+'I',data,20)[0]
    off=24; count=0; proto=Counter(); endpoints=Counter(); samples=[]; malformed=0
    while off+16<=len(data) and count<packet_limit:
        ts_sec,ts_frac,incl,orig=struct.unpack_from(endian+'IIII',data,off); pkt_off=off+16; off=pkt_off+incl
        if off>len(data): malformed+=1; break
        pkt=data[pkt_off:off]; count+=1
        if network!=1 or len(pkt)<14: continue
        eth_type=struct.unpack_from('!H',pkt,12)[0]
        l3=14
        if eth_type==0x8100 and len(pkt)>=18: eth_type=struct.unpack_from('!H',pkt,16)[0]; l3=18
        if eth_type!=0x0800 or len(pkt)<l3+20: continue
        ver_ihl=pkt[l3]; ihl=(ver_ihl&0x0f)*4
        if ver_ihl>>4!=4 or ihl<20 or len(pkt)<l3+ihl: continue
        pr=pkt[l3+9]; src=_ip(pkt[l3+12:l3+16]); dst=_ip(pkt[l3+16:l3+20]); name={6:'tcp',17:'udp'}.get(pr,str(pr)); proto[name]+=1
        sport=dport=None
        if pr in (6,17) and len(pkt)>=l3+ihl+4: sport,dport=struct.unpack_from('!HH',pkt,l3+ihl)
        key=f"{src}:{sport or 0}->{dst}:{dport or 0}/{name}"; endpoints[key]+=1
        if len(samples)<sample_limit: samples.append({"packet":count,"timestamp":ts_sec+(ts_frac/(1_000_000_000 if nano else 1_000_000)),"src":src,"dst":dst,"protocol":name,"src_port":sport,"dst_port":dport,"captured_len":incl})
    warnings=[]
    if network!=1: warnings.append(f"linktype {network} is not Ethernet; transport parsing was skipped")
    if malformed: warnings.append("truncated/malformed packet encountered")
    if count>=packet_limit: warnings.append(f"packet parsing limited to {packet_limit}")
    top=[{"flow":k,"packets":v} for k,v in endpoints.most_common(100)]
    return Observation("network.pcap_inventory",Status.PARTIAL if malformed else Status.OK,f"Parsed {count} packet(s)",facts={"linktype":network,"packet_count":count,"protocol_counts":dict(proto),"top_flows":top,"samples":samples},evidence=[Evidence(str(p),'pcap_summary',f"{count} packets",locator='pcap-records')],warnings=warnings,meta={"source_sha256":src})

# ---- PCAPNG and lightweight application-protocol extraction ----

def _parse_ipv4_frame(pkt:bytes):
    if len(pkt)<14: return None
    eth_type=struct.unpack_from('!H',pkt,12)[0]; l3=14
    if eth_type in (0x8100,0x88a8) and len(pkt)>=18:
        eth_type=struct.unpack_from('!H',pkt,16)[0]; l3=18
    if eth_type!=0x0800 or len(pkt)<l3+20: return None
    ihl=(pkt[l3]&0x0f)*4
    if pkt[l3]>>4!=4 or ihl<20 or len(pkt)<l3+ihl: return None
    total=struct.unpack_from('!H',pkt,l3+2)[0]; end=min(len(pkt),l3+total) if total else len(pkt)
    proto=pkt[l3+9]; src=_ip(pkt[l3+12:l3+16]); dst=_ip(pkt[l3+16:l3+20]); l4=l3+ihl
    sport=dport=None; payload=b''
    if proto==6 and end>=l4+20:
        sport,dport=struct.unpack_from('!HH',pkt,l4); doff=((pkt[l4+12]>>4)&0xf)*4
        if doff>=20 and end>=l4+doff: payload=pkt[l4+doff:end]
    elif proto==17 and end>=l4+8:
        sport,dport=struct.unpack_from('!HH',pkt,l4); payload=pkt[l4+8:end]
    return {'src':src,'dst':dst,'proto':proto,'src_port':sport,'dst_port':dport,'payload':payload}

def _classic_packets(data:bytes,limit:int):
    magic=data[:4]; fmts={b'\xd4\xc3\xb2\xa1':('<',False),b'\xa1\xb2\xc3\xd4':('>',False),b'M<\xb2\xa1':('<',True),b'\xa1\xb2<M':('>',True)}
    if magic not in fmts: raise PcapError('not classic PCAP')
    endian,nano=fmts[magic]; linktype=struct.unpack_from(endian+'I',data,20)[0]; off=24; count=0
    while off+16<=len(data) and count<limit:
        sec,frac,incl,_=struct.unpack_from(endian+'IIII',data,off); start=off+16; end=start+incl
        if end>len(data): break
        count+=1; yield count,linktype,sec+(frac/(1_000_000_000 if nano else 1_000_000)),data[start:end]
        off=end

def _pcapng_packets(data:bytes,limit:int):
    if len(data)<12 or data[:4]!=b'\x0a\x0d\x0d\x0a': raise PcapError('not PCAPNG')
    off=0; endian='<'; interfaces=[]; count=0
    while off+12<=len(data) and count<limit:
        btype=struct.unpack_from(endian+'I',data,off)[0] if off else 0x0a0d0d0a
        if off==0 or btype==0x0a0d0d0a:
            if off+12>len(data): break
            bom=data[off+8:off+12]
            if bom==b'\x4d\x3c\x2b\x1a': endian='<'
            elif bom==b'\x1a\x2b\x3c\x4d': endian='>'
            else: raise PcapError('invalid PCAPNG byte-order magic')
            btype=0x0a0d0d0a
        blen=struct.unpack_from(endian+'I',data,off+4)[0]
        if blen<12 or off+blen>len(data): raise PcapError(f'invalid PCAPNG block at {off}')
        if struct.unpack_from(endian+'I',data,off+blen-4)[0]!=blen: raise PcapError(f'PCAPNG block length mismatch at {off}')
        body=off+8
        if btype==1 and blen>=20:
            link=struct.unpack_from(endian+'H',data,body)[0]; interfaces.append({'linktype':link})
        elif btype==6 and blen>=32:
            iid,tsh,tsl,caplen,_=struct.unpack_from(endian+'IIIII',data,body)
            start=body+20; end=start+caplen
            if end<=off+blen-4:
                count+=1; link=interfaces[iid]['linktype'] if iid<len(interfaces) else -1
                # Default PCAPNG timestamp resolution is 10^-6 unless if_tsresol says otherwise.
                yield count,link,((tsh<<32)|tsl)/1_000_000,data[start:end]
        elif btype==3 and blen>=16:
            packet_len=struct.unpack_from(endian+'I',data,body)[0]; start=body+4; end=min(start+packet_len,off+blen-4)
            count+=1; link=interfaces[0]['linktype'] if interfaces else -1
            yield count,link,None,data[start:end]
        off+=blen

def _capture_packets(data:bytes,limit:int):
    if data[:4]==b'\x0a\x0d\x0d\x0a': return _pcapng_packets(data,limit),'pcapng'
    return _classic_packets(data,limit),'pcap'

def _dns_name(msg:bytes,off:int,depth:int=0):
    if depth>10: return '<compression-loop>',off
    labels=[]; original_next=None
    while off<len(msg):
        n=msg[off]
        if n==0:
            off+=1; return '.'.join(labels), original_next or off
        if n&0xc0==0xc0:
            if off+1>=len(msg): return '<truncated>',len(msg)
            ptr=((n&0x3f)<<8)|msg[off+1]; original_next=original_next or off+2
            suffix,_=_dns_name(msg,ptr,depth+1); labels.append(suffix); return '.'.join(x for x in labels if x),original_next
        off+=1
        if off+n>len(msg): return '<truncated>',len(msg)
        
        raw_label=msg[off:off+n]
        try:
            ascii_label=raw_label.decode('ascii')
            label=ascii_label.encode('ascii').decode('idna') if ascii_label.lower().startswith('xn--') else ascii_label
        except (UnicodeDecodeError,UnicodeError):
            label=raw_label.decode('ascii','replace')
        labels.append(label); off+=n
    return '<truncated>',off

def _dns_questions(payload:bytes):
    if len(payload)<12: return []
    qd=struct.unpack_from('!H',payload,4)[0]; off=12; out=[]
    for _ in range(min(qd,50)):
        name,off=_dns_name(payload,off)
        if off+4>len(payload): break
        qtype,qclass=struct.unpack_from('!HH',payload,off); off+=4
        out.append({'name':name,'type':qtype,'class':qclass})
    return out

def _parse_dns(payload:bytes):
    """Return (questions, answers) from a DNS message. Answers carry resolved
    A/AAAA addresses and CNAME targets, which is what links a queried name to an IP."""
    if len(payload)<12: return [], []
    qd=struct.unpack_from('!H',payload,4)[0]; an=struct.unpack_from('!H',payload,6)[0]; off=12
    questions=[]
    for _ in range(min(qd,50)):
        name,off=_dns_name(payload,off)
        if off+4>len(payload): break
        qtype,qclass=struct.unpack_from('!HH',payload,off); off+=4
        questions.append({'name':name,'type':qtype,'class':qclass})
    answers=[]
    for _ in range(min(an,200)):
        if off+10>len(payload): break
        name,off=_dns_name(payload,off)
        atype,aclass=struct.unpack_from('!HH',payload,off); ttl=struct.unpack_from('!I',payload,off+4)[0]; rdlen=struct.unpack_from('!H',payload,off+8)[0]; off+=10
        if off+rdlen>len(payload): break
        rdata=payload[off:off+rdlen]; off+=rdlen
        rec={'name':name,'type':atype,'ttl':ttl}
        if atype==1 and rdlen==4:
            rec['address']=socket.inet_ntoa(rdata)
        elif atype==28 and rdlen==16:
            rec['address']=':'.join(f'{rdata[i:i+2].hex()}' for i in range(0,16,2))
        elif atype==5:
            cn,_=_dns_name(rdata,0); rec['cname']=cn
        answers.append(rec)
    return questions, answers

_RE_HTTP_RESP=re.compile(rb'HTTP/(1\.[01]) (\d{3}) ([^\r\n]*)')
def _http_response(payload:bytes):
    if not payload: return None
    m=_RE_HTTP_RESP.search(payload)
    if not m: return None
    headers={}
    text=payload[:16384].decode('iso-8859-1','replace')
    for line in text.split('\r\n')[1:]:
        if not line: break
        if ':' in line:
            k,v=line.split(':',1); headers[k.strip().lower()]=v.strip()
    return {'status':m.group(2).decode(),'reason':m.group(3).decode('iso-8859-1','replace'),'server':headers.get('server')}

def _http_request(payload:bytes):
    if not payload: return None
    head=payload[:16384]
    try: text=head.decode('iso-8859-1')
    except UnicodeDecodeError: return None
    lines=text.split('\r\n')
    if not lines: return None
    m=re.match(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+HTTP/(1\.[01]|2)$',lines[0])
    if not m: return None
    headers={}
    for line in lines[1:]:
        if not line: break
        if ':' in line:
            k,v=line.split(':',1); headers[k.strip().lower()]=v.strip()
    return {'method':m.group(1),'target':m.group(2),'host':headers.get('host'),'user_agent':headers.get('user-agent'),'content_type':headers.get('content-type')}

def _tls_sni(payload:bytes):
    # Best-effort parser for a complete TLS ClientHello contained in one TCP segment.
    if len(payload)<9 or payload[0]!=22: return None
    rec_len=struct.unpack_from('!H',payload,3)[0]
    if 5+rec_len>len(payload) or payload[5]!=1: return None
    hs_len=int.from_bytes(payload[6:9],'big')
    if 9+hs_len>len(payload): return None
    p=9+2+32
    if p>=len(payload): return None
    sid=payload[p]; p+=1+sid
    if p+2>len(payload): return None
    cs=struct.unpack_from('!H',payload,p)[0]; p+=2+cs
    if p>=len(payload): return None
    comp=payload[p]; p+=1+comp
    if p+2>len(payload): return None
    ext_total=struct.unpack_from('!H',payload,p)[0]; p+=2; end=min(len(payload),p+ext_total)
    while p+4<=end:
        et,el=struct.unpack_from('!HH',payload,p); p+=4
        if p+el>end: break
        if et==0 and el>=5:
            q=p+2
            while q+3<=p+el:
                nt=payload[q]; nl=struct.unpack_from('!H',payload,q+1)[0]; q+=3
                if q+nl>p+el: break
                if nt==0:
                    try:return payload[q:q+nl].decode('idna')
                    except UnicodeDecodeError:return payload[q:q+nl].decode('ascii','replace')
                q+=nl
        p+=el
    return None

@registry.tool(name='network.pcapng_inventory',description='Parse PCAPNG interface and enhanced/simple packet blocks and summarize Ethernet IPv4 TCP/UDP flows.',
 safety=SafetyLevel.READ_ONLY,tags=('network','pcapng'),produces=('network_flows',),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'packet_limit':{'type':'integer','default':200000},'sample_limit':{'type':'integer','default':200}},'required':['path']})
def pcapng_inventory(path:str,packet_limit:int=200000,sample_limit:int=200)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('network.pcapng_inventory',Status.ERROR,'PCAPNG not found',errors=[str(p)])
    data,err,src=read_file_bounded_observation('network.pcapng_inventory',p,4*1024*1024*1024)
    if err: return err
    flows=Counter(); protos=Counter(); samples=[]; count=0; unsupported_links=Counter()
    try:
        for num,link,ts,pkt in _pcapng_packets(data,packet_limit):
            count=num
            if link!=1: unsupported_links[link]+=1; continue
            ip=_parse_ipv4_frame(pkt)
            if not ip: continue
            name={6:'tcp',17:'udp'}.get(ip['proto'],str(ip['proto'])); protos[name]+=1
            key=f"{ip['src']}:{ip['src_port'] or 0}->{ip['dst']}:{ip['dst_port'] or 0}/{name}"; flows[key]+=1
            if len(samples)<sample_limit: samples.append({'packet':num,'timestamp':ts,'src':ip['src'],'dst':ip['dst'],'protocol':name,'src_port':ip['src_port'],'dst_port':ip['dst_port']})
    except PcapError as e:
        return Observation('network.pcapng_inventory',Status.UNSUPPORTED,'PCAPNG parsing failed',errors=[str(e)],meta={'source_sha256':src})
    warnings=[f'unsupported linktype {k}: {v} packet(s)' for k,v in unsupported_links.items()]
    if count>=packet_limit: warnings.append(f'packet parsing limited to {packet_limit}')
    return Observation('network.pcapng_inventory',Status.PARTIAL if unsupported_links else Status.OK,f'Parsed {count} PCAPNG packet(s)',facts={'packet_count':count,'protocol_counts':dict(protos),'top_flows':[{'flow':k,'packets':v} for k,v in flows.most_common(100)],'samples':samples},evidence=[Evidence(str(p),'pcapng_summary',count,locator='blocks')],warnings=warnings,meta={'source_sha256':src})

@registry.tool(name='network.capture_protocols',description='Extract bounded DNS questions, plaintext HTTP requests and TLS ClientHello SNI from classic PCAP or PCAPNG.',
 safety=SafetyLevel.READ_ONLY,tags=('network','protocols','pcap'),produces=('dns_queries','http_requests','tls_sni'),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'packet_limit':{'type':'integer','default':200000},'limit':{'type':'integer','default':5000}},'required':['path']})
def capture_protocols(path:str,packet_limit:int=200000,limit:int=5000)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('network.capture_protocols',Status.ERROR,'Capture not found',errors=[str(p)])
    data,err,src=read_file_bounded_observation('network.capture_protocols',p,4*1024*1024*1024)
    if err: return err
    dns=[]; dns_ans=[]; http=[]; http_resp=[]; tls=[]; warnings=[]; count=0
    try: packets,fmt=_capture_packets(data,packet_limit)
    except PcapError as e: return Observation('network.capture_protocols',Status.UNSUPPORTED,'Unsupported capture',errors=[str(e)],meta={'source_sha256':src})
    try:
        for num,link,ts,pkt in packets:
            count=num
            if link!=1: continue
            ip=_parse_ipv4_frame(pkt)
            if not ip: continue
            ports={ip['src_port'],ip['dst_port']}; payload=ip['payload']
            if ip['proto']==17 and 53 in ports:
                questions,answers=_parse_dns(payload)
                for q in questions:
                    dns.append({'packet':num,'time':ts,'src':ip['src'],'dst':ip['dst'],**q})
                for a in answers:
                    dns_ans.append({'packet':num,'time':ts,'src':ip['src'],'dst':ip['dst'],**a})
            elif ip['proto']==6:
                req=_http_request(payload)
                if req: http.append({'packet':num,'time':ts,'src':ip['src'],'dst':ip['dst'],**req})
                resp=_http_response(payload)
                if resp: http_resp.append({'packet':num,'time':ts,'src':ip['src'],'dst':ip['dst'],**resp})
                sni=_tls_sni(payload)
                if sni: tls.append({'packet':num,'time':ts,'src':ip['src'],'dst':ip['dst'],'server_name':sni})
            if len(dns)+len(dns_ans)+len(http)+len(http_resp)+len(tls)>=limit: break
    except PcapError as e:
        warnings.append(str(e))
    if len(dns)+len(dns_ans)+len(http)+len(http_resp)+len(tls)>=limit: warnings.append(f'protocol findings limited to {limit}')
    ev=[]
    for r in dns[:100]: ev.append(Evidence(str(p),'dns_query',r['name'],locator=f"packet:{r['packet']}",method='DNS question parser'))
    for r in dns_ans[:100]:
        val=r.get('address') or r.get('cname') or f"type {r.get('type')}"
        ev.append(Evidence(str(p),'dns_answer',f"{r['name']} -> {val}",locator=f"packet:{r['packet']}",method='DNS answer parser'))
    for r in http[:100]: ev.append(Evidence(str(p),'http_request',f"{r['method']} {r['host'] or ''}{r['target']}",locator=f"packet:{r['packet']}",method='HTTP/1 request parser'))
    for r in http_resp[:100]: ev.append(Evidence(str(p),'http_response',f"{r['status']} {r.get('server') or ''}",locator=f"packet:{r['packet']}",method='HTTP/1 response parser'))
    for r in tls[:100]: ev.append(Evidence(str(p),'tls_sni',r['server_name'],locator=f"packet:{r['packet']}",method='TLS ClientHello parser'))
    return Observation('network.capture_protocols',Status.PARTIAL if warnings else Status.OK,f'Extracted {len(dns)} DNS q, {len(dns_ans)} DNS ans, {len(http)} HTTP req, {len(http_resp)} HTTP resp, {len(tls)} TLS SNI',facts={'format':fmt,'dns_questions':dns,'dns_answers':dns_ans,'http_requests':http,'http_responses':http_resp,'tls_sni':tls,'packets_scanned':count},evidence=ev,warnings=warnings,meta={'source_sha256':sha256_file(p)})

# =============================================================================
# Network Forensics 2.0 — flow / session / reassembly layer (DFTK 3.5.0)
#
# The 3.3 tools parsed capture *packets* locally. 3.5.0 builds the next layer:
#   Packet -> Flow -> TCP stream -> Protocol session -> DerivedArtifact
# Everything is pure-Python (socket/struct/re), bounded, and never writes the
# evidence file. Body extraction (http_sessions) is the only STATEFUL step and
# registers each recovered object as a DerivedArtifact so the recovery chain is
# provable (it is what powers the Demo-4 chain: PCAP -> stream -> HTTP download
# -> PE/YARA).
# =============================================================================

_RECORD_CAP = 256  # hex preview length for reassembled streams


def _parse_l4(pkt: bytes) -> dict | None:
    """Parse a single Ethernet/IPv4 frame into L3+L4 fields.

    Returns a dict with ``src/dst`` (IP), ``src_port/dst_port``, ``proto`` and,
    for TCP, a ``tcp`` sub-dict carrying ``seq/ack/flags/payload``. Returns
    ``None`` for non-Ethernet/non-IPv4 or truncated frames.
    """
    if len(pkt) < 14:
        return None
    eth = struct.unpack_from('!H', pkt, 12)[0]
    l3 = 14
    if eth in (0x8100, 0x88a8) and len(pkt) >= 18:
        eth = struct.unpack_from('!H', pkt, 16)[0]
        l3 = 18
    if eth != 0x0800 or len(pkt) < l3 + 20:
        return None
    ihl = (pkt[l3] & 0x0f) * 4
    if pkt[l3] >> 4 != 4 or ihl < 20 or len(pkt) < l3 + ihl:
        return None
    total = struct.unpack_from('!H', pkt, l3 + 2)[0]
    end = min(len(pkt), l3 + total) if total else len(pkt)
    proto = pkt[l3 + 9]
    src = _ip(pkt[l3 + 12:l3 + 16])
    dst = _ip(pkt[l3 + 16:l3 + 20])
    l4 = l3 + ihl
    if proto == 6 and end >= l4 + 20:
        sport, dport = struct.unpack_from('!HH', pkt, l4)
        doff = ((pkt[l4 + 12] >> 4) & 0x0f) * 4
        if doff < 20 or end < l4 + doff:
            return {'src': src, 'dst': dst, 'proto': 6, 'src_port': sport,
                    'dst_port': dport, 'payload': b'', 'tcp': None}
        seq = struct.unpack_from('!I', pkt, l4 + 4)[0]
        ack = struct.unpack_from('!I', pkt, l4 + 8)[0]
        flags = pkt[l4 + 13]
        payload = pkt[l4 + doff:end]
        tcp = {
            'seq': seq, 'ack': ack,
            'flags': {'syn': bool(flags & 0x02), 'fin': bool(flags & 0x01),
                      'rst': bool(flags & 0x04), 'psh': bool(flags & 0x08),
                      'ack': bool(flags & 0x10)},
            'window': struct.unpack_from('!H', pkt, l4 + 14)[0],
            'payload': payload,
        }
        return {'src': src, 'dst': dst, 'proto': 6, 'src_port': sport,
                'dst_port': dport, 'payload': payload, 'tcp': tcp}
    if proto == 17 and end >= l4 + 8:
        sport, dport = struct.unpack_from('!HH', pkt, l4)
        return {'src': src, 'dst': dst, 'proto': 17, 'src_port': sport,
                'dst_port': dport, 'payload': pkt[l4 + 8:end], 'tcp': None}
    return None


def _merge_reassemble(chunks: list[tuple[int, bytes]], cap: int):
    """Merge (offset, data) segments with overlap/retransmission handling.

    Overlapping bytes keep the *earlier* segment's data (retransmissions do not
    clobber). Holes between segments are filled with NUL so byte offsets stay
    aligned; ``gaps`` counts the number of holes inserted. Returns ``(bytes, gaps)``.
    """
    merged: list[list] = []  # [start, end, data]
    for off, data in sorted(chunks, key=lambda c: c[0]):
        if not data:
            continue
        if len(data) > cap:
            data = data[:cap]
        s, e = off, off + len(data)
        remainders = [(s, e)]
        for ms, me, _ in merged:
            nr = []
            for rs, re in remainders:
                if re <= ms or rs >= me:
                    nr.append((rs, re))
                else:
                    if rs < ms:
                        nr.append((rs, ms))
                    if me < re:
                        nr.append((me, re))
            remainders = nr
        for rs, re in remainders:
            if rs < re:
                merged.append([rs, re, data[rs - off:re - off]])
    merged.sort(key=lambda x: x[0])
    out = bytearray()
    pos = 0
    gaps = 0
    for s, e, d in merged:
        if s > pos:
            out.extend(b'\x00' * (s - pos))
            gaps += 1
            pos = s
        if s >= pos:
            out.extend(d)
            pos = e
        else:
            tail = pos - s
            out.extend(d[tail:])
            pos = e
    return bytes(out), gaps


def _reasm_dir(segments: list[tuple[int, bytes, bool]], base: int, cap: int):
    """Reassemble one direction's TCP payload stream.

    ``segments`` are ``(seq, payload, is_syn)``. ``base`` is the sequence number
    of the first data byte (``ISN+1`` when a SYN was seen, else the lowest seq),
    so the logical stream begins at offset 0 with no leading hole. Relative
    offsets wrap on 32 bits. Returns ``(data, gaps, truncated)``.
    """
    chunks = []
    total = 0
    truncated = False
    for seq, payload, _syn in segments:
        if not payload:
            continue
        rel = (seq - base) % (2 ** 32)
        chunks.append((rel, payload))
        total += len(payload)
        if total > cap:
            truncated = True
            break
    data, gaps = _merge_reassemble(chunks, cap)
    return data, gaps, truncated


def _syn_isn(segments):
    """Return ``(isn, syn_seen)``.

    ``isn`` is the SYN's sequence number, or the lowest observed seq when no SYN
    is present (the reassembler then treats that as the stream base).
    """
    syn = [s for s in segments if s[2]]
    if syn:
        return syn[0][0], True
    return (min((s[0] for s in segments), default=0), False)


def _tcp_stream_key(p: dict) -> tuple:
    a = (p['src'], p['src_port'])
    b = (p['dst'], p['dst_port'])
    return tuple(sorted([a, b]))


def _dechunk(data: bytes):
    """Decode chunked-transfer-encoding body. Returns ``(body, consumed)``."""
    body = bytearray()
    off = 0
    n = len(data)
    while off + 1 < n:
        nl = data.find(b'\r\n', off)
        if nl == -1:
            break
        sline = data[off:nl].split(b';')[0].strip()
        try:
            size = int(sline, 16)
        except ValueError:
            break
        if size == 0:
            return bytes(body), nl + 2
        start = nl + 2
        end = start + size
        if end > n:
            body += data[start:n]
            return bytes(body), n
        body += data[start:end]
        off = end + 2
    return bytes(body), n


_DOWNLOAD_CT = {
    'application/octet-stream', 'application/zip',
    'application/vnd.android.package-archive', 'application/x-msdownload',
    'application/x-dosexec', 'application/x-executable', 'application/pdf',
    'application/x-apk', 'application/java-archive', 'application/x-7z-compressed',
    'application/gzip', 'application/x-rar-compressed', 'image/png',
    'image/jpeg', 'image/gif', 'video/mp4', 'video/x-matroska', 'audio/mpeg',
}
_MAGICS = {
    b'PK\x03\x04': 'zip/apk', b'MZ': 'pe', b'\x7fELF': 'elf',
    b'%PDF': 'pdf', b'\x89PNG': 'png', b'\xff\xd8\xff': 'jpeg',
    b'GIF8': 'gif', b'\x1f\x8b': 'gzip', b'Rar': 'rar', b'7z\xbc\xaf': '7z',
}

# GREASE values (RFC 8701) are randomly-chosen filler in cipher suites,
# extensions and supported groups. The JA3 spec removes them before hashing,
# otherwise every connection from a GREASE-capable client gets a unique hash.
_GREASE = frozenset({
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
})


def _looks_like_file(ct: str, body: bytes) -> bool:
    if not body:
        return False
    if ct in _DOWNLOAD_CT:
        return True
    for m in _MAGICS:
        if body[:len(m)] == m:
            return True
    return False


def _iter_http_messages(data: bytes, is_request: bool):
    """Yield ``(meta, body)`` for each HTTP message in a reassembled stream.

    Handles Content-Length and chunked bodies. For the (rare) no-CL /
    non-chunked case the trailing bytes are treated as the final body.
    """
    off = 0
    n = len(data)
    while off < n:
        idx = data.find(b'\r\n\r\n', off)
        if idx == -1:
            break
        head = data[off:idx]
        lines = head.split(b'\r\n')
        if not lines:
            break
        if is_request:
            m = re.match(rb'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+HTTP/(1\.[01])$', lines[0])
            if not m:
                off = idx + 4
                continue
        else:
            m = re.match(rb'^HTTP/(1\.[01])\s+(\d{3})', lines[0])
            if not m:
                off = idx + 4
                continue
        headers = {}
        for ln in lines[1:]:
            if b':' in ln:
                k, v = ln.split(b':', 1)
                headers[k.strip().lower()] = v.strip()
        body_start = idx + 4
        cl_raw = headers.get(b'content-length')
        cl = int(cl_raw) if cl_raw and cl_raw.isdigit() else 0
        te = headers.get(b'transfer-encoding', b'')
        if te and b'chunked' in te.lower():
            body, consumed = _dechunk(data[body_start:])
            off = body_start + consumed
        elif cl > 0:
            body = data[body_start:body_start + cl]
            off = body_start + cl
        else:
            body = data[body_start:]
            off = n
        ct = headers.get(b'content-type', b'').decode('iso-8859-1', 'replace').split(';')[0].strip().lower()
        if is_request:
            meta = {'method': m.group(1).decode(), 'target': m.group(2).decode('iso-8859-1', 'replace'),
                    'host': headers.get(b'host', b'').decode('iso-8859-1', 'replace'),
                    'user_agent': headers.get(b'user-agent', b'').decode('iso-8859-1', 'replace'),
                    'content_type': ct}
        else:
            meta = {'status': m.group(2).decode(), 'reason': b'',
                    'server': headers.get(b'server', b'').decode('iso-8859-1', 'replace'),
                    'content_type': ct}
        yield meta, body


def _parse_client_hello(payload: bytes):
    """Parse a TLS ClientHello. Returns JA3 fields or ``None`` on failure."""
    if len(payload) < 9 or payload[0] != 22:
        return None
    rec_ver = struct.unpack_from('!H', payload, 1)[0]
    rec_len = struct.unpack_from('!H', payload, 3)[0]
    if 5 + rec_len > len(payload) or payload[5] != 1:
        return None
    hs_len = int.from_bytes(payload[6:9], 'big')
    if 9 + hs_len > len(payload):
        return None
    body = payload[9:9 + hs_len]
    if len(body) < 38:
        return None
    ch_ver = struct.unpack_from('!H', body, 0)[0]
    p = 2 + 32
    sid_len = body[p]
    p += 1 + sid_len
    if p + 2 > len(body):
        return None
    cs_len = struct.unpack_from('!H', body, p)[0]
    p += 2
    ciphers = []
    if p + cs_len <= len(body):
        for i in range(0, cs_len, 2):
            if p + i + 2 > len(body):
                break
            ciphers.append(struct.unpack_from('!H', body, p + i)[0])
        p += cs_len
    if p + 1 > len(body):
        return None
    comp_len = body[p]
    p += 1 + comp_len
    if p + 2 > len(body):
        return None
    ext_total = struct.unpack_from('!H', body, p)[0]
    p += 2
    end = min(len(body), p + ext_total)
    exts = []
    alpn = []
    sni = None
    curves = []
    ec_point_formats = []
    supported_versions = None
    while p + 4 <= end:
        et, el = struct.unpack_from('!HH', body, p)
        p += 4
        if p + el > end:
            break
        edata = body[p:p + el]
        p += el
        exts.append(et)
        if et == 0:  # SNI
            if len(edata) >= 2:
                slen = struct.unpack_from('!H', edata, 0)[0]
                q = 2
                while q + 3 <= 2 + slen and q + 3 <= len(edata):
                    nt = edata[q]
                    nl = struct.unpack_from('!H', edata, q + 1)[0]
                    q += 3
                    if q + nl > len(edata):
                        break
                    if nt == 0:
                        try:
                            sni = edata[q:q + nl].decode('idna')
                        except UnicodeDecodeError:
                            sni = edata[q:q + nl].decode('ascii', 'replace')
                    q += nl
        elif et == 16:  # ALPN
            if len(edata) >= 2:
                q = 2
                while q + 1 <= len(edata):
                    pl = edata[q]
                    q += 1
                    if q + pl > len(edata):
                        break
                    try:
                        alpn.append(edata[q:q + pl].decode('ascii', 'replace'))
                    except UnicodeDecodeError:
                        pass
                    q += pl
        elif et == 10:  # supported_groups / elliptic_curves
            if len(edata) >= 2:
                q = 2
                while q + 2 <= len(edata):
                    curves.append(struct.unpack_from('!H', edata, q)[0])
                    q += 2
        elif et == 11:  # ec_point_formats
            if len(edata) >= 1:
                q = 1
                while q < len(edata):
                    ec_point_formats.append(edata[q])
                    q += 1
        elif et == 43:  # supported_versions
            if len(edata) >= 2:
                q = 2
                while q + 2 <= len(edata):
                    supported_versions = struct.unpack_from('!H', edata, q)[0]
                    q += 2
    # JA3 spec: SSLVersion is the *handshake* ClientHello version
    # (e.g. 771 = 0x0303 TLS1.2), NOT the record-layer version (769 = 0x0301).
    # Within each field values are dash-separated; fields are comma-separated.
    # GREASE values are stripped so GREASE-capable clients stay stable.
    ja3_str = (f"{ch_ver},"
               f"{'-'.join(str(c) for c in ciphers if c not in _GREASE)},"
               f"{'-'.join(str(e) for e in exts if e not in _GREASE)},"
               f"{'-'.join(str(c) for c in curves if c not in _GREASE)},"
               f"{'-'.join(str(f) for f in ec_point_formats)}")
    return {
        'record_version': rec_ver, 'client_version': ch_ver,
        'supported_versions': supported_versions, 'cipher_suites': ciphers,
        'extensions': exts, 'alpn': alpn, 'sni': sni, 'curves': curves,
        'ec_point_formats': ec_point_formats, 'ja3': hashlib.md5(ja3_str.encode()).hexdigest(),
        'ja3_string': ja3_str,
    }


@registry.tool(name='network.flows',description='Group captured packets into network flows (TCP conversations and UDP 5-tuples) with packet/byte counts, timestamps and TCP flag summary, without external libraries.',
 safety=SafetyLevel.READ_ONLY,tags=('network','flow','pcap'),produces=('network_flows',),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'packet_limit':{'type':'integer','default':200000},'max_flows':{'type':'integer','default':500}},'required':['path']})
def network_flows(path:str,packet_limit:int=200000,max_flows:int=500)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('network.flows',Status.ERROR,'Capture not found',errors=[str(p)])
    data,err, src=read_file_bounded_observation('network.flows',p,4*1024*1024*1024)
    if err: return err
    try: packets,fmt=_capture_packets(data,packet_limit)
    except PcapError as e: return Observation('network.flows',Status.UNSUPPORTED,'Unsupported capture',errors=[str(e)],meta={'source_sha256':sha256_file(p)})
    flows={}
    count=0
    for num,link,ts,pkt in packets:
        count=num
        if link!=1: continue
        f=_parse_l4(pkt)
        if not f: continue
        if f['proto']==6:
            key=_tcp_stream_key(f)
        else:
            key=(f['src'],f['src_port'],f['dst'],f['dst_port'],f['proto'])
        rec=flows.get(key)
        if rec is None:
            rec={'key':key,'proto':'tcp' if f['proto']==6 else 'udp','packets':0,'bytes':0,
                 'first':ts,'last':ts,'dir_bytes':{}}
            flows[key]=rec
        rec['packets']+=1
        rec['bytes']+=len(f['payload'])
        rec['first']=min(rec['first'],ts); rec['last']=max(rec['last'],ts)
        ep=(f['src'],f['src_port'])
        rec['dir_bytes'][ep]=rec['dir_bytes'].get(ep,0)+len(f['payload'])
        if f['proto']==6 and f['tcp']:
            fl=f['tcp']['flags']
            if fl['syn']: rec.setdefault('flags',set()).add('SYN')
            if fl['fin']: rec.setdefault('flags',set()).add('FIN')
            if fl['rst']: rec.setdefault('flags',set()).add('RST')
    out=[]
    for rec in flows.values():
        src,dst = rec['key'][0], rec['key'][1]
        if rec['proto']=='tcp':
            a,b=rec['key']
            endpoints={'client':{'ip':a[0],'port':a[1]},'server':{'ip':b[0],'port':b[1]}}
        else:
            endpoints={'src':{'ip':rec['key'][0],'port':rec['key'][1]},
                       'dst':{'ip':rec['key'][2],'port':rec['key'][3]}}
        out.append({'protocol':rec['proto'],'endpoints':endpoints,'packets':rec['packets'],
                    'bytes':rec['bytes'],'first_seen':rec['first'],'last_seen':rec['last'],
                    'tcp_flags':sorted(rec.get('flags',[])),
                    'direction_byte_counts':{f"{k[0]}:{k[1]}":v for k,v in rec['dir_bytes'].items()}})
    out.sort(key=lambda x:(x['last_seen']-x['first_seen']),reverse=True)
    warnings=[]
    if count>=packet_limit: warnings.append(f'packet parsing limited to {packet_limit}')
    if len(out)>=max_flows: warnings.append(f'flow list limited to {max_flows}')
    return Observation('network.flows',Status.PARTIAL if warnings else Status.OK,
        f'Grouped {len(out)} flow(s) from {count} packet(s)',
        facts={'format':fmt,'flow_count':len(out),'flows':out[:max_flows],'packets_scanned':count},
        evidence=[Evidence(str(p),'network_flows',len(out),locator='flow-summary')],
        warnings=warnings,meta={'source_sha256':sha256_file(p)})


def _build_tcp_streams(p,packet_limit:int):
    """Return (streams, count, fmt, src_sha, error).

    ``streams`` maps a canonical stream key to a dict with ``client`` endpoint,
    and two segment lists (client->server, server->client) of (seq, payload, syn).
    """
    data,err, src=read_file_bounded_observation('network.tcp_reassemble',p,4*1024*1024*1024)
    if err: return None,0,None,'',err
    try: packets,fmt=_capture_packets(data,packet_limit)
    except PcapError as e: return None,0,None,'',Observation('network.tcp_reassemble',Status.UNSUPPORTED,'Unsupported capture',errors=[str(e)],meta={'source_sha256':sha256_file(p)})
    streams={}
    count=0
    for num,link,ts,pkt in packets:
        count=num
        if link!=1: continue
        f=_parse_l4(pkt)
        if not f or f['proto']!=6 or not f['tcp']: continue
        key=_tcp_stream_key(f)
        st=streams.get(key)
        if st is None:
            # Client = endpoint that sent the SYN; fall back to sorted[0].
            client=(f['src'],f['src_port'])
            st={'client':client,'c2s':[],'s2c':[]}
            streams[key]=st
        direction='c2s' if (f['src'],f['src_port'])==st['client'] else 's2c'
        st[direction].append((f['tcp']['seq'], f['tcp']['payload'], f['tcp']['flags']['syn']))
    return streams,count,fmt,sha256_file(p),None


@registry.tool(name='network.tcp_reassemble',description='Reassemble TCP streams from a capture: per direction it overlays segments by sequence number (handling retransmission, out-of-order and overlap) and emits a hash + bounded hex preview of the logical byte stream. READ_ONLY: the evidence file is never written.',
 safety=SafetyLevel.READ_ONLY,tags=('network','tcp','reassembly'),produces=('tcp_streams',),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'packet_limit':{'type':'integer','default':200000},'max_streams':{'type':'integer','default':300},'max_stream_bytes':{'type':'integer','default':8388608}},'required':['path']})
def tcp_reassemble(path:str,packet_limit:int=200000,max_streams:int=300,max_stream_bytes:int=8388608)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('network.tcp_reassemble',Status.ERROR,'Capture not found',errors=[str(p)])
    streams,count,fmt,src_sha,err=_build_tcp_streams(p,packet_limit)
    if err: return err
    results=[]; warnings=[]
    for key,st in streams.items():
        if len(results)>=max_streams:
            warnings.append(f'stream output limited to {max_streams}')
            break
        c2s_seg=st['c2s']; s2c_seg=st['s2c']
        c_isn,c_syn=_syn_isn(c2s_seg); s_isn,s_syn=_syn_isn(s2c_seg)
        c_data,c_gap,c_trunc=_reasm_dir(c2s_seg,c_isn+(1 if c_syn else 0),max_stream_bytes)
        s_data,s_gap,s_trunc=_reasm_dir(s2c_seg,s_isn+(1 if s_syn else 0),max_stream_bytes)
        def preview(b): return b[:_RECORD_CAP].hex()+('...' if len(b)>_RECORD_CAP else '')
        results.append({
            'stream':{'client':{'ip':st['client'][0],'port':st['client'][1]},
                      'server':{'ip':key[1][0] if key[0]==st['client'] else key[0][0],
                                'port':key[1][1] if key[0]==st['client'] else key[0][1]}},
            'client_to_server':{'length':len(c_data),'sha256':hashlib.sha256(c_data).hexdigest(),
                                'hex_preview':preview(c_data),'gaps':c_gap,'truncated':c_trunc},
            'server_to_client':{'length':len(s_data),'sha256':hashlib.sha256(s_data).hexdigest(),
                                'hex_preview':preview(s_data),'gaps':s_gap,'truncated':s_trunc},
        })
    if count>=packet_limit: warnings.append(f'packet parsing limited to {packet_limit}')
    return Observation('network.tcp_reassemble',Status.PARTIAL if warnings else Status.OK,
        f'Reassembled {len(results)} TCP stream(s) from {count} packet(s)',
        facts={'format':fmt,'stream_count':len(results),'streams':results,'packets_scanned':count},
        evidence=[Evidence(str(p),'tcp_stream',len(results),locator='reassembled-streams')],
        warnings=warnings,meta={'source_sha256':src_sha})


@registry.tool(name='network.http_sessions',description='Reassemble TCP streams and correlate HTTP request/response pairs. When a response body is a file-like object (by content-type or magic), it is extracted to the workspace and registered as a DerivedArtifact, forming the PCAP -> download -> binary analysis chain. STATEFUL: writes only to the workspace.',
 safety=SafetyLevel.STATEFUL,tags=('network','http','session','extract'),produces=('http_sessions','derived_artifacts'),cost_hint='high',
 parameters={'type':'object','properties':{'path':{'type':'string'},'output_dir':{'type':'string'},'packet_limit':{'type':'integer','default':200000},'max_sessions':{'type':'integer','default':200},'max_body_bytes':{'type':'integer','default':16777216}},'required':['path','output_dir']},
 path_roles={'path':'EVIDENCE_INPUT','output_dir':'WORKSPACE_OUTPUT'})
def http_sessions(path:str,output_dir:str,packet_limit:int=200000,max_sessions:int=200,max_body_bytes:int=16777216)->Observation:
    from dftk import __version__ as DFTK_VERSION
    p=Path(path)
    if not p.is_file(): return Observation('http_sessions',Status.ERROR,'Capture not found',errors=[str(p)])
    out=Path(output_dir); out.mkdir(parents=True,exist_ok=True); root=out.resolve()
    streams,count,fmt,src_sha,err=_build_tcp_streams(p,packet_limit)
    if err: return err
    sessions=[]; derived=[]; extracted=[]; warnings=[]
    prov=ProvenanceIndex()
    source_art=prov.add(source_artifact='',locator=f'file:{p.name}',tool='network.http_sessions',
                        version=DFTK_VERSION,sha256=src_sha,size=p.stat().st_size,kind='evidence',state='LIVE')
    derived.append(source_art)
    for key,st in streams.items():
        if len(sessions)>=max_sessions:
            warnings.append(f'session output limited to {max_sessions}'); break
        c_isn,c_syn=_syn_isn(st['c2s']); s_isn,s_syn=_syn_isn(st['s2c'])
        c_data,_,_=_reasm_dir(st['c2s'],c_isn+(1 if c_syn else 0),max_body_bytes)
        s_data,_,_=_reasm_dir(st['s2c'],s_isn+(1 if s_syn else 0),max_body_bytes)
        reqs=list(_iter_http_messages(c_data,True))
        resps=list(_iter_http_messages(s_data,False))
        for i in range(min(len(reqs),len(resps))):
            rmeta,rbody=reqs[i]; smeta,sbody=resps[i]
            entry={'index':i,'client':{'ip':st['client'][0],'port':st['client'][1]},
                   'method':rmeta.get('method'),'host':rmeta.get('host'),'target':rmeta.get('target'),
                   'status':smeta.get('status'),'server':smeta.get('server'),
                   'request_content_type':rmeta.get('content_type'),
                   'response_content_type':smeta.get('content_type'),'extracted':False}
            if _looks_like_file(smeta.get('content_type',''), sbody) and len(sbody)<=max_body_bytes:
                body_sha=hashlib.sha256(sbody).hexdigest()
                fname=f"http_{i}_{body_sha[:12]}.bin"
                dest=(root/fname).resolve()
                try: dest.relative_to(root)
                except ValueError:
                    warnings.append(f'refused unsafe extract path: {fname}'); continue
                dest.write_bytes(sbody)
                art=prov.add(source_artifact=source_art.artifact_id,
                             locator=f'http_response:{i}:{rmeta.get("host","")}{rmeta.get("target","")}',
                             tool='network.http_sessions',version=DFTK_VERSION,
                             sha256=body_sha,size=len(sbody),state='LIVE',path=str(dest))
                derived.append(art)
                extracted.append({'path':str(dest),'sha256':body_sha,'size':len(sbody),'host':rmeta.get('host'),'target':rmeta.get('target'),'content_type':smeta.get('content_type'),'magic':_magic_of(sbody)})
                entry['extracted']=True; entry['body_sha256']=body_sha
                entry['artifact_id']=art.artifact_id
            sessions.append(entry)
    if count>=packet_limit: warnings.append(f'packet parsing limited to {packet_limit}')
    return Observation('network.http_sessions',Status.PARTIAL if warnings else Status.OK,
        f'Correlated {len(sessions)} HTTP session(s); extracted {len(extracted)} object(s)',
        facts={'format':fmt,'session_count':len(sessions),'sessions':sessions,'extracted':extracted,'packets_scanned':count},
        evidence=[Evidence(str(p),'http_session',len(sessions),locator='reassembled-streams',artifact_id=source_art.artifact_id,derivation={'tool':'network.http_sessions','version':DFTK_VERSION})],
        warnings=warnings,derived_artifacts=derived,meta={'source_sha256':src_sha,'provenance':prov.to_dict()})


def _magic_of(body: bytes) -> str:
    for m,name in _MAGICS.items():
        if body[:len(m)]==m: return name
    return ''


@registry.tool(name='network.dns_transactions',description='Correlate DNS query and response messages by transaction id and question name, resolving A/AAAA/CNAME answers to their queried names. READ_ONLY.',
 safety=SafetyLevel.READ_ONLY,tags=('network','dns','transaction'),produces=('dns_transactions',),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'packet_limit':{'type':'integer','default':200000},'limit':{'type':'integer','default':5000}},'required':['path']})
def dns_transactions(path:str,packet_limit:int=200000,limit:int=5000)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('dns_transactions',Status.ERROR,'Capture not found',errors=[str(p)])
    data,err, src=read_file_bounded_observation('dns_transactions',p,4*1024*1024*1024)
    if err: return err
    try: packets,fmt=_capture_packets(data,packet_limit)
    except PcapError as e: return Observation('dns_transactions',Status.UNSUPPORTED,'Unsupported capture',errors=[str(e)],meta={'source_sha256':sha256_file(p)})
    queries=[]; responses={}
    count=0
    for num,link,ts,pkt in packets:
        count=num
        if link!=1: continue
        f=_parse_l4(pkt)
        if not f or f['proto']!=17: continue
        pl=f['payload']
        if len(pl)<12: continue
        tid=struct.unpack_from('!H',pl,0)[0]
        flags=struct.unpack_from('!H',pl,2)[0]
        qr=(flags>>15)&1
        questions,answers=_parse_dns(pl)
        if qr==0:
            for q in questions:
                queries.append({'txn':tid,'time':ts,'src':f['src'],'dst':f['dst'],
                                'name':q['name'],'type':q['type']})
        else:
            for q in questions:
                responses.setdefault((tid,q['name'],q['type']),[]).append(
                    {'time':ts,'src':f['src'],'dst':f['dst'],'answers':answers})
    txns=[]; warnings=[]
    for q in queries:
        key=(q['txn'],q['name'],q['type'])
        resp=responses.get(key)
        rec={'transaction_id':q['txn'],'time':q['time'],'query':{'name':q['name'],'type':q['type'],'src':q['src'],'dst':q['dst']},
             'answered':bool(resp),'responses':[]}
        if resp:
            for r in resp:
                rec['responses'].append({'time':r['time'],'src':r['src'],'dst':r['dst'],
                    'answers':[{k:v for k,v in a.items() if k in ('name','type','address','cname','ttl')} for a in r['answers']]})
        txns.append(rec)
        if len(txns)>=limit: warnings.append(f'DNS transactions limited to {limit}'); break
    return Observation('dns_transactions',Status.PARTIAL if warnings else Status.OK,
        f"Correlated {len(txns)} DNS transaction(s) ({sum(1 for t in txns if t['answered'])} answered)",
        facts={'format':fmt,'transaction_count':len(txns),'transactions':txns,'packets_scanned':count},
        evidence=[Evidence(str(p),'dns_transaction',len(txns),locator='dns-correlation')],
        warnings=warnings,meta={'source_sha256':sha256_file(p)})


@registry.tool(name='network.tls_inventory',description='Inventory TLS ClientHello records from a capture: SNI, ALPN, record/client version, supported versions, cipher suites, extensions and a JA3 fingerprint (MD5). READ_ONLY.',
 safety=SafetyLevel.READ_ONLY,tags=('network','tls','ja3'),produces=('tls_client_hellos',),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'packet_limit':{'type':'integer','default':200000},'limit':{'type':'integer','default':5000}},'required':['path']})
def tls_inventory(path:str,packet_limit:int=200000,limit:int=5000)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('tls_inventory',Status.ERROR,'Capture not found',errors=[str(p)])
    data,err, src=read_file_bounded_observation('tls_inventory',p,4*1024*1024*1024)
    if err: return err
    try: packets,fmt=_capture_packets(data,packet_limit)
    except PcapError as e: return Observation('tls_inventory',Status.UNSUPPORTED,'Unsupported capture',errors=[str(e)],meta={'source_sha256':sha256_file(p)})
    hellos=[]; warnings=[]; count=0; seen=set()
    for num,link,ts,pkt in packets:
        count=num
        if link!=1: continue
        f=_parse_l4(pkt)
        if not f or f['proto']!=6: continue
        pl=f['payload']
        if len(pl)<9 or pl[0]!=22: continue
        ch=_parse_client_hello(pl)
        if not ch: continue
        # de-dup by JA3 + SNI to keep inventory readable
        dedupe=(ch['ja3'],ch['sni'])
        if dedupe in seen: continue
        seen.add(dedupe)
        hellos.append({'packet':num,'time':ts,'src':f['src'],'dst':f['dst'],'src_port':f['src_port'],
                       'sni':ch['sni'],'alpn':ch['alpn'],'record_version':ch['record_version'],
                       'client_version':ch['client_version'],'supported_versions':ch['supported_versions'],
                       'cipher_suite_count':len(ch['cipher_suites']),
                       'extension_count':len(ch['extensions']),'ja3':ch['ja3'],
                       'ja3_string':ch['ja3_string']})
        if len(hellos)>=limit: warnings.append(f'TLS inventory limited to {limit}'); break
    return Observation('tls_inventory',Status.PARTIAL if warnings else Status.OK,
        f'Inventoried {len(hellos)} TLS ClientHello(s)',
        facts={'format':fmt,'hello_count':len(hellos),'client_hellos':hellos,'packets_scanned':count},
        evidence=[Evidence(str(p),'tls_client_hello',h['sni'] or h['ja3'],locator=f"packet:{h['packet']}",method='TLS ClientHello parser') for h in hellos[:100]],
        warnings=warnings,meta={'source_sha256':sha256_file(p)})
