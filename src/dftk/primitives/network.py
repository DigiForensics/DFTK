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
import struct,socket,re
from collections import Counter
from dftk.core.registry import registry
from dftk.core.models import Observation,Evidence,Status,SafetyLevel
from dftk.core.helpers import sha256_file, read_file_bounded_observation

class PcapError(ValueError): pass

def _ip(b): return socket.inet_ntoa(b)

@registry.tool(name="network.pcap_inventory",description="Parse classic PCAP packet headers and summarize IPv4 TCP/UDP endpoint tuples without external libraries.",safety=SafetyLevel.READ_ONLY,
 parameters={"type":"object","properties":{"path":{"type":"string"},"packet_limit":{"type":"integer","default":200000},"sample_limit":{"type":"integer","default":200}},"required":["path"]})
def pcap_inventory(path:str,packet_limit:int=200000,sample_limit:int=200)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation("network.pcap_inventory",Status.ERROR,"PCAP not found",errors=[str(p)])
    data,err=read_file_bounded_observation('network.pcap_inventory',p,4*1024*1024*1024)
    if err: return err
    if len(data)<24: return Observation("network.pcap_inventory",Status.UNSUPPORTED,"PCAP too small",meta={"source_sha256":sha256_file(p)})
    magic=data[:4]
    fmts={b'\xd4\xc3\xb2\xa1':('<',False),b'\xa1\xb2\xc3\xd4':('>',False),b'M<\xb2\xa1':('<',True),b'\xa1\xb2<M':('>',True)}
    if magic not in fmts:
        return Observation("network.pcap_inventory",Status.UNSUPPORTED,"Only classic PCAP is supported (not PCAPNG)",meta={"source_sha256":sha256_file(p)})
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
    return Observation("network.pcap_inventory",Status.PARTIAL if malformed else Status.OK,f"Parsed {count} packet(s)",facts={"linktype":network,"packet_count":count,"protocol_counts":dict(proto),"top_flows":top,"samples":samples},evidence=[Evidence(str(p),'pcap_summary',f"{count} packets",locator='pcap-records')],warnings=warnings,meta={"source_sha256":sha256_file(p)})

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
    data,err=read_file_bounded_observation('network.pcapng_inventory',p,4*1024*1024*1024)
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
        return Observation('network.pcapng_inventory',Status.UNSUPPORTED,'PCAPNG parsing failed',errors=[str(e)],meta={'source_sha256':sha256_file(p)})
    warnings=[f'unsupported linktype {k}: {v} packet(s)' for k,v in unsupported_links.items()]
    if count>=packet_limit: warnings.append(f'packet parsing limited to {packet_limit}')
    return Observation('network.pcapng_inventory',Status.PARTIAL if unsupported_links else Status.OK,f'Parsed {count} PCAPNG packet(s)',facts={'packet_count':count,'protocol_counts':dict(protos),'top_flows':[{'flow':k,'packets':v} for k,v in flows.most_common(100)],'samples':samples},evidence=[Evidence(str(p),'pcapng_summary',count,locator='blocks')],warnings=warnings,meta={'source_sha256':sha256_file(p)})

@registry.tool(name='network.capture_protocols',description='Extract bounded DNS questions, plaintext HTTP requests and TLS ClientHello SNI from classic PCAP or PCAPNG.',
 safety=SafetyLevel.READ_ONLY,tags=('network','protocols','pcap'),produces=('dns_queries','http_requests','tls_sni'),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'packet_limit':{'type':'integer','default':200000},'limit':{'type':'integer','default':5000}},'required':['path']})
def capture_protocols(path:str,packet_limit:int=200000,limit:int=5000)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('network.capture_protocols',Status.ERROR,'Capture not found',errors=[str(p)])
    data,err=read_file_bounded_observation('network.capture_protocols',p,4*1024*1024*1024)
    if err: return err
    dns=[]; http=[]; tls=[]; warnings=[]; count=0
    try: packets,fmt=_capture_packets(data,packet_limit)
    except PcapError as e: return Observation('network.capture_protocols',Status.UNSUPPORTED,'Unsupported capture',errors=[str(e)],meta={'source_sha256':sha256_file(p)})
    try:
        for num,link,ts,pkt in packets:
            count=num
            if link!=1: continue
            ip=_parse_ipv4_frame(pkt)
            if not ip: continue
            ports={ip['src_port'],ip['dst_port']}; payload=ip['payload']
            if ip['proto']==17 and 53 in ports:
                for q in _dns_questions(payload):
                    dns.append({'packet':num,'time':ts,'src':ip['src'],'dst':ip['dst'],**q})
            elif ip['proto']==6:
                req=_http_request(payload)
                if req: http.append({'packet':num,'time':ts,'src':ip['src'],'dst':ip['dst'],**req})
                sni=_tls_sni(payload)
                if sni: tls.append({'packet':num,'time':ts,'src':ip['src'],'dst':ip['dst'],'server_name':sni})
            if len(dns)+len(http)+len(tls)>=limit: break
    except PcapError as e:
        warnings.append(str(e))
    if len(dns)+len(http)+len(tls)>=limit: warnings.append(f'protocol findings limited to {limit}')
    ev=[]
    for r in dns[:100]: ev.append(Evidence(str(p),'dns_query',r['name'],locator=f"packet:{r['packet']}",method='DNS question parser'))
    for r in http[:100]: ev.append(Evidence(str(p),'http_request',f"{r['method']} {r['host'] or ''}{r['target']}",locator=f"packet:{r['packet']}",method='HTTP/1 request parser'))
    for r in tls[:100]: ev.append(Evidence(str(p),'tls_sni',r['server_name'],locator=f"packet:{r['packet']}",method='TLS ClientHello parser'))
    return Observation('network.capture_protocols',Status.PARTIAL if warnings else Status.OK,f'Extracted {len(dns)} DNS, {len(http)} HTTP and {len(tls)} TLS SNI finding(s)',facts={'format':fmt,'dns_questions':dns,'http_requests':http,'tls_sni':tls,'packets_scanned':count},evidence=ev,warnings=warnings,meta={'source_sha256':sha256_file(p)})
