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
from email import policy
from email.parser import BytesParser
from email.header import decode_header
from email.utils import parseaddr
import re, hashlib, os
from dftk.core.registry import registry
from dftk.core.models import Observation,Evidence,Status,SafetyLevel
from dftk.core.helpers import sha256_file


def _decode(v:str)->str:
    if not v:return ''
    out=[]
    for part,cs in decode_header(v):
        if isinstance(part,bytes):
            try: out.append(part.decode(cs or 'utf-8','replace'))
            except LookupError: out.append(part.decode('utf-8','replace'))
        else: out.append(str(part))
    return ''.join(out)

def _domain(addr:str)->str:
    return addr.rsplit('@',1)[1].lower().rstrip('.') if '@' in addr else ''

def _parse_auth_results(headers:list[str]):
    rows=[]
    method_rx=re.compile(r'\b(spf|dkim|dmarc|arc)\s*=\s*([A-Za-z0-9_-]+)',re.I)
    for h in headers:
        authserv=h.split(';',1)[0].strip() if ';' in h else ''
        methods=[{"method":m.group(1).lower(),"result":m.group(2).lower()} for m in method_rx.finditer(h)]
        rows.append({"authserv_id":authserv,"methods":methods,"raw":h})
    return rows

def _parse_dkim_domains(headers:list[str]):
    out=[]
    for h in headers:
        d=re.search(r'(?:^|;)\s*d=([^;\s]+)',h,re.I); s=re.search(r'(?:^|;)\s*s=([^;\s]+)',h,re.I)
        out.append({"domain":d.group(1).lower() if d else '',"selector":s.group(1) if s else ''})
    return out

@registry.tool(name="email.auth_analyze",description="Offline EML analysis of sender headers, DKIM identifiers and Authentication-Results. Header mismatches are context, not automatic spoofing verdicts.",safety=SafetyLevel.READ_ONLY,
 parameters={"type":"object","properties":{"path":{"type":"string"}},"required":["path"]})
def auth_analyze(path:str)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation("email.auth_analyze",Status.ERROR,"EML file not found",errors=[str(p)])
    raw=p.read_bytes()
    try: msg=BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as e: return Observation("email.auth_analyze",Status.ERROR,"Email parse failed",errors=[str(e)],meta={"source_sha256":sha256_file(p)})
    from_name,from_addr=parseaddr(_decode(msg.get('From','')))
    sender_name,sender_addr=parseaddr(_decode(msg.get('Sender','')))
    _,reply_addr=parseaddr(_decode(msg.get('Reply-To','')))
    rp=msg.get('Return-Path','').strip().strip('<>')
    dkims=_parse_dkim_domains(msg.get_all('DKIM-Signature',[]))
    auth=_parse_auth_results(msg.get_all('Authentication-Results',[]))
    relationships=[]
    if sender_addr and sender_addr.lower()!=from_addr.lower(): relationships.append({"type":"from_sender_differ","severity":"info","from":from_addr,"sender":sender_addr})
    if reply_addr and reply_addr.lower()!=from_addr.lower(): relationships.append({"type":"from_reply_to_differ","severity":"info","from":from_addr,"reply_to":reply_addr})
    if rp and _domain(rp)!=_domain(from_addr): relationships.append({"type":"return_path_domain_differs","severity":"info","from_domain":_domain(from_addr),"return_path_domain":_domain(rp)})
    if dkims:
        for d in dkims:
            if d['domain'] and d['domain']!=_domain(from_addr): relationships.append({"type":"dkim_domain_differs","severity":"info","from_domain":_domain(from_addr),"dkim_domain":d['domain']})
    # Do not trust Authentication-Results blindly: it is meaningful only from a trusted receiving boundary.
    claimed=[]
    for row in auth:
        claimed.extend(row['methods'])
    facts={"subject":_decode(msg.get('Subject','')),"date":msg.get('Date',''),"message_id":msg.get('Message-ID',''),
           "from":{"name":from_name,"address":from_addr,"domain":_domain(from_addr)},"sender":{"name":sender_name,"address":sender_addr},
           "reply_to":reply_addr,"return_path":rp,"dkim_identifiers":dkims,"authentication_results":auth,
           "claimed_authentication":claimed,"header_relationships":relationships,
           "verdict":"undetermined_offline","verdict_reason":"Offline header analysis cannot by itself establish sender authenticity."}
    ev=[Evidence(str(p),'email_header',f"From: {from_addr}",locator='header:From')]
    for i,d in enumerate(dkims): ev.append(Evidence(str(p),'dkim_identifier',d,locator=f'header:DKIM-Signature[{i}]'))
    warnings=[]
    if auth: warnings.append("Authentication-Results is recorded as a claim; trust it only if the receiving authentication service is within the established evidence boundary.")
    return Observation("email.auth_analyze",Status.OK,"Offline email authentication context extracted",facts=facts,evidence=ev,warnings=warnings,meta={"source_sha256":sha256_file(p)})

@registry.tool(name="email.dkim_verify",description="Verify DKIM signatures using dkimpy and DNS. This is signature verification, not DKIM-Signature repair.",safety=SafetyLevel.READ_ONLY,network=True,requires=('dkimpy','dnspython'),tags=('email','dkim'),produces=('dkim_verification',),
 parameters={"type":"object","properties":{"path":{"type":"string"}},"required":["path"]})
def dkim_verify(path:str)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation("email.dkim_verify",Status.ERROR,"EML file not found",errors=[str(p)])
    try: import dkim
    except ImportError: return Observation("email.dkim_verify",Status.UNSUPPORTED,"dkimpy is not installed",errors=["install optional dependency: pip install 'dftk[email]'"],meta={"source_sha256":sha256_file(p)})
    raw=p.read_bytes()
    try:
        ok=bool(dkim.verify(raw))
    except Exception as e:
        return Observation("email.dkim_verify",Status.ERROR,"DKIM verification failed to execute",errors=[f"{type(e).__name__}: {e}"],meta={"source_sha256":sha256_file(p)})
    return Observation("email.dkim_verify",Status.OK,"DKIM verification completed",facts={"verified":ok},evidence=[Evidence(str(p),'dkim_verification',ok,locator='DKIM-Signature')],meta={"source_sha256":sha256_file(p)})

@registry.tool(name="email.spf_verify",description="Evaluate SPF for a supplied sending IP and SMTP envelope identity using pyspf and DNS; it does not infer IP from From headers.",safety=SafetyLevel.READ_ONLY,network=True,requires=('pyspf','dnspython'),tags=('email','spf'),produces=('spf_result',),
 parameters={"type":"object","properties":{"ip":{"type":"string"},"mail_from":{"type":"string"},"helo":{"type":"string"}},"required":["ip","mail_from","helo"]})
def spf_verify(ip:str,mail_from:str,helo:str)->Observation:
    try: import spf
    except ImportError: return Observation("email.spf_verify",Status.UNSUPPORTED,"pyspf is not installed",errors=["install optional dependency: pip install 'dftk[email]' "])
    try:
        result,code,explanation=spf.check2(i=ip,s=mail_from,h=helo)
    except Exception as e: return Observation("email.spf_verify",Status.ERROR,"SPF evaluation failed",errors=[f"{type(e).__name__}: {e}"])
    return Observation("email.spf_verify",Status.OK,"SPF evaluation completed",facts={"result":result,"smtp_code":code,"explanation":explanation,"ip":ip,"mail_from":mail_from,"helo":helo})

@registry.tool(name='email.mime_inventory',description='Parse an RFC-style email file and inventory headers, MIME parts and attachment hashes without extracting or executing content.',
 safety=SafetyLevel.READ_ONLY,tags=('email','mime','attachments'),produces=('email_headers','mime_parts','attachments'),
 parameters={'type':'object','properties':{'path':{'type':'string'},'include_body_preview':{'type':'boolean','default':False},'preview_chars':{'type':'integer','default':1000}},'required':['path']})
def mime_inventory(path:str,include_body_preview:bool=False,preview_chars:int=1000)->Observation:
    from email import policy
    from email.parser import BytesParser
    import hashlib
    p=Path(path)
    if not p.is_file(): return Observation('email.mime_inventory',Status.ERROR,'Email file not found',errors=[str(p)])
    try: msg=BytesParser(policy=policy.default).parsebytes(p.read_bytes())
    except Exception as e: return Observation('email.mime_inventory',Status.ERROR,'Email parsing failed',errors=[f'{type(e).__name__}: {e}'],meta={'source_sha256':sha256_file(p)})
    headers={k:str(v) for k,v in msg.items()}; parts=[]; attachments=[]; ev=[]
    iterable=list(msg.walk()) if msg.is_multipart() else [msg]
    for idx,part in enumerate(iterable):
        if part.is_multipart():
            parts.append({'index':idx,'content_type':part.get_content_type(),'multipart':True}); continue
        payload=part.get_payload(decode=True) or b''; filename=part.get_filename(); disp=part.get_content_disposition()
        row={'index':idx,'content_type':part.get_content_type(),'charset':part.get_content_charset(),'content_disposition':disp,'filename':filename,'size':len(payload),'sha256':hashlib.sha256(payload).hexdigest()}
        if include_body_preview and not filename and part.get_content_maintype()=='text':
            try: row['preview']=payload.decode(part.get_content_charset() or 'utf-8','replace')[:preview_chars]
            except LookupError: row['preview']=payload.decode('utf-8','replace')[:preview_chars]
        parts.append(row)
        if filename or disp=='attachment':
            attachments.append(row); ev.append(Evidence(str(p),'email_attachment',filename or f'part-{idx}',locator=f'mime-part:{idx}',note=row['sha256'],method='MIME parser'))
    return Observation('email.mime_inventory',Status.OK,f'Parsed email with {len(parts)} MIME part(s) and {len(attachments)} attachment(s)',facts={'headers':headers,'parts':parts,'attachments':attachments},evidence=ev,meta={'source_sha256':sha256_file(p)})
