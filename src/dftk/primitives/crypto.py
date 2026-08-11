from __future__ import annotations
from pathlib import Path
import hashlib,re,importlib.resources
from dftk.core.registry import registry
from dftk.core.models import Observation,Evidence,Status,SafetyLevel
from dftk.core.helpers import bounded_files,sha256_file

VALID_LENGTHS={12,15,18,21,24}

def load_wordlist()->list[str]:
    p=importlib.resources.files('dftk').joinpath('data/bip39_english.txt')
    words=[x.strip() for x in p.read_text(encoding='utf-8').splitlines() if x.strip()]
    if len(words)!=2048 or len(set(words))!=2048: raise RuntimeError(f"invalid packaged BIP39 word list ({len(words)} entries)")
    return words

def validate_bip39(words:list[str],wordlist:list[str]|None=None)->dict:
    wordlist=wordlist or load_wordlist(); idx={w:i for i,w in enumerate(wordlist)}
    if len(words) not in VALID_LENGTHS: return {"valid":False,"reason":"invalid_word_count"}
    if any(w not in idx for w in words): return {"valid":False,"reason":"word_not_in_list"}
    bits=''.join(f'{idx[w]:011b}' for w in words)
    ent=len(bits)*32//33; cs=len(bits)-ent
    entropy_bits=bits[:ent]; checksum_bits=bits[ent:]
    entropy=int(entropy_bits,2).to_bytes(ent//8,'big')
    expected=f'{hashlib.sha256(entropy).digest()[0]:08b}'[:cs]
    return {"valid":checksum_bits==expected,"reason":"checksum_ok" if checksum_bits==expected else "checksum_mismatch","entropy_hex":entropy.hex(),"checksum_bits":checksum_bits,"expected_checksum_bits":expected}

def _scan_text(text:str,wordlist:list[str],max_candidates:int):
    known=set(wordlist); tokens=[m.group(0).lower() for m in re.finditer(r"[A-Za-z]+",text)]
    out=[]; i=0
    while i<len(tokens):
        if tokens[i] not in known: i+=1; continue
        j=i
        while j<len(tokens) and tokens[j] in known: j+=1
        run=tokens[i:j]
        for n in sorted(VALID_LENGTHS,reverse=True):
            if len(run)<n: continue
            for k in range(0,len(run)-n+1):
                phrase=run[k:k+n]; verdict=validate_bip39(phrase,wordlist)
                out.append({"words":phrase,"word_count":n,**verdict})
                if len(out)>=max_candidates: return out
        i=j
    # deduplicate phrase candidates
    seen=set(); uniq=[]
    for c in out:
        key=tuple(c['words'])
        if key not in seen: seen.add(key); uniq.append(c)
    return uniq[:max_candidates]

@registry.tool(name="crypto.bip39_validate",description="Validate a BIP39 English mnemonic including its checksum.",safety=SafetyLevel.READ_ONLY,
 parameters={"type":"object","properties":{"mnemonic":{"type":"string"}},"required":["mnemonic"]})
def bip39_validate(mnemonic:str)->Observation:
    words=mnemonic.strip().lower().split(); verdict=validate_bip39(words)
    return Observation("crypto.bip39_validate",Status.OK,"BIP39 validation complete",facts={"word_count":len(words),**verdict})

@registry.tool(name="crypto.bip39_scan",description="Scan one file or directory for BIP39 English word sequences and distinguish checksum-valid mnemonics.",safety=SafetyLevel.READ_ONLY,
 parameters={"type":"object","properties":{"path":{"type":"string"},"max_files":{"type":"integer","default":5000},"max_bytes_per_file":{"type":"integer","default":8388608},"max_candidates":{"type":"integer","default":200}},"required":["path"]})
def bip39_scan(path:str,max_files:int=5000,max_bytes_per_file:int=8*1024*1024,max_candidates:int=200)->Observation:
    p=Path(path); wordlist=load_wordlist(); files=[p] if p.is_file() else list(bounded_files(p,max_files=max_files)) if p.is_dir() else []
    if not files: return Observation("crypto.bip39_scan",Status.ERROR,"Input path not found or empty",errors=[str(p)])
    hits=[]; skipped=0
    for f in files:
        try:
            if f.stat().st_size>max_bytes_per_file: skipped+=1; continue
            text=f.read_bytes().decode('utf-8','ignore')
            cs=_scan_text(text,wordlist,max_candidates-len(hits))
            for c in cs: hits.append({"file":str(f),**c})
            if len(hits)>=max_candidates: break
        except OSError: skipped+=1
    valid=[h for h in hits if h['valid']]
    ev=[Evidence(h['file'],"bip39_mnemonic"," ".join(h['words']),locator="text-scan",note="checksum valid") for h in valid[:100]]
    warnings=[]
    if skipped: warnings.append(f"skipped {skipped} unreadable/oversized file(s)")
    if len(hits)>=max_candidates: warnings.append(f"candidate result limited to {max_candidates}")
    return Observation("crypto.bip39_scan",Status.OK,f"Found {len(hits)} dictionary-sequence candidate(s), {len(valid)} checksum-valid",facts={"candidates":hits,"valid_count":len(valid),"wordlist_size":len(wordlist)},evidence=ev,warnings=warnings)

import math,base64,binascii,urllib.parse
from collections import Counter

def _entropy(data:bytes)->float:
    if not data: return 0.0
    counts=Counter(data); n=len(data)
    return -sum((c/n)*math.log2(c/n) for c in counts.values())

@registry.tool(name='crypto.entropy_profile',description='Compute bounded Shannon entropy per file block to highlight compressed/encrypted/high-entropy regions; does not classify encryption by itself.',
 safety=SafetyLevel.READ_ONLY,tags=('crypto','entropy','binary'),produces=('entropy_profile',),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'block_size':{'type':'integer','default':4096},'block_limit':{'type':'integer','default':100000}},'required':['path']})
def entropy_profile(path:str,block_size:int=4096,block_limit:int=100000)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('crypto.entropy_profile',Status.ERROR,'File not found',errors=[str(p)])
    if block_size<256 or block_size>16*1024*1024: return Observation('crypto.entropy_profile',Status.ERROR,'block_size outside supported range',errors=['256..16777216'])
    rows=[]
    with p.open('rb') as f:
        for idx in range(block_limit):
            data=f.read(block_size)
            if not data: break
            rows.append({'index':idx,'offset':idx*block_size,'size':len(data),'entropy':round(_entropy(data),6)})
    vals=[r['entropy'] for r in rows]; warnings=[]
    if len(rows)>=block_limit and p.stat().st_size>block_limit*block_size: warnings.append(f'profile limited to {block_limit} blocks')
    facts={'block_size':block_size,'blocks':rows,'mean_entropy':sum(vals)/len(vals) if vals else 0.0,'max_entropy':max(vals) if vals else 0.0,'high_entropy_blocks':sum(v>=7.5 for v in vals)}
    return Observation('crypto.entropy_profile',Status.OK,f'Computed entropy for {len(rows)} block(s)',facts=facts,evidence=[Evidence(str(p),'entropy_profile',facts['mean_entropy'],locator=f'blocks:{block_size}',note='high entropy is not proof of encryption')],warnings=warnings,meta={'source_sha256':sha256_file(p)})

@registry.tool(name='encoding.decode_candidates',description='Try common reversible text encodings (hex, Base64/Base64URL, percent-encoding) and return bounded decoded candidates with printable ratios.',
 safety=SafetyLevel.READ_ONLY,tags=('encoding','triage'),produces=('decoded_candidates',),
 parameters={'type':'object','properties':{'value':{'type':'string'},'max_output_bytes':{'type':'integer','default':1048576}},'required':['value']})
def decode_candidates(value:str,max_output_bytes:int=1024*1024)->Observation:
    candidates=[]; seen=set()
    def add(kind:str,data:bytes):
        data=data[:max_output_bytes]; key=data
        if key in seen: return
        seen.add(key); printable=sum((32<=b<=126) or b in (9,10,13) for b in data)/(len(data) or 1)
        candidates.append({'encoding':kind,'size':len(data),'printable_ratio':round(printable,4),'text_preview':data[:4096].decode('utf-8','replace'),'hex_preview':data[:256].hex()})
    text=value.strip()
    try:
        if len(text)%2==0 and re.fullmatch(r'[0-9a-fA-F]+',text): add('hex',bytes.fromhex(text))
    except ValueError: pass
    for kind,decoder in [('base64',base64.b64decode),('base64url',base64.urlsafe_b64decode)]:
        try:
            padded=text+'='*((4-len(text)%4)%4); data=decoder(padded.encode('ascii'))
            if data: add(kind,data)
        except (ValueError,binascii.Error,UnicodeEncodeError): continue
    try:
        decoded=urllib.parse.unquote_to_bytes(text)
        if decoded!=text.encode('utf-8'): add('percent',decoded)
    except (UnicodeEncodeError,ValueError): pass
    return Observation('encoding.decode_candidates',Status.OK,f'Produced {len(candidates)} decode candidate(s)',facts={'candidates':candidates},warnings=['candidates are syntactic decodings, not proof of intended encoding'])
