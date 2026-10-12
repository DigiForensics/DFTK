# Copyright 2026 DyNooob @ DigiForensics
# Licensed under the Apache License, Version 2.0.
"""Streaming byte-block comparison; never executes either input."""
from __future__ import annotations
import hashlib
from pathlib import Path
from dftk.core.models import Evidence, Observation, SafetyLevel, Status
from dftk.core.registry import registry


@registry.tool(name='binary.compare', description='Compare two files by fixed byte blocks, computing both SHA-256 digests in one streaming pass. Report changed block offsets/sizes and bounded previews; does not infer semantic equivalence or execute inputs.',
 safety=SafetyLevel.READ_ONLY, tags=('binary','diff','comparison','reverse'), produces=('binary_diff','hash'), cost_hint='medium',
 path_roles={'left':'EVIDENCE_INPUT','right':'EVIDENCE_INPUT'},
 parameters={'type':'object','properties':{'left':{'type':'string'},'right':{'type':'string'},
 'block_size':{'type':'integer','default':65536,'minimum':1,'maximum':1048576},
 'limit':{'type':'integer','default':1000,'minimum':1,'maximum':100000},
 'max_bytes':{'type':'integer','default':536870912,'minimum':1}},'required':['left','right']})
def compare(left:str,right:str,block_size:int=65536,limit:int=1000,max_bytes:int=536870912)->Observation:
    tool='binary.compare'
    if any(isinstance(n,bool) or not isinstance(n,int) for n in (block_size,limit,max_bytes)) or not 1<=block_size<=1048576 or not 1<=limit<=100000 or max_bytes<1:
        return Observation(tool,Status.ERROR,'Invalid comparison bounds',errors=['positive integer bounds are required'])
    paths=[Path(left),Path(right)]
    try:
        if not all(p.is_file() for p in paths):
            raise FileNotFoundError('Both inputs must be regular files')
        if any(p.stat().st_size>max_bytes for p in paths):
            return Observation(tool,Status.UNSUPPORTED,'Input exceeds comparison byte limit',errors=[f'max_bytes={max_bytes} per input'])
        hashes=[hashlib.sha256(),hashlib.sha256()]; sizes=[0,0]; differences=[]; changed=0; offset=0
        with paths[0].open('rb') as a,paths[1].open('rb') as b:
            while True:
                chunks=[a.read(min(block_size,max_bytes-sizes[0]+1)),b.read(min(block_size,max_bytes-sizes[1]+1))]
                if not any(chunks): break
                for i,chunk in enumerate(chunks):
                    sizes[i]+=len(chunk)
                    if sizes[i]>max_bytes:
                        return Observation(tool,Status.ERROR,'Input grew beyond comparison limit',errors=['acquisition is not stable; comparison incomplete'])
                    hashes[i].update(chunk)
                if chunks[0]!=chunks[1]:
                    changed+=1
                    if len(differences)<limit:
                        differences.append({'offset':offset,'left_size':len(chunks[0]),'right_size':len(chunks[1]),
                          'left_sha256':hashlib.sha256(chunks[0]).hexdigest(),'right_sha256':hashlib.sha256(chunks[1]).hexdigest(),
                          'left_preview_hex':chunks[0][:32].hex(),'right_preview_hex':chunks[1][:32].hex()})
                offset+=block_size
        digests=[h.hexdigest() for h in hashes]
        warnings=[f'Changed-block preview limited to {limit} records; counts/digests cover the complete inputs.'] if changed>limit else []
        facts={'identical':digests[0]==digests[1] and sizes[0]==sizes[1], 'left':{'path':str(paths[0]),'size':sizes[0],'sha256':digests[0]},
               'right':{'path':str(paths[1]),'size':sizes[1],'sha256':digests[1]},'block_size':block_size,'changed_blocks':changed,'differences':differences,
               'comparison_semantics':'fixed byte offsets; insertions can shift subsequent blocks'}
        evidence=[Evidence(str(p),'binary_comparison_input',digest,locator='whole-file',source_sha256=digest,method='streaming SHA-256') for p,digest in zip(paths,digests)]
        return Observation(tool,Status.PARTIAL if warnings else Status.OK,f'Compared inputs: {changed} changed block(s)',facts=facts,evidence=evidence,warnings=warnings)
    except OSError as exc:
        return Observation(tool,Status.ERROR,'Comparison read failed',errors=[str(exc)])
