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
from dftk.core.registry import registry
from dftk.core.models import Observation,Status,SafetyLevel
from dftk.core.aggregate import aggregate
from dftk.core.safety import SafetyPolicy

@registry.tool(name="recipe.server.offline_triage",description="Compose offline Linux, package-history, Docker and web-config discovery for a mounted server root.",safety=SafetyLevel.READ_ONLY,
 parameters={"type":"object","properties":{"root":{"type":"string"}},"required":["root"]})
def server_offline_triage(root:str)->Observation:
    p=SafetyPolicy()
    children=[registry.run('linux.offline_inventory',{'root':root},p),registry.run('linux.package_events',{'root':root},p),registry.run('docker.offline_inventory',{'root':root},p),registry.run('web.config_candidates',{'root':root},p)]
    return aggregate('recipe.server.offline_triage',children,"Offline server triage complete")

@registry.tool(name="recipe.android.static_triage",description="Compose APK inventory with targeted DEX searches for URLs, crypto API names and storage/network indicators.",safety=SafetyLevel.READ_ONLY,
 parameters={"type":"object","properties":{"path":{"type":"string"},"extra_query":{"type":"string"}},"required":["path"]})
def android_static_triage(path:str,extra_query:str|None=None)->Observation:
    p=SafetyPolicy(); children=[registry.run('android.apk_inventory',{'path':path},p)]
    patterns=[r'https?://',r'(?i)(AES|DES|RC4|Cipher|SecretKeySpec|MessageDigest)',r'(?i)(shared_prefs|sqlite|content://|android.permission|socket|upload|download)']
    if extra_query: patterns.append(extra_query)
    for pat in patterns: children.append(registry.run('android.apk_search',{'path':path,'query':pat,'regex':True,'limit':300},p))
    return aggregate('recipe.android.static_triage',children,"APK static triage complete")

@registry.tool(name="recipe.email.offline_triage",description="Run offline email authentication-context extraction without DNS or remote lookups.",safety=SafetyLevel.READ_ONLY,
 parameters={"type":"object","properties":{"path":{"type":"string"}},"required":["path"]})
def email_offline_triage(path:str)->Observation:
    return registry.run('email.auth_analyze',{'path':path},SafetyPolicy())

@registry.tool(name="recipe.wallet.mnemonic_scan",description="Scan an extracted evidence tree for checksum-valid BIP39 English mnemonics.",safety=SafetyLevel.READ_ONLY,
 parameters={"type":"object","properties":{"path":{"type":"string"},"max_files":{"type":"integer","default":5000}},"required":["path"]})
def mnemonic_scan(path:str,max_files:int=5000)->Observation:
    return registry.run('crypto.bip39_scan',{'path':path,'max_files':max_files},SafetyPolicy())

@registry.tool(name='recipe.server.deep_offline_triage',description='Compose offline Linux inventory, package/auth/persistence, Docker metadata/logs and web configuration/access-log discovery.',
 safety=SafetyLevel.READ_ONLY,tags=('recipe','linux','server','triage'),produces=('server_triage',),cost_hint='high',
 parameters={'type':'object','properties':{'root':{'type':'string'},'query':{'type':'string'}},'required':['root']})
def server_deep_offline_triage(root:str,query:str|None=None)->Observation:
    p=SafetyPolicy(); children=[
        registry.run('linux.offline_inventory',{'root':root},p),
        registry.run('linux.package_events',{'root':root},p),
        registry.run('linux.auth_events',{'root':root},p),
        registry.run('linux.persistence_inventory',{'root':root},p),
        registry.run('docker.offline_inventory',{'root':root},p),
        registry.run('docker.offline_logs',{'root':root,**({'query':query} if query else {})},p),
        registry.run('web.config_candidates',{'root':root},p),
        registry.run('web.access_log_summary',{'root':root},p),
    ]
    if query:
        children.append(registry.run('file.search_tree',{'path':root,'query':query,'limit':1000},p))
    return aggregate('recipe.server.deep_offline_triage',children,'Deep offline server triage complete')

@registry.tool(name='recipe.android.deep_static_triage',description='Compose APK inventory, binary manifest parsing, signing scheme inventory and targeted DEX searches.',
 safety=SafetyLevel.READ_ONLY,tags=('recipe','android','apk','triage'),produces=('android_triage',),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'extra_query':{'type':'string'}},'required':['path']})
def android_deep_static_triage(path:str,extra_query:str|None=None)->Observation:
    p=SafetyPolicy(); children=[
        registry.run('android.apk_inventory',{'path':path},p),
        registry.run('android.apk_manifest',{'path':path},p),
        registry.run('android.apk_signing_inventory',{'path':path},p),
    ]
    patterns=[r'https?://',r'(?i)(AES|DES|RC4|Cipher|SecretKeySpec|MessageDigest|Mac|getInstance)',r'(?i)(shared_prefs|sqlite|content://|socket|upload|download|record|camera|contacts|sms)']
    if extra_query: patterns.append(extra_query)
    for pat in patterns:
        children.append(registry.run('android.apk_search',{'path':path,'query':pat,'regex':True,'limit':500},p))
    return aggregate('recipe.android.deep_static_triage',children,'Deep APK static triage complete')

@registry.tool(name='recipe.network.capture_triage',description='Auto-triage classic PCAP or PCAPNG and extract DNS, HTTP and TLS SNI observations.',
 safety=SafetyLevel.READ_ONLY,tags=('recipe','network','pcap','triage'),produces=('network_triage',),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'packet_limit':{'type':'integer','default':200000}},'required':['path']})
def capture_triage(path:str,packet_limit:int=200000)->Observation:
    p=SafetyPolicy(); probe=registry.run('artifact.inspect',{'path':path},p); kind=probe.facts.get('kind')
    children=[probe]
    if kind=='pcap': children.append(registry.run('network.pcap_inventory',{'path':path,'packet_limit':packet_limit},p))
    elif kind=='pcapng': children.append(registry.run('network.pcapng_inventory',{'path':path,'packet_limit':packet_limit},p))
    else: children.append(Observation('network.capture_inventory',Status.UNSUPPORTED,'Artifact is not recognized as PCAP/PCAPNG'))
    children.append(registry.run('network.capture_protocols',{'path':path,'packet_limit':packet_limit},p))
    return aggregate('recipe.network.capture_triage',children,'Network capture triage complete')

@registry.tool(name='recipe.windows.offline_triage',description='Compose offline Windows artifact triage from a SYSTEM Registry hive and/or EVTX file.',
 safety=SafetyLevel.READ_ONLY,tags=('recipe','windows','triage'),produces=('windows_triage',),cost_hint='medium',
 parameters={'type':'object','properties':{'system_hive':{'type':'string'},'evtx':{'type':'string'}},'anyOf':[{'required':['system_hive']},{'required':['evtx']}]})
def windows_offline_triage(system_hive:str|None=None,evtx:str|None=None)->Observation:
    p=SafetyPolicy(); children=[]
    if system_hive:
        children.extend([registry.run('windows.registry_inventory',{'path':system_hive,'depth':1},p),registry.run('windows.usb_artifacts',{'system_hive':system_hive},p)])
    if evtx: children.extend([registry.run('windows.evtx_summary',{'path':evtx},p),registry.run('windows.evtx_hunt',{'path':evtx},p)])
    return aggregate('recipe.windows.offline_triage',children,'Windows offline triage complete')

@registry.tool(name='recipe.database.triage',description='Identify and inventory SQLite databases or SQL text dumps without writes/imports.',
 safety=SafetyLevel.READ_ONLY,tags=('recipe','database','triage'),produces=('database_triage',),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'}},'required':['path']})
def database_triage(path:str)->Observation:
    p=SafetyPolicy(); probe=registry.run('artifact.inspect',{'path':path},p); children=[probe]
    if probe.facts.get('kind')=='sqlite': children.append(registry.run('database.sqlite_inventory',{'path':path},p))
    else: children.append(registry.run('database.sql_dump_inventory',{'path':path},p))
    return aggregate('recipe.database.triage',children,'Database artifact triage complete')

@registry.tool(name='recipe.artifact.auto_triage',description='Deterministic first-pass routing by artifact magic. This is a convenience baseline; an Agent may choose deeper primitives based on the question.',
 safety=SafetyLevel.READ_ONLY,tags=('recipe','artifact','triage'),produces=('triage',),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'}},'required':['path']})
def artifact_auto_triage(path:str)->Observation:
    p=SafetyPolicy(); probe=registry.run('artifact.inspect',{'path':path},p); kind=probe.facts.get('kind'); children=[probe]
    route={
        'apk':('recipe.android.deep_static_triage',{'path':path}),
        'dex':('android.dex_strings',{'path':path,'limit':5000}),
        'elf':('binary.elf_inventory',{'path':path}),
        'pe':('binary.pe_inventory',{'path':path}),
        'sqlite':('database.sqlite_inventory',{'path':path}),
        'pcap':('recipe.network.capture_triage',{'path':path}),
        'pcapng':('recipe.network.capture_triage',{'path':path}),
        'windows_registry_hive':('windows.registry_inventory',{'path':path}),
        'ewf_e01':('image.e01_inventory',{'path':path}),
        'zip':('archive.inventory',{'path':path}),
        'jar_or_zip':('archive.inventory',{'path':path}),
    }
    if kind in route:
        name,params=route[kind]; children.append(registry.run(name,params,p))
    else:
        children.append(registry.run('file.strings',{'path':path,'limit':2000},p))
    out=aggregate('recipe.artifact.auto_triage',children,f'Auto-triage routed artifact kind: {kind}')
    out.meta['route_kind']=kind
    return out

@registry.tool(name='recipe.browser.history_triage',description='Identify a browser history database and try Chromium and Firefox history parsers read-only.',
 safety=SafetyLevel.READ_ONLY,tags=('recipe','browser','history','triage'),produces=('browser_triage',),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'limit':{'type':'integer','default':5000}},'required':['path']})
def browser_history_triage(path:str,limit:int=5000)->Observation:
    p=SafetyPolicy(); children=[registry.run('artifact.inspect',{'path':path},p),registry.run('browser.chromium_history',{'path':path,'limit':limit},p),registry.run('browser.chromium_downloads',{'path':path,'limit':limit},p),registry.run('browser.firefox_history',{'path':path,'limit':limit},p)]
    return aggregate('recipe.browser.history_triage',children,'Browser history triage complete')

@registry.tool(name='recipe.android.appdata_triage',description='Inventory extracted Android app data and inspect discovered SQLite databases read-only.',
 safety=SafetyLevel.READ_ONLY,tags=('recipe','android','appdata','triage'),produces=('android_appdata_triage',),cost_hint='medium',
 parameters={'type':'object','properties':{'root':{'type':'string'},'database_limit':{'type':'integer','default':20}},'required':['root']})
def android_appdata_triage(root:str,database_limit:int=20)->Observation:
    p=SafetyPolicy(); base=registry.run('android.appdata_inventory',{'root':root},p); children=[base]
    for db in base.facts.get('database_candidates',[])[:database_limit]:
        children.append(registry.run('database.sqlite_inventory',{'path':db['path'],'count_rows':True},p))
    return aggregate('recipe.android.appdata_triage',children,'Android app-data triage complete')

@registry.tool(name='recipe.email.full_offline_triage',description='Compose MIME/attachment inventory with offline authentication-context analysis; no DNS/network lookup.',
 safety=SafetyLevel.READ_ONLY,tags=('recipe','email','triage'),produces=('email_triage',),
 parameters={'type':'object','properties':{'path':{'type':'string'}},'required':['path']})
def email_full_offline_triage(path:str)->Observation:
    p=SafetyPolicy(); children=[registry.run('email.mime_inventory',{'path':path},p),registry.run('email.auth_analyze',{'path':path},p)]
    return aggregate('recipe.email.full_offline_triage',children,'Email offline triage complete')

@registry.tool(name='recipe.timeline.unified',description='Build a unified, source-attributed timeline from a filesystem evidence tree and optional extra dftk Observation sources.',
 safety=SafetyLevel.READ_ONLY,tags=('recipe','timeline','correlation'),produces=('timeline',),cost_hint='medium',
 parameters={'type':'object','properties':{'root':{'type':'string'},'extra_sources':{'type':'array','items':{'type':'string'},'description':'Optional paths to dftk Observation JSON files to merge in'},'limit':{'type':'integer','default':200000}},'required':['root']})
def unified_timeline(root:str,extra_sources:list[str]|None=None,limit:int=200000)->Observation:
    p=SafetyPolicy()
    fs=registry.run('timeline.file_metadata',{'root':root,'limit':limit},p)
    sources=[{'source':'filesystem','events':fs.facts.get('events',[])}]
    for f in (extra_sources or []):
        sources.append({'file':f})
    merged=registry.run('timeline.merge',{'inline':sources,'limit':limit},p)
    return aggregate('recipe.timeline.unified',[fs,merged],'Unified timeline built')


@registry.tool(name='recipe.agent.guided_intake',description='Agent-first bounded first response: create an evidence intake manifest, then execute a small deterministic subset of its read-only evidence-derived routes. Returns executed and deferred actions for review.',
 safety=SafetyLevel.READ_ONLY,tags=('recipe','agent','intake','triage','forensics'),produces=('guided_triage','evidence_manifest','next_actions'),cost_hint='high',
 parameters={'type':'object','properties':{'path':{'type':'string'},'objective':{'type':'string','description':'Optional investigation objective used only to prioritize matching route names/reasons.'},'max_steps':{'type':'integer','default':2,'minimum':0,'maximum':5},'max_files':{'type':'integer','default':5000}},'required':['path']})
def agent_guided_intake(path:str,objective:str|None=None,max_steps:int=2,max_files:int=5000)->Observation:
    if not 0 <= max_steps <= 5:
        return Observation('recipe.agent.guided_intake',Status.ERROR,'max_steps must be between 0 and 5')
    policy=SafetyPolicy()
    intake=registry.run('evidence.intake',{'path':path,'max_files':max_files},policy)
    children=[intake]
    steps=[]
    for step in intake.facts.get('next_steps',[]) if isinstance(intake.facts,dict) else []:
        if isinstance(step,dict) and isinstance(step.get('tool'),str) and isinstance(step.get('params'),dict):
            steps.append(step)
    objective_words=set((objective or '').lower().replace('_',' ').split())
    def priority(step):
        hay=' '.join([step.get('tool',''),step.get('reason','')]).lower()
        return (-sum(word in hay for word in objective_words),step.get('tool',''),repr(step.get('params',{})))
    steps.sort(key=priority)
    executed=[]; deferred=[]
    for step in steps:
        if len(executed) >= max_steps:
            deferred.append(step); continue
        try:
            spec=registry.get(step['tool'])
        except KeyError:
            deferred.append({**step,'deferred_reason':'capability unavailable'}); continue
        if spec.safety != SafetyLevel.READ_ONLY or spec.network:
            deferred.append({**step,'deferred_reason':'not eligible for automatic read-only first response'}); continue
        child=registry.run(step['tool'],step['params'],policy)
        children.append(child); executed.append({'tool':step['tool'],'params':step['params'],'reason':step.get('reason','evidence-intake route'),'status':child.status.value})
    result=aggregate('recipe.agent.guided_intake',children,f'Agent guided intake executed {len(executed)} evidence-derived step(s)')
    result.facts['executed_actions']=executed
    result.facts['deferred_actions']=deferred
    result.facts['objective']=objective
    result.facts['guidance']='Review each child Observation before executing deferred actions. This recipe never enables network access or stateful/destructive capabilities.'
    return result
