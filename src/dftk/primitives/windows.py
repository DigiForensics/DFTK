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
from collections import Counter
from pathlib import Path
import xml.etree.ElementTree as ET
from dftk.core.registry import registry
from dftk.core.models import Observation,Evidence,Status,SafetyLevel
from dftk.core.helpers import sha256_file


def _registry_module():
    try:
        from Registry import Registry as RegistryModule
        return RegistryModule
    except ImportError:
        return None

@registry.tool(name='windows.registry_inventory',description='Inventory a Windows Registry hive using python-registry when installed; never modifies the hive.',
 safety=SafetyLevel.READ_ONLY,tags=('windows','registry'),produces=('registry_inventory',),requires=('python-registry',),
 parameters={'type':'object','properties':{'path':{'type':'string'},'key_limit':{'type':'integer','default':10000},'depth':{'type':'integer','default':2}},'required':['path']})
def registry_inventory(path:str,key_limit:int=10000,depth:int=2)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('windows.registry_inventory',Status.ERROR,'Registry hive not found',errors=[str(p)])
    RegistryModule=_registry_module()
    if RegistryModule is None:
        return Observation('windows.registry_inventory',Status.UNSUPPORTED,'python-registry is not installed',errors=['install dftk[windows] or python-registry'],meta={'source_sha256':sha256_file(p)})
    try:
        hive=RegistryModule.Registry(str(p)); root=hive.root()
        h=sha256_file(p)
        rows=[]; ev=[]
        stack=[(root,0)]
        while stack and len(rows)<key_limit:
            key,d=stack.pop()
            vals=[]
            for v in key.values()[:100]:
                try: value=v.value()
                except Exception as e: value=f'<unreadable:{type(e).__name__}>'
                if isinstance(value,bytes): value={'bytes_hex':value[:64].hex(),'length':len(value)}
                vals.append({'name':v.name(),'type':v.value_type(),'value':value})
            row={'path':key.path(),'timestamp':key.timestamp().isoformat() if key.timestamp() else None,'value_count':len(key.values()),'subkey_count':len(key.subkeys()),'values':vals}
            rows.append(row); ev.append(Evidence(str(p),'registry_key',key.path(),locator=key.path(),source_sha256=h,method='python-registry'))
            if d<depth:
                for child in reversed(key.subkeys()): stack.append((child,d+1))
        warnings=[f'key inventory limited to {key_limit}'] if len(rows)>=key_limit else []
        return Observation('windows.registry_inventory',Status.OK,f'Inventoried {len(rows)} registry key(s)',facts={'root':root.path(),'keys':rows},evidence=ev[:300],warnings=warnings,meta={'source_sha256':h})
    except Exception as e:
        return Observation('windows.registry_inventory',Status.ERROR,'Registry parsing failed',errors=[f'{type(e).__name__}: {e}'],meta={'source_sha256':sha256_file(p)})


def _key_values(key):
    out={}
    for v in key.values():
        try: value=v.value()
        except Exception as e: value=f'<unreadable:{type(e).__name__}>'
        if isinstance(value,bytes): value={'bytes_hex':value[:128].hex(),'length':len(value)}
        out[v.name()]=value
    return out

@registry.tool(name='windows.usb_artifacts',description='Extract USBSTOR and MountedDevices artifacts from an offline SYSTEM Registry hive.',
 safety=SafetyLevel.READ_ONLY,tags=('windows','registry','usb'),produces=('usb_devices',),requires=('python-registry',),
 parameters={'type':'object','properties':{'system_hive':{'type':'string'}},'required':['system_hive']})
def usb_artifacts(system_hive:str)->Observation:
    p=Path(system_hive)
    if not p.is_file(): return Observation('windows.usb_artifacts',Status.ERROR,'SYSTEM hive not found',errors=[str(p)])
    RegistryModule=_registry_module()
    if RegistryModule is None:
        return Observation('windows.usb_artifacts',Status.UNSUPPORTED,'python-registry is not installed',errors=['install dftk[windows] or python-registry'],meta={'source_sha256':sha256_file(p)})
    try:
        hive=RegistryModule.Registry(str(p))
        current=1
        try: current=int(hive.open('Select').value('Current').value())
        except (KeyError,ValueError,TypeError): current=1
        ccs=f'ControlSet{current:03d}'
        devices=[]; ev=[]; warnings=[]
        try:
            usb=hive.open(ccs+r'\Enum\USBSTOR')
            for devclass in usb.subkeys():
                for inst in devclass.subkeys():
                    vals=_key_values(inst)
                    row={'device_class':devclass.name(),'instance_id':inst.name(),'key_path':inst.path(),'timestamp':inst.timestamp().isoformat() if inst.timestamp() else None,'values':vals}
                    devices.append(row); ev.append(Evidence(str(p),'usb_device',inst.name(),locator=inst.path(),method='python-registry'))
        except RegistryModule.RegistryKeyNotFoundException:
            warnings.append(f'{ccs}\\Enum\\USBSTOR not present')
        mounted=[]
        try:
            key=hive.open('MountedDevices')
            for v in key.values():
                raw=v.value(); decoded=None
                if isinstance(raw,bytes):
                    try: decoded=raw.decode('utf-16le').rstrip('\x00')
                    except UnicodeDecodeError: decoded=None
                mounted.append({'name':v.name(),'decoded':decoded,'raw_hex':raw.hex() if isinstance(raw,bytes) else str(raw)})
                ev.append(Evidence(str(p),'mounted_device',v.name(),locator=key.path(),method='python-registry'))
        except RegistryModule.RegistryKeyNotFoundException:
            warnings.append('MountedDevices not present')
        return Observation('windows.usb_artifacts',Status.OK,f'Recovered {len(devices)} USBSTOR instance(s)',facts={'control_set':ccs,'usb_devices':devices,'mounted_devices':mounted},evidence=ev[:300],warnings=warnings,meta={'source_sha256':sha256_file(p)})
    except Exception as e:
        return Observation('windows.usb_artifacts',Status.ERROR,'USB Registry parsing failed',errors=[f'{type(e).__name__}: {e}'],meta={'source_sha256':sha256_file(p)})

@registry.tool(name='windows.evtx_summary',description='Summarize EVTX providers, event IDs and timestamps using python-evtx when installed.',
 safety=SafetyLevel.READ_ONLY,tags=('windows','evtx','timeline'),produces=('event_log_summary','timeline'),requires=('python-evtx',),cost_hint='medium',
 parameters={'type':'object','properties':{'path':{'type':'string'},'limit':{'type':'integer','default':100000},'sample_limit':{'type':'integer','default':500}},'required':['path']})
def evtx_summary(path:str,limit:int=100000,sample_limit:int=500)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('windows.evtx_summary',Status.ERROR,'EVTX file not found',errors=[str(p)])
    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        return Observation('windows.evtx_summary',Status.UNSUPPORTED,'python-evtx is not installed',errors=['install dftk[windows] or python-evtx'],meta={'source_sha256':sha256_file(p)})
    providers=Counter(); ids=Counter(); samples=[]; count=0; malformed=0
    ns={'e':'http://schemas.microsoft.com/win/2004/08/events/event'}
    try:
        with Evtx(str(p)) as log:
            for rec in log.records():
                if count>=limit: break
                count+=1
                try:
                    root=ET.fromstring(rec.xml())
                    sys=root.find('e:System',ns)
                    provider=''; event_id=''; timestamp=''
                    if sys is not None:
                        pe=sys.find('e:Provider',ns); ie=sys.find('e:EventID',ns); te=sys.find('e:TimeCreated',ns)
                        if pe is not None: provider=pe.attrib.get('Name','')
                        if ie is not None and ie.text: event_id=ie.text
                        if te is not None: timestamp=te.attrib.get('SystemTime','')
                    providers[provider or '<unknown>']+=1; ids[event_id or '<unknown>']+=1
                    if len(samples)<sample_limit: samples.append({'record_id':rec.record_num(),'provider':provider,'event_id':event_id,'time':timestamp})
                except (ET.ParseError,ValueError,AttributeError): malformed+=1
    except Exception as e:
        return Observation('windows.evtx_summary',Status.ERROR,'EVTX parsing failed',errors=[f'{type(e).__name__}: {e}'],meta={'source_sha256':sha256_file(p)})
    warnings=[]
    if malformed: warnings.append(f'{malformed} record(s) could not be parsed as XML')
    if count>=limit: warnings.append(f'event parsing limited to {limit}')
    return Observation('windows.evtx_summary',Status.PARTIAL if malformed else Status.OK,f'Parsed {count} EVTX record(s)',facts={'event_count':count,'providers':dict(providers.most_common(100)),'event_ids':dict(ids.most_common(200)),'samples':samples},evidence=[Evidence(str(p),'evtx_summary',count,locator='records',source_sha256=sha256_file(p),method='python-evtx')],warnings=warnings,meta={'source_sha256':sha256_file(p)})


_EVTX_NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
_EVTX_HUNTS = {
    ('Microsoft-Windows-Security-Auditing', '4624'): ('low', 'Successful logon'),
    ('Microsoft-Windows-Security-Auditing', '4625'): ('medium', 'Failed logon'),
    ('Microsoft-Windows-Security-Auditing', '4648'): ('medium', 'Explicit credential logon'),
    ('Microsoft-Windows-Security-Auditing', '4688'): ('medium', 'Process creation'),
    ('Microsoft-Windows-Security-Auditing', '4698'): ('high', 'Scheduled task created'),
    ('Microsoft-Windows-Security-Auditing', '1102'): ('high', 'Security audit log cleared'),
    ('Microsoft-Windows-PowerShell', '4104'): ('high', 'PowerShell script block logged'),
    ('Microsoft-Windows-TaskScheduler', '106'): ('medium', 'Scheduled task registered'),
    ('Service Control Manager', '7045'): ('high', 'Service installed'),
    ('Microsoft-Windows-Sysmon', '1'): ('medium', 'Sysmon process creation'),
    ('Microsoft-Windows-Sysmon', '3'): ('medium', 'Sysmon network connection'),
    ('Microsoft-Windows-Sysmon', '11'): ('medium', 'Sysmon file creation'),
    ('Microsoft-Windows-Sysmon', '22'): ('medium', 'Sysmon DNS query'),
}


def _evtx_text(element):
    return (element.text or '').strip() if element is not None else ''


def _evtx_event(xml: str, record_id: int | str = '') -> dict:
    """Normalize one EVTX XML record without making a detection claim."""
    root = ET.fromstring(xml)
    system = root.find('e:System', _EVTX_NS)
    provider = event_id = timestamp = channel = computer = user_sid = ''
    if system is not None:
        provider_node = system.find('e:Provider', _EVTX_NS)
        time_node = system.find('e:TimeCreated', _EVTX_NS)
        security_node = system.find('e:Security', _EVTX_NS)
        provider = provider_node.attrib.get('Name', '') if provider_node is not None else ''
        event_id = _evtx_text(system.find('e:EventID', _EVTX_NS))
        timestamp = time_node.attrib.get('SystemTime', '') if time_node is not None else ''
        channel = _evtx_text(system.find('e:Channel', _EVTX_NS))
        computer = _evtx_text(system.find('e:Computer', _EVTX_NS))
        user_sid = security_node.attrib.get('UserID', '') if security_node is not None else ''
    data: dict[str, str] = {}
    for index, node in enumerate(root.findall('.//e:EventData/e:Data', _EVTX_NS)):
        data[node.attrib.get('Name') or f'Data{index}'] = _evtx_text(node)
    # UserData schemas vary. Preserve named leaf values under stable XML tag keys.
    for node in root.findall('.//e:UserData//*', _EVTX_NS):
        if len(node) == 0 and _evtx_text(node):
            key = node.attrib.get('Name') or node.tag.rsplit('}', 1)[-1]
            data.setdefault(key, _evtx_text(node))
    return {
        'record_id': record_id, 'time': timestamp, 'provider': provider,
        'event_id': event_id, 'channel': channel, 'computer': computer,
        'user_sid': user_sid, 'data': data,
    }


def _evtx_hunt(event: dict) -> dict | None:
    key = (event['provider'], event['event_id'])
    match = _EVTX_HUNTS.get(key)
    if match is None:
        return None
    severity, title = match
    return {
        'record_id': event['record_id'], 'time': event['time'], 'severity': severity,
        'title': title, 'provider': event['provider'], 'event_id': event['event_id'],
        'channel': event['channel'], 'data': event['data'],
    }


@registry.tool(name='windows.evtx_hunt',description='Parse EVTX records into a source-linked timeline and flag high-value Windows security, PowerShell, service, scheduled-task, and Sysmon event classes. Hits are triage leads, not verdicts.',
 safety=SafetyLevel.READ_ONLY,tags=('windows','evtx','hunt','timeline','threat-hunting'),produces=('evtx_events','timeline','hunt_hits'),requires=('python-evtx',),cost_hint='high',
 parameters={'type':'object','properties':{'path':{'type':'string'},'limit':{'type':'integer','default':100000},'event_limit':{'type':'integer','default':5000},'query':{'type':'string','description':'Optional case-insensitive text filter across normalized event fields.'},'event_ids':{'type':'array','items':{'type':'integer'},'description':'Optional EventID allow-list.'}},'required':['path']})
def evtx_hunt(path:str,limit:int=100000,event_limit:int=5000,query:str|None=None,event_ids:list[int]|None=None)->Observation:
    p=Path(path)
    if not p.is_file(): return Observation('windows.evtx_hunt',Status.ERROR,'EVTX file not found',errors=[str(p)])
    try:
        from Evtx.Evtx import Evtx
    except ImportError:
        return Observation('windows.evtx_hunt',Status.UNSUPPORTED,'python-evtx is not installed',errors=['install dftk[windows] or python-evtx'],meta={'source_sha256':sha256_file(p)})
    wanted={str(value) for value in (event_ids or [])}; needle=(query or '').lower()
    events=[]; hits=[]; malformed=0; parsed=0; filtered=0
    source_hash=sha256_file(p)
    try:
        with Evtx(str(p)) as log:
            for record in log.records():
                if parsed>=limit: break
                parsed+=1
                try:
                    event=_evtx_event(record.xml(),record.record_num())
                except (ET.ParseError,ValueError,AttributeError):
                    malformed+=1; continue
                if wanted and event['event_id'] not in wanted:
                    filtered+=1; continue
                searchable=' '.join([event['provider'],event['event_id'],event['channel'],event['computer'],event['user_sid'],*event['data'].values()]).lower()
                if needle and needle not in searchable:
                    filtered+=1; continue
                if len(events)<event_limit:
                    events.append(event)
                else:
                    filtered+=1
                    continue
                hit=_evtx_hunt(event)
                if hit: hits.append(hit)
    except Exception as e:
        return Observation('windows.evtx_hunt',Status.ERROR,'EVTX parsing failed',errors=[f'{type(e).__name__}: {e}'],meta={'source_sha256':source_hash})
    events.sort(key=lambda item:(item['time'],str(item['record_id'])))
    severity=Counter(hit['severity'] for hit in hits)
    warnings=[]
    if malformed: warnings.append(f'{malformed} record(s) could not be parsed as XML')
    if parsed>=limit: warnings.append(f'event parsing limited to {limit}')
    if len(events)>=event_limit: warnings.append(f'normalized event output limited to {event_limit}')
    facts={'event_count':len(events),'parsed_records':parsed,'filtered_records':filtered,'events':events,'hunt_hits':hits,'hunt_counts':dict(severity),'query':query,'event_ids':sorted(wanted)}
    evidence=[Evidence(str(p),'evtx_record',str(event['event_id']),locator=f"record:{event['record_id']}",source_sha256=source_hash,method='python-evtx XML') for event in events[:300]]
    status=Status.PARTIAL if warnings else Status.OK
    return Observation('windows.evtx_hunt',status,f'Parsed {len(events)} EVTX event(s); {len(hits)} high-value triage hit(s)',facts=facts,evidence=evidence,warnings=warnings,meta={'source_sha256':source_hash})
