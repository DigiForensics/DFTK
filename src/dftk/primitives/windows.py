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
            rows.append(row); ev.append(Evidence(str(p),'registry_key',key.path(),locator=key.path(),source_sha256=sha256_file(p),method='python-registry'))
            if d<depth:
                for child in reversed(key.subkeys()): stack.append((child,d+1))
        warnings=[f'key inventory limited to {key_limit}'] if len(rows)>=key_limit else []
        return Observation('windows.registry_inventory',Status.OK,f'Inventoried {len(rows)} registry key(s)',facts={'root':root.path(),'keys':rows},evidence=ev[:300],warnings=warnings,meta={'source_sha256':sha256_file(p)})
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
