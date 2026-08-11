from __future__ import annotations
from pathlib import Path
import gzip,re,json
from dftk.core.registry import registry
from dftk.core.models import Observation,Evidence,Status,SafetyLevel
from dftk.core.helpers import bounded_files,safe_rel


def _read_text(p:Path,limit:int=8*1024*1024)->str:
    try:
        if p.stat().st_size>limit: return p.read_bytes()[:limit].decode('utf-8','replace')
        if p.suffix=='.gz':
            with gzip.open(p,'rt',encoding='utf-8',errors='replace') as f: return f.read(limit)
        return p.read_text(encoding='utf-8',errors='replace')
    except OSError: return ''

def _root(root:str)->Path:
    return Path(root).resolve()

@registry.tool(name="linux.offline_inventory",description="Inventory a mounted/offline Linux root filesystem: OS release, accounts, package logs, web roots and Docker metadata presence.",safety=SafetyLevel.READ_ONLY,
 parameters={"type":"object","properties":{"root":{"type":"string"},"account_limit":{"type":"integer","default":1000}},"required":["root"]})
def offline_inventory(root:str,account_limit:int=1000)->Observation:
    r=_root(root)
    if not r.is_dir(): return Observation("linux.offline_inventory",Status.ERROR,"Root filesystem directory not found",errors=[str(r)])
    facts={"root":str(r)}; ev=[]; warnings=[]
    osr=r/'etc/os-release'
    if osr.is_file():
        vals={}
        for line in _read_text(osr).splitlines():
            if '=' in line:
                k,v=line.split('=',1); vals[k]=v.strip().strip('"')
        facts['os_release']=vals; ev.append(Evidence(str(osr),'os_release',vals,locator='lines:1-'))
    passwd=r/'etc/passwd'; accounts=[]
    if passwd.is_file():
        for n,line in enumerate(_read_text(passwd).splitlines(),1):
            parts=line.split(':')
            if len(parts)>=7:
                try: uid=int(parts[2]); gid=int(parts[3])
                except ValueError: continue
                accounts.append({"name":parts[0],"uid":uid,"gid":gid,"home":parts[5],"shell":parts[6],"interactive":parts[6] not in ('/usr/sbin/nologin','/sbin/nologin','/bin/false','/usr/bin/false')})
            if len(accounts)>=account_limit: break
        facts['accounts']=accounts; facts['interactive_accounts']=[a for a in accounts if a['interactive']]
        ev.append(Evidence(str(passwd),'account_inventory',f"{len(accounts)} accounts",locator='lines:1-'))
    pkg_candidates=[]
    for rel in ['var/log/dpkg.log','var/log/apt/history.log','var/log/yum.log','var/log/dnf.log','var/log/pacman.log']:
        base=r/rel
        if base.exists(): pkg_candidates.append(str(base))
        for q in base.parent.glob(base.name+'.*'):
            if q.is_file(): pkg_candidates.append(str(q))
    facts['package_log_candidates']=sorted(set(pkg_candidates))
    web=[]
    for rel in ['var/www','www','data/www','srv/www','usr/share/nginx/html','opt/lampp/htdocs']:
        p=r/rel
        if p.exists(): web.append(str(p))
    facts['web_root_candidates']=web
    docker=r/'var/lib/docker'
    facts['docker_data_root']=str(docker) if docker.is_dir() else None
    facts['interesting_paths']={rel:str(r/rel) for rel in ['etc/ssh','etc/nginx','etc/apache2','var/log','home','root'] if (r/rel).exists()}
    return Observation("linux.offline_inventory",Status.OK,"Offline Linux root inventory complete",facts=facts,evidence=ev,warnings=warnings)

@registry.tool(name="linux.package_events",description="Extract package install/upgrade/remove events from common Debian/RPM/Pacman logs in an offline Linux root.",safety=SafetyLevel.READ_ONLY,
 parameters={"type":"object","properties":{"root":{"type":"string"},"package":{"type":"string"},"limit":{"type":"integer","default":5000}},"required":["root"]})
def package_events(root:str,package:str|None=None,limit:int=5000)->Observation:
    r=_root(root)
    if not r.is_dir(): return Observation("linux.package_events",Status.ERROR,"Root filesystem directory not found",errors=[str(r)])
    files=[]
    for pat in ['var/log/dpkg.log*','var/log/apt/history.log*','var/log/yum.log*','var/log/dnf.log*','var/log/pacman.log*']:
        files.extend(sorted(r.glob(pat)))
    events=[]; ev=[]
    pkg_l=package.lower() if package else None
    rx_dpkg=re.compile(r'^(\S+\s+\S+)\s+(install|upgrade|remove|purge)\s+(\S+)(?:\s+(\S+)\s+(\S+))?')
    rx_apt_date=re.compile(r'^Start-Date:\s*(.*)')
    for f in files:
        text=_read_text(f); current_date=''
        for line_no,line in enumerate(text.splitlines(),1):
            m=rx_apt_date.match(line)
            if m: current_date=m.group(1).strip()
            md=rx_dpkg.match(line)
            if md:
                row={"source":str(f),"line":line_no,"time":md.group(1),"action":md.group(2),"package":md.group(3),"from_version":md.group(4),"to_version":md.group(5),"raw":line}
            elif line.startswith(('Install:','Upgrade:','Remove:','Purge:')):
                action=line.split(':',1)[0].lower(); body=line.split(':',1)[1].strip(); row={"source":str(f),"line":line_no,"time":current_date,"action":action,"package":body,"raw":line}
            elif re.search(r'\b(Installed|Updated|Erased):\s+',line):
                row={"source":str(f),"line":line_no,"time":line[:16],"action":"rpm_event","package":line,"raw":line}
            elif '[ALPM] installed ' in line or '[ALPM] upgraded ' in line or '[ALPM] removed ' in line:
                row={"source":str(f),"line":line_no,"time":line.split(']')[0].lstrip('['),"action":"pacman_event","package":line,"raw":line}
            else: continue
            if pkg_l and pkg_l not in row['package'].lower() and pkg_l not in line.lower(): continue
            events.append(row); ev.append(Evidence(str(f),'package_event',line,locator=f"line:{line_no}"))
            if len(events)>=limit: break
        if len(events)>=limit: break
    return Observation("linux.package_events",Status.OK,f"Extracted {len(events)} package event(s)",facts={"events":events,"sources":[str(x) for x in files]},evidence=ev[:300],warnings=[f"result limited to {limit}"] if len(events)>=limit else [])

@registry.tool(name="docker.offline_inventory",description="Recover Docker container configuration from an offline /var/lib/docker tree without starting Docker.",safety=SafetyLevel.READ_ONLY,
 parameters={"type":"object","properties":{"root":{"type":"string"},"limit":{"type":"integer","default":1000}},"required":["root"]})
def docker_offline_inventory(root:str,limit:int=1000)->Observation:
    r=_root(root); base=r/'var/lib/docker/containers'
    if not base.is_dir(): return Observation("docker.offline_inventory",Status.UNSUPPORTED,"Docker container metadata directory not present",facts={"expected":str(base)})
    containers=[]; ev=[]; warnings=[]
    for d in sorted(base.iterdir()):
        if not d.is_dir(): continue
        cfg=d/'config.v2.json'; host=d/'hostconfig.json'
        if not cfg.is_file(): continue
        try: c=json.loads(_read_text(cfg,16*1024*1024))
        except Exception as e: warnings.append(f"{cfg}: {e}"); continue
        try: h=json.loads(_read_text(host,16*1024*1024)) if host.is_file() else {}
        except Exception: h={}
        row={"id":d.name,"name":c.get('Name','').lstrip('/'),"image":c.get('Config',{}).get('Image') or c.get('Image'),"created":c.get('Created'),"path":c.get('Path'),"args":c.get('Args'),"env":c.get('Config',{}).get('Env',[]),"labels":c.get('Config',{}).get('Labels',{}),"ports":h.get('PortBindings',{}),"binds":h.get('Binds',[]),"network_mode":h.get('NetworkMode')}
        containers.append(row); ev.append(Evidence(str(cfg),'docker_container',row['name'] or row['id'],locator='json:/'))
        if len(containers)>=limit: break
    return Observation("docker.offline_inventory",Status.PARTIAL if warnings else Status.OK,f"Recovered {len(containers)} Docker container configuration(s)",facts={"containers":containers},evidence=ev,warnings=warnings)

@registry.tool(name="web.config_candidates",description="Discover likely web/application configuration files under an offline directory; optionally extract key names while redacting values.",safety=SafetyLevel.READ_ONLY,
 parameters={"type":"object","properties":{"root":{"type":"string"},"max_files":{"type":"integer","default":20000},"extract_keys":{"type":"boolean","default":True}},"required":["root"]})
def web_config_candidates(root:str,max_files:int=20000,extract_keys:bool=True)->Observation:
    r=_root(root)
    if not r.is_dir(): return Observation("web.config_candidates",Status.ERROR,"Directory not found",errors=[str(r)])
    names={'.env','config.php','database.php','settings.php','wp-config.php','application.yml','application.yaml','application.properties','config.json','config.yaml','config.yml','web.config','appsettings.json'}
    suffixes={'.ini','.conf'}; candidates=[]; ev=[]
    key_rx=re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_.-]{1,80})\s*(?:=|:)')
    for f in bounded_files(r,max_files=max_files):
        low=f.name.lower()
        if low not in names and not (f.suffix.lower() in suffixes and any(x in low for x in ('db','database','app','site','nginx','apache','php'))): continue
        row={"path":str(f),"relative":safe_rel(f,r),"size":f.stat().st_size}
        if extract_keys and f.stat().st_size<=2*1024*1024:
            keys=[]
            for line in _read_text(f,2*1024*1024).splitlines():
                m=key_rx.match(line)
                if m and m.group(1) not in keys: keys.append(m.group(1))
            row['keys']=keys[:200]
        candidates.append(row); ev.append(Evidence(str(f),'config_candidate',row['relative'],locator='file'))
    return Observation("web.config_candidates",Status.OK,f"Found {len(candidates)} configuration candidate(s)",facts={"candidates":candidates},evidence=ev[:300])

from collections import Counter

@registry.tool(name='linux.auth_events',description='Extract SSH authentication and sudo events from common offline Linux auth logs (including rotated gzip files).',
 safety=SafetyLevel.READ_ONLY,tags=('linux','auth','timeline'),produces=('auth_events','timeline'),cost_hint='medium',
 parameters={'type':'object','properties':{'root':{'type':'string'},'user':{'type':'string'},'ip':{'type':'string'},'limit':{'type':'integer','default':10000}},'required':['root']})
def auth_events(root:str,user:str|None=None,ip:str|None=None,limit:int=10000)->Observation:
    r=_root(root)
    if not r.is_dir(): return Observation('linux.auth_events',Status.ERROR,'Root filesystem directory not found',errors=[str(r)])
    files=[]
    for pat in ('var/log/auth.log*','var/log/secure*'):
        files.extend(sorted(x for x in r.glob(pat) if x.is_file()))
    ssh_rx=re.compile(r'(?P<action>Accepted|Failed) (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)')
    sudo_rx=re.compile(r'sudo:\s+(?P<user>\S+)\s*:.*COMMAND=(?P<cmd>.*)$')
    events=[]; ev=[]
    for f in files:
        text=_read_text(f,64*1024*1024)
        for line_no,line in enumerate(text.splitlines(),1):
            m=ssh_rx.search(line)
            if m:
                row={'source':str(f),'line':line_no,'kind':'ssh_auth','action':m.group('action').lower(),'method':m.group('method'),'user':m.group('user'),'ip':m.group('ip'),'port':int(m.group('port')),'raw':line}
            else:
                s=sudo_rx.search(line)
                if not s: continue
                row={'source':str(f),'line':line_no,'kind':'sudo','user':s.group('user'),'command':s.group('cmd'),'raw':line}
            if user and row.get('user','').lower()!=user.lower(): continue
            if ip and row.get('ip')!=ip: continue
            events.append(row); ev.append(Evidence(str(f),row['kind'],line,locator=f'line:{line_no}'))
            if len(events)>=limit: break
        if len(events)>=limit: break
    return Observation('linux.auth_events',Status.OK,f'Extracted {len(events)} authentication/sudo event(s)',facts={'events':events,'sources':[str(x) for x in files]},evidence=ev[:300],warnings=[f'results limited to {limit}'] if len(events)>=limit else [])

@registry.tool(name='linux.persistence_inventory',description='Inventory common offline Linux persistence and operator-history locations: cron, systemd overrides, rc.local, SSH authorized_keys and shell histories.',
 safety=SafetyLevel.READ_ONLY,tags=('linux','persistence','triage'),produces=('persistence_candidates',),
 parameters={'type':'object','properties':{'root':{'type':'string'},'max_files':{'type':'integer','default':5000}},'required':['root']})
def persistence_inventory(root:str,max_files:int=5000)->Observation:
    r=_root(root)
    if not r.is_dir(): return Observation('linux.persistence_inventory',Status.ERROR,'Root filesystem directory not found',errors=[str(r)])
    fixed=['etc/crontab','etc/rc.local','etc/ld.so.preload','var/spool/cron','var/spool/cron/crontabs','etc/cron.d','etc/cron.daily','etc/cron.hourly','etc/systemd/system','usr/lib/systemd/system']
    candidates=[]; ev=[]
    for rel in fixed:
        p=r/rel
        if p.is_file():
            candidates.append({'path':str(p),'relative':rel,'kind':'persistence_file','size':p.stat().st_size}); ev.append(Evidence(str(p),'persistence_candidate',rel,locator='file'))
        elif p.is_dir():
            for f in bounded_files(p,max_files=max_files):
                try: size=f.stat().st_size
                except OSError: continue
                candidates.append({'path':str(f),'relative':safe_rel(f,r),'kind':'persistence_file','size':size}); ev.append(Evidence(str(f),'persistence_candidate',safe_rel(f,r),locator='file'))
                if len(candidates)>=max_files: break
    for base in [r/'root',r/'home']:
        if not base.exists(): continue
        for f in bounded_files(base,max_files=max_files):
            if f.name in ('authorized_keys','.bash_history','.zsh_history','.python_history'):
                candidates.append({'path':str(f),'relative':safe_rel(f,r),'kind':'account_artifact','size':f.stat().st_size}); ev.append(Evidence(str(f),'account_artifact',safe_rel(f,r),locator='file'))
                if len(candidates)>=max_files: break
    return Observation('linux.persistence_inventory',Status.OK,f'Found {len(candidates)} persistence/history candidate(s)',facts={'candidates':candidates},evidence=ev[:300],warnings=[f'results limited to {max_files}'] if len(candidates)>=max_files else [])

_ACCESS_RX=re.compile(r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<uri>\S+)(?:\s+HTTP/[^\"]+)?"\s+(?P<status>\d{3})\s+(?P<size>\S+)')

@registry.tool(name='web.access_log_summary',description='Summarize common Nginx/Apache access logs in an offline tree: clients, methods, status codes and requested URIs.',
 safety=SafetyLevel.READ_ONLY,tags=('web','logs','network'),produces=('web_requests','web_log_summary'),cost_hint='medium',
 parameters={'type':'object','properties':{'root':{'type':'string'},'limit':{'type':'integer','default':200000},'sample_limit':{'type':'integer','default':1000}},'required':['root']})
def web_access_log_summary(root:str,limit:int=200000,sample_limit:int=1000)->Observation:
    r=_root(root)
    if not r.is_dir(): return Observation('web.access_log_summary',Status.ERROR,'Root directory not found',errors=[str(r)])
    files=[]
    patterns=['var/log/nginx/*access*.log*','var/log/apache2/*access*.log*','var/log/httpd/*access_log*','www/server/panel/vhost/logs/*.log*']
    for pat in patterns: files.extend(sorted(x for x in r.glob(pat) if x.is_file()))
    ips=Counter(); methods=Counter(); statuses=Counter(); uris=Counter(); samples=[]; parsed=0
    for f in files:
        for line_no,line in enumerate(_read_text(f,128*1024*1024).splitlines(),1):
            m=_ACCESS_RX.match(line)
            if not m: continue
            parsed+=1; d=m.groupdict(); ips[d['ip']]+=1; methods[d['method']]+=1; statuses[d['status']]+=1; uris[d['uri']]+=1
            if len(samples)<sample_limit: samples.append({'source':str(f),'line':line_no,**d})
            if parsed>=limit: break
        if parsed>=limit: break
    facts={'requests_parsed':parsed,'sources':[str(x) for x in files],'top_clients':dict(ips.most_common(100)),'methods':dict(methods),'statuses':dict(statuses),'top_uris':dict(uris.most_common(200)),'samples':samples}
    return Observation('web.access_log_summary',Status.OK,f'Parsed {parsed} web access-log request(s)',facts=facts,evidence=[Evidence(str(f),'web_access_log','parsed',locator='lines') for f in files[:100]],warnings=[f'requests limited to {limit}'] if parsed>=limit else [])

@registry.tool(name='docker.offline_logs',description='Read bounded Docker json-file container logs from an offline Docker data root, optionally filtering for a literal query.',
 safety=SafetyLevel.READ_ONLY,tags=('docker','logs','timeline'),produces=('container_logs','timeline'),cost_hint='medium',
 parameters={'type':'object','properties':{'root':{'type':'string'},'query':{'type':'string'},'limit':{'type':'integer','default':5000}},'required':['root']})
def docker_offline_logs(root:str,query:str|None=None,limit:int=5000)->Observation:
    r=_root(root); base=r/'var/lib/docker/containers'
    if not base.is_dir(): return Observation('docker.offline_logs',Status.UNSUPPORTED,'Docker container metadata directory not present',facts={'expected':str(base)})
    events=[]; ev=[]; warnings=[]; q=query.lower() if query else None
    for d in sorted(base.iterdir()):
        if not d.is_dir(): continue
        for f in sorted(d.glob('*-json.log')):
            try:
                with f.open('rt',encoding='utf-8',errors='replace') as fh:
                    for line_no,line in enumerate(fh,1):
                        if q and q not in line.lower(): continue
                        try: obj=json.loads(line)
                        except json.JSONDecodeError:
                            warnings.append(f'{f}:{line_no}: invalid JSON log record'); continue
                        row={'container_id':d.name,'source':str(f),'line':line_no,'time':obj.get('time'),'stream':obj.get('stream'),'log':obj.get('log','').rstrip('\n')}
                        events.append(row); ev.append(Evidence(str(f),'docker_log',row['log'],locator=f'line:{line_no}'))
                        if len(events)>=limit: break
            except OSError as e: warnings.append(f'{f}: {e}')
            if len(events)>=limit: break
        if len(events)>=limit: break
    if len(events)>=limit: warnings.append(f'results limited to {limit}')
    return Observation('docker.offline_logs',Status.PARTIAL if warnings else Status.OK,f'Recovered {len(events)} Docker log event(s)',facts={'events':events},evidence=ev[:300],warnings=warnings)

@registry.tool(name='web.config_extract',description='Parse one explicit configuration file and return key/value structure. Secret-like values are redacted unless include_values=true.',
 safety=SafetyLevel.READ_ONLY,tags=('web','config','extract'),produces=('config_values',),
 parameters={'type':'object','properties':{'path':{'type':'string'},'include_values':{'type':'boolean','default':False},'limit':{'type':'integer','default':1000}},'required':['path']})
def web_config_extract(path:str,include_values:bool=False,limit:int=1000)->Observation:
    import configparser
    p=Path(path)
    if not p.is_file(): return Observation('web.config_extract',Status.ERROR,'Configuration file not found',errors=[str(p)])
    if p.stat().st_size>8*1024*1024: return Observation('web.config_extract',Status.BLOCKED,'Configuration file exceeds parser size limit',errors=['8 MiB limit'])
    text=_read_text(p,8*1024*1024); rows=[]; warnings=[]
    secret_rx=re.compile(r'(?i)(password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential)')
    def add(key,value,locator):
        if len(rows)>=limit: return
        redacted=(not include_values and bool(secret_rx.search(key)))
        rows.append({'key':key,'value':'<redacted>' if redacted else value,'redacted':redacted,'locator':locator})
    suffix=p.suffix.lower()
    parsed=False
    if suffix=='.json' or p.name.lower().endswith('.json'):
        try:
            obj=json.loads(text)
            def walk(x,prefix=''):
                if len(rows)>=limit: return
                if isinstance(x,dict):
                    for k,v in x.items(): walk(v,f'{prefix}.{k}' if prefix else str(k))
                elif isinstance(x,list):
                    for i,v in enumerate(x[:200]): walk(v,f'{prefix}[{i}]')
                else: add(prefix,x,f'json:{prefix}')
            walk(obj); parsed=True
        except json.JSONDecodeError as e: warnings.append(f'JSON parse failed: {e}')
    if not parsed and suffix in ('.ini','.conf','.cfg'):
        cp=configparser.ConfigParser(interpolation=None,strict=False)
        try:
            cp.read_string(text)
            for section in cp.sections():
                for k,v in cp.items(section): add(f'{section}.{k}',v,f'ini:{section}.{k}')
            if cp.sections(): parsed=True
        except configparser.Error as e: warnings.append(f'INI parse failed: {e}')
    if not parsed:
        kv=re.compile(r'^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]{0,120})\s*(?:=|:)\s*(.*?)\s*$')
        for line_no,line in enumerate(text.splitlines(),1):
            if not line.strip() or line.lstrip().startswith(('#',';','//')): continue
            m=kv.match(line)
            if not m: continue
            val=m.group(2).strip().strip('"\'')
            add(m.group(1),val,f'line:{line_no}')
        parsed=bool(rows)
    status=Status.PARTIAL if warnings else Status.OK
    if not parsed: status=Status.UNSUPPORTED; warnings.append('no supported key/value structure recognized')
    if len(rows)>=limit: warnings.append(f'values limited to {limit}')
    ev=[Evidence(str(p),'config_value',r['value'],locator=r['locator'],note=r['key'],method='structured config parser') for r in rows[:300]]
    return Observation('web.config_extract',status,f'Extracted {len(rows)} configuration value(s)',facts={'values':rows,'include_values':include_values},evidence=ev,warnings=warnings)
