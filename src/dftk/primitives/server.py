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
import os
from collections import OrderedDict
from dftk.core.registry import registry
from dftk.core.models import Observation,Evidence,Status,SafetyLevel

COMMANDS={
    "os_release":"cat /etc/os-release 2>/dev/null || true",
    "uname":"uname -a 2>/dev/null || true",
    "accounts":"getent passwd 2>/dev/null || cat /etc/passwd 2>/dev/null || true",
    "listeners":"ss -lntup 2>/dev/null || netstat -lntup 2>/dev/null || true",
    "packages_deb":"dpkg-query -W -f='${Package}\t${Version}\\n' 2>/dev/null | head -5000 || true",
    "docker_version":"docker version --format '{{.Server.Version}}' 2>/dev/null || true",
    "docker_containers":"docker ps -a --no-trunc --format '{{json .}}' 2>/dev/null || true",
    "docker_images":"docker image ls --no-trunc --format '{{json .}}' 2>/dev/null || true",
}

# These commands are intentionally fixed. A caller can choose a profile, but never
# supplies shell text. Each command is a read-only observation and is bounded again
# locally before it becomes an Observation.
REMOTE_PROFILES = {
    "baseline": COMMANDS,
    "incident": OrderedDict({
        **COMMANDS,
        "identity": "id; hostnamectl 2>/dev/null || hostname",
        "uptime": "uptime; date -Is; timedatectl 2>/dev/null | head -80 || true",
        "logged_in": "who; w -h 2>/dev/null | head -200 || true; last -n 100 -F 2>/dev/null || true",
        "processes": "ps -eo user:32,pid,ppid,lstart,etime,args --sort=-lstart 2>/dev/null | head -5000 || ps auxww 2>/dev/null | head -5000 || true",
        "routes": "ip route 2>/dev/null || route -n 2>/dev/null || true",
        "systemd_services": "systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null | head -5000 || true",
        "systemd_timers": "systemctl list-timers --all --no-pager --no-legend 2>/dev/null | head -1000 || true",
        "cron": "(cat /etc/crontab 2>/dev/null; find /etc/cron.* -maxdepth 1 -type f -print -exec sed -n '1,120p' {} \\; 2>/dev/null) | head -10000 || true",
        "persistence": "(find /etc/systemd/system /usr/lib/systemd/system -maxdepth 2 -type f -name '*.service' -o -name '*.timer' 2>/dev/null; find /root /home -maxdepth 3 -path '*/.ssh/authorized_keys' -type f -print 2>/dev/null) | head -5000 || true",
        "auth_log_tail": "(journalctl --no-pager -n 1000 2>/dev/null || cat /var/log/auth.log 2>/dev/null || cat /var/log/secure 2>/dev/null) | tail -1000 || true",
        "recent_files": "find /etc /usr/local /var/www -xdev -type f -mtime -7 -printf '%TY-%Tm-%TdT%TH:%TM:%TS %s %p\\n' 2>/dev/null | sort -r | head -5000 || true",
    }),
    "containers": OrderedDict({
        "docker_version": COMMANDS["docker_version"], "docker_containers": COMMANDS["docker_containers"],
        "docker_images": COMMANDS["docker_images"],
        "docker_networks": "docker network ls --no-trunc 2>/dev/null || true",
        "docker_volumes": "docker volume ls 2>/dev/null || true",
        "container_processes": "docker ps -q 2>/dev/null | head -100 | xargs -r -n1 docker top 2>/dev/null || true",
    }),
    "web": OrderedDict({
        "listeners": COMMANDS["listeners"],
        "web_processes": "ps -eo user,pid,ppid,etime,args 2>/dev/null | grep -Ei '[n]ginx|[a]pache|[c]addy|[p]hp-fpm|[n]ode|[u]wsgi|[g]unicorn' | head -2000 || true",
        "web_service_units": "systemctl list-unit-files 2>/dev/null | grep -Ei 'nginx|apache|httpd|caddy|php|gunicorn|uwsgi' | head -1000 || true",
        "web_config_paths": "find /etc /opt /var/www -xdev -type f \\( -name '*.conf' -o -name 'nginx.conf' -o -name '.env' -o -name 'docker-compose*.yml' \\) 2>/dev/null | head -5000 || true",
        "web_log_tail": "(find /var/log/nginx /var/log/apache2 /var/log/httpd -type f -name '*access*' -o -name '*error*' 2>/dev/null | head -50 | xargs -r tail -n 200) 2>/dev/null | tail -10000 || true",
    }),
}


def _bounded_text(stream, limit: int) -> tuple[str, bool]:
    raw = stream.read(max(1, limit) + 1)
    truncated = len(raw) > limit
    if truncated:
        raw = raw[:limit]
    return raw.decode('utf-8', 'replace'), truncated


def _profile_commands(profile: str) -> OrderedDict:
    selected = REMOTE_PROFILES.get(profile.lower())
    if selected is None:
        raise ValueError(f"unknown remote snapshot profile: {profile}")
    return OrderedDict(selected)


def _connect(host, username, port, identity_file, password_env, timeout):
    try:
        import paramiko
    except ImportError:
        return None, Observation("server.remote_snapshot",Status.UNSUPPORTED,"paramiko is not installed",errors=["install optional dependency: pip install 'dftk[ssh]'"])
    password=os.getenv(password_env) if password_env else None
    client=paramiko.SSHClient(); client.load_system_host_keys(); client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(hostname=host,port=port,username=username,password=password,key_filename=identity_file,timeout=timeout,look_for_keys=True,allow_agent=True)
    except Exception as e:
        return None, Observation("server.remote_snapshot",Status.ERROR,"SSH connection failed",errors=[f"{type(e).__name__}: {e}"],warnings=["Unknown host keys are rejected. Add the target host key to the local known_hosts file before acquisition."])
    return client, None


@registry.tool(name="server.remote_snapshot",description="Collect a fixed, bounded, read-only SSH forensic snapshot. Profiles cover baseline host inventory, incident-response state, containers, or web exposure; arbitrary shell commands are never accepted.",safety=SafetyLevel.READ_ONLY,network=True,requires=('paramiko',),tags=('server','ssh','remote','incident-response','forensics'),produces=('remote_snapshot','server_inventory','remote_hunt_leads'),cost_hint='high',
 parameters={"type":"object","properties":{"host":{"type":"string"},"username":{"type":"string"},"port":{"type":"integer","default":22},"identity_file":{"type":"string"},"password_env":{"type":"string","default":"DFTK_SSH_PASSWORD"},"timeout":{"type":"integer","default":15},"profile":{"type":"string","enum":["baseline","incident","containers","web"],"default":"incident"},"max_output_bytes":{"type":"integer","default":65536}},"required":["host","username"]})
def remote_snapshot(host:str,username:str,port:int=22,identity_file:str|None=None,password_env:str='DFTK_SSH_PASSWORD',timeout:int=15,profile:str='incident',max_output_bytes:int=65536)->Observation:
    try: commands=_profile_commands(profile)
    except ValueError as exc: return Observation('server.remote_snapshot',Status.ERROR,'Invalid remote snapshot profile',errors=[str(exc)])
    if not 1024 <= max_output_bytes <= 1_048_576:
        return Observation('server.remote_snapshot',Status.ERROR,'max_output_bytes must be between 1024 and 1048576')
    client, failure = _connect(host,username,port,identity_file,password_env,timeout)
    if failure is not None: return failure
    facts={}; warnings=[]; evidence=[]
    fingerprint=''; key_type=''
    try:
        transport=client.get_transport(); key=transport.get_remote_server_key() if transport else None
        fingerprint=key.get_fingerprint().hex() if key else ''
        key_type=key.get_name() if key else ''
        for name,cmd in commands.items():
            try:
                _,stdout,stderr=client.exec_command(cmd,timeout=timeout)
                out,out_truncated=_bounded_text(stdout,max_output_bytes)
                err,err_truncated=_bounded_text(stderr,min(max_output_bytes,8192))
                exit_status=stdout.channel.recv_exit_status()
                facts[name]={'exit_status':exit_status,'stdout':out,'stderr':err,'truncated':out_truncated or err_truncated,'command':cmd}
                if err.strip(): warnings.append(f"{name}: stderr captured ({len(err)} bytes)")
                if out_truncated or err_truncated: warnings.append(f"{name}: output truncated at {max_output_bytes} bytes")
                evidence.append(Evidence(f"ssh://{username}@{host}:{port}","remote_command",out[:4000],locator=f"command:{name}",note=f"exit={exit_status}; {cmd}",method='paramiko fixed command'))
            except Exception as e: warnings.append(f"{name}: {type(e).__name__}: {e}")
    finally: client.close()
    return Observation('server.remote_snapshot',Status.PARTIAL if warnings else Status.OK,f'Remote {profile} snapshot completed: {len(facts)}/{len(commands)} fixed read-only commands',facts={'host':host,'port':port,'username':username,'profile':profile,'host_key':{'type':key_type,'fingerprint_md5_hex':fingerprint},'commands':facts},evidence=evidence,warnings=warnings,meta={'network':True,'arbitrary_command_execution':False,'command_set':list(commands)})

@registry.tool(name="server.readonly_inventory",description="Run a fixed read-only inventory set over SSH. No arbitrary command parameter is exposed.",safety=SafetyLevel.READ_ONLY,network=True,requires=('paramiko',),tags=('server','ssh','inventory'),produces=('server_inventory',),
 parameters={"type":"object","properties":{"host":{"type":"string"},"username":{"type":"string"},"port":{"type":"integer","default":22},"identity_file":{"type":"string"},"password_env":{"type":"string","default":"DFTK_SSH_PASSWORD"},"timeout":{"type":"integer","default":15}},"required":["host","username"]})
def readonly_inventory(host:str,username:str,port:int=22,identity_file:str|None=None,password_env:str='DFTK_SSH_PASSWORD',timeout:int=15)->Observation:
    try: import paramiko
    except ImportError: return Observation("server.readonly_inventory",Status.UNSUPPORTED,"paramiko is not installed",errors=["install optional dependency: pip install 'dftk[ssh]'"])
    password=os.getenv(password_env) if password_env else None
    client=paramiko.SSHClient(); client.load_system_host_keys(); client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(hostname=host,port=port,username=username,password=password,key_filename=identity_file,timeout=timeout,look_for_keys=True,allow_agent=True)
    except Exception as e:
        return Observation("server.readonly_inventory",Status.ERROR,"SSH connection failed",errors=[f"{type(e).__name__}: {e}"],warnings=["Unknown host keys are rejected. Add the target host key to the local known_hosts file before acquisition."])
    facts={}; warnings=[]; ev=[]
    try:
        for name,cmd in COMMANDS.items():
            try:
                _,stdout,stderr=client.exec_command(cmd,timeout=timeout)
                out=stdout.read().decode('utf-8','replace'); err=stderr.read().decode('utf-8','replace')
                facts[name]=out
                if err.strip(): warnings.append(f"{name}: {err.strip()[:300]}")
                ev.append(Evidence(f"ssh://{username}@{host}:{port}","command_output",out[:4000],locator=f"command:{name}",note=cmd))
            except Exception as e: warnings.append(f"{name}: {type(e).__name__}: {e}")
    finally: client.close()
    return Observation("server.readonly_inventory",Status.PARTIAL if warnings else Status.OK,"Read-only SSH inventory complete",facts=facts,evidence=ev,warnings=warnings,meta={"host":host,"port":port,"username":username,"command_set":list(COMMANDS)})
