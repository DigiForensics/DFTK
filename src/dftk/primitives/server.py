from __future__ import annotations
import os
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
