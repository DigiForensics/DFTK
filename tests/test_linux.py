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

from pathlib import Path
from dftk.primitives.linux import offline_inventory,package_events,docker_offline_inventory
import json

def test_offline_linux_and_package_events(tmp_path):
    (tmp_path/'etc').mkdir(); (tmp_path/'etc/os-release').write_text('ID=debian\nVERSION_ID="12"\n'); (tmp_path/'etc/passwd').write_text('root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n')
    (tmp_path/'var/log').mkdir(parents=True); (tmp_path/'var/log/dpkg.log').write_text('2026-01-01 12:00:00 install python3.10-dev:amd64 <none> 3.10.1\n')
    inv=offline_inventory(str(tmp_path)); assert inv.facts['os_release']['ID']=='debian'; assert len(inv.facts['interactive_accounts'])==1
    ev=package_events(str(tmp_path),'python3.10-dev'); assert len(ev.facts['events'])==1; assert ev.facts['events'][0]['action']=='install'

def test_docker_offline_inventory(tmp_path):
    d=tmp_path/'var/lib/docker/containers/abc'; d.mkdir(parents=True)
    (d/'config.v2.json').write_text(json.dumps({'Name':'/web','Config':{'Image':'nginx:1.25','Env':['A=B']},'Created':'x'}))
    (d/'hostconfig.json').write_text(json.dumps({'PortBindings':{'80/tcp':[{'HostPort':'8080'}]},'Binds':['/x:/y']}))
    obs=docker_offline_inventory(str(tmp_path)); assert obs.facts['containers'][0]['name']=='web'; assert obs.facts['containers'][0]['image']=='nginx:1.25'
