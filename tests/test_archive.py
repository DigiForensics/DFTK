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

import zipfile
from dftk.primitives.files import archive_inventory

def test_zip_inventory(tmp_path):
    p=tmp_path/'a.zip'
    with zipfile.ZipFile(p,'w') as z:z.writestr('x.txt','abc')
    obs=archive_inventory(str(p)); assert obs.facts['format']=='zip'; assert obs.facts['members'][0]['name']=='x.txt'

def test_zip_inventory_limits_output_not_whole_directory(tmp_path):
    # 25 entries, ask for 10: the lazy reader must STOP at 10 and never
    # materialize the full central directory (no OOM on huge archives).
    p=tmp_path/'big.zip'
    with zipfile.ZipFile(p,'w') as z:
        for i in range(25):
            z.writestr(f'f{i:03d}.txt','x'*(i+1))
    obs=archive_inventory(str(p),limit=10)
    assert obs.facts['format']=='zip'
    assert len(obs.facts['members'])==10
    assert obs.facts['members'][0]['name']=='f000.txt'
    assert obs.facts['members'][0]['size']==1
    assert obs.facts['members'][9]['name']=='f009.txt'

def test_zip_inventory_matches_stdlib_and_dir_flag(tmp_path):
    p=tmp_path/'c.zip'
    with zipfile.ZipFile(p,'w') as z:
        z.writestr('a/b/',b'')        # directory entry
        z.writestr('a/b/c.txt','hello')
    obs=archive_inventory(str(p))
    names=[m['name'] for m in obs.facts['members']]
    assert names==['a/b/','a/b/c.txt']
    assert obs.facts['members'][0]['is_dir'] is True
    assert obs.facts['members'][0]['size']==0
    assert obs.facts['members'][1]['size']==5

def test_tar_inventory_limits_output(tmp_path):
    import tarfile as _tarfile
    p=tmp_path/'big.tar'
    with _tarfile.open(p,'w') as t:
        for i in range(25):
            data=f'entry{i:03d}'.encode()
            info=_tarfile.TarInfo(name=f'e{i:03d}.txt'); info.size=len(data)
            import io
            t.addfile(info, io.BytesIO(data))
    obs=archive_inventory(str(p),limit=10)
    assert obs.facts['format']=='tar'
    assert len(obs.facts['members'])==10
    assert obs.facts['members'][0]['name']=='e000.txt'
