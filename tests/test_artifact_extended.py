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
import os,time,zipfile
from dftk.primitives.artifact import artifact_inspect,tree_inventory,search_tree,metadata_timeline
from dftk.catalog import load_builtin_tools
from dftk.core.registry import registry
from dftk.core.models import SafetyLevel,Status
from dftk.core.safety import SafetyPolicy


def test_artifact_tree_search_timeline(tmp_path):
    root=tmp_path/'root'; root.mkdir(); (root/'a.txt').write_text('hello forensic world',encoding='utf-8'); (root/'b.bin').write_bytes(b'xxforensicxx')
    inv=tree_inventory(str(root)); assert inv.facts['file_count']==2
    hits=search_tree(str(root),'forensic'); assert len(hits.facts['matches'])==2
    tl=metadata_timeline(str(root)); assert len(tl.facts['events'])==6


def test_apk_magic_identification(tmp_path):
    p=tmp_path/'sample.apk'
    with zipfile.ZipFile(p,'w') as z:
        z.writestr('AndroidManifest.xml',b'x'); z.writestr('classes.dex',b'dex\n')
    obs=artifact_inspect(str(p)); assert obs.facts['kind']=='apk'; assert obs.facts['confidence']==1.0


def test_safe_extract_authorized_and_zip_slip_rejected(tmp_path):
    load_builtin_tools(); z=tmp_path/'ok.zip'
    with zipfile.ZipFile(z,'w') as f: f.writestr('folder/a.txt','abc')
    policy=SafetyPolicy(max_level=SafetyLevel.STATEFUL)
    obs=registry.run('archive.extract_safe',{'path':str(z),'output_dir':str(tmp_path/'out')},policy)
    assert obs.status==Status.OK and (tmp_path/'out/folder/a.txt').read_text()=='abc'
    bad=tmp_path/'bad.zip'
    with zipfile.ZipFile(bad,'w') as f: f.writestr('../escape.txt','x')
    obs=registry.run('archive.extract_safe',{'path':str(bad),'output_dir':str(tmp_path/'out2')},policy)
    assert obs.status==Status.ERROR
    assert not (tmp_path/'escape.txt').exists()

from dftk.primitives.files import file_strings_unicode

def test_utf16_strings(tmp_path):
    p=tmp_path/'u.bin'; p.write_bytes(b'xx'+('ForensicValue'.encode('utf-16le'))+b'yy')
    obs=file_strings_unicode(str(p),min_length=4)
    assert any(x['value']=='ForensicValue' for x in obs.facts['strings'])
