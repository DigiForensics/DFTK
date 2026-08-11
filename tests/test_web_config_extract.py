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

from dftk.primitives.linux import web_config_extract


def test_config_extract_redaction_and_explicit_values(tmp_path):
    p=tmp_path/'.env'; p.write_text('API_URL=https://api.example\nPASSWORD=secret123\n',encoding='utf-8')
    obs=web_config_extract(str(p)); vals={x['key']:x for x in obs.facts['values']}
    assert vals['API_URL']['value']=='https://api.example'; assert vals['PASSWORD']['value']=='<redacted>'
    obs2=web_config_extract(str(p),include_values=True); vals2={x['key']:x for x in obs2.facts['values']}; assert vals2['PASSWORD']['value']=='secret123'
