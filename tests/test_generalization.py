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
import ast,re

CASE_TERMS=['192.168.75.131','boshicai','kingshop','WorkBuddy','com.android.axh','libypojzsnw.so','ksksdb']

def test_registered_source_has_no_known_case_constants_or_bare_except():
    src=Path(__file__).parents[1]/'src/dftk'
    for p in src.rglob('*.py'):
        text=p.read_text(encoding='utf-8')
        assert not any(term in text for term in CASE_TERMS), p
        assert not re.search(r'[A-Za-z]:\\\\',text), p
        tree=ast.parse(text)
        assert not any(isinstance(n,ast.ExceptHandler) and n.type is None for n in ast.walk(tree)), p
