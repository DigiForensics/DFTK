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

from dftk.primitives.crypto import entropy_profile,decode_candidates


def test_entropy_profile(tmp_path):
    p=tmp_path/'x.bin'; p.write_bytes(b'\0'*4096+bytes(range(256))*16)
    obs=entropy_profile(str(p),block_size=4096); assert len(obs.facts['blocks'])==2; assert obs.facts['blocks'][0]['entropy']==0.0; assert obs.facts['blocks'][1]['entropy']>7.9


def test_decode_candidates_hex_and_base64():
    h=decode_candidates('68656c6c6f'); assert any(c['text_preview']=='hello' for c in h.facts['candidates'])
    b=decode_candidates('aGVsbG8='); assert any(c['text_preview']=='hello' for c in b.facts['candidates'])
