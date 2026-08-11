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

from dftk.primitives.crypto import load_wordlist,validate_bip39

def test_wordlist_is_complete():
    w=load_wordlist(); assert len(w)==2048; assert len(set(w))==2048

def test_known_vector_checksum():
    words=('abandon '*11+'about').split()
    v=validate_bip39(words); assert v['valid'] is True

def test_invalid_checksum():
    words=('abandon '*12).split()
    v=validate_bip39(words); assert v['valid'] is False; assert v['reason']=='checksum_mismatch'
