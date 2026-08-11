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

from dftk.primitives.email_auth import auth_analyze

def test_header_difference_is_not_spoof_verdict(tmp_path):
    p=tmp_path/'m.eml'; p.write_bytes(b'From: Alice <alice@example.com>\r\nSender: relay@sender.example\r\nReply-To: help@example.net\r\nSubject: hi\r\n\r\nbody')
    obs=auth_analyze(str(p))
    assert obs.facts['verdict']=='undetermined_offline'
    assert any(x['type']=='from_sender_differ' for x in obs.facts['header_relationships'])
