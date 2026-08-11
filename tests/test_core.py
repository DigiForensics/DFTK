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

from dftk.catalog import load_builtin_tools
from dftk.core.registry import registry
from dftk.core.safety import SafetyPolicy
from dftk.core.models import SafetyLevel,Status


def test_default_tool_surface_is_read_only_except_explicit_workspace_actions():
    load_builtin_tools()
    specs=registry.specs()
    assert specs
    stateful=[s.name for s in specs if s.safety == SafetyLevel.STATEFUL]
    destructive=[s.name for s in specs if s.safety == SafetyLevel.DESTRUCTIVE]
    assert stateful == ['archive.extract_safe']
    assert destructive == []


def test_stateful_is_blocked_by_default(tmp_path):
    load_builtin_tools()
    obs=registry.run('archive.extract_safe',{'path':str(tmp_path/'x.zip'),'output_dir':str(tmp_path/'out')},SafetyPolicy())
    assert obs.status == Status.BLOCKED


def test_network_is_blocked_by_default(tmp_path):
    load_builtin_tools()
    obs=registry.run('email.dkim_verify',{'path':str(tmp_path/'x.eml')},SafetyPolicy())
    assert obs.status == Status.BLOCKED


def test_manifest_has_agent_metadata():
    load_builtin_tools()
    spec=registry.get('android.apk_manifest')
    assert 'android' in spec.tags
    assert 'android_manifest' in spec.produces
    assert spec.deterministic is True
