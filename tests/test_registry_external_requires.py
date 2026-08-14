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

from dftk.core.registry import ToolRegistry
from dftk.core import registry as registry_mod
from dftk.core.models import SafetyLevel, Status, Observation, ToolSpec


def _noop():
    return Observation("demo.ext", Status.OK, "ran")


def _reg_with(requires):
    reg = ToolRegistry()
    reg.register(
        ToolSpec(
            name="demo.ext",
            description="demo tool with external dep",
            safety=SafetyLevel.READ_ONLY,
            parameters={},
            requires=requires,
        ),
        _noop,
    )
    return reg


def test_run_blocks_missing_external_tool(monkeypatch):
    monkeypatch.setattr(registry_mod, "external_tool_available", lambda n: False)
    reg = _reg_with(("jadx",))
    obs = reg.run("demo.ext", {})
    assert obs.status == Status.UNSUPPORTED
    assert any("jadx" in e for e in obs.errors)


def test_run_allows_present_external_tool(monkeypatch):
    monkeypatch.setattr(registry_mod, "external_tool_available", lambda n: True)
    reg = _reg_with(("jadx",))
    obs = reg.run("demo.ext", {})
    assert obs.status == Status.OK


def test_run_does_not_external_gate_python_requires(monkeypatch):
    # Python-module requires (e.g. pyewf) are not external names, so the
    # external gate is skipped; their enforcement stays per-tool as before.
    monkeypatch.setattr(registry_mod, "external_tool_available", lambda n: False)
    reg = _reg_with(("pyewf",))
    obs = reg.run("demo.ext", {})
    assert obs.status == Status.OK
