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

"""Tests for the SRUM (ESE) adapter — graceful degradation when esedb is absent."""

from __future__ import annotations

from dftk.core.registry import registry


def test_srum_registered():
    assert registry.get("windows.srum") is not None


def test_srum_unsupported_without_esedb():
    # python-libesedb is not installed in this environment.
    obs = registry.run("windows.srum", {"path": "/no/such/SRUDB.dat"})
    assert obs.status.value == "unsupported"
    assert any("esedb" in e or "libesedb" in e.lower() for e in obs.errors + obs.warnings)
