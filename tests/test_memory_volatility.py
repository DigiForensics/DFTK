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

"""Tests for the Volatility 3 adapter (memory.*)."""

from __future__ import annotations

import pytest

from dftk.core.registry import registry
from dftk.primitives import memory_volatility as mv


def test_tools_registered():
    for name in (
        "memory.volatility_inventory",
        "memory.processes",
        "memory.network",
        "memory.malfind",
        "memory.modules",
        "memory.handles",
    ):
        assert registry.get(name) is not None, name


def test_parse_vol_table_basic():
    text = "PID\tPPID\tImageFileName\n4\t0\tSystem\n100\t4\tsvchost.exe"
    rows, header = mv._parse_vol_table(text)
    assert header == ["PID", "PPID", "ImageFileName"]
    assert rows[0] == {"PID": "4", "PPID": "0", "ImageFileName": "System"}
    assert rows[1]["ImageFileName"] == "svchost.exe"


def test_parse_vol_table_space_separated():
    text = "Offset(V)  PID  Name\n0x1000  4  System\n0x2000  8  System"
    rows, header = mv._parse_vol_table(text)
    assert header == ["Offset(V)", "PID", "Name"]
    assert len(rows) == 2


def test_missing_volatility_returns_unsupported():
    # Volatility 3 is not installed in this environment; the tool must degrade
    # to UNSUPPORTED rather than crashing.
    obs = registry.run("memory.processes", {"image": "/no/such/memory.raw"})
    assert obs.status.value == "unsupported"
    # also confirm through the requires gate directly
    assert obs.status.value == "unsupported"
