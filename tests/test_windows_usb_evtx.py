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

"""Empirical coverage for the two Windows-host adapters that wrap external libs.

`windows.usb_artifacts` (python-registry) and `windows.evtx_summary` (python-evtx)
had **zero** tests before this. They are thin adapters, so the real risk is not a
byte-offset bug but an *integration* bug: wrong control-set resolution, wrong
USBSTOR key path, or wrong value-name extraction from the library objects.

python-registry is read-only (cannot author a hive) and python-evtx is not
installed in this environment, so we drive the REAL adapter code against faithful
fakes of the external APIs. The EVTX test feeds genuine EVTX XML (the real
`http://schemas.microsoft.com/win/2004/08/events/event` schema), so its
namespace-parsing logic is genuinely exercised — only record iteration is faked.
This pins each adapter to its library's documented API contract; a real-hive /
real-evtx test remains the gold standard but is heavier to provision.
"""

from __future__ import annotations

import sys
import types
from datetime import datetime, timezone

import pytest

from dftk.primitives.windows import usb_artifacts, evtx_summary


# --------------------------------------------------------------------------- #
# python-registry faithful fake
# --------------------------------------------------------------------------- #
class _FakeValue:
    def __init__(self, name, data, vtype=1):
        self._name = name
        self._data = data
        self._vtype = vtype

    def name(self):
        return self._name

    def value(self):
        return self._data

    def value_type(self):
        return self._vtype


class _FakeKey:
    def __init__(self, name, path, timestamp=None, subkeys=None, values=None):
        self._name = name
        self._path = path
        self._ts = timestamp
        self._subkeys = list(subkeys or [])
        self._values = list(values or [])

    def name(self):
        return self._name

    def path(self):
        return self._path

    def timestamp(self):
        return self._ts

    def subkeys(self):
        return list(self._subkeys)

    def values(self):
        return list(self._values)

    def value(self, name):
        for v in self._values:
            if v.name() == name:
                return v
        raise KeyError(name)


class _RegistryKeyNotFound(Exception):
    pass


class _FakeRegistry:
    """Minimal, faithful python-registry surrogate keyed by full path."""

    def __init__(self, path):  # path is ignored (no real file)
        self._path = path
        self._keys = {}
        self._register("Select", _FakeKey("Select", "Select", values=[
            _FakeValue("Current", 1, vtype=4),  # REG_DWORD -> int
        ]))
        devclass = _FakeKey(
            "Disk&Ven_FOO&Prod_BAR&Rev_1.0",
            "ControlSet001\\Enum\\USBSTOR\\Disk&Ven_FOO&Prod_BAR&Rev_1.0",
            timestamp=datetime(2024, 5, 1, 12, 0, 0, tzinfo=timezone.utc),
            subkeys=[
                _FakeKey(
                    "ABC123",
                    "ControlSet001\\Enum\\USBSTOR\\Disk&Ven_FOO&Prod_BAR&Rev_1.0\\ABC123",
                    timestamp=datetime(2024, 5, 1, 12, 0, 0, tzinfo=timezone.utc),
                    values=[
                        _FakeValue("DeviceDesc", "USB Mass Storage Device", vtype=1),
                        _FakeValue("FriendlyName", "FOO BAR Disk", vtype=1),
                        _FakeValue("Service", "USBSTOR", vtype=1),
                    ],
                )
            ],
        )
        usbstor = _FakeKey(
            "USBSTOR",
            "ControlSet001\\Enum\\USBSTOR",
            subkeys=[devclass],
        )
        enum = _FakeKey("Enum", "ControlSet001\\Enum", subkeys=[usbstor])
        ccs = _FakeKey("ControlSet001", "ControlSet001", subkeys=[enum])
        md = _FakeKey(
            "MountedDevices",
            "MountedDevices",
            values=[
                _FakeValue(
                    "\\DosDevices\\F:",
                    "\\??\\Volume{11111111-2222-3333-4444-555555555555}".encode("utf-16-le"),
                    vtype=3,  # REG_BINARY -> bytes
                ),
                _FakeValue(
                    "\\DosDevices\\G:",
                    b"\x01\x00\x02\x03not-utf16",  # undecodable -> decoded=None, raw_hex path
                    vtype=3,
                ),
            ],
        )
        self._register("ControlSet001", ccs)
        self._register("ControlSet001\\Enum", enum)
        self._register("ControlSet001\\Enum\\USBSTOR", usbstor)
        self._register("MountedDevices", md)

    def _register(self, path, key):
        self._keys[path] = key

    def open(self, subpath):
        key = self._keys.get(subpath)
        if key is None:
            raise _RegistryKeyNotFound(subpath)
        return key

    def root(self):
        # root not exercised by usb_artifacts, but provide it for completeness
        return _FakeKey("", "", subkeys=[self._keys.get("ControlSet001")])


class _FakeRegistryModule:
    Registry = _FakeRegistry
    RegistryKeyNotFoundException = _RegistryKeyNotFound


@pytest.fixture
def patch_registry(monkeypatch):
    monkeypatch.setattr(
        "dftk.primitives.windows._registry_module",
        lambda: _FakeRegistryModule,
    )


def test_usb_artifacts_extracts_control_set_and_devices(patch_registry, tmp_path):
    hive = tmp_path / "SYSTEM"
    hive.write_bytes(b"dummy-hive-bytes")  # content unused by the fake
    obs = usb_artifacts(str(hive))
    assert obs.status.value == "ok", obs.summary
    assert obs.facts["control_set"] == "ControlSet001"
    devs = obs.facts["usb_devices"]
    assert len(devs) == 1
    d = devs[0]
    assert d["device_class"] == "Disk&Ven_FOO&Prod_BAR&Rev_1.0"
    assert d["instance_id"] == "ABC123"
    assert d["values"]["DeviceDesc"] == "USB Mass Storage Device"
    assert d["values"]["FriendlyName"] == "FOO BAR Disk"
    assert d["timestamp"] is not None


def test_usb_artifacts_mounted_devices_decode(patch_registry, tmp_path):
    hive = tmp_path / "SYSTEM"
    hive.write_bytes(b"dummy")
    obs = usb_artifacts(str(hive))
    mounted = {m["name"]: m for m in obs.facts["mounted_devices"]}
    assert "\\DosDevices\\F:" in mounted
    assert mounted["\\DosDevices\\F:"]["decoded"].endswith("555555555555}")
    # undecodable binary still yields raw_hex, never raises
    assert mounted["\\DosDevices\\G:"]["decoded"] is None
    assert "raw_hex" in mounted["\\DosDevices\\G:"]


def test_usb_artifacts_missing_keys_warn(tmp_path):
    """With a hive that has no Select/USBSTOR/MountedDevices the adapter must
    degrade gracefully (OK + warnings), not hard-error. This exercises the
    `RegistryKeyNotFoundException` guard around control-set resolution."""
    hive = tmp_path / "SYSTEM"
    hive.write_bytes(b"dummy")

    class _EmptyReg:
        def __init__(self, path):
            self.path = path

        def open(self, sub):
            raise _RegistryKeyNotFound(sub)

        def root(self):
            return _FakeKey("", "")

    class _EmptyMod:
        Registry = _EmptyReg
        RegistryKeyNotFoundException = _RegistryKeyNotFound

    import dftk.primitives.windows as w

    old = w._registry_module
    w._registry_module = lambda: _EmptyMod
    try:
        obs = usb_artifacts(str(hive))
    finally:
        w._registry_module = old
    assert obs.status.value == "ok"
    assert obs.facts["usb_devices"] == []
    assert any("not present" in wmsg for wmsg in obs.warnings)


# --------------------------------------------------------------------------- #
# python-evtx faithful fake (real EVTX XML, only iteration faked)
# --------------------------------------------------------------------------- #
_EVTX_XML = """<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/>
    <EventID>4624</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2024-01-02T03:04:05.0000000Z"/>
    <EventRecordID>12345</EventRecordID>
    <Execution ProcessID="1234" ThreadID="5678"/>
    <Channel>Security</Channel>
    <Computer>DC01.contoso.local</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">alice</Data>
  </EventData>
</Event>"""


class _FakeRecord:
    def __init__(self, rid, xml):
        self._rid = rid
        self._xml = xml

    def xml(self):
        return self._xml

    def record_num(self):
        return self._rid


class _FakeEvtx:
    def __init__(self, path):
        self._path = path

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def records(self):
        yield _FakeRecord(12345, _EVTX_XML)
        yield _FakeRecord(12346, _EVTX_XML)
        # malformed record -> exercises the ParseError handling branch
        yield _FakeRecord(12347, "<<not valid xml")


@pytest.fixture
def patch_evtx(monkeypatch):
    fake_top = types.ModuleType("Evtx")
    fake_sub = types.ModuleType("Evtx.Evtx")
    fake_sub.Evtx = _FakeEvtx
    monkeypatch.setitem(sys.modules, "Evtx", fake_top)
    monkeypatch.setitem(sys.modules, "Evtx.Evtx", fake_sub)


def test_evtx_summary_parses_real_xml(patch_evtx, tmp_path):
    log = tmp_path / "Security.evtx"
    log.write_bytes(b"dummy")  # content unused by the fake
    obs = evtx_summary(str(log))
    assert obs.status.value in ("ok", "partial"), obs.summary
    assert obs.facts["event_count"] == 3
    # Provider.Name + EventID + TimeCreated.SystemTime all extracted from real XML
    assert obs.facts["providers"].get("Microsoft-Windows-Security-Auditing") == 2
    assert obs.facts["event_ids"].get("4624") == 2
    sample = obs.facts["samples"][0]
    assert sample["provider"] == "Microsoft-Windows-Security-Auditing"
    assert sample["event_id"] == "4624"
    assert sample["time"] == "2024-01-02T03:04:05.0000000Z"
    # one malformed record counted, never raises
    assert any("could not be parsed" in w for w in obs.warnings)


def test_evtx_summary_no_lib_returns_unsupported(tmp_path):
    """When python-evtx is genuinely absent the tool must degrade to UNSUPPORTED
    (no crash), not raise."""
    if _real_evtx_available():
        pytest.skip("python-evtx is installed; this asserts the absent-lib path")
    log = tmp_path / "Security.evtx"
    log.write_bytes(b"dummy")
    obs = evtx_summary(str(log))
    assert obs.status.value == "unsupported"


def _real_evtx_available():
    try:
        import Evtx  # noqa: F401
        return True
    except ImportError:
        return False


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
