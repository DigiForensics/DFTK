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

"""Live independent-oracle differential gate (P0-1 credibility layer).

Previously the suite pinned PE imphash/exports and network parsing against
*frozen* golden values derived (long ago) from pefile, with the oracle value
never actually re-executed. That masks silent drift: a regression in DFTK's
parser could still "pass" if the frozen constant drifted with it.

These tests invert that: an independent oracle re-derives the expected value
on every run --

  * pefile re-parses the same PE bytes DFTK parsed (imphash, exports, sections);
  * scapy *generates* a real classic PCAP that DFTK never touched, then dpkt
    independently re-parses it (packet count, TCP reassembly);
  * best-effort: a real PE on disk and a real evidence .pcap (when present)
    are cross-checked against pefile/dpkt, giving genuine real-world coverage
    that synthetic bytes alone cannot.

Every oracle is optional: if it is not installed the relevant test skips, so
the gate degrades gracefully. Install with ``pip install -e '.[credibility]'``.
"""

import hashlib
import pytest
from pathlib import Path

from dftk.primitives import binary_deep as bd
from dftk.primitives import network as net

import corpus_generators as cg


# ---------------------------------------------------------------------------
# PE -- live pefile oracle on synthetic (byte-exact) inputs
# ---------------------------------------------------------------------------
def test_pe_imphash_live_pefile(tmp_path):
    if not (cg.HAVE_PEFILE and cg.HAVE_SYNTHETIC_BUILDERS):
        pytest.skip("pefile oracle or synthetic builders unavailable")
    data = cg._build_pe_imphash_multidll()
    p = tmp_path / "multidll.exe"
    p.write_bytes(data)
    obs = bd.pe_imports(str(p))
    assert obs.status.value == "ok", obs.errors
    dftk_ih = obs.facts["imphash"]
    oracle_ih = cg.pefile_imphash(data)
    # Live oracle: not the frozen IMPHASH_GOLDEN constant.
    assert dftk_ih == oracle_ih, (dftk_ih, oracle_ih)


def test_pe_exports_live_pefile(tmp_path):
    if not (cg.HAVE_PEFILE and cg.HAVE_SYNTHETIC_BUILDERS):
        pytest.skip("pefile oracle or synthetic builders unavailable")
    data = cg._build_pe_with_exports()
    p = tmp_path / "withexports.exe"
    p.write_bytes(data)
    obs = bd.pe_exports(str(p))
    assert obs.status.value == "ok", obs.errors
    dftk_set = {(e["name"], e["ordinal"], e["address"])
                for e in obs.facts["exports"]}
    oracle_set = cg.pefile_exports_set(data)
    assert dftk_set == oracle_set, (dftk_set, oracle_set)


def test_pe_section_count_live_pefile(tmp_path):
    if not (cg.HAVE_PEFILE and cg.HAVE_SYNTHETIC_BUILDERS):
        pytest.skip("pefile oracle or synthetic builders unavailable")
    data = cg._build_pe32plus()
    p = tmp_path / "sample.exe"
    p.write_bytes(data)
    obs = bd.pe_headers(str(p))
    assert obs.status.value == "ok", obs.errors
    dftk_n = obs.facts["section_count"]
    oracle_n = cg.pefile_section_count(data)
    assert dftk_n == oracle_n, (dftk_n, oracle_n)


# ---------------------------------------------------------------------------
# Network -- independent generation (scapy) + independent re-parse (dpkt)
# ---------------------------------------------------------------------------
def _write_scapy_pcap(tmp_path):
    p = tmp_path / "session.pcap"
    p.write_bytes(cg.build_pcap_via_scapy())
    return str(p)


def test_pcap_packet_count_live_dpkt(tmp_path):
    if not (cg.HAVE_SCAPY and cg.HAVE_DPKT):
        pytest.skip("scapy/dpkt oracles unavailable")
    path = _write_scapy_pcap(tmp_path)
    obs = net.pcap_inventory(path)
    assert obs.status.value in ("ok", "partial"), obs.errors
    dftk_count = obs.facts["packet_count"]
    oracle_count = cg.dpkt_packet_count(path)
    # 7 packets: SYN, SYN-ACK, ACK, req, server-ACK, resp, final-ACK
    assert dftk_count == oracle_count == 7, (dftk_count, oracle_count)


def test_tcp_reassembly_live_dpkt(tmp_path):
    if not (cg.HAVE_SCAPY and cg.HAVE_DPKT):
        pytest.skip("scapy/dpkt oracles unavailable")
    path = _write_scapy_pcap(tmp_path)
    obs = net.tcp_reassemble(path)
    assert obs.status.value in ("ok", "partial"), obs.errors
    s2c = None
    for s in obs.facts["streams"]:
        if s["server_to_client"]["length"] > 0:
            s2c = s["server_to_client"]
            break
    assert s2c is not None, "no server->client stream reassembled"
    # DFTK emits the sha256 of the *full* reassembled stream; compare against
    # dpkt's independently reassembled raw bytes (immune to preview truncation).
    flows = cg.dpkt_reassemble(path)
    C, S, Cp, Sp = (cg._ip_int("10.0.0.1"), cg._ip_int("10.0.0.2"), 1111, 80)
    oracle_raw = flows.get((S, C, Sp, Cp))
    assert oracle_raw is not None, "dpkt found no server->client payload"
    assert s2c["sha256"] == hashlib.sha256(oracle_raw).hexdigest(), (
        s2c["sha256"], hashlib.sha256(oracle_raw).hexdigest())


def test_network_flows_endpoints(tmp_path):
    if not cg.HAVE_SCAPY:
        pytest.skip("scapy oracle unavailable")
    path = _write_scapy_pcap(tmp_path)
    obs = net.network_flows(path)
    assert obs.status.value in ("ok", "partial"), obs.errors
    flows = obs.facts["flows"]
    assert flows, "no flows grouped"
    found = any(
        f.get("endpoints", {}).get("client", {}).get("ip") == "10.0.0.1"
        and f.get("endpoints", {}).get("server", {}).get("ip") == "10.0.0.2"
        and f["endpoints"]["server"]["port"] == 80
        for f in flows
    )
    assert found, flows


# ---------------------------------------------------------------------------
# Best-effort real-world evidence (truly independent bytes)
# ---------------------------------------------------------------------------
def test_real_pe_imphash_and_sections():
    path = cg.find_real_pe()
    if not path:
        pytest.skip("no real PE found on this machine (set DFTK_REAL_PE)")
    obs = bd.pe_imports(path)
    if obs.status.value != "ok":
        pytest.skip(f"DFTK could not parse {path}: {obs.errors}")
    dftk_ih = obs.facts.get("imphash")
    oracle_ih = cg.pefile_imphash(open(path, "rb").read())
    if dftk_ih and oracle_ih:
        assert dftk_ih == oracle_ih, (path, dftk_ih, oracle_ih)
    if cg.HAVE_LIEF:
        dftk_n = bd.pe_headers(path).facts["section_count"]
        lief_n = cg.lief_section_count(path)
        assert dftk_n == lief_n, (path, dftk_n, lief_n)


def test_real_evidence_pcap_if_present():
    cand = (Path(__file__).resolve().parent.parent / "examples" / "demos"
            / "output" / "evidence" / "capture.pcap")
    if not cand.is_file():
        pytest.skip("real evidence capture.pcap not present")
    if not cg.HAVE_DPKT:
        pytest.skip("dpkt oracle unavailable")
    obs = net.pcap_inventory(str(cand))
    dftk_n = obs.facts.get("packet_count")
    oracle_n = cg.dpkt_packet_count(str(cand))
    assert dftk_n == oracle_n, (dftk_n, oracle_n)
