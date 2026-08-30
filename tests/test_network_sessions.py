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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied
# or implied. See the License for the specific language governing permissions and
# limitations under the License.

"""End-to-end tests for Network Forensics 2.0 (flows / reassembly / sessions).

A synthetic classic PCAP is built by hand so the tests need no external capture
or optional dependency. It exercises: TCP reassembly across two segments, HTTP
response body extraction into the workspace as a DerivedArtifact, DNS
query/response correlation, and TLS ClientHello JA3/SNI inventory.
"""

from __future__ import annotations

import hashlib
import socket
import struct

from dftk.core.models import Status
from dftk.primitives import network as net


# --- synthetic packet builders -------------------------------------------------

def _ip_to_int(ip: str) -> int:
    return int.from_bytes(socket.inet_aton(ip), "big")


def _eth_ip_tcp(src_ip, dst_ip, sport, dport, seq, ack, flags, payload=b""):
    eth = b"\x00" * 6 + b"\x11" * 6 + b"\x08\x00"
    total = 20 + 20 + len(payload)
    ip_hdr = struct.pack("!BBHHHBBHII", 0x45, 0, total, 0x1234, 0, 64, 6, 0,
                         _ip_to_int(src_ip), _ip_to_int(dst_ip))
    off_flags = (5 << 12) | flags
    tcp_hdr = struct.pack("!HHIIHHHH", sport, dport, seq, ack, off_flags, 65535, 0, 0)
    return eth + ip_hdr + tcp_hdr + payload


def _eth_ip_udp(src_ip, dst_ip, sport, dport, payload):
    eth = b"\x00" * 6 + b"\x11" * 6 + b"\x08\x00"
    total = 20 + 8 + len(payload)
    ip_hdr = struct.pack("!BBHHHBBHII", 0x45, 0, total, 0x2222, 0, 64, 17, 0,
                         _ip_to_int(src_ip), _ip_to_int(dst_ip))
    udp_hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    return eth + ip_hdr + udp_hdr + payload


def _pcap_global() -> bytes:
    # classic PCAP, little-endian, linktype 1 (Ethernet)
    return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def _pcap_record(ts: float, data: bytes) -> bytes:
    sec = int(ts)
    usec = int((ts - sec) * 1_000_000)
    return struct.pack("<IIII", sec, usec, len(data), len(data)) + data


def _dns_name(n: str) -> bytes:
    out = b""
    for part in n.split("."):
        out += bytes([len(part)]) + part.encode()
    return out + b"\x00"


def _build_dns_query() -> bytes:
    hdr = struct.pack(">HHHHHH", 0x1234, 0x0000, 1, 0, 0, 0)
    q = _dns_name("example.com") + struct.pack(">HH", 1, 1)
    return hdr + q


def _build_dns_response() -> bytes:
    hdr = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
    q = _dns_name("example.com") + struct.pack(">HH", 1, 1)
    name = struct.pack(">H", 0xC00C)
    typ = struct.pack(">HHIH", 1, 1, 60, 4)
    rdata = socket.inet_aton("1.2.3.4")
    return hdr + q + name + typ + rdata


def _build_client_hello() -> bytes:
    sni_host = b"example.com"
    sni_inner = b"\x00" + struct.pack(">H", len(sni_host)) + sni_host
    sni_list = struct.pack(">H", len(sni_inner)) + sni_inner
    sni_ext = struct.pack(">HH", 0, len(sni_list)) + sni_list
    groups = struct.pack(">HH", 0x001D, 0x0017)
    sg_ext = struct.pack(">HH", 10, len(groups)) + groups
    ecpf = struct.pack(">B", 1) + struct.pack(">B", 0)
    ec_ext = struct.pack(">HH", 11, len(ecpf)) + ecpf
    extensions = sni_ext + sg_ext + ec_ext
    ciphers = struct.pack(">HH", 0x1301, 0x002F)
    random = b"\x00" * 32
    body = (struct.pack(">H", 0x0303) + random + b"\x00"
            + struct.pack(">H", len(ciphers)) + ciphers
            + b"\x01\x00"
            + struct.pack(">H", len(extensions)) + extensions)
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    record = b"\x16" + struct.pack(">H", 0x0301) + struct.pack(">H", len(handshake)) + handshake
    return record


def _build_capture() -> bytes:
    pkts = []
    c_ip, s_ip, c_port, s_port = "10.0.0.1", "10.0.0.2", 1111, 80
    # TCP handshake
    pkts.append(_eth_ip_tcp(c_ip, s_ip, c_port, s_port, 1000, 0, 0x02))            # SYN
    pkts.append(_eth_ip_tcp(s_ip, c_ip, s_port, c_port, 5000, 1001, 0x12))         # SYN-ACK
    pkts.append(_eth_ip_tcp(c_ip, s_ip, c_port, s_port, 1001, 5001, 0x10))         # ACK
    get = b"GET /x.zip HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkts.append(_eth_ip_tcp(c_ip, s_ip, c_port, s_port, 1001, 5001, 0x18, get))    # GET
    # HTTP response, split across two TCP segments
    resp_head = (b"HTTP/1.1 200 OK\r\nContent-Type: application/zip\r\n"
                 b"Content-Length: 20\r\n\r\nPK\x03\x04")
    pkts.append(_eth_ip_tcp(s_ip, c_ip, s_port, c_port, 5001, 1001 + len(get), 0x18, resp_head))
    seg2 = b"FAKEDATAFAKEDATA"  # total body = 4 + 16 = 20 bytes
    pkts.append(_eth_ip_tcp(s_ip, c_ip, s_port, c_port, 5001 + len(resp_head),
                            1001 + len(get), 0x18, seg2))
    # DNS query / response (UDP)
    pkts.append(_eth_ip_udp(c_ip, "8.8.8.8", 3333, 53, _build_dns_query()))
    pkts.append(_eth_ip_udp("8.8.8.8", c_ip, 53, 3333, _build_dns_response()))
    # TLS ClientHello
    pkts.append(_eth_ip_tcp(c_ip, "10.0.0.9", 1112, 443, 2000, 0, 0x18, _build_client_hello()))
    data = _pcap_global()
    ts = 1700000000.0
    for i, pkt in enumerate(pkts):
        data += _pcap_record(ts + i * 0.001, pkt)
    return data


# --- tests ---------------------------------------------------------------------

def test_tcp_reassembly_recovers_split_http(tmp_path):
    cap = tmp_path / "cap.pcap"
    cap.write_bytes(_build_capture())
    obs = net.tcp_reassemble(str(cap))
    assert obs.status == Status.OK, obs.errors
    assert obs.facts["stream_count"] >= 1
    # find the HTTP stream (server->client contains the HTTP response)
    s2c = None
    for s in obs.facts["streams"]:
        if b"HTTP/1.1 200 OK" in bytes.fromhex(s["server_to_client"]["hex_preview"]):
            s2c = s
            break
    assert s2c is not None, "reassembled stream missing HTTP response"
    # The two segments must be concatenated in order: header then 'FAKEDATA...'
    full = s2c["server_to_client"]
    # hex_preview only shows first 256 bytes; assert no gap and full length
    assert full["gaps"] == 0
    # Body length 20 + header bytes; just confirm it is bounded and non-truncated
    assert full["length"] > 20


def test_http_sessions_extracts_derived_artifact(tmp_path):
    cap = tmp_path / "cap.pcap"
    cap.write_bytes(_build_capture())
    out = tmp_path / "ws"
    obs = net.http_sessions(str(cap), str(out))
    assert obs.status in (Status.OK, Status.PARTIAL), obs.errors
    assert len(obs.facts["extracted"]) >= 1
    ex = obs.facts["extracted"][0]
    body = b"PK\x03\x04FAKEDATAFAKEDATA"
    assert ex["sha256"] == hashlib.sha256(body).hexdigest()
    assert (tmp_path / "ws" / ex["path"].split("/")[-1]).read_bytes() == body
    # provenance: original evidence + one derived artifact for the extracted body
    arts = obs.derived_artifacts
    assert arts[0].kind == "evidence"
    assert any(a.locator.startswith("http_response:") for a in arts)
    # the evidence item must carry the artifact id
    assert obs.evidence[0].artifact_id == arts[0].artifact_id


def test_dns_transactions_correlate(tmp_path):
    cap = tmp_path / "cap.pcap"
    cap.write_bytes(_build_capture())
    obs = net.dns_transactions(str(cap))
    assert obs.status == Status.OK, obs.errors
    txns = obs.facts["transactions"]
    assert any(t["answered"] and t["query"]["name"] == "example.com" for t in txns)
    answered = [t for t in txns if t["answered"]][0]
    ans = answered["responses"][0]["answers"][0]
    assert ans["address"] == "1.2.3.4"


def test_tls_inventory_ja3_and_sni(tmp_path):
    cap = tmp_path / "cap.pcap"
    cap.write_bytes(_build_capture())
    obs = net.tls_inventory(str(cap))
    assert obs.status == Status.OK, obs.errors
    hellos = obs.facts["client_hellos"]
    assert any(h["sni"] == "example.com" for h in hellos)
    hello = [h for h in hellos if h["sni"] == "example.com"][0]
    assert len(hello["ja3"]) == 32 and all(c in "0123456789abcdef" for c in hello["ja3"])
    assert hello["record_version"] == 0x0301


def test_flows_groups_tcp_conversation(tmp_path):
    cap = tmp_path / "cap.pcap"
    cap.write_bytes(_build_capture())
    obs = net.network_flows(str(cap))
    assert obs.status == Status.OK, obs.errors
    tcp = [f for f in obs.facts["flows"] if f["protocol"] == "tcp"]
    assert any(f["endpoints"]["client"]["ip"] == "10.0.0.1" for f in tcp)


# --- JA3 canonical-compliance regression (golden values from the JA3 spec) ---

def _client_hello_ex(rec_ver=0x0301, ch_ver=0x0303, ciphers=(0x1301, 0x002F),
                     curves=(0x001D, 0x0017), ecpf=(1,), sni=b"example.com"):
    """Build a well-formed TLS ClientHello (RFC 8446 supported_groups carries a
    2-byte list-length prefix, as real captures do)."""
    sni_inner = b"\x00" + struct.pack(">H", len(sni)) + sni
    sni_list = struct.pack(">H", len(sni_inner)) + sni_inner
    sni_ext = struct.pack(">HH", 0, len(sni_list)) + sni_list
    groups = struct.pack(">H", len(curves) * 2) + b"".join(struct.pack(">H", c) for c in curves)
    sg_ext = struct.pack(">HH", 10, len(groups)) + groups
    ecpf_b = bytes([len(ecpf)]) + bytes(ecpf)
    ec_ext = struct.pack(">HH", 11, len(ecpf_b)) + ecpf_b
    extensions = sni_ext + sg_ext + ec_ext
    cph = b"".join(struct.pack(">H", c) for c in ciphers)
    random = b"\x00" * 32
    body = (struct.pack(">H", ch_ver) + random + b"\x00"
            + struct.pack(">H", len(cph)) + cph
            + b"\x01\x00" + struct.pack(">H", len(extensions)) + extensions)
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16" + struct.pack(">H", rec_ver) + struct.pack(">H", len(handshake)) + handshake


def test_tls_ja3_canonical_string(tmp_path):
    # Canonical JA3 (salesforce/abuse.ch): SSLVersion is the HANDSHAKE
    # client_version (771 = 0x0303), fields are dash-separated, GREASE stripped.
    ch = _client_hello_ex()
    pkts = [_eth_ip_tcp("10.0.0.1", "10.0.0.9", 1112, 443, 2000, 0, 0x18, ch)]
    cap = tmp_path / "cap.pcap"
    cap.write_bytes(_pcap_global() + b"".join(_pcap_record(1700000000.0 + i * 0.001, p) for i, p in enumerate(pkts)))
    obs = net.tls_inventory(str(cap))
    hello = [h for h in obs.facts["client_hellos"] if h["sni"] == "example.com"][0]
    expected = "771,4865-47,0-10-11,29-23,1"
    assert hello["ja3_string"] == expected, hello["ja3_string"]
    assert hello["ja3"] == hashlib.md5(expected.encode()).hexdigest()
    # both supported_groups must be present (no first-curve drop)
    assert hello["cipher_suite_count"] == 2


def test_tls_ja3_strips_grease():
    # A GREASE-laden ClientHello must hash identically to its GREASE-free twin.
    # Tested at the parser level (tls_inventory de-dupes by (ja3, sni) on purpose).
    base = _client_hello_ex()
    grease = _client_hello_ex(ciphers=(0x0A0A, 0x1301, 0x002F),
                              curves=(0x0A0A, 0x001D, 0x0017))
    jb = net._parse_client_hello(base)["ja3_string"]
    jg = net._parse_client_hello(grease)["ja3_string"]
    assert jb == jg == "771,4865-47,0-10-11,29-23,1", (jb, jg)


# --- TCP reassembly edge cases (previously untested) -------------------------

def _tcp_stream(tmp_path, server_segments, client_isn=1000, server_isn=5000):
    """Build a capture: handshake then server->client `server_segments` (list of
    (seq, payload)). Returns the reassembled server->client stream bytes."""
    C, S, CP, SP = "10.0.0.1", "10.0.0.2", 40000, 80
    pkts = [
        _eth_ip_tcp(C, S, CP, SP, client_isn, 0, 0x02),
        _eth_ip_tcp(S, C, SP, CP, server_isn, client_isn + 1, 0x12),
        _eth_ip_tcp(C, S, CP, SP, client_isn + 1, server_isn + 1, 0x10),
    ]
    for seq, payload in server_segments:
        pkts.append(_eth_ip_tcp(S, C, SP, CP, seq, client_isn + 1, 0x18, payload))
    cap = tmp_path / "stream.pcap"
    cap.write_bytes(_pcap_global() + b"".join(_pcap_record(1700000000.0 + i * 0.001, p) for i, p in enumerate(pkts)))
    obs = net.tcp_reassemble(str(cap))
    s2c = [s for s in obs.facts["streams"] if s["server_to_client"]["length"] >= 1][0]
    return bytes.fromhex(s2c["server_to_client"]["hex_preview"].rstrip(".")), s2c["server_to_client"]["gaps"]


def test_tcp_reassembly_out_of_order(tmp_path):
    # Contiguous payloads (seqs 3 bytes apart) delivered out of order 2,1,3.
    data = b"AAABBBCCC"
    segs = [(5004, b"BBB"), (5001, b"AAA"), (5007, b"CCC")]
    out, gaps = _tcp_stream(tmp_path, segs)
    assert out[:9] == data, out[:9]
    assert gaps == 0


def test_tcp_reassembly_overlap_keeps_earlier(tmp_path):
    # seq 5001 "HELLO" then overlapping 5003 "LLOWORLD" -> "HELLOWORLD"
    out, gaps = _tcp_stream(tmp_path, [(5001, b"HELLO"), (5003, b"LLOWORLD")])
    assert out[:10] == b"HELLOWORLD", out[:10]
    assert gaps == 0


def test_tcp_reassembly_gap_fills_nul(tmp_path):
    # missing middle: 5001 "AAAA", 5009 "CCCC" -> hole of 4 NUL bytes
    out, gaps = _tcp_stream(tmp_path, [(5001, b"AAAA"), (5009, b"CCCC")])
    assert out[:12] == b"AAAA\x00\x00\x00\x00CCCC", out[:12]
    assert gaps == 1


def test_tcp_reassembly_seq_wraparound(tmp_path):
    # server ISN at the 2^32 boundary; data seqs wrap 0xFFFFFFFF -> 0
    WRAP = 0xFFFFFFFC
    C, S, CP, SP = "10.0.0.1", "10.0.0.2", 40000, 80
    pkts = [
        _eth_ip_tcp(C, S, CP, SP, 1000, 0, 0x02),
        _eth_ip_tcp(S, C, SP, CP, WRAP, 1001, 0x12),
        _eth_ip_tcp(C, S, CP, SP, 1001, WRAP + 1, 0x10),
        _eth_ip_tcp(S, C, SP, CP, WRAP + 1, 1001, 0x18, b"AB"),
        _eth_ip_tcp(S, C, SP, CP, WRAP + 3, 1001, 0x18, b"CD"),
    ]
    cap = tmp_path / "wrap.pcap"
    cap.write_bytes(_pcap_global() + b"".join(_pcap_record(1700000000.0 + i * 0.001, p) for i, p in enumerate(pkts)))
    obs = net.tcp_reassemble(str(cap))
    s2c = [s for s in obs.facts["streams"] if s["server_to_client"]["length"] >= 4][0]
    assert bytes.fromhex(s2c["server_to_client"]["hex_preview"].rstrip("."))[:4] == b"ABCD"
    assert s2c["server_to_client"]["gaps"] == 0

