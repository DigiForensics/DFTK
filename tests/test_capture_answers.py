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

"""network.capture_protocols: DNS answer + HTTP response extraction (no tshark)."""

from __future__ import annotations

import struct
import socket
from pathlib import Path
import tempfile

from dftk.catalog import load_builtin_tools
from dftk.core.registry import registry

load_builtin_tools()


def _name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def _dns_message(qname: str, answer_ip: str) -> bytes:
    q = _name(qname) + struct.pack("!HH", 1, 1)  # A, IN
    a = _name(qname) + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(answer_ip)
    return struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + q + a


def _ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    ihl = 5
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, total, 0, 0, 64, proto, 0) + socket.inet_aton(src) + socket.inet_aton(dst)
    return hdr + payload


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _tcp(sport: int, dport: int, payload: bytes) -> bytes:
    hdr = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, 0x18, 0x0400, 0, 0)
    return hdr + payload


def _ether(ip: bytes) -> bytes:
    return b"\x00\x00\x00\x00\x00\x01" + b"\x00\x00\x00\x00\x00\x02" + b"\x08\x00" + ip


def _pcap(frames: list[bytes]) -> bytes:
    out = bytearray()
    out += b"\xd4\xc3\xb2\xa1"  # little-endian classic
    out += struct.pack("<H", 2)  # version major
    out += struct.pack("<H", 4)  # version minor
    out += struct.pack("<I", 0)  # thiszone
    out += struct.pack("<I", 0)  # sigfigs
    out += struct.pack("<I", 65535)  # snaplen
    out += struct.pack("<I", 1)  # linktype ethernet
    for fr in frames:
        ts = struct.pack("<II", 1700000000, 0)
        out += ts + struct.pack("<II", len(fr), len(fr)) + fr
    return bytes(out)


def _write_tmp(data: bytes, suffix: str) -> Path:
    d = Path(tempfile.mkdtemp(prefix="dftk-cap-"))
    f = d / suffix
    f.write_bytes(data)
    return f


def test_capture_dns_answer_and_http_response():
    dns = _ether(_ipv4("10.0.0.5", "8.8.8.8", 17, _udp(33333, 53, _dns_message("example.com", "93.184.216.34"))))
    http_req = _ether(_ipv4("10.0.0.5", "93.184.216.34", 6, _tcp(40000, 80, b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")))
    http_resp = _ether(_ipv4("93.184.216.34", "10.0.0.5", 6, _tcp(80, 40000, b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n")))
    f = _write_tmp(_pcap([dns, http_req, http_resp]), "capture.pcap")
    obs = registry.run("network.capture_protocols", {"path": str(f)})
    assert obs.status.value in ("ok", "partial"), obs.errors
    assert obs.facts["dns_questions"][0]["name"] == "example.com"
    assert any(a["address"] == "93.184.216.34" for a in obs.facts["dns_answers"]), obs.facts["dns_answers"]
    assert obs.facts["http_requests"][0]["host"] == "example.com"
    assert obs.facts["http_responses"][0]["status"] == "200"
    assert obs.facts["http_responses"][0]["server"] == "nginx"
