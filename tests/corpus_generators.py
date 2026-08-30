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

"""Canonical forensic sample generators + independent-oracle helpers.

This module is the single source of truth for the byte-exact sample builders
used across DFTK's differential (credibility) test gate, and it wraps the
independent oracles (pefile, lief, scapy, dpkt, regipy) so tests can skip
gracefully when an oracle is missing.

Why this module exists (P0-1 credibility gap)
---------------------------------------------
The committed gate previously used *frozen* golden values and synthetic
inputs, with pefile only referenced in comments -- its value was never
actually executed. These helpers convert that into a *live* differential:

  * an independent tool RE-GENERATES the bytes (lief builds a PE, scapy
    builds a PCAP), OR
  * an independent tool RE-PARSES DFTK's inputs (pefile on the PE bytes,
    dpkt on the PCAP bytes),

and DFTK's output is cross-checked against it on every run. A future DFTK
regression cannot silently drift, because the oracle re-derives the expected
value independently each time.
"""

from __future__ import annotations

import io
import os
import socket
import struct

# --- oracle availability ----------------------------------------------------
try:
    import pefile  # type: ignore
    HAVE_PEFILE = True
except Exception:  # pragma: no cover - exercised only when pefile absent
    pefile = None
    HAVE_PEFILE = False

try:
    import lief  # type: ignore
    HAVE_LIEF = True
except Exception:  # pragma: no cover
    lief = None
    HAVE_LIEF = False

try:
    import scapy.all as scapy  # type: ignore
    HAVE_SCAPY = True
except Exception:  # pragma: no cover
    scapy = None
    HAVE_SCAPY = False

try:
    import dpkt  # type: ignore
    HAVE_DPKT = True
except Exception:  # pragma: no cover
    dpkt = None
    HAVE_DPKT = False

try:
    import regipy  # type: ignore
    HAVE_REGIPY = True
except Exception:  # pragma: no cover
    regipy = None
    HAVE_REGIPY = False

# Reuse the byte-exact synthetic builders from the deep-binary suite so the
# differential gate and the frozen-golden baseline share one definition.
try:
    from test_binary_deep import (  # type: ignore
        _build_authenticode,
        _build_elf64,
        _build_pe32plus,
        _build_pe_imphash_multidll,
        _build_pe_with_exports,
    )
    HAVE_SYNTHETIC_BUILDERS = True
except Exception:  # pragma: no cover - only when the test module is absent
    HAVE_SYNTHETIC_BUILDERS = False
    _build_pe32plus = _build_pe_imphash_multidll = _build_pe_with_exports = None
    _build_authenticode = _build_elf64 = None


# ---------------------------------------------------------------------------
# Independent PE oracle (pefile) -- executes the value the suite used to freeze
# ---------------------------------------------------------------------------
def pefile_imphash(data: bytes) -> str:
    """Live imphash from pefile; None if pefile is unavailable."""
    if not HAVE_PEFILE:
        return None
    pe = pefile.PE(data=data)
    return pe.get_imphash()


def pefile_exports_set(data: bytes):
    """Live export (name, ordinal, rva) set from pefile, excluding forwarders."""
    if not HAVE_PEFILE:
        return None
    pe = pefile.PE(data=data)
    out = set()
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return out
    for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if getattr(sym, "forwarder", None):
            continue
        name = sym.name.decode() if isinstance(sym.name, bytes) else sym.name
        out.add((name, int(sym.ordinal), int(sym.address)))
    return out


def pefile_section_count(data: bytes):
    if not HAVE_PEFILE:
        return None
    pe = pefile.PE(data=data)
    return len(pe.sections)


# ---------------------------------------------------------------------------
# Independent network oracle (dpkt) -- re-parses the PCAP DFTK parsed
# ---------------------------------------------------------------------------
def dpkt_packet_count(path: str) -> int:
    """Count every record in a classic PCAP using dpkt (independent of DFTK)."""
    if not HAVE_DPKT:
        return -1
    n = 0
    with open(path, "rb") as fh:
        reader = dpkt.pcap.Reader(fh)
        for _ts, _buf in reader:
            n += 1
    return n


def dpkt_reassemble(path: str) -> dict:
    """Reassemble raw TCP payloads per direction using dpkt.

    Returns {(src_ip_int, dst_ip_int, sport, dport): raw_bytes} for every
    flow that carried non-empty payload. Independent reassembly oracle for
    DFTK's tcp_reassemble.
    """
    if not HAVE_DPKT:
        return {}
    flows: dict = {}
    with open(path, "rb") as fh:
        reader = dpkt.pcap.Reader(fh)
        for _ts, buf in reader:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except Exception:
                continue
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            tcp = ip.data
            if not tcp.data:
                continue
            key = (int.from_bytes(ip.src, "big"), int.from_bytes(ip.dst, "big"),
                   tcp.sport, tcp.dport)
            flows.setdefault(key, []).append((tcp.seq, bytes(tcp.data)))
    out = {}
    for key, segs in flows.items():
        segs.sort(key=lambda x: x[0])
        out[key] = b"".join(d for _seq, d in segs)
    return out


# ---------------------------------------------------------------------------
# Independent sample generator: a real classic PCAP via scapy
# ---------------------------------------------------------------------------
def build_pcap_via_scapy() -> bytes:
    """Build a classic PCAP containing a full TCP/HTTP session via scapy.

    Client 10.0.0.1:1111 -> Server 10.0.0.2:80
      SYN / SYN-ACK / ACK handshake
      GET /login  (client->server)
      HTTP/1.1 200 chunked "Wikipedia"  (server->client)
    The bytes are produced entirely by scapy, so DFTK's parser is checked
    against an independently-generated capture, not a hand-rolled one.
    """
    if not HAVE_SCAPY:
        raise RuntimeError("scapy not available")

    C, S, Cp, Sp = "10.0.0.1", "10.0.0.2", 1111, 80
    req = b"GET /login HTTP/1.1\r\nHost: example.org\r\nUser-Agent: dftk-test\r\n\r\n"
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n")

    def pkt(src, dst, sp, dp, seq, ack, flags, payload=b""):
        return (scapy.Ether() / scapy.IP(src=src, dst=dst) /
                scapy.TCP(sport=sp, dport=dp, seq=seq, ack=ack, flags=flags) /
                scapy.Raw(load=payload))

    pkts = [
        pkt(C, S, Cp, Sp, 1000, 0, "S"),
        pkt(S, C, Sp, Cp, 5000, 1001, "SA"),
        pkt(C, S, Cp, Sp, 1001, 5001, "A"),
        pkt(C, S, Cp, Sp, 1001, 5001, "PA", req),
        pkt(S, C, Sp, Cp, 5001, 1001 + len(req), "A"),
        pkt(S, C, Sp, Cp, 5001, 1001 + len(req), "PA", resp),
        pkt(C, S, Cp, Sp, 1001 + len(req), 5001 + len(resp), "A"),
    ]
    buf = io.BytesIO()
    writer = scapy.PcapWriter(buf, linktype=1)
    for p in pkts:
        writer.write(p)
    data = buf.getvalue()  # capture before close() tears down the buffer
    writer.close()
    return data


# Flow addressing helpers for cross-checking scapy/dpkt keys with DFTK output.
def _ip_int(s: str) -> int:
    return struct.unpack("!I", socket.inet_aton(s))[0]


# ---------------------------------------------------------------------------
# Best-effort real-world evidence (truly independent bytes, not generated)
# ---------------------------------------------------------------------------
def find_real_pe(candidates=None) -> str | None:
    """Locate a real PE on disk that pefile can parse (best-effort).

    Searches DFTK_REAL_PE env, then a few common bundle locations. Returns the
    first path pefile accepts, else None (caller should skip).
    """
    if not HAVE_PEFILE:
        return None
    search = []
    env = os.environ.get("DFTK_REAL_PE")
    if env:
        search.append(env)
    search += [
        "/Applications/PyCharm.app/Contents",
        "/Applications/PyCharm CE.app/Contents",
        "/usr/bin", "/bin", "/opt",
    ]
    for root in search:
        if not root or not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                if fn.lower().endswith((".dll", ".exe")):
                    path = os.path.join(dirpath, fn)
                    try:
                        with open(path, "rb") as fh:
                            head = fh.read(2)
                        if head != b"MZ":
                            continue
                        pefile.PE(path)
                        return path
                    except Exception:
                        continue
    return None


def lief_section_count(path: str):
    """Independent section count via lief (third oracle for PE headers)."""
    if not HAVE_LIEF:
        return None
    binary = lief.parse(path)
    if binary is None:
        return None
    return len(binary.sections)
