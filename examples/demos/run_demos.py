#!/usr/bin/env python
"""DFTK 3.5.0 — five end-to-end forensic demos.

Unit tests prove parsers work; these demos prove the *chains* work. Each demo
builds small but structurally valid synthetic evidence and then walks a real
investigation chain through the DFTK registry:

  Demo 1  SQLite     Android msg.db + WAL + deleted rows  -> recovered chat candidates
  Demo 2  Disk image raw image + MBR partition            -> extract -> SHA-256 -> provenance
  Demo 3  Windows    $MFT + $UsnJrnl:$J + Amcache.hve     -> program activity timeline
  Demo 4  Network    PCAP -> TCP -> HTTP -> download -> PE -> binary triage
  Demo 5  Memory     memory.raw -> Volatility adapter (degrades to UNSUPPORTED)

Everything runs under an explicit SafetyPolicy that separates a read-only
Evidence Root from a writable Workspace (3.5.0 path policy), every call is
recorded in an audit ledger, and the collected observations are rendered into a
single HTML report that is then verified with ``case.verify``.

Run:  python examples/demos/run_demos.py
"""

from __future__ import annotations

import shutil
import sqlite3
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Reuse the synthetic-evidence builders that the test-suite already validates,
# so the demos cannot drift away from the parsers they exercise.
sys.path.insert(0, str(ROOT / "tests"))

import dftk                       # importing the package registers every primitive
from dftk.core.audit import ToolAuditLog
from dftk.core.models import SafetyLevel, Status
from dftk.core.safety import SafetyPolicy

registry = dftk.get_registry()

OUT = Path(__file__).resolve().parent / "output"
EVIDENCE = OUT / "evidence"       # read-only Evidence Root
WORKSPACE = OUT / "workspace"     # writable Workspace

POLICY: SafetyPolicy | None = None
AUDIT: ToolAuditLog | None = None


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def run(name: str, params: dict):
    return registry.run(name, params, policy=POLICY, audit=AUDIT, caller="demo")


def show(obs, keys: tuple[str, ...] = ()):
    print(f"  {obs.tool}: {obs.status.value} — {obs.summary}")
    for k in keys:
        if k in obs.facts:
            v = obs.facts[k]
            if isinstance(v, list):
                v = f"{len(v)} item(s)" + (f", e.g. {v[0]}" if v else "")
            print(f"      {k}: {v}")
    for w in obs.warnings[:2]:
        print(f"      ! {w}")
    for e in obs.errors[:2]:
        print(f"      x {e}")
    return obs


def banner(n: int, title: str) -> None:
    print(f"\n=== Demo {n}: {title} ===")


# --------------------------------------------------------------------------- #
# Demo 1 — SQLite: WAL + deleted-record recovery
# --------------------------------------------------------------------------- #
def _fresh_db(path: Path) -> None:
    """Remove a database plus its WAL/SHM sidecars so a demo run is repeatable."""
    for p in [path] + [Path(str(path) + s) for s in ("-wal", "-shm")]:
        if p.exists():
            p.unlink()


_SCHEMA = ("CREATE TABLE messages (id INTEGER PRIMARY KEY, thread_id INTEGER, "
           "address TEXT, body TEXT, date INTEGER)")
_ROWS = [(1, "+15550001", "meet me at the usual place", 1588593600000),
         (1, "+15550002", "DELETED: wire transfer confirmed", 1588593700000),
         (1, "+15550001", "ok, moving to another channel", 1588593800000)]


def demo1_sqlite(obs: list) -> None:
    banner(1, "SQLite — deleted-record recovery (DB-page residue + WAL overlay)")

    # --- Case A: the DELETE was checkpointed back into the DB page -------- #
    # The common real-world case: the row's bytes survive as freeblock /
    # unallocated residue *inside the database file itself*, so carving the DB
    # alone is enough.
    print("  [A] delete checkpointed into the DB page")
    db = EVIDENCE / "msg.db"
    _fresh_db(db)
    conn = sqlite3.connect(str(db))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(_SCHEMA)
    conn.executemany("INSERT INTO messages (thread_id,address,body,date) VALUES (?,?,?,?)", _ROWS)
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")     # flush rows into the DB
    conn.execute("DELETE FROM messages WHERE id=2")     # drop the interesting row
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")     # residue now lives in the DB page
    conn.close()

    obs.append(show(run("database.sqlite_forensic_inventory", {"path": str(db)}),
                    ("page_size", "page_count", "wal_present")))
    obs.append(show(run("database.sqlite_freelist", {"path": str(db)}), ("freelist_total",)))
    obs.append(show(run("database.sqlite_deleted_records", {"path": str(db)})))
    obs.append(show(run("database.sqlite_recover", {"path": str(db)})))
    # The generic messaging profile normalises the same database.
    obs.append(show(run("application.profile_apply", {"path": str(db)}),
                    ("matched", "record_count")))

    # --- Case B: the newest rows exist ONLY in the WAL -------------------- #
    # The DB file alone holds no trace of them; valid WAL frames must be
    # overlaid onto the DB pages before recovery can see them.
    print("  [B] newest rows live only in the WAL (never checkpointed)")
    live = EVIDENCE / "msg_wal.db"
    _fresh_db(live)
    conn2 = sqlite3.connect(str(live))
    conn2.execute("PRAGMA journal_mode=WAL")
    conn2.execute("PRAGMA wal_autocheckpoint=0")        # never checkpoint
    conn2.execute(_SCHEMA)
    conn2.executemany("INSERT INTO messages (thread_id,address,body,date) VALUES (?,?,?,?)", _ROWS)
    conn2.commit()
    conn2.execute("INSERT INTO messages (thread_id,address,body,date) VALUES (?,?,?,?)",
                  (1, "+15550003", "WAL-ONLY: new drop point", 1588593900000))
    conn2.commit()
    wal = Path(str(live) + "-wal")

    obs.append(show(run("database.sqlite_wal", {"wal_path": str(wal), "db_path": str(live)}),
                    ("frame_count", "valid_frames", "committed_frames")))
    print("      (the DB page alone cannot show WAL-only rows — sqlite_recover")
    print("       overlays valid WAL frames onto the DB pages first)")
    obs.append(show(run("database.sqlite_recover", {"path": str(live), "wal_path": str(wal)})))
    conn2.close()


# --------------------------------------------------------------------------- #
# Demo 2 — Disk image: partition -> extract -> provenance
# --------------------------------------------------------------------------- #
def demo2_disk(obs: list) -> None:
    banner(2, "Disk image — raw image + MBR partition -> extract -> provenance")
    img = EVIDENCE / "disk.raw"
    mbr = bytearray(512)
    mbr[510:512] = b"\x55\xaa"
    part = bytearray(16)
    part[0] = 0x80                              # bootable
    part[4] = 0x0C                              # FAT32 (LBA)
    struct.pack_into("<I", part, 8, 2048)       # LBA start = 1 MiB
    struct.pack_into("<I", part, 12, 2048)      # 1 MiB long
    mbr[0x1BE:0x1BE + 16] = part

    payload = b"PK\x03\x04" + b"CONFIDENTIAL-EVIDENCE-PAYLOAD" * 8
    region = bytearray(1024 * 1024)
    region[0:len(payload)] = payload
    img.write_bytes(bytes(mbr) + b"\x00" * (1024 * 1024 - 512) + bytes(region))

    obs.append(show(run("image.partitions", {"path": str(img)}), ("sector_size",)))
    obs.append(show(run("filesystem.read", {"path": str(img), "length": 64, "preview_bytes": 64}),
                    ("mode", "length", "sha256")))
    obs.append(show(run("filesystem.extract", {
        "path": str(img), "output_dir": str(WORKSPACE),
        "offset": 0, "length": len(payload), "name": "recovered.bin"}),
        ("sha256",)))


# --------------------------------------------------------------------------- #
# Demo 3 — Windows: MFT + USN + Amcache timeline
# --------------------------------------------------------------------------- #
def demo3_windows(obs: list) -> None:
    banner(3, "Windows — $MFT + $UsnJrnl:$J + Amcache -> program activity")
    import test_windows_usn as tusn
    import test_windows_amcache as tam

    mft_src = tusn._build_mft([(5, ".", 5, True), (30, "Users", 5, True),
                               (45, "payload.exe", 30, False), (46, "notes.txt", 30, False)])
    t1 = tusn._filetime(datetime(2026, 3, 11, 9, 14, 2, tzinfo=timezone.utc))
    t2 = tusn._filetime(datetime(2026, 3, 11, 9, 15, 40, tzinfo=timezone.utc))
    j_src = tusn._build_j([
        tusn._usn_record(30, 5, 100, t1, tusn._R_FILE_CREATE, "Users", attrs=0x10),
        tusn._usn_record(45, 30, 200, t2, tusn._R_CLOSE, "payload.exe", attrs=0x20),
    ])

    # The path policy requires evidence inputs to live under the Evidence Root.
    mft_path = EVIDENCE / "$MFT"
    shutil.copy(mft_src, mft_path)
    j_path = EVIDENCE / "$J"
    shutil.copy(j_src, j_path)
    am_path = EVIDENCE / "Amcache.hve"
    am_path.write_bytes(tam._build_amcache_hive())

    obs.append(show(run("windows.mft", {"path": str(mft_path)}), ("record_count", "resolved_paths")))
    # USN entries resolved to full NTFS paths via the $MFT index.
    obs.append(show(run("windows.usnjrnl", {"path": str(j_path), "mft_path": str(mft_path)}),
                    ("record_count", "resolved_path_count", "reason_summary")))
    obs.append(show(run("windows.amcache", {"path": str(am_path)}),
                    ("file_count", "program_count")))
    print("      note: the synthetic hive carries InventoryApplicationFile only; a real")
    print("            Amcache.hve also holds InventoryApplication (publisher/version/date),")
    print("            which is why program_count is 0 here.")


# --------------------------------------------------------------------------- #
# Demo 4 — Network: PCAP -> TCP -> HTTP -> download -> PE
# --------------------------------------------------------------------------- #
def demo4_network(obs: list) -> None:
    banner(4, "Network — PCAP -> TCP -> HTTP -> download -> PE triage")
    import test_binary_deep as tbd
    import test_network_sessions as tns

    pe = tbd._build_pe32plus()
    c_ip, s_ip, c_port, s_port = "10.0.0.5", "10.0.0.9", 2222, 80

    get = b"GET /payload.exe HTTP/1.1\r\nHost: cdn.evil.example\r\n\r\n"
    head = (b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
            b"Content-Length: " + str(len(pe)).encode() + b"\r\n\r\n")
    half = len(pe) // 2

    pkts = [
        tns._eth_ip_tcp(c_ip, s_ip, c_port, s_port, 1000, 0, 0x02),              # SYN
        tns._eth_ip_tcp(s_ip, c_ip, s_port, c_port, 5000, 1001, 0x12),           # SYN-ACK
        tns._eth_ip_tcp(c_ip, s_ip, c_port, s_port, 1001, 5001, 0x10),           # ACK
        tns._eth_ip_tcp(c_ip, s_ip, c_port, s_port, 1001, 5001, 0x18, get),      # GET
        # response split across two TCP segments -> forces real reassembly
        tns._eth_ip_tcp(s_ip, c_ip, s_port, c_port, 5001, 1001 + len(get), 0x18, head + pe[:half]),
        tns._eth_ip_tcp(s_ip, c_ip, s_port, c_port, 5001 + len(head) + half,
                        1001 + len(get), 0x18, pe[half:]),
        tns._eth_ip_udp(c_ip, "8.8.8.8", 3333, 53, tns._build_dns_query()),
        tns._eth_ip_udp("8.8.8.8", c_ip, 53, 3333, tns._build_dns_response()),
        tns._eth_ip_tcp(c_ip, "10.0.0.9", 1112, 443, 2000, 0, 0x18, tns._build_client_hello()),
    ]
    data = tns._pcap_global()
    ts = 1700000000.0
    for i, pkt in enumerate(pkts):
        data += tns._pcap_record(ts + i * 0.001, pkt)

    cap = EVIDENCE / "capture.pcap"
    cap.write_bytes(data)

    obs.append(show(run("network.flows", {"path": str(cap)}), ("flow_count",)))
    obs.append(show(run("network.tcp_reassemble", {"path": str(cap)}), ("stream_count",)))
    hs = run("network.http_sessions", {"path": str(cap), "output_dir": str(WORKSPACE)})
    obs.append(show(hs, ("session_count",)))
    obs.append(show(run("network.dns_transactions", {"path": str(cap)}), ("transaction_count",)))
    obs.append(show(run("network.tls_inventory", {"path": str(cap)}), ("hello_count",)))

    # Feed the recovered download straight into the binary parsers.
    extracted = hs.facts.get("extracted") or []
    if not extracted:
        print("      (no object extracted — skipping binary triage)")
        return
    dl = Path(extracted[0]["path"])
    print(f"      recovered: {dl.name} ({extracted[0]['size']} bytes, sha256={extracted[0]['sha256'][:16]}…)")
    obs.append(show(run("binary.pe_headers", {"path": str(dl)})))
    obs.append(show(run("binary.pe_imports", {"path": str(dl)}), ("imphash",)))
    obs.append(show(run("binary.pe_signing", {"path": str(dl)})))


# --------------------------------------------------------------------------- #
# Demo 5 — Memory: Volatility adapter (graceful degradation)
# --------------------------------------------------------------------------- #
def demo5_memory(obs: list) -> None:
    banner(5, "Memory — memory.raw -> Volatility 3 adapter")
    mem = EVIDENCE / "memory.raw"
    # A structurally irrelevant blob: this demo shows the *adapter* contract,
    # not the memory format. DFTK never parses dumps itself.
    mem.write_bytes(b"\x00" * 4096 + b"DFTK-DEMO-MEMORY-IMAGE")

    for tool in ("memory.volatility_inventory", "memory.processes", "memory.network",
                 "memory.malfind", "memory.modules", "memory.handles"):
        o = run(tool, {"image": str(mem), "timeout": 30})
        obs.append(show(o))
    print("      note: Volatility 3 is an *adapter* — DFTK resolves `vol`, fixes the")
    print("            plugin per capability, bounds the run, and exposes no arbitrary")
    print("            arguments. Absent -> UNSUPPORTED, never a crash.")


# --------------------------------------------------------------------------- #
def main() -> int:
    global POLICY, AUDIT

    if OUT.exists():
        shutil.rmtree(OUT)
    EVIDENCE.mkdir(parents=True)
    WORKSPACE.mkdir(parents=True)

    ledger = WORKSPACE / "audit_ledger.jsonl"
    AUDIT = ToolAuditLog(str(ledger))
    # 3.5.0 path policy: read-only Evidence Root + writable Workspace.
    POLICY = SafetyPolicy(max_level=SafetyLevel.STATEFUL,
                          evidence_root=EVIDENCE, workspace_root=WORKSPACE)

    print("DFTK 3.5.0 — five end-to-end forensic demos")
    print(f"evidence root : {EVIDENCE} (read-only)")
    print(f"workspace     : {WORKSPACE} (writable)")

    observations: list = []
    demo1_sqlite(observations)
    demo2_disk(observations)
    demo3_windows(observations)
    demo4_network(observations)
    demo5_memory(observations)

    # ---- report + verification ------------------------------------------- #
    print("\n=== Report & verification ===")
    report = run("case.report_html", {
        "output_dir": str(WORKSPACE),
        "observations": [o.to_dict() for o in observations],
        "case_id": "DEMO-3.5.0",
        "title": "DFTK 3.5.0 — five-demo forensic walkthrough",
    })
    show(report, ("report_path", "sha256", "size", "observation_count", "audit_verdict"))

    verify = run("case.verify", {"audit_log": str(ledger)})
    show(verify, ("verdict", "records", "broken_at", "reason"))

    def acceptable(o) -> bool:
        if o.status in (Status.OK, Status.PARTIAL):
            return True
        # Volatility is an optional external engine: UNSUPPORTED is the designed
        # outcome when it is absent, not a tool failure.
        return o.status == Status.UNSUPPORTED and o.tool.startswith("memory.")

    failed = [o.tool for o in observations if not acceptable(o)]
    print(f"\nobservations: {len(observations)}   tools not OK/PARTIAL: {failed or 'none'}")
    print(f"report      : {report.facts.get('report_path')}")
    print(f"ledger      : {ledger}  verdict={verify.facts.get('verdict')}")
    return 0 if not failed and verify.facts.get("verdict") == "VALID" else 1


if __name__ == "__main__":
    sys.exit(main())
