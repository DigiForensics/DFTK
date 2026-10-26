# Copyright 2026 DyNooob @ DigiForensics
# Licensed under the Apache License, Version 2.0.
"""Tests for the agent-native capability suggestion layer (dftk.suggest)."""
import json
from pathlib import Path

import pytest

from dftk.suggest import suggest


def _names(r):
    return [x["name"] for x in r["results"]]


def test_consume_by_extension_pcap():
    r = suggest("/cases/x/capture.pcap", direction="consume")
    assert r["ok"]
    assert "pcap" in r["inferred_kinds"]
    names = _names(r)
    assert names, "expected at least one pcap-ingesting capability"
    # network tools should dominate the top of the list
    assert any("network" in n for n in names[:3])
    assert all(x["why"] for x in r["results"]), "every suggestion must explain why"


def test_consume_by_bare_forensic_filename():
    r = suggest("$MFT", direction="consume")
    assert r["ok"]
    assert "mft" in r["inferred_kinds"]
    names = _names(r)
    assert any("mft" in n or "filesystem" in n for n in names), names


def test_consume_by_kind_token():
    r = suggest("registry", direction="consume")
    assert r["ok"]
    names = _names(r)
    assert any("registry" in n or "reg" in n for n in names), names


def test_produce_downstream_planning():
    # "given network data, what can I derive?" -> tools that emit tls/flows/etc.
    r = suggest("network", direction="produce")
    assert r["ok"]
    names = _names(r)
    # at least one network primitive should be able to produce network evidence
    assert any("network" in n for n in names), names


def test_magic_byte_fallback(tmp_path):
    # A carve with no extension but an MZ header must still resolve to PE tools.
    f = tmp_path / "carved_blob"
    f.write_bytes(b"MZ" + b"\x00" * 64)
    r = suggest(str(f), direction="consume")
    assert r["ok"]
    assert "pe" in r["inferred_kinds"], r["inferred_kinds"]
    names = _names(r)
    assert any("binary" in n or "pe" in n for n in names), names


def test_empty_and_bad_direction():
    assert suggest("").get("ok") is False
    assert suggest("foo", direction="sideways").get("ok") is False


def test_cli_suggest_runs(capsys):
    from dftk.cli import main

    # main() returns an int (the entry point wraps it in SystemExit); it does
    # not raise on its own, so assert the return code rather than SystemExit.
    rc = main(["suggest", "/cases/x.cap", "--direction", "consume"])
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["ok"]
    assert "pcap" in data["inferred_kinds"]


def test_mcp_tool_registered():
    from dftk.mcp_server import DFTKMCPGateway

    gw = DFTKMCPGateway(root=".")
    r = gw.suggest("Amcache.hve", direction="consume")
    assert r["ok"]
    assert "amcache" in r["inferred_kinds"], r["inferred_kinds"]
    names = [x["name"] for x in r["results"]]
    assert any("amcache" in n or "registry" in n for n in names), names


@pytest.mark.parametrize('header,kind,specialist', [
    (b'Salted__', 'openssl', 'crypto.openssl_decrypt'),
    (b'\x7fELF', 'elf', 'binary.elf_inventory'),
    (b'SQLite format 3\x00', 'sqlite', 'database.sqlite_inventory'),
    (b'regf', 'registry', 'windows.registry_tree'),
    (b'ElfFile\x00', 'evtx', 'windows.evtx_summary'),
    (b'dex\n035\x00', 'dex', 'android.dex_strings'),
    (b'\x1a\x00\x00\x00SCCA', 'prefetch', 'windows.prefetch'),
    (b'\xd4\xc3\xb2\xa1', 'pcap', 'network.pcap_inventory'),
    (b'\x0a\x0d\x0d\x0a', 'pcapng', 'network.pcapng_inventory'),
    (b'EVF\x09\x0d\x0a\xff\x00', 'e01', 'image.e01_inventory'),
])
def test_header_recognition_without_extension(tmp_path, header, kind, specialist):
    source = tmp_path / 'carve'
    source.write_bytes(header + b'\x00' * 32)
    result = suggest(str(source), limit=50)
    assert kind in result['inferred_kinds']
    assert specialist in _names(result)


def test_signature_ranks_above_misleading_extension(tmp_path):
    source = tmp_path / 'misnamed.exe'
    source.write_bytes(b'SQLite format 3\x00' + b'\x00' * 64)
    result = suggest(str(source))
    assert result['results'][0]['name'].startswith('database.sqlite_')
    assert result['warnings']


def test_produce_uses_outputs_not_input_description():
    from dftk.core.models import ToolSpec, SafetyLevel
    from dftk.core.registry import ToolRegistry
    reg = ToolRegistry()
    reg.register(ToolSpec('test.input', 'Read TLS files', SafetyLevel.READ_ONLY, {},
                          tags=('tls',), produces=('addresses',)), lambda: None)
    reg.register(ToolSpec('test.output', 'Extract a protocol', SafetyLevel.READ_ONLY, {},
                          tags=('protocol',), produces=('tls_sni',)), lambda: None)
    assert _names(suggest('tls', direction='produce', registry_ref=reg)) == ['test.output']
    assert _names(suggest('tls', direction='consume', registry_ref=reg)) == ['test.input']


def test_produce_never_reads_files(tmp_path, monkeypatch):
    import dftk.suggest as module
    def forbidden(*args):
        pytest.fail('produce mode must not inspect the filesystem')
    monkeypatch.setattr(module, '_magic_kinds', forbidden)
    monkeypatch.setattr(Path, 'is_file', forbidden)
    result = suggest(str(tmp_path / 'x.exe'), direction='produce')
    assert result['ok']


@pytest.mark.parametrize('query', ['../outside.exe', '/etc/passwd', r'C:\evidence\sample.exe', r'\\server\share\x'])
def test_mcp_suggest_rejects_escape_before_probing(tmp_path, monkeypatch, query):
    import dftk.suggest as module
    from dftk.mcp_server import DFTKMCPGateway
    def forbidden(*args):
        pytest.fail('escaped query must never be probed')
    monkeypatch.setattr(module, '_magic_kinds', forbidden)
    assert not DFTKMCPGateway(root=tmp_path).suggest(query)['ok']


def test_mcp_suggest_relative_extensionless_and_symlink(tmp_path):
    from dftk.mcp_server import DFTKMCPGateway
    root = tmp_path / 'root'
    root.mkdir()
    (root / 'carve').write_bytes(b'regf' + b'\x00' * 32)
    outside = tmp_path / 'outside'
    outside.write_bytes(b'MZ')
    (root / 'link').symlink_to(outside)
    gateway = DFTKMCPGateway(root=root)
    assert 'registry' in gateway.suggest('carve')['inferred_kinds']
    assert not gateway.suggest('link')['ok']
    assert gateway.suggest('not-fetched.evtx')['ok']


def test_policy_metadata_does_not_promise_runtime_availability(tmp_path):
    from dftk.mcp_server import DFTKMCPGateway
    readonly = DFTKMCPGateway(root=tmp_path).suggest('archive', limit=50)
    extraction = next(item for item in readonly['results'] if item['name'] == 'archive.extract_safe')
    assert not extraction['policy_allowed']
    assert extraction['policy_blockers']
    stateful = DFTKMCPGateway(root=tmp_path, max_safety='STATEFUL').suggest('archive', limit=50)
    assert next(item for item in stateful['results'] if item['name'] == 'archive.extract_safe')['policy_allowed']
    network = DFTKMCPGateway(root=tmp_path).suggest('spf', limit=50)
    assert not next(item for item in network['results'] if item['name'] == 'email.spf_verify')['policy_allowed']


def test_unknown_and_invalid_queries(capsys):
    from dftk.cli import main
    assert suggest('xyz987654321')['results'] == []
    for query in [None, 12, '', '\x00']:
        assert not suggest(query)['ok']
    for limit in [None, 'not-an-int', float('inf')]:
        assert not suggest('pcap', limit=limit)['ok']
    assert main(['suggest', '']) == 1
    assert not json.loads(capsys.readouterr().out)['ok']


def test_suggestion_is_deterministic():
    assert suggest('registry', limit=50) == suggest('registry', limit=50)
    assert len(suggest('windows', limit=1000)['results']) <= 50


def test_cold_python_process_loads_builtin_registry():
    import subprocess
    import sys
    process = subprocess.run([sys.executable, '-c',
                              'from dftk.suggest import suggest; print(suggest("sample.evtx")["results"][0]["name"])'],
                             capture_output=True, text=True, check=True)
    assert process.stdout.strip() in {'windows.evtx_summary', 'windows.evtx_hunt'}


def test_single_kind_contract_and_cost_hint():
    from dftk.core.registry import ToolRegistry
    reg = ToolRegistry()
    @reg.tool(name='custom.read', description='Example', parameters={},
              tags='custom', produces='custom_records', requires='dependency', cost_hint='high')
    def read():
        pass
    spec = reg.get('custom.read')
    assert spec.tags == ('custom',)
    assert spec.produces == ('custom_records',)
    assert spec.requires == ('dependency',)
    assert spec.cost_hint == 'high'
    assert _names(suggest('custom_records', direction='produce', registry_ref=reg)) == ['custom.read']


def test_live_registry_outputs_are_not_single_characters():
    import dftk
    specs = dftk.get_registry().specs()
    assert all(len(kind) > 1 for spec in specs for kind in spec.produces)
    assert 'partition_table' in dftk.get_registry().get('image.partitions').produces


def test_pipe_probe_does_not_block(tmp_path):
    import os
    from dftk.suggest import _magic_kinds
    if not hasattr(os, 'mkfifo'):
        pytest.skip('FIFO is POSIX-only')
    pipe = tmp_path / 'pipe.pcap'
    os.mkfifo(pipe)
    assert _magic_kinds(pipe) == []


@pytest.mark.parametrize("filename, expected", [
    ("History", "browser.chromium_history"),
    ("Cookies", "browser.chromium_cookies"),
    ("places.sqlite", "browser.firefox_history"),
])
def test_browser_specialist_ranks_before_generic_sqlite(tmp_path, filename, expected):
    source = tmp_path / filename
    source.write_bytes(b"SQLite format 3\x00" + b"\x00" * 64)
    names = _names(suggest(str(source), limit=50))
    assert names.index(expected) < names.index("database.sqlite_inventory")
    assert names.index(expected) < names.index("browser.chromium_downloads")
