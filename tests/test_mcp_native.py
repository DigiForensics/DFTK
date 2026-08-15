from __future__ import annotations

from pathlib import Path
import importlib.metadata

import pytest

from dftk.mcp_server import DFTKMCPGateway, _validate_params, create_server
from dftk.doctor import _mcp_version_supported


def test_mcp_default_policy_and_root_guard(tmp_path: Path):
    gateway = DFTKMCPGateway(root=tmp_path)
    report = gateway.preflight()
    assert report["mcp_policy"]["max_safety"] == "READ_ONLY"
    assert report["mcp_policy"]["allow_network"] is False
    assert report["mcp_policy"]["destructive_allowed"] is False

    with pytest.raises(ValueError):
        _validate_params({"path": "../outside.bin"}, root=tmp_path.resolve())

    # Future primitives may introduce a path-bearing parameter name that does
    # not match DFTK's current vocabulary. Path-shaped relative values still
    # fail closed instead of relying only on parameter-name heuristics.
    with pytest.raises(ValueError):
        _validate_params({"apk": "../../outside.apk"}, root=tmp_path.resolve())

    # Query-like values can legitimately look like POSIX routes and SQLite
    # bound parameters may contain arbitrary path-shaped strings as data.
    _validate_params({"regex": "/api/v1/login"}, root=tmp_path.resolve())
    _validate_params({"contains": "/system/bin/sh"}, root=tmp_path.resolve())
    _validate_params({"params": ["/api/v1/login"]}, root=tmp_path.resolve())


def test_mcp_stateful_is_server_owned(tmp_path: Path):
    source = tmp_path / "evidence.zip"
    source.write_bytes(b"not-a-real-zip")
    gateway = DFTKMCPGateway(root=tmp_path)
    gateway.preflight()
    result = gateway.run(
        "archive.extract_safe",
        {"path": str(source), "output_dir": str(tmp_path / "derived")},
    )
    assert result["ok"] is False
    assert result["status"] == "blocked"


def test_mcp_tool_surface_is_six(tmp_path: Path):
    # dev extra pins MCP so release CI performs a real in-memory client/server
    # round trip. Minimal/base environments may intentionally omit the extra.
    try:
        mcp_version = importlib.metadata.version("mcp")
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("DFTK MCP extra is not installed in this environment")
    if not _mcp_version_supported(mcp_version):
        pytest.skip("DFTK MCP contract requires mcp >=2.0.0,<3")
    import asyncio
    from mcp import Client

    gateway = DFTKMCPGateway(root=tmp_path)
    gateway.preflight()
    server = create_server(gateway)

    async def round_trip():
        async with Client(server) as client:
            result = await client.list_tools()
            names = [tool.name for tool in result.tools]
            assert names == [
                "dftk_doctor",
                "dftk_search_capabilities",
                "dftk_describe",
                "dftk_run",
                "dftk_case",
                "dftk_read_case_run",
            ]
            doctor = await client.call_tool("dftk_doctor", {})
            assert doctor.structured_content is not None

    asyncio.run(round_trip())
