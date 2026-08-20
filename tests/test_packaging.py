# Copyright 2026 DyNooob @ DigiForensics
# Licensed under the Apache License, Version 2.0.
from pathlib import Path


def test_mcp_extra_matches_runtime_supported_range():
    project = (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert 'mcp = ["mcp>=2.0.0,<3"]' in project
    assert '"mcp==2.0.0"' not in project


def test_yara_extra_is_available_for_malware_scanning():
    project = (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    assert 'yara = ["yara-python>=4.5"]' in project
