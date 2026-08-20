from __future__ import annotations

from dftk.core.models import Status
from dftk.primitives.malware import _normalise_yara_strings, yara_scan


class _Instance:
    offset = 12
    matched_data = b"evil"


class _StringMatch:
    identifier = "$a"
    instances = [_Instance()]


class _ModernMatch:
    strings = [_StringMatch()]


def test_yara_string_normalization_supports_modern_api():
    assert _normalise_yara_strings(_ModernMatch()) == [{
        "identifier": "$a", "offset": 12, "matched_hex": b"evil".hex(), "matched_length": 4,
    }]


def test_yara_scan_has_explicit_optional_dependency_or_rule_error(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"test")
    observation = yara_scan(str(target), rule_text="rule test { condition: true }")
    assert observation.status in (Status.OK, Status.UNSUPPORTED, Status.ERROR)
    if observation.status == Status.UNSUPPORTED:
        assert "yara-python" in observation.errors[0]
