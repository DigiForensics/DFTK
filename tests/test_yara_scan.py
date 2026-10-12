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


def test_yara_compile_disallows_implicit_file_includes(monkeypatch):
    import sys
    from types import SimpleNamespace
    from dftk.primitives.malware import _compile_yara
    def compile_rule(**kwargs):
        assert kwargs['includes'] is False
        raise ValueError('include directives disabled')
    monkeypatch.setitem(sys.modules,'yara',SimpleNamespace(compile=compile_rule))
    rules,error=_compile_yara(None,'include "/outside/rules"')
    assert rules is None and 'disabled' in error
