from pathlib import Path

from dftk.skill_bundle import install_bundled_skill


def test_complete_skill_bundle_installs(tmp_path: Path):
    dest = install_bundled_skill(tmp_path)
    assert (dest / "SKILL.md").is_file()
    assert (dest / "references" / "claim-patterns.md").is_file()
    assert (dest / "references" / "negative-findings.md").is_file()
    assert (dest / "references" / "domains" / "android.md").is_file()
    assert (dest / "templates" / "answer-card.md").is_file()


def test_root_skill_snapshot_matches_bundle():
    import dftk

    package = Path(dftk.__file__).resolve().parent
    root = (package / "SKILL.md").read_text(encoding="utf-8")
    bundled = (package / "skill" / "SKILL.md").read_text(encoding="utf-8")
    assert root == bundled
    assert "DFTK Agent Bridge" not in bundled
    assert "dftk_read_case_run" in bundled
