from pathlib import Path


SCRIPT = Path("lab/scripts/release-manifest")


def test_release_manifest_script_exists():
    assert SCRIPT.exists()


def test_release_manifest_script_is_executable():
    assert SCRIPT.stat().st_mode & 0o111


def test_release_manifest_records_safety_assertions():
    text = SCRIPT.read_text()
    assert "public target support remains disabled" in text
    assert "active dry-run executes zero requests" in text
    assert "bounded fuzz dry-run executes zero requests" in text
    assert "exploit payloads remain prohibited" in text


def test_release_manifest_records_operator_commands():
    text = SCRIPT.read_text()
    assert "./lab/scripts/passive-audit" in text
    assert "./lab/scripts/active-dry-run" in text
    assert "./lab/scripts/fuzz-dry-run" in text
    assert "./lab/scripts/readiness-check" in text


def test_release_manifest_writes_expected_files():
    text = SCRIPT.read_text()
    assert "openmythos_lab_manifest.json" in text
    assert "openmythos_lab_manifest.md" in text
