from pathlib import Path


GUIDE = Path("lab/OPERATOR_GUIDE.md")


def test_operator_guide_exists():
    assert GUIDE.exists()


def test_operator_guide_documents_core_commands():
    text = GUIDE.read_text()
    assert "./lab/scripts/passive-audit" in text
    assert "./lab/scripts/active-dry-run" in text
    assert "./lab/scripts/fuzz-dry-run" in text
    assert "./lab/scripts/dryrun-evidence-report" in text
    assert "./lab/scripts/readiness-check" in text
    assert "./lab/scripts/release-manifest" in text


def test_operator_guide_documents_approval_phrases():
    text = GUIDE.read_text()
    assert "I_APPROVE_LOCAL_ONLY_HTTP_GET" in text
    assert "I_APPROVE_ACTIVE_LOCAL_ONLY_TEST" in text
    assert "I_APPROVE_BOUNDED_LOCAL_ONLY_FUZZING" in text


def test_operator_guide_documents_safety_invariants():
    text = GUIDE.read_text()
    assert "public target support remains disabled" in text
    assert "active dry-run executes zero requests" in text
    assert "bounded fuzz dry-run executes zero requests" in text
    assert "exploit payloads remain prohibited" in text
    assert "login attempts remain prohibited" in text
    assert "broad crawling remains prohibited" in text


def test_operator_guide_documents_canonical_tags():
    text = GUIDE.read_text()
    assert "lab-localhost-v1.6" in text
    assert "active-lab-v0.4-release-manifest" in text
    assert "active-lab-v0.4-readiness" in text
    assert "active-lab-v0.4-dryrun-report" in text
