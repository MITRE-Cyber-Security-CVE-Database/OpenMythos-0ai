from pathlib import Path


SCRIPT = Path("lab/scripts/readiness-check")


def test_readiness_check_script_exists():
    assert SCRIPT.exists()


def test_readiness_check_script_is_executable():
    assert SCRIPT.stat().st_mode & 0o111


def test_readiness_check_verifies_zero_execution():
    text = SCRIPT.read_text()
    assert "executes_requests" in text
    assert "execution_blocked" in text
    assert "active dry-run executes zero requests" in text
    assert "fuzz dry-run executes zero requests" in text


def test_readiness_check_verifies_public_target_blocking():
    text = SCRIPT.read_text()
    assert "http://example.com" in text
    assert "active dry-run blocks public URL" in text
    assert "fuzz dry-run blocks public URL" in text


def test_readiness_check_writes_latest_reports():
    text = SCRIPT.read_text()
    assert "latest_readiness.json" in text
    assert "latest_readiness.md" in text


def test_readiness_check_verifies_disabled_risky_capabilities():
    text = SCRIPT.read_text()
    assert "exploit modules" in text
    assert "broad crawling" in text
    assert "public target support" in text
    assert "auth_login_attempts" in text
    assert "exploit_execution" in text
