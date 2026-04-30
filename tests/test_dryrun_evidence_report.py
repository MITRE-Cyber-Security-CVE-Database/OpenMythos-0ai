from pathlib import Path


SCRIPT = Path("lab/scripts/dryrun-evidence-report")


def test_dryrun_evidence_report_script_exists():
    assert SCRIPT.exists()


def test_dryrun_evidence_report_is_executable():
    assert SCRIPT.stat().st_mode & 0o111


def test_dryrun_evidence_report_uses_zero_execution_planners():
    text = SCRIPT.read_text()
    assert "./lab/scripts/active-dry-run" in text
    assert "./lab/scripts/fuzz-dry-run" in text
    assert "executes_requests" in text
    assert "executed zero HTTP requests" in text


def test_dryrun_evidence_report_requires_local_preflight():
    text = SCRIPT.read_text()
    assert "curl -fsS -I --max-time 10" in text
    assert "Start it with: sudo ./lab/scripts/labctl up" in text


def test_dryrun_evidence_report_writes_expected_outputs():
    text = SCRIPT.read_text()
    assert "active-dry-run.json" in text
    assert "fuzz-dry-run.json" in text
    assert "dryrun-summary.json" in text
    assert "dryrun-summary.md" in text
    assert "mcp_audit_tail.jsonl" in text
