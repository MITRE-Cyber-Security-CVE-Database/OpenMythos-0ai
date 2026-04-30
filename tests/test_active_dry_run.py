import json
import subprocess
from pathlib import Path


SCRIPT = Path("lab/scripts/active-dry-run")


def run_dry(url, approval=""):
    proc = subprocess.run(
        [str(SCRIPT), url, approval],
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(proc.stdout)


def test_active_dry_run_script_exists():
    assert SCRIPT.exists()


def test_active_dry_run_executes_no_requests():
    result = run_dry("http://127.0.0.1:3000", "I_APPROVE_ACTIVE_LOCAL_ONLY_TEST")
    assert result["executes_requests"] is False
    for req in result["planned_requests"]:
        assert req["executes"] is False


def test_active_dry_run_blocks_public_url():
    result = run_dry("http://example.com", "I_APPROVE_ACTIVE_LOCAL_ONLY_TEST")
    assert result["blocked"] is True


def test_active_dry_run_requires_approval_or_kill_switch_blocks():
    result = run_dry("http://127.0.0.1:3000")
    assert result["blocked"] is True
