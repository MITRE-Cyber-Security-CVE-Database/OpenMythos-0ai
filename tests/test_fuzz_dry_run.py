import json
import subprocess
from pathlib import Path


SCRIPT = Path("lab/scripts/fuzz-dry-run")


def run_fuzz_dry(url, approval=""):
    proc = subprocess.run(
        [str(SCRIPT), url, approval],
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(proc.stdout)


def test_fuzz_dry_run_script_exists():
    assert SCRIPT.exists()


def test_fuzz_dry_run_requires_approval():
    result = run_fuzz_dry("http://127.0.0.1:3000")
    assert result["blocked"] is True
    assert result["required_approval"] == "I_APPROVE_BOUNDED_LOCAL_ONLY_FUZZING"


def test_fuzz_dry_run_blocks_public_url():
    result = run_fuzz_dry(
        "http://example.com",
        "I_APPROVE_BOUNDED_LOCAL_ONLY_FUZZING",
    )
    assert result["blocked"] is True
    assert result["ok"] is False


def test_fuzz_dry_run_executes_zero_requests():
    result = run_fuzz_dry(
        "http://127.0.0.1:3000",
        "I_APPROVE_BOUNDED_LOCAL_ONLY_FUZZING",
    )
    assert result["ok"] is True
    assert result["executes_requests"] is False
    assert result["execution_blocked"] is True
    for case in result["planned_cases"]:
        assert case["executes"] is False
        assert case["request_preview_only"] is True


def test_fuzz_dry_run_honors_request_cap():
    result = run_fuzz_dry(
        "http://127.0.0.1:3000",
        "I_APPROVE_BOUNDED_LOCAL_ONLY_FUZZING",
    )
    assert result["planned_case_count"] <= result["policy"]["max_requests_per_run"]
    assert result["planned_case_count"] == len(result["planned_cases"])


def test_fuzz_dry_run_uses_only_benign_classes():
    result = run_fuzz_dry(
        "http://127.0.0.1:3000",
        "I_APPROVE_BOUNDED_LOCAL_ONLY_FUZZING",
    )
    allowed = {
        "benign_length_variation",
        "benign_ascii_boundary_values",
        "benign_numeric_boundary_values",
        "benign_empty_value",
        "benign_unicode_smoke_value",
    }
    prohibited_fragments = {
        "sql",
        "xss",
        "command",
        "shell",
        "exploit",
        "traversal",
        "credential",
        "auth",
    }

    for case in result["planned_cases"]:
        assert case["class"] in allowed
        lowered = json.dumps(case).lower()
        for frag in prohibited_fragments:
            assert frag not in lowered
