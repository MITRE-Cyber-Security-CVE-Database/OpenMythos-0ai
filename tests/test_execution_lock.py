import json
import subprocess
from pathlib import Path


LOCK = Path("lab/policies/execution_lock.json")
ACTIVE_CONTROLS = Path("lab/policies/active_controls.json")
FUZZ_POLICY = Path("lab/policies/bounded_fuzzing_policy.json")


def load(path):
    return json.loads(path.read_text())


def run_json(args):
    proc = subprocess.run(args, text=True, capture_output=True, check=True)
    return json.loads(proc.stdout)


def test_execution_lock_exists_and_is_dry_run_only():
    lock = load(LOCK)
    assert lock["status"] == "locked_dry_run_only"
    assert lock["active_execution_allowed"] is False
    assert lock["fuzzing_execution_allowed"] is False
    assert lock["public_target_support_allowed"] is False


def test_execution_lock_requires_review_to_change():
    lock = load(LOCK)
    assert lock["requires_security_review_to_change"] is True
    assert lock["requires_new_milestone_to_change"] is True
    assert lock["requires_ci_update_to_change"] is True


def test_execution_lock_matches_active_controls():
    lock = load(LOCK)
    controls = load(ACTIVE_CONTROLS)

    assert controls["active_tools_enabled"] is lock["active_tools_enabled_required"]
    assert controls["kill_switch_enabled"] is lock["kill_switch_enabled_required"]
    assert controls["default_mode"] == lock["default_mode_required"]


def test_execution_lock_matches_fuzz_policy():
    lock = load(LOCK)
    policy = load(FUZZ_POLICY)

    assert policy["fuzzing_enabled"] is lock["fuzzing_enabled_required"]
    assert policy["public_targets_allowed"] is lock["public_target_support_allowed"]
    assert policy["default_mode"] == lock["default_mode_required"]


def test_locked_scripts_do_not_contain_runtime_execution_markers():
    lock = load(LOCK)
    markers = lock["prohibited_runtime_markers"]

    for script in lock["locked_scripts"]:
        text = Path(script).read_text()
        for marker in markers:
            assert marker not in text, f"{script} contains prohibited marker: {marker}"


def test_active_dry_run_still_executes_zero_requests():
    data = run_json([
        "lab/scripts/active-dry-run",
        "http://127.0.0.1:3000",
        "I_APPROVE_ACTIVE_LOCAL_ONLY_TEST",
    ])

    assert data["ok"] is True
    assert data["executes_requests"] is False
    assert data["execution_blocked"] is True
    for request in data["planned_requests"]:
        assert request["executes"] is False


def test_fuzz_dry_run_still_executes_zero_requests():
    data = run_json([
        "lab/scripts/fuzz-dry-run",
        "http://127.0.0.1:3000",
        "I_APPROVE_BOUNDED_LOCAL_ONLY_FUZZING",
    ])

    assert data["ok"] is True
    assert data["executes_requests"] is False
    assert data["execution_blocked"] is True
    for case in data["planned_cases"]:
        assert case["executes"] is False
        assert case["request_preview_only"] is True


def test_public_targets_remain_blocked_by_locked_scripts():
    active = run_json([
        "lab/scripts/active-dry-run",
        "http://example.com",
        "I_APPROVE_ACTIVE_LOCAL_ONLY_TEST",
    ])

    fuzz = run_json([
        "lab/scripts/fuzz-dry-run",
        "http://example.com",
        "I_APPROVE_BOUNDED_LOCAL_ONLY_FUZZING",
    ])

    assert active["ok"] is False
    assert active["blocked"] is True
    assert fuzz["ok"] is False
    assert fuzz["blocked"] is True
