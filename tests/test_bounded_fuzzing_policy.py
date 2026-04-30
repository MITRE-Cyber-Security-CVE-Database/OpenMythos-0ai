import json
from pathlib import Path


def load_policy():
    return json.loads(Path("lab/policies/bounded_fuzzing_policy.json").read_text())


def test_bounded_fuzzing_policy_is_policy_only():
    policy = load_policy()
    assert policy["status"] == "policy_only_no_fuzzing_execution_enabled"
    assert policy["fuzzing_enabled"] is False
    assert policy["default_mode"] == "dry_run"


def test_bounded_fuzzing_is_localhost_only():
    policy = load_policy()
    assert policy["localhost_only"] is True
    assert policy["public_targets_allowed"] is False
    allowed = set(policy["allowed_targets"])
    assert "127.0.0.1" in allowed
    assert "localhost" in allowed
    assert "::1" in allowed


def test_bounded_fuzzing_requires_kill_switch_and_approval():
    policy = load_policy()
    assert policy["requires_kill_switch"] is True
    assert policy["requires_explicit_approval"] is True
    assert policy["approval_phrase"] == "I_APPROVE_BOUNDED_LOCAL_ONLY_FUZZING"


def test_bounded_fuzzing_caps_are_hard_limited():
    policy = load_policy()
    assert policy["max_requests_per_run"] <= 10
    assert policy["max_request_rate_per_second"] <= 1
    assert policy["timeout_seconds"] <= 5


def test_exploit_payload_classes_are_prohibited():
    policy = load_policy()
    prohibited = set(policy["prohibited_payload_classes"])
    assert "sql_injection" in prohibited
    assert "xss" in prohibited
    assert "command_injection" in prohibited
    assert "path_traversal" in prohibited
    assert "shell_metacharacter_payloads" in prohibited
    assert "exploit_payloads" in prohibited
    assert "destructive_payloads" in prohibited


def test_risky_actions_are_prohibited():
    policy = load_policy()
    prohibited = set(policy["prohibited_actions"])
    assert "auth_login_attempts" in prohibited
    assert "credential_stuffing" in prohibited
    assert "state_changing_requests" in prohibited
    assert "exploit_execution" in prohibited
    assert "broad_crawling" in prohibited
    assert "public_target_testing" in prohibited
    assert "data_exfiltration" in prohibited
    assert "denial_of_service" in prohibited
