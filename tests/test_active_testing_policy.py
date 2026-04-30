import json
from pathlib import Path


def load_policy():
    return json.loads(Path("lab/policies/active_testing_policy.json").read_text())


def test_active_policy_exists_and_is_policy_only():
    policy = load_policy()
    assert policy["status"] == "policy_only_no_active_tools_enabled"


def test_active_policy_blocks_public_targets():
    policy = load_policy()
    blocked = set(policy["blocked"])
    assert "public IP testing" in blocked
    assert "third-party domains" in blocked
    assert "external networks" in blocked


def test_active_policy_disables_dangerous_capabilities():
    policy = load_policy()
    disabled = set(policy["disabled_capabilities"])
    assert "fuzzing" in disabled
    assert "login attempts" in disabled
    assert "payload injection" in disabled
    assert "exploit modules" in disabled
    assert "broad crawling" in disabled
    assert "public target support" in disabled


def test_active_policy_requires_kill_switch_caps_and_dry_run():
    policy = load_policy()
    controls = set(policy["required_controls_before_active_tools"])
    assert "hard request cap" in controls
    assert "rate limit" in controls
    assert "kill switch" in controls
    assert "dry-run mode" in controls
    assert "CI public-target block tests" in controls


def test_active_policy_has_separate_approval_phrases():
    policy = load_policy()
    phrases = policy["approval_phrases"]
    assert phrases["active_local_only"] == "I_APPROVE_ACTIVE_LOCAL_ONLY_TEST"
    assert phrases["bounded_local_only_fuzzing"] == "I_APPROVE_BOUNDED_LOCAL_ONLY_FUZZING"
