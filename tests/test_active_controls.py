import json
from pathlib import Path


def load_controls():
    return json.loads(Path("lab/policies/active_controls.json").read_text())


def test_active_tools_disabled_by_default():
    controls = load_controls()
    assert controls["active_tools_enabled"] is False
    assert controls["default_mode"] == "dry_run"


def test_kill_switch_enabled_by_default():
    controls = load_controls()
    assert controls["kill_switch_enabled"] is True


def test_request_caps_exist():
    controls = load_controls()
    assert controls["max_requests_per_run"] <= 25
    assert controls["max_request_rate_per_second"] <= 1
    assert controls["timeout_seconds"] <= 10


def test_only_local_hosts_allowed():
    controls = load_controls()
    assert set(controls["allowed_hosts"]) == {"127.0.0.1", "localhost", "::1"}


def test_dangerous_capabilities_disabled():
    controls = load_controls()
    disabled = set(controls["disabled_capabilities"])
    assert "fuzzing" in disabled
    assert "login attempts" in disabled
    assert "payload injection" in disabled
    assert "exploit modules" in disabled
    assert "broad crawling" in disabled
    assert "public target support" in disabled


def test_explicit_approval_required():
    controls = load_controls()
    assert controls["require_explicit_approval"] is True
    assert controls["approval_phrase"] == "I_APPROVE_ACTIVE_LOCAL_ONLY_TEST"
