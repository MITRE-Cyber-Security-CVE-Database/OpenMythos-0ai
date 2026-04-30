import importlib.util
from pathlib import Path


def load_mcp():
    path = Path("mcp/openmythos_0ai_mcp.py")
    spec = importlib.util.spec_from_file_location("openmythos_mcp", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_local_targets_allowed():
    mod = load_mcp()
    for target in ["127.0.0.1", "localhost", "::1"]:
        assert mod.openmythos_validate_target(target)["ok"] is True


def test_public_targets_blocked():
    mod = load_mcp()
    for target in ["8.8.8.8", "192.168.1.1", "example.com"]:
        assert mod.openmythos_validate_target(target)["ok"] is False


def test_local_urls_allowed():
    mod = load_mcp()
    for url in ["http://127.0.0.1:3000", "http://localhost:3000"]:
        assert mod.openmythos_validate_url(url)["ok"] is True


def test_public_urls_blocked():
    mod = load_mcp()
    for url in ["http://8.8.8.8", "http://example.com", "file:///etc/passwd"]:
        assert mod.openmythos_validate_url(url)["ok"] is False


def test_get_requires_approval():
    mod = load_mcp()
    result = mod.openmythos_http_get_preview("http://127.0.0.1:3000")
    assert result["ok"] is False
    assert result["blocked"] is True
    assert result["required_approval"] == "I_APPROVE_LOCAL_ONLY_HTTP_GET"


def test_public_report_generation_blocked():
    mod = load_mcp()
    result = mod.openmythos_generate_lab_report(
        "http://example.com",
        approval="I_APPROVE_LOCAL_ONLY_HTTP_GET",
    )
    assert result["ok"] is False
    assert result["blocked"] is True


def test_static_asset_inventory_requires_approval():
    mod = load_mcp()
    result = mod.openmythos_http_static_asset_inventory("http://127.0.0.1:3000")
    assert result["ok"] is False
    assert result["blocked"] is True
    assert result["required_approval"] == "I_APPROVE_LOCAL_ONLY_HTTP_GET"


def test_static_asset_inventory_blocks_public_url():
    mod = load_mcp()
    result = mod.openmythos_http_static_asset_inventory(
        "http://example.com",
        approval="I_APPROVE_LOCAL_ONLY_HTTP_GET",
    )
    assert result["ok"] is False
    assert result["blocked"] is True


def test_header_diff_blocks_public_base_url():
    mod = load_mcp()
    result = mod.openmythos_http_header_diff(
        base_url="http://example.com",
        paths=["/"],
    )
    assert result["ok"] is False
    assert result["blocked"] is True


def test_header_diff_blocks_external_absolute_path():
    mod = load_mcp()
    result = mod.openmythos_http_header_diff(
        base_url="http://127.0.0.1:3000",
        paths=["http://example.com/"],
    )
    assert result["ok"] is True
    assert result["blocked_path_count"] == 1


def test_severity_normalization_known_values():
    mod = load_mcp()
    assert mod.normalize_severity("info")["score"] == 0
    assert mod.normalize_severity("review")["score"] == 1
    assert mod.normalize_severity("low")["score"] == 2
    assert mod.normalize_severity("medium")["score"] == 3
    assert mod.normalize_severity("high")["score"] == 4
    assert mod.normalize_severity("critical")["score"] == 5


def test_severity_normalization_unknown_defaults_to_review():
    mod = load_mcp()
    result = mod.normalize_severity("unexpected")
    assert result["severity"] == "review"
    assert result["score"] == 1
