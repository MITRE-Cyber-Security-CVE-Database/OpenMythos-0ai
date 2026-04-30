import json
from pathlib import Path


def test_lab_report_schema_loads():
    path = Path("lab/schemas/lab_report.schema.json")
    data = json.loads(path.read_text())
    assert data["title"] == "OpenMythos Localhost Lab Report"
    assert "required" in data
    assert "url_validation" in data["required"]
    assert "security_headers" in data["required"]


def test_audit_event_schema_loads():
    path = Path("lab/schemas/mcp_audit_event.schema.json")
    data = json.loads(path.read_text())
    assert data["title"] == "OpenMythos MCP Audit Event"
    assert data["required"] == ["ts", "action", "payload"]


def test_generated_report_has_required_contract_if_present():
    path = Path("lab/reports/latest_lab_report.json")
    if not path.exists():
        return

    report = json.loads(path.read_text())
    required = json.loads(Path("lab/schemas/lab_report.schema.json").read_text())["required"]

    for key in required:
        assert key in report
    assert report["mode"] == "local_only_passive_lab_report"
