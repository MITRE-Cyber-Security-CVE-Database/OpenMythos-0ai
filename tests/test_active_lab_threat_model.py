import json
from pathlib import Path


MD = Path("lab/policies/active_lab_threat_model.md")
JSON_PATH = Path("lab/policies/active_lab_threat_model.json")


def load_model():
    return json.loads(JSON_PATH.read_text())


def test_threat_model_files_exist():
    assert MD.exists()
    assert JSON_PATH.exists()


def test_threat_model_is_documentation_only():
    model = load_model()
    assert model["status"] == "documentation_only"


def test_threat_model_documents_assets_and_boundaries():
    model = load_model()
    assert "operator workstation" in model["assets_protected"]
    assert "public networks and third-party systems" in model["assets_protected"]
    assert "localhost-only lab boundary to public networks" in model["trust_boundaries"]


def test_threat_model_documents_abuse_cases():
    model = load_model()
    abuse = set(model["abuse_cases"])
    assert "accidentally enabling real active traffic" in abuse
    assert "allowing public target URLs" in abuse
    assert "introducing exploit payloads" in abuse
    assert "adding login attempts or credential workflows" in abuse
    assert "adding broad crawling" in abuse


def test_threat_model_documents_safety_controls():
    model = load_model()
    controls = set(model["safety_controls"])
    assert "localhost-only target validation" in controls
    assert "public target blocking" in controls
    assert "zero-request active dry-run planner" in controls
    assert "zero-request bounded fuzzing dry-run planner" in controls
    assert "execution lock policy" in controls


def test_threat_model_documents_prohibited_transitions():
    model = load_model()
    transitions = set(model["prohibited_transitions"])
    assert "dry-run planner to active request sender" in transitions
    assert "benign fuzz-case planner to fuzz executor" in transitions
    assert "localhost-only policy to public target support" in transitions
    assert "policy-only exploit prohibition to exploit module implementation" in transitions
    assert "no-login policy to login workflow implementation" in transitions


def test_threat_model_documents_review_requirements():
    model = load_model()
    reqs = set(model["review_requirements_before_execution"])
    assert "updated threat model" in reqs
    assert "updated execution lock policy" in reqs
    assert "explicit request budget and rate limit" in reqs
    assert "local-only scope file" in reqs
    assert "CI tests proving public targets remain blocked" in reqs


def test_threat_model_non_goals_block_active_abuse():
    model = load_model()
    non_goals = set(model["non_goals"])
    assert "public target support" in non_goals
    assert "exploit modules" in non_goals
    assert "login attempts" in non_goals
    assert "payload injection execution" in non_goals
    assert "broad crawling" in non_goals
