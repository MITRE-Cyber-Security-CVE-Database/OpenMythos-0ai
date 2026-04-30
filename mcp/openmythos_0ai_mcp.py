import os
import sys
import json
import ipaddress
import time
import pathlib
import subprocess
import re

REDACT_PATTERNS = [
    re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|authorization)[=:]\S+"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
]

def redact(text: str) -> str:
    for pat in REDACT_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    return text


def assert_repo_safe() -> None:
    if not REPO.exists():
        raise RuntimeError(f"Repo does not exist: {REPO}")
    expected = pathlib.Path.home().resolve() / "OpenMythos-0ai"
    if REPO != expected:
        raise RuntimeError(f"Unsafe OPENMYTHOS_REPO override: {REPO}")

from typing import Dict, Any, List
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastmcp import FastMCP

mcp = FastMCP("openmythos-0ai-kali")

REPO = pathlib.Path(os.environ.get("OPENMYTHOS_REPO", str(pathlib.Path.home() / "OpenMythos-0ai"))).resolve()
PYTHON = os.environ.get("OPENMYTHOS_PYTHON", sys.executable)
TIMEOUT = int(os.environ.get("OPENMYTHOS_TIMEOUT", "90"))


AUDIT_LOG = REPO / "lab_audit" / "logs" / "mcp_audit.jsonl"
LOCAL_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}
LOCAL_ALLOWED_CIDRS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]


def audit_event(action: str, payload: Dict[str, Any]) -> None:
    """
    Append a JSONL audit event for every lab/pentest-relevant MCP action.
    """
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "payload": payload,
    }
    with AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, sort_keys=True) + "\n")


def validate_local_target(target: str) -> Dict[str, Any]:
    """
    Permit only localhost / loopback targets.

    This deliberately blocks public IPs, private LAN ranges, and domains until
    the lab policy is expanded deliberately.
    """
    target = str(target).strip()

    if target in LOCAL_ALLOWED_HOSTS:
        return {
            "ok": True,
            "target": target,
            "reason": "explicit localhost allowlist",
        }

    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        return {
            "ok": False,
            "target": target,
            "reason": "target is not a permitted localhost name or loopback IP",
        }

    for net in LOCAL_ALLOWED_CIDRS:
        if ip in net:
            return {
                "ok": True,
                "target": target,
                "reason": f"target is inside allowed loopback CIDR {net}",
            }

    return {
        "ok": False,
        "target": target,
        "reason": "blocked: only localhost / loopback targets are allowed",
    }


def validate_local_url(url: str) -> Dict[str, Any]:
    """
    Permit only HTTP(S) URLs whose hostname resolves to the local-only policy.
    """
    url = str(url).strip()
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        return {
            "ok": False,
            "url": url,
            "reason": "blocked: only http/https URLs are allowed",
        }

    if not parsed.hostname:
        return {
            "ok": False,
            "url": url,
            "reason": "blocked: URL has no hostname",
        }

    target_validation = validate_local_target(parsed.hostname)

    if not target_validation["ok"]:
        return {
            "ok": False,
            "url": url,
            "scheme": parsed.scheme,
            "hostname": parsed.hostname,
            "port": parsed.port,
            "target_validation": target_validation,
            "reason": "blocked: URL hostname is outside local-only policy",
        }

    return {
        "ok": True,
        "url": url,
        "scheme": parsed.scheme,
        "hostname": parsed.hostname,
        "port": parsed.port,
        "path": parsed.path or "/",
        "target_validation": target_validation,
        "reason": "URL allowed by local-only policy",
    }


def require_explicit_approval(approval: str) -> bool:
    """
    Require a deliberate approval phrase for active local scans.
    """
    return approval == "I_APPROVE_LOCAL_ONLY_SCAN"


def run_cmd(args: List[str], timeout: int = TIMEOUT) -> Dict[str, Any]:
    """
    Safe command runner: no shell=True, fixed argv only, repo-bound.
    """
    assert_repo_safe()

    start = time.time()
    try:
        proc = subprocess.run(
            args,
            cwd=str(REPO),
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "elapsed_seconds": round(time.time() - start, 3),
            "stdout": redact(proc.stdout[-12000:]),
            "stderr": redact(proc.stderr[-12000:]),
            "cwd": str(REPO),
            "cmd": args,
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        return {
            "ok": False,
            "error": "timeout",
            "timeout_seconds": timeout,
            "stdout": redact(stdout[-12000:] if isinstance(stdout, str) else ""),
            "stderr": redact(stderr[-12000:] if isinstance(stderr, str) else ""),
            "cwd": str(REPO),
            "cmd": args,
        }



@mcp.tool()
def openmythos_repo_info() -> Dict[str, Any]:
    """
    Return basic repository structure and setup files.
    """
    files = []
    for p in REPO.rglob("*"):
        if ".git" in p.parts or ".venv" in p.parts or "__pycache__" in p.parts:
            continue
        if p.is_file():
            files.append(str(p.relative_to(REPO)))
        if len(files) >= 300:
            break

    markers = {
        "pyproject.toml": (REPO / "pyproject.toml").exists(),
        "setup.py": (REPO / "setup.py").exists(),
        "requirements.txt": (REPO / "requirements.txt").exists(),
        "README.md": (REPO / "README.md").exists(),
        "tests": (REPO / "tests").exists(),
        "open_mythos": (REPO / "open_mythos").exists(),
    }

    return {
        "repo": str(REPO),
        "exists": REPO.exists(),
        "markers": markers,
        "sample_files": files[:300],
    }


@mcp.tool()
def openmythos_git_status() -> Dict[str, Any]:
    """
    Return git branch/status/remotes for the local OpenMythos-0ai repo.
    """
    return {
        "status": run_cmd(["git", "status", "--short"]),
        "branch": run_cmd(["git", "branch", "--show-current"]),
        "remote": run_cmd(["git", "remote", "-v"]),
        "last_commit": run_cmd(["git", "log", "-1", "--oneline", "--decorate"]),
    }


@mcp.tool()
def openmythos_pytest(maxfail: int = 1) -> Dict[str, Any]:
    """
    Run pytest safely against the repo.
    """
    maxfail = max(1, min(int(maxfail), 10))
    return run_cmd([PYTHON, "-m", "pytest", "-q", f"--maxfail={maxfail}"], timeout=180)


@mcp.tool()
def openmythos_import_probe() -> Dict[str, Any]:
    """
    Probe common OpenMythos import paths.
    """
    code = r'''
import importlib
mods = [
    "open_mythos",
    "open_mythos.main",
    "openmythos",
    "openmythos.main",
    "main",
]
result = {}
for m in mods:
    try:
        mod = importlib.import_module(m)
        result[m] = {
            "ok": True,
            "file": getattr(mod, "__file__", None),
            "attrs": [a for a in dir(mod) if not a.startswith("_")][:80],
        }
    except Exception as e:
        result[m] = {
            "ok": False,
            "error": repr(e),
        }
print(result)
'''
    return run_cmd([PYTHON, "-c", code])


@mcp.tool()
def openmythos_smoketest() -> Dict[str, Any]:
    """
    Try a CPU-safe OpenMythos forward pass using common package names.

    This works if the repo exposes OpenMythos and MythosConfig under:
    - open_mythos.main
    - openmythos.main
    - main
    """
    code = r'''
import importlib
import torch

candidates = ["open_mythos.main", "openmythos.main", "main"]
last_error = None

for modname in candidates:
    try:
        mod = importlib.import_module(modname)

        if not hasattr(mod, "OpenMythos") or not hasattr(mod, "MythosConfig"):
            last_error = f"{modname} missing OpenMythos/MythosConfig"
            continue

        OpenMythos = getattr(mod, "OpenMythos")
        MythosConfig = getattr(mod, "MythosConfig")

        cfg_kwargs = dict(
            vocab_size=512,
            dim=128,
            n_heads=4,
            n_kv_heads=2,
            max_seq_len=64,
            max_loop_iters=2,
            prelude_layers=1,
            coda_layers=1,
            n_experts=4,
            n_shared_experts=1,
            n_experts_per_tok=2,
            expert_dim=64,
            lora_rank=4,
            attn_type="gqa",
        )

        try:
            cfg = MythosConfig(**cfg_kwargs)
        except TypeError:
            # Fallback for config variants.
            cfg = MythosConfig()

        model = OpenMythos(cfg).eval()
        ids = torch.randint(0, getattr(cfg, "vocab_size", 512), (1, 16))

        with torch.inference_mode():
            try:
                out = model(ids, n_loops=1)
            except TypeError:
                out = model(ids)

        params = sum(p.numel() for p in model.parameters())

        print({
            "ok": True,
            "module": modname,
            "output_shape": tuple(out.shape) if hasattr(out, "shape") else str(type(out)),
            "params": params,
            "device": "cpu",
            "note": "This is a local CPU smoke test. Chat quality requires trained weights/tokenizer."
        })
        raise SystemExit(0)

    except SystemExit:
        raise
    except Exception as e:
        last_error = f"{modname}: {repr(e)}"

print({
    "ok": False,
    "error": last_error,
    "note": "Run openmythos_import_probe first to inspect the repo package layout."
})
raise SystemExit(1)
'''
    return run_cmd([PYTHON, "-c", code], timeout=180)



@mcp.tool()
def openmythos_safety_policy() -> Dict[str, Any]:
    """
    Return the current safety posture for OpenMythos MCP.
    """
    return {
        "network_tools_enabled": False,
        "shell_enabled": False,
        "public_target_scanning_enabled": False,
        "allowed_targets": ["127.0.0.1", "localhost", "local Docker labs only"],
        "blocked": [
            "public IP scanning",
            "third-party domains",
            "credential attacks",
            "persistence",
            "evasion",
            "malware deployment",
            "destructive exploitation",
            "data exfiltration",
        ],
        "status": "repo/test/model smoke MCP only",
    }



@mcp.tool()
def openmythos_validate_url(url: str) -> Dict[str, Any]:
    """
    Validate whether a URL is allowed under the local-only lab policy.
    """
    result = validate_local_url(url)
    audit_event("validate_url", result)
    return result


@mcp.tool()
def openmythos_validate_target(target: str) -> Dict[str, Any]:
    """
    Validate whether a target is allowed under the local-only lab policy.
    """
    result = validate_local_target(target)
    audit_event("validate_target", result)
    return result


@mcp.tool()
def openmythos_lab_scan_plan(target: str = "127.0.0.1", ports: str = "1-1024") -> Dict[str, Any]:
    """
    Return a dry-run local scan plan. Does not execute nmap or any network tool.
    """
    validation = validate_local_target(target)

    plan = {
        "ok": validation["ok"],
        "mode": "dry_run",
        "target_validation": validation,
        "would_run": None,
        "policy": {
            "network_tools_enabled": False,
            "public_target_scanning_enabled": False,
            "allowed_targets": sorted(LOCAL_ALLOWED_HOSTS),
            "requires_explicit_approval_for_active_scan": True,
        },
    }

    if validation["ok"]:
        plan["would_run"] = ["nmap", "-sV", "-Pn", "-p", ports, target]

    audit_event("lab_scan_plan", plan)
    return plan


@mcp.tool()
def openmythos_localhost_nmap_dryrun(target: str = "127.0.0.1", ports: str = "1-1024") -> Dict[str, Any]:
    """
    Alias for dry-run localhost scan planning. Does not execute nmap.
    """
    return openmythos_lab_scan_plan(target=target, ports=ports)


@mcp.tool()
def openmythos_localhost_nmap_active(
    target: str = "127.0.0.1",
    ports: str = "1-1024",
    approval: str = "",
) -> Dict[str, Any]:
    """
    Run a strictly localhost-only nmap scan.

    Requires approval='I_APPROVE_LOCAL_ONLY_SCAN'.
    Blocks all non-loopback targets.
    """
    validation = validate_local_target(target)

    if not validation["ok"]:
        result = {
            "ok": False,
            "blocked": True,
            "target_validation": validation,
            "reason": "active scan blocked by local-only target policy",
        }
        audit_event("localhost_nmap_active_blocked", result)
        return result

    if not require_explicit_approval(approval):
        result = {
            "ok": False,
            "blocked": True,
            "target_validation": validation,
            "reason": "missing explicit approval phrase",
            "required_approval": "I_APPROVE_LOCAL_ONLY_SCAN",
        }
        audit_event("localhost_nmap_active_missing_approval", result)
        return result

    cmd = ["nmap", "-sV", "-Pn", "-p", ports, target]
    result = run_cmd(cmd, timeout=120)
    audit_event("localhost_nmap_active", {
        "target": target,
        "ports": ports,
        "ok": result.get("ok"),
        "returncode": result.get("returncode"),
    })
    return result


if __name__ == "__main__":
    mcp.run()
