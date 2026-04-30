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
from html.parser import HTMLParser
from urllib.parse import urlparse, urljoin
import urllib.request
import urllib.error

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



def _http_probe(url: str, method: str = "HEAD", max_bytes: int = 4096) -> Dict[str, Any]:
    """
    Perform a minimal HTTP request against a validated local-only URL.
    """
    validation = validate_local_url(url)
    if not validation["ok"]:
        result = {
            "ok": False,
            "blocked": True,
            "url_validation": validation,
            "reason": "blocked by local-only URL policy",
        }
        audit_event("http_probe_blocked", result)
        return result

    method = method.upper()
    if method not in {"HEAD", "GET"}:
        result = {
            "ok": False,
            "blocked": True,
            "url_validation": validation,
            "reason": "blocked: only HEAD and GET are supported",
        }
        audit_event("http_probe_bad_method", result)
        return result

    req = urllib.request.Request(
        url,
        method=method,
        headers={
            "User-Agent": "OpenMythos-LocalLab/0.1",
            "Accept": "text/html,application/json,text/plain,*/*",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = b""
            if method == "GET":
                body = resp.read(max(0, min(int(max_bytes), 16384)))

            result = {
                "ok": True,
                "url": url,
                "method": method,
                "status": getattr(resp, "status", None),
                "reason": getattr(resp, "reason", None),
                "headers": dict(resp.headers.items()),
                "body_preview": body.decode("utf-8", errors="replace") if body else "",
                "body_preview_bytes": len(body),
                "url_validation": validation,
            }
            audit_event("http_probe", {
                "ok": True,
                "url": url,
                "method": method,
                "status": result["status"],
                "body_preview_bytes": result["body_preview_bytes"],
            })
            return result

    except urllib.error.HTTPError as exc:
        body = exc.read(max(0, min(int(max_bytes), 16384))) if method == "GET" else b""
        result = {
            "ok": False,
            "url": url,
            "method": method,
            "status": exc.code,
            "reason": str(exc.reason),
            "headers": dict(exc.headers.items()) if exc.headers else {},
            "body_preview": body.decode("utf-8", errors="replace") if body else "",
            "body_preview_bytes": len(body),
            "url_validation": validation,
        }
        audit_event("http_probe_http_error", {
            "ok": False,
            "url": url,
            "method": method,
            "status": exc.code,
        })
        return result

    except Exception as exc:
        result = {
            "ok": False,
            "url": url,
            "method": method,
            "error": repr(exc),
            "url_validation": validation,
        }
        audit_event("http_probe_error", {
            "ok": False,
            "url": url,
            "method": method,
            "error": repr(exc),
        })
        return result


@mcp.tool()
def openmythos_http_head(url: str) -> Dict[str, Any]:
    """
    Send a HEAD request to an allowed localhost-only URL.
    """
    return _http_probe(url=url, method="HEAD", max_bytes=0)


@mcp.tool()
def openmythos_http_get_preview(
    url: str,
    approval: str = "",
    max_bytes: int = 4096,
) -> Dict[str, Any]:
    """
    Send a GET request to an allowed localhost-only URL and return a bounded preview.

    Requires approval='I_APPROVE_LOCAL_ONLY_HTTP_GET'.
    """
    if approval != "I_APPROVE_LOCAL_ONLY_HTTP_GET":
        validation = validate_local_url(url)
        result = {
            "ok": False,
            "blocked": True,
            "url_validation": validation,
            "reason": "missing explicit approval phrase",
            "required_approval": "I_APPROVE_LOCAL_ONLY_HTTP_GET",
        }
        audit_event("http_get_missing_approval", result)
        return result

    return _http_probe(url=url, method="GET", max_bytes=max_bytes)



@mcp.tool()
def openmythos_http_fingerprint(
    url: str = "http://127.0.0.1:3000",
    approval: str = "",
) -> Dict[str, Any]:
    """
    Passive fingerprint of an allowed localhost-only HTTP app.

    This performs:
    - HEAD request
    - approved bounded GET preview
    - simple header/title/meta keyword extraction

    It does not fuzz, exploit, brute force, submit forms, or mutate state.
    """
    validation = validate_local_url(url)
    if not validation["ok"]:
        result = {
            "ok": False,
            "blocked": True,
            "url_validation": validation,
            "reason": "blocked by local-only URL policy",
        }
        audit_event("http_fingerprint_blocked", result)
        return result

    if approval != "I_APPROVE_LOCAL_ONLY_HTTP_GET":
        result = {
            "ok": False,
            "blocked": True,
            "url_validation": validation,
            "reason": "missing explicit approval phrase",
            "required_approval": "I_APPROVE_LOCAL_ONLY_HTTP_GET",
        }
        audit_event("http_fingerprint_missing_approval", result)
        return result

    head = _http_probe(url=url, method="HEAD", max_bytes=0)
    get = _http_probe(url=url, method="GET", max_bytes=4096)

    body = get.get("body_preview", "") or ""
    lower = body.lower()

    title = None
    if "<title>" in lower and "</title>" in lower:
        start = lower.find("<title>")
        end = lower.find("</title>", start)
        if start >= 0 and end > start:
            title = body[start + len("<title>"):end].strip()[:200]

    indicators = []
    checks = {
        "owasp_juice_shop": ["owasp juice shop", "probably the most modern and sophisticated insecure web application"],
        "angular": ["ng-version", "ng-app", "data-beasties-container"],
        "express": ["x-powered-by: express"],
        "security_headers_present": ["x-frame-options", "x-content-type-options"],
        "cors_wildcard": ["access-control-allow-origin: *"],
    }

    header_text = "\\n".join(f"{k}: {v}" for k, v in (head.get("headers") or {}).items()).lower()
    combined = header_text + "\\n" + lower

    for name, needles in checks.items():
        if any(n in combined for n in needles):
            indicators.append(name)

    result = {
        "ok": bool(head.get("ok") or get.get("ok")),
        "url": url,
        "url_validation": validation,
        "head_status": head.get("status"),
        "get_status": get.get("status"),
        "title": title,
        "headers": head.get("headers", {}),
        "indicators": indicators,
        "body_preview_bytes": get.get("body_preview_bytes", 0),
        "notes": [
            "passive fingerprint only",
            "localhost-only URL policy enforced",
            "no fuzzing, exploitation, authentication, or form submission performed",
        ],
    }

    audit_event("http_fingerprint", {
        "ok": result["ok"],
        "url": url,
        "title": title,
        "indicators": indicators,
        "body_preview_bytes": result["body_preview_bytes"],
    })

    return result


class _OpenMythosRouteParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.refs = []

    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if key and value and key.lower() in {"href", "src", "action"}:
                self.refs.append({
                    "tag": tag.lower(),
                    "attr": key.lower(),
                    "raw": str(value).strip(),
                })


@mcp.tool()
def openmythos_http_route_discovery(
    url: str = "http://127.0.0.1:3000",
    approval: str = "",
    max_bytes: int = 32768,
    max_routes: int = 200,
) -> Dict[str, Any]:
    # Passive single-page route discovery.
    # No crawling, fuzzing, form submission, auth, JS execution, or mutation.
    validation = validate_local_url(url)
    if not validation["ok"]:
        result = {
            "ok": False,
            "blocked": True,
            "url_validation": validation,
            "reason": "blocked by local-only URL policy",
        }
        audit_event("http_route_discovery_blocked", result)
        return result

    if approval != "I_APPROVE_LOCAL_ONLY_HTTP_GET":
        result = {
            "ok": False,
            "blocked": True,
            "url_validation": validation,
            "reason": "missing explicit approval phrase",
            "required_approval": "I_APPROVE_LOCAL_ONLY_HTTP_GET",
        }
        audit_event("http_route_discovery_missing_approval", result)
        return result

    max_bytes = max(1024, min(int(max_bytes), 131072))
    max_routes = max(1, min(int(max_routes), 1000))

    get = _http_probe(url=url, method="GET", max_bytes=max_bytes)
    if not get.get("ok"):
        result = {
            "ok": False,
            "url": url,
            "url_validation": validation,
            "fetch": get,
            "reason": "GET probe failed",
        }
        audit_event("http_route_discovery_fetch_failed", {
            "ok": False,
            "url": url,
            "status": get.get("status"),
            "error": get.get("error"),
        })
        return result

    body = get.get("body_preview", "") or ""

    parser = _OpenMythosRouteParser()
    parser.feed(body)
    refs = parser.refs

    base = urlparse(url)
    base_origin = (
        f"{base.scheme}://{base.hostname}:{base.port}"
        if base.port
        else f"{base.scheme}://{base.hostname}"
    )

    same_origin = []
    blocked_refs = []
    seen = set()

    for ref in refs:
        raw = ref["raw"]

        if not raw or raw.startswith(("javascript:", "mailto:", "tel:", "data:")):
            blocked_refs.append({
                "tag": ref.get("tag"),
                "attr": ref["attr"],
                "raw": raw,
                "reason": "non-http navigational reference ignored",
            })
            continue

        absolute = urljoin(url, raw)
        ref_validation = validate_local_url(absolute)

        parsed = urlparse(absolute)
        origin = (
            f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"
            if parsed.port
            else f"{parsed.scheme}://{parsed.hostname}"
        )

        if not ref_validation["ok"]:
            blocked_refs.append({
                "tag": ref.get("tag"),
                "attr": ref["attr"],
                "raw": raw,
                "absolute": absolute,
                "reason": "blocked by local-only URL policy",
            })
            continue

        if origin != base_origin:
            blocked_refs.append({
                "tag": ref.get("tag"),
                "attr": ref["attr"],
                "raw": raw,
                "absolute": absolute,
                "reason": "blocked: allowed-local but different origin",
            })
            continue

        normalized = {
            "tag": ref.get("tag"),
            "attr": ref["attr"],
            "raw": raw,
            "url": absolute,
            "path": parsed.path or "/",
            "query": parsed.query,
        }

        key = (normalized["url"], normalized["attr"])
        if key in seen:
            continue

        seen.add(key)
        same_origin.append(normalized)

        if len(same_origin) >= max_routes:
            break

    result = {
        "ok": True,
        "mode": "passive_single_page",
        "url": url,
        "url_validation": validation,
        "status": get.get("status"),
        "body_preview_bytes": get.get("body_preview_bytes"),
        "same_origin_route_count": len(same_origin),
        "blocked_reference_count": len(blocked_refs),
        "same_origin_routes": same_origin,
        "blocked_references": blocked_refs[:100],
        "notes": [
            "single-page parse only",
            "no crawling",
            "no fuzzing",
            "no form submission",
            "no JavaScript execution",
            "localhost-only URL policy enforced",
        ],
    }

    audit_event("http_route_discovery", {
        "ok": True,
        "url": url,
        "same_origin_route_count": len(same_origin),
        "blocked_reference_count": len(blocked_refs),
        "body_preview_bytes": get.get("body_preview_bytes"),
    })

    return result


if __name__ == "__main__":
    mcp.run()
