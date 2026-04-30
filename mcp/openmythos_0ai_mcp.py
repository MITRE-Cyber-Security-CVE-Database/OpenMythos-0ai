import os
import sys
import json
import time
import pathlib
import subprocess
from typing import Dict, Any, List

from fastmcp import FastMCP

mcp = FastMCP("openmythos-0ai-kali")

REPO = pathlib.Path(os.environ.get("OPENMYTHOS_REPO", str(pathlib.Path.home() / "OpenMythos-0ai"))).resolve()
PYTHON = os.environ.get("OPENMYTHOS_PYTHON", sys.executable)
TIMEOUT = int(os.environ.get("OPENMYTHOS_TIMEOUT", "90"))


def run_cmd(args: List[str], timeout: int = TIMEOUT) -> Dict[str, Any]:
    """
    Safe command runner: no shell=True.
    """
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
            "stdout": proc.stdout[-12000:],
            "stderr": proc.stderr[-12000:],
            "cwd": str(REPO),
            "cmd": args,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "ok": False,
            "error": "timeout",
            "timeout_seconds": timeout,
            "stdout": (exc.stdout or "")[-12000:] if isinstance(exc.stdout, str) else "",
            "stderr": (exc.stderr or "")[-12000:] if isinstance(exc.stderr, str) else "",
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


if __name__ == "__main__":
    mcp.run()
