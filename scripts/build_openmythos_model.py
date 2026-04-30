#!/usr/bin/env python3
"""
Build a CPU-safe OpenMythos development checkpoint.

This creates:
  artifacts/openmythos_0ai_cpu_dev.pt

It does not pretend this is a trained chat model. It builds the architecture,
runs a forward-pass smoke test, and saves a PyTorch checkpoint.
"""

from __future__ import annotations

import importlib
import inspect
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict

import torch


ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
ARTIFACTS.mkdir(exist_ok=True)

DEVICE = os.environ.get("OPENMYTHOS_DEVICE", "cpu")
THREADS = int(os.environ.get("OPENMYTHOS_THREADS", "4"))

torch.set_num_threads(THREADS)


CANDIDATE_MODULES = [
    "open_mythos.main",
    "openmythos.main",
    "main",
]


SMALL_CONFIG: Dict[str, Any] = {
    "vocab_size": 512,
    "dim": 128,
    "hidden_dim": 256,
    "n_layers": 2,
    "num_layers": 2,
    "prelude_layers": 1,
    "coda_layers": 1,
    "n_heads": 4,
    "num_heads": 4,
    "n_kv_heads": 2,
    "max_seq_len": 64,
    "max_position_embeddings": 64,
    "max_loop_iters": 2,
    "n_experts": 4,
    "num_experts": 4,
    "n_shared_experts": 1,
    "n_experts_per_tok": 2,
    "expert_dim": 64,
    "lora_rank": 4,
    "attn_type": "gqa",
}


def load_symbols():
    last_error = None

    for modname in CANDIDATE_MODULES:
        try:
            mod = importlib.import_module(modname)
            if hasattr(mod, "OpenMythos") and hasattr(mod, "MythosConfig"):
                return modname, mod.OpenMythos, mod.MythosConfig
            last_error = f"{modname} imported but lacks OpenMythos/MythosConfig"
        except Exception as exc:
            last_error = f"{modname}: {exc!r}"

    raise RuntimeError(f"Could not locate OpenMythos symbols. Last error: {last_error}")


def make_config(MythosConfig):
    """
    Build a small config without assuming exact constructor names.
    """
    try:
        sig = inspect.signature(MythosConfig)
        params = sig.parameters

        accepts_kwargs = any(
            p.kind == inspect.Parameter.VAR_KEYWORD
            for p in params.values()
        )

        if accepts_kwargs:
            cfg = MythosConfig(**SMALL_CONFIG)
        else:
            filtered = {
                k: v for k, v in SMALL_CONFIG.items()
                if k in params
            }
            cfg = MythosConfig(**filtered)
    except Exception:
        cfg = MythosConfig()

    # Force small values where the config allows mutation.
    for key, value in SMALL_CONFIG.items():
        try:
            if hasattr(cfg, key):
                setattr(cfg, key, value)
        except Exception:
            pass

    return cfg


def config_to_dict(cfg) -> Dict[str, Any]:
    out = {}
    for name in dir(cfg):
        if name.startswith("_"):
            continue
        try:
            value = getattr(cfg, name)
        except Exception:
            continue
        if isinstance(value, (str, int, float, bool, type(None), list, tuple, dict)):
            out[name] = value
    return out


def main() -> int:
    started = time.time()

    modname, OpenMythos, MythosConfig = load_symbols()
    cfg = make_config(MythosConfig)

    model = OpenMythos(cfg).to(DEVICE).eval()
    params = sum(p.numel() for p in model.parameters())

    vocab_size = int(getattr(cfg, "vocab_size", 512))
    max_seq_len = int(getattr(cfg, "max_seq_len", 64))
    seq_len = min(16, max_seq_len)

    input_ids = torch.randint(0, vocab_size, (1, seq_len), device=DEVICE)

    forward_ok = False
    output_shape = None
    forward_error = None

    with torch.inference_mode():
        try:
            output = model(input_ids, n_loops=1)
            forward_ok = True
            output_shape = tuple(output.shape) if hasattr(output, "shape") else str(type(output))
        except TypeError:
            output = model(input_ids)
            forward_ok = True
            output_shape = tuple(output.shape) if hasattr(output, "shape") else str(type(output))
        except Exception as exc:
            forward_error = repr(exc)

    artifact_path = ARTIFACTS / "openmythos_0ai_cpu_dev.pt"

    checkpoint = {
        "model_name": "openmythos-0ai-cpu-dev",
        "module": modname,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "device": DEVICE,
        "threads": THREADS,
        "params": params,
        "config": config_to_dict(cfg),
        "state_dict": model.state_dict(),
        "forward_smoke_test": {
            "ok": forward_ok,
            "input_shape": tuple(input_ids.shape),
            "output_shape": output_shape,
            "error": forward_error,
        },
        "warning": "Random/untrained checkpoint unless this repo already loads trained weights.",
    }

    torch.save(checkpoint, artifact_path)

    summary = {
        "ok": True,
        "artifact": str(artifact_path),
        "module": modname,
        "params": params,
        "device": DEVICE,
        "threads": THREADS,
        "forward_smoke_test": checkpoint["forward_smoke_test"],
        "elapsed_seconds": round(time.time() - started, 3),
    }

    print(json.dumps(summary, indent=2))

    if not forward_ok:
        print("\nWARNING: checkpoint saved, but forward smoke test failed.", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
