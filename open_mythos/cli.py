from __future__ import annotations

import argparse
import inspect
import sys
from typing import Any

import torch

import open_mythos
import open_mythos.main as om


def _model_classes() -> list[tuple[str, type]]:
    classes: list[tuple[str, type]] = []
    for name in dir(om):
        obj = getattr(om, name)
        if inspect.isclass(obj) and "OpenMythos" in name:
            classes.append((name, obj))
    return classes


def _select_model_class(name: str | None = None) -> tuple[str, type]:
    classes = _model_classes()
    if not classes:
        raise RuntimeError("No OpenMythos model class found in open_mythos.main")

    if name:
        for cls_name, cls in classes:
            if cls_name == name:
                return cls_name, cls
        available = ", ".join(cls_name for cls_name, _ in classes)
        raise RuntimeError(f"Unknown model class {name!r}. Available: {available}")

    preferred = ["OpenMythos", "OpenMythosMLA", "OpenMythosGQA"]
    for preferred_name in preferred:
        for cls_name, cls in classes:
            if cls_name == preferred_name:
                return cls_name, cls

    return classes[0]


def _safe_device(requested: str) -> torch.device:
    if requested.startswith("cuda") and not torch.cuda.is_available():
        print("[!] CUDA requested but no CUDA GPU/runtime is available; falling back to CPU")
        return torch.device("cpu")
    return torch.device(requested)


def _filtered_kwargs(callable_obj: Any, candidates: dict[str, Any]) -> dict[str, Any]:
    sig = inspect.signature(callable_obj)
    return {
        key: value
        for key, value in candidates.items()
        if key in sig.parameters
    }


def _build_config(args: argparse.Namespace) -> Any:
    if not hasattr(om, "MythosConfig"):
        raise RuntimeError("OpenMythos requires cfg, but MythosConfig was not found")

    cfg_cls = om.MythosConfig

    candidates: dict[str, Any] = {
        "vocab_size": args.vocab_size,
        "dim": args.dim,
        "d_model": args.dim,
        "hidden_dim": args.hidden_dim,
        "intermediate_size": args.hidden_dim,
        "n_layers": args.layers,
        "num_layers": args.layers,
        "n_heads": args.heads,
        "num_heads": args.heads,
        "n_kv_heads": args.kv_heads,
        "num_kv_heads": args.kv_heads,
        "max_seq_len": args.max_seq_len,
        "max_position_embeddings": args.max_seq_len,
        "dropout": 0.0,
        "attn_type": args.attn_type,
    }

    kwargs = _filtered_kwargs(cfg_cls, candidates)

    print(f"[+] config class: MythosConfig{inspect.signature(cfg_cls)}")
    print(f"[+] config kwargs: {kwargs}")

    return cfg_cls(**kwargs)


def _build_model(cls: type, args: argparse.Namespace) -> Any:
    sig = inspect.signature(cls)

    if "cfg" in sig.parameters:
        cfg = _build_config(args)
        return cls(cfg)

    if "config" in sig.parameters:
        cfg = _build_config(args)
        return cls(config=cfg)

    candidates: dict[str, Any] = {
        "vocab_size": args.vocab_size,
        "dim": args.dim,
        "d_model": args.dim,
        "hidden_dim": args.hidden_dim,
        "intermediate_size": args.hidden_dim,
        "n_layers": args.layers,
        "num_layers": args.layers,
        "n_heads": args.heads,
        "num_heads": args.heads,
        "n_kv_heads": args.kv_heads,
        "num_kv_heads": args.kv_heads,
        "max_seq_len": args.max_seq_len,
        "max_position_embeddings": args.max_seq_len,
        "dropout": 0.0,
        "attn_type": args.attn_type,
    }

    kwargs = _filtered_kwargs(cls, candidates)
    print(f"[+] model kwargs: {kwargs}")
    return cls(**kwargs)


def cmd_info(args: argparse.Namespace) -> int:
    print("[+] open_mythos package loaded")
    print(f"[+] package path: {getattr(open_mythos, '__file__', 'unknown')}")
    print(f"[+] main module: {om.__file__}")
    print(f"[+] torch: {torch.__version__}")
    print(f"[+] cuda available: {torch.cuda.is_available()}")

    if hasattr(om, "MythosConfig"):
        print(f"[+] config: MythosConfig{inspect.signature(om.MythosConfig)}")

    classes = _model_classes()
    if not classes:
        print("[!] No OpenMythos model classes discovered")
        return 1

    print("[+] model classes:")
    for name, cls in classes:
        print(f"    {name}{inspect.signature(cls)}")

    return 0


def cmd_smoke(args: argparse.Namespace) -> int:
    device = _safe_device(args.device)

    cls_name, cls = _select_model_class(args.model_class)

    print(f"[+] selected model class: {cls_name}")
    print(f"[+] constructor: {cls_name}{inspect.signature(cls)}")
    print(f"[+] device: {device}")

    model = _build_model(cls, args).to(device)
    model.eval()

    x = torch.randint(
        low=0,
        high=args.vocab_size,
        size=(args.batch_size, args.seq_len),
        dtype=torch.long,
        device=device,
    )

    print(f"[+] input shape: {tuple(x.shape)}")

    with torch.no_grad():
        out = model(x)

    if isinstance(out, dict):
        primary = out.get("logits")
        if primary is None and out:
            primary = next(iter(out.values()))
    elif isinstance(out, (tuple, list)):
        primary = out[0]
    else:
        primary = out

    print(f"[+] forward output type: {type(out).__name__}")
    if hasattr(primary, "shape"):
        print(f"[+] forward output shape: {tuple(primary.shape)}")

    if hasattr(model, "generate"):
        seed = x[:, : min(4, args.seq_len)]
        with torch.no_grad():
            try:
                generated = model.generate(seed, max_new_tokens=args.max_new_tokens)
            except TypeError:
                generated = model.generate(seed, args.max_new_tokens)

        print(f"[+] generate output shape: {tuple(generated.shape)}")
        print(f"[+] generated token ids[0]: {generated[0].detach().cpu().tolist()}")
    else:
        print("[!] model has no generate() method; forward smoke test passed")

    print("[+] OpenMythos smoke test completed")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openmythos",
        description="OpenMythos local model runner",
    )

    sub = parser.add_subparsers(dest="command")

    p_info = sub.add_parser("info", help="Show package, torch, and model metadata")
    p_info.set_defaults(func=cmd_info)

    p_smoke = sub.add_parser("smoke", help="Run a small local forward/generate smoke test")
    p_smoke.add_argument("--model-class", default=None, help="Specific model class name")
    p_smoke.add_argument("--device", default="cpu", help="cpu, cuda, cuda:0, etc.")
    p_smoke.add_argument("--vocab-size", type=int, default=512)
    p_smoke.add_argument("--dim", type=int, default=128)
    p_smoke.add_argument("--hidden-dim", type=int, default=256)
    p_smoke.add_argument("--layers", type=int, default=2)
    p_smoke.add_argument("--heads", type=int, default=4)
    p_smoke.add_argument("--kv-heads", type=int, default=2)
    p_smoke.add_argument("--max-seq-len", type=int, default=128)
    p_smoke.add_argument("--seq-len", type=int, default=16)
    p_smoke.add_argument("--batch-size", type=int, default=1)
    p_smoke.add_argument("--max-new-tokens", type=int, default=8)
    p_smoke.add_argument("--attn-type", default="mla", choices=["mla", "gqa"])
    p_smoke.set_defaults(func=cmd_smoke)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        args = parser.parse_args(["info"])

    try:
        return args.func(args)
    except Exception as exc:
        print(f"[!] openmythos failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
