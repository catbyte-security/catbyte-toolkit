"""cb context - Context-window budget management."""
import argparse
import json
import sys

from cb.output import add_output_args, make_formatter, load_piped_input
from cb.config import load_config, save_config


def estimate_tokens(text):
    """Estimate token count from text (roughly 1 token per 4 chars)."""
    return len(text) // 4


def recommend_max_results(current_tokens, budget):
    """Recommend max_results to fit within budget."""
    if budget <= 0 or current_tokens <= 0:
        return 50
    ratio = budget / current_tokens
    if ratio >= 1.0:
        return 50
    return max(1, int(50 * ratio))


def register(subparsers):
    p = subparsers.add_parser("context", help="Context-window budget management")
    p.add_argument("--set-default", action="store_true",
                   help="Save budget as default in config (use with --budget)")
    p.add_argument("--estimate", action="store_true",
                   help="Estimate token count of piped input")
    add_output_args(p)
    p.set_defaults(func=run)


def run(args):
    out = make_formatter(args)
    cfg = load_config()

    if getattr(args, "estimate", False):
        piped = load_piped_input()
        if piped is None:
            text = sys.stdin.read() if not sys.stdin.isatty() else ""
        else:
            text = json.dumps(piped, default=str)
        tokens = estimate_tokens(text)
        current_budget = cfg.get("context_budget", 0)
        result = {
            "estimated_tokens": tokens,
            "current_budget": current_budget,
            "fits_budget": current_budget == 0 or tokens <= current_budget,
        }
        if current_budget > 0 and tokens > current_budget:
            result["recommended_max_results"] = recommend_max_results(
                tokens, current_budget)
        out.emit(result, "context")
        return

    budget = getattr(args, "budget", None)
    if budget is not None and getattr(args, "set_default", False):
        cfg["context_budget"] = budget
        save_config(cfg)
        out.emit({
            "action": "set_default",
            "context_budget": budget,
            "status": "saved",
        }, "context")
        return

    # Show current settings
    out.emit({
        "context_budget": cfg.get("context_budget", 0),
        "cache_enabled": cfg.get("cache_enabled", True),
        "cache_dir": cfg.get("cache_dir", ""),
    }, "context")


def main():
    parser = argparse.ArgumentParser(prog="cbcontext",
                                     description="Context budget management")
    parser.add_argument("--set-default", action="store_true")
    parser.add_argument("--estimate", action="store_true")
    add_output_args(parser)
    args = parser.parse_args()
    run(args)
