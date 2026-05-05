"""cb crypto - identify cryptographic primitives in a binary.

Detects AES, SHA family, MD5, DES, ChaCha20, RC4, RSA, ECC, CRC and more by
their immutable byte fingerprints (S-boxes, round constants, curve parameters).
Flags weak/deprecated algorithms (MD5, DES, RC4, SHA-1) and rolled crypto
(modified S-boxes).

Examples:
  cb crypto /opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib
  cb crypto malware.bin --format text
  cb crypto firmware.bin --format markdown -o report.md
  cb crypto bin --no-heuristics    # constants only, fastest
"""
from __future__ import annotations

import argparse
import json
import mmap
import os
import sys

from cb.output import add_output_args, make_formatter


def register(subparsers):
    p = subparsers.add_parser(
        "crypto",
        help="Identify cryptographic primitives in a binary",
        description="Find AES, SHA, MD5, DES, ChaCha20, ECC, RSA, etc. via "
                    "byte fingerprints. Flags weak/broken crypto and rolled "
                    "S-boxes.",
    )
    p.add_argument("binary", help="Path to binary")
    p.add_argument("--no-heuristics", action="store_true",
                   help="Skip entropy/modified-S-box scans (constants only)")
    p.add_argument("--no-entropy", action="store_true",
                   help="Skip high-entropy region detection")
    p.add_argument("--no-sbox-scan", action="store_true",
                   help="Skip modified-S-box scan (slowest part)")
    p.add_argument("--sbox-step", type=int, default=64,
                   help="Stride for modified-S-box scan (lower = more thorough, "
                        "higher = faster). Default: 64")
    p.add_argument("--entropy-threshold", type=float, default=7.5,
                   help="Min entropy (bits/byte) to flag a region. Default: 7.5")
    p.add_argument("--max-hits-per-pattern", type=int, default=32,
                   help="Cap matches per fingerprint. Default: 32")
    p.add_argument("--algorithms", type=str, default=None,
                   help="Comma-separated list to restrict scan (aes,sha256,md5,...)")
    p.add_argument("--render", choices=["json", "text", "markdown"],
                   default=None,
                   help="Override --format with a specific renderer "
                        "(text=colored TUI, markdown=audit doc)")
    add_output_args(p)
    p.set_defaults(func=run)


def run(args):
    out = make_formatter(args)
    path = args.binary

    out.status(f"Loading fingerprints…")

    from cb.crypto.constants import CRYPTO_FINGERPRINTS
    from cb.crypto.scanner import scan_binary
    from cb.crypto.heuristics import analyze
    from cb.crypto.report import to_dict, render_text, render_markdown

    # Filter fingerprints if requested
    fps = CRYPTO_FINGERPRINTS
    if args.algorithms:
        wanted = {a.strip().lower() for a in args.algorithms.split(",") if a.strip()}
        fps = [f for f in CRYPTO_FINGERPRINTS if f.algorithm in wanted]
        if not fps:
            print(f"[!] no fingerprints match --algorithms {args.algorithms}",
                  file=sys.stderr)
            sys.exit(1)

    # Cache check
    cache_args = {
        "no_heuristics": args.no_heuristics,
        "no_entropy": args.no_entropy,
        "no_sbox_scan": args.no_sbox_scan,
        "sbox_step": args.sbox_step,
        "entropy_threshold": args.entropy_threshold,
        "max_hits_per_pattern": args.max_hits_per_pattern,
        "algorithms": args.algorithms or "",
    }
    if not getattr(args, "no_cache", False):
        try:
            from cb.result_cache import ResultCache
            cache = ResultCache()
            cached = cache.get(path, "crypto", cache_args)
            if cached:
                cached.setdefault("_meta", {})["cached"] = True
                _emit_or_render(args, out, cached)
                return
        except Exception:
            pass

    out.status(f"Scanning {os.path.getsize(path):,} bytes for {len(fps)} fingerprints…")
    result = scan_binary(path, fingerprints=fps,
                         max_hits_per_pattern=args.max_hits_per_pattern)

    # Heuristics
    run_sbox = not args.no_heuristics and not args.no_sbox_scan
    run_entropy = not args.no_heuristics and not args.no_entropy

    if run_sbox or run_entropy:
        out.status("Running heuristics (entropy / modified S-box / clusters)…")
        with open(path, "rb") as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                a = analyze(result, mm,
                             entropy_threshold=args.entropy_threshold,
                             modified_sbox_step=args.sbox_step,
                             run_modified_sbox=run_sbox,
                             run_entropy=run_entropy)
    else:
        a = analyze(result, None, run_modified_sbox=False, run_entropy=False)

    data = to_dict(result, a["hits"], a["clusters"],
                   a["modified_sboxes"], a["high_entropy"])

    # Cache store
    if not getattr(args, "no_cache", False):
        try:
            from cb.result_cache import ResultCache
            cache = ResultCache()
            cache.put(path, "crypto", cache_args, data)
        except Exception:
            pass

    _emit_or_render(args, out, data)


def _emit_or_render(args, out, data: dict) -> None:
    """Honor --render text|markdown|json (overrides --format)."""
    render = getattr(args, "render", None)
    if render == "text":
        # Bypass JSON emission, write the colored TUI
        text = _build_text_report(data)
        # don't shadow user --output
        sys.stdout.write(text + "\n")
        return
    if render == "markdown":
        from cb.crypto.report import render_markdown
        sys.stdout.write(render_markdown(data) + "\n")
        return
    out.emit(data, "crypto")


def _build_text_report(data: dict) -> str:
    from cb.crypto.report import render_text
    return render_text(data)


def main():
    parser = argparse.ArgumentParser(
        prog="cbcrypto",
        description="Identify cryptographic primitives in a binary",
    )
    parser.add_argument("binary", help="Path to binary")
    parser.add_argument("--no-heuristics", action="store_true")
    parser.add_argument("--no-entropy", action="store_true")
    parser.add_argument("--no-sbox-scan", action="store_true")
    parser.add_argument("--sbox-step", type=int, default=64)
    parser.add_argument("--entropy-threshold", type=float, default=7.5)
    parser.add_argument("--max-hits-per-pattern", type=int, default=32)
    parser.add_argument("--algorithms", type=str, default=None)
    parser.add_argument("--render", choices=["json", "text", "markdown"],
                        default=None)
    add_output_args(parser)
    args = parser.parse_args()
    run(args)
