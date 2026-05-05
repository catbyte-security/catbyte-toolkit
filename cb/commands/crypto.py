"""cb crypto - identify cryptographic primitives in a binary.

Detects AES, SHA family, MD5, DES, ChaCha20, RC4, RSA, ECC, CRC and more by
their immutable byte fingerprints (S-boxes, round constants, curve parameters).
Resolves cross-references to attribute primitives to functions. Detects
hardcoded keys / static IVs from data references inside crypto-touching
functions. Flags weak/deprecated algorithms and rolled crypto.

Examples:
  cb crypto /opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib
  cb crypto malware.bin --render text
  cb crypto firmware.bin --render markdown -o report.md
  cb crypto bin --no-xrefs                 # constants only, fastest
  cb crypto diff old.bin new.bin           # diff two binaries' crypto
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
                    "byte fingerprints. Resolves xrefs, finds hardcoded keys, "
                    "flags weak crypto and rolled S-boxes. "
                    "Use 'cb crypto diff OLD NEW' to compare two binaries.",
    )

    p.add_argument("binary", help="Path to binary")
    p.add_argument("--diff", type=str, default=None, metavar="OTHER_BINARY",
                   help="Compare this binary's crypto profile against OTHER_BINARY")
    p.add_argument("--no-heuristics", action="store_true",
                   help="Skip entropy/modified-S-box scans (constants only)")
    p.add_argument("--no-entropy", action="store_true",
                   help="Skip high-entropy region detection")
    p.add_argument("--no-sbox-scan", action="store_true",
                   help="Skip modified-S-box scan (slowest part)")
    p.add_argument("--no-xrefs", action="store_true",
                   help="Skip cross-reference resolution (function attribution)")
    p.add_argument("--no-secrets", action="store_true",
                   help="Skip hardcoded key/IV detection")
    p.add_argument("--no-xray", action="store_true",
                   help="Skip ASCII x-ray visualization in text mode")
    p.add_argument("--sbox-step", type=int, default=64,
                   help="Stride for modified-S-box scan. Default: 64")
    p.add_argument("--entropy-threshold", type=float, default=7.5,
                   help="Min entropy (bits/byte) to flag a region. Default: 7.5")
    p.add_argument("--secret-entropy", type=float, default=4.5,
                   help="Min entropy for hardcoded-key candidates. Default: 4.5")
    p.add_argument("--max-hits-per-pattern", type=int, default=32,
                   help="Cap matches per fingerprint. Default: 32")
    p.add_argument("--max-xrefs", type=int, default=4096,
                   help="Cap total cross-references. Default: 4096")
    p.add_argument("--xray-width", type=int, default=96,
                   help="X-ray visualization width in columns. Default: 96")
    p.add_argument("--algorithms", type=str, default=None,
                   help="Comma-separated list to restrict scan (aes,sha256,md5,...)")
    p.add_argument("--render", choices=["json", "text", "markdown"],
                   default=None,
                   help="Override --format with a specific renderer")
    add_output_args(p)
    p.set_defaults(func=_dispatch)


def _dispatch(args):
    """Route to single-binary scan or diff mode based on --diff flag."""
    if getattr(args, "diff", None):
        args.binary_old = args.binary
        args.binary_new = args.diff
        return run_diff(args)
    return run(args)


def _scan(path: str, args, out) -> dict:
    """Run the full scan + analysis pipeline on a single binary."""
    from cb.crypto.constants import CRYPTO_FINGERPRINTS
    from cb.crypto.scanner import scan_binary
    from cb.crypto.heuristics import analyze
    from cb.crypto.report import to_dict

    fps = CRYPTO_FINGERPRINTS
    if getattr(args, "algorithms", None):
        wanted = {a.strip().lower() for a in args.algorithms.split(",") if a.strip()}
        fps = [f for f in CRYPTO_FINGERPRINTS if f.algorithm in wanted]

    out.status(f"Scanning {os.path.getsize(path):,} bytes for {len(fps)} fingerprints…")
    result = scan_binary(path, fingerprints=fps,
                         max_hits_per_pattern=args.max_hits_per_pattern)

    run_sbox = not args.no_heuristics and not args.no_sbox_scan
    run_entropy = not args.no_heuristics and not args.no_entropy

    a = {"hits": result.hits, "clusters": [],
         "modified_sboxes": [], "high_entropy": []}
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

    # Cross-reference resolution — uses refined hits
    xrefs_by_hit = {}
    if not args.no_xrefs:
        out.status("Resolving function-level cross-references…")
        from cb.crypto.xref import resolve_xrefs
        # We need to map refined hits to original hits for VA-based xref lookup
        # The refined hits are a subset, so we pass through `result` with the
        # refined list as a temporary view.
        refined_result = type(result)(
            binary_path=result.binary_path,
            file_size=result.file_size,
            hits=a["hits"],
            sections=result.sections,
            format=result.format,
            architecture=result.architecture,
            scanned_bytes=result.scanned_bytes,
            scan_seconds=result.scan_seconds,
        )
        try:
            xrefs_by_hit = resolve_xrefs(path, refined_result,
                                          max_xrefs=args.max_xrefs)
        except Exception as e:
            out.debug(f"xref resolution failed: {e}", e)

    # Hardcoded key/IV detection — uses xref data
    secrets = []
    if not args.no_secrets and xrefs_by_hit:
        out.status("Hunting hardcoded keys / static IVs…")
        from cb.crypto.secrets import find_secret_candidates
        try:
            refined_result = type(result)(
                binary_path=result.binary_path,
                file_size=result.file_size,
                hits=a["hits"],
                sections=result.sections,
                format=result.format,
                architecture=result.architecture,
                scanned_bytes=result.scanned_bytes,
                scan_seconds=result.scan_seconds,
            )
            secrets = find_secret_candidates(path, refined_result, xrefs_by_hit,
                                              entropy_threshold=args.secret_entropy)
        except Exception as e:
            out.debug(f"secret detection failed: {e}", e)

    data = to_dict(result, a["hits"], a["clusters"],
                   a["modified_sboxes"], a["high_entropy"],
                   xrefs_by_hit=xrefs_by_hit,
                   secrets=secrets)

    # X-ray visualization (computed on demand for text rendering)
    if not getattr(args, "no_xray", False):
        try:
            from cb.crypto.xray import render_xray
            xray_color = (getattr(args, "render", None) == "text") and sys.stdout.isatty()
            data["_xray"] = render_xray(path, result,
                                          width=getattr(args, "xray_width", 96),
                                          color=xray_color)
        except Exception as e:
            out.debug(f"x-ray rendering failed: {e}", e)

    return data


def run(args):
    out = make_formatter(args)
    path = args.binary
    if not path:
        print("[!] cb crypto requires a binary path (or 'diff' subcommand)",
              file=sys.stderr)
        sys.exit(2)

    cache_args = {
        "no_heuristics": args.no_heuristics,
        "no_entropy": args.no_entropy,
        "no_sbox_scan": args.no_sbox_scan,
        "no_xrefs": args.no_xrefs,
        "no_secrets": args.no_secrets,
        "no_xray": args.no_xray,
        "sbox_step": args.sbox_step,
        "entropy_threshold": args.entropy_threshold,
        "secret_entropy": args.secret_entropy,
        "max_hits_per_pattern": args.max_hits_per_pattern,
        "max_xrefs": args.max_xrefs,
        "algorithms": args.algorithms or "",
        "xray_width": args.xray_width,
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

    data = _scan(path, args, out)

    if not getattr(args, "no_cache", False):
        try:
            from cb.result_cache import ResultCache
            cache = ResultCache()
            cache.put(path, "crypto", cache_args, data)
        except Exception:
            pass

    _emit_or_render(args, out, data)


def run_diff(args):
    """`cb crypto OLD --diff NEW` — diff crypto profiles."""
    out = make_formatter(args)
    from cb.crypto.diff import diff_reports, render_diff_text
    from cb.validation import validate_binary_path
    err = validate_binary_path(args.binary_new)
    if err:
        print(f"[!] --diff: {err}", file=sys.stderr)
        sys.exit(1)

    # Build minimal scan args struct for both binaries
    class _ScanArgs:
        no_heuristics = True
        no_entropy = True
        no_sbox_scan = True
        no_xrefs = True
        no_secrets = True
        no_xray = True
        sbox_step = 64
        entropy_threshold = 7.5
        secret_entropy = 4.5
        max_hits_per_pattern = 32
        max_xrefs = 1
        algorithms = None
        xray_width = 96
        verbose = False

    scan_args = _ScanArgs()

    out.status(f"Scanning old: {args.binary_old}…")
    old_data = _scan(args.binary_old, scan_args, out)
    out.status(f"Scanning new: {args.binary_new}…")
    new_data = _scan(args.binary_new, scan_args, out)

    diff = diff_reports(old_data, new_data)

    render = getattr(args, "render", None) or "text"
    if render == "text":
        sys.stdout.write(render_diff_text(diff, args.binary_old, args.binary_new,
                                            color=sys.stdout.isatty()) + "\n")
        return

    # JSON
    out.emit({
        "old": args.binary_old,
        "new": args.binary_new,
        "diff": diff.to_dict(),
    }, "crypto-diff")


def _emit_or_render(args, out, data: dict) -> None:
    render = getattr(args, "render", None)
    if render == "text":
        from cb.crypto.report import render_text
        sys.stdout.write(render_text(data) + "\n")
        return
    if render == "markdown":
        from cb.crypto.report import render_markdown
        sys.stdout.write(render_markdown(data) + "\n")
        return
    out.emit(data, "crypto")


def main():
    parser = argparse.ArgumentParser(
        prog="cbcrypto",
        description="Identify cryptographic primitives in a binary",
    )
    parser.add_argument("binary", help="Path to binary")
    parser.add_argument("--no-heuristics", action="store_true")
    parser.add_argument("--no-entropy", action="store_true")
    parser.add_argument("--no-sbox-scan", action="store_true")
    parser.add_argument("--no-xrefs", action="store_true")
    parser.add_argument("--no-secrets", action="store_true")
    parser.add_argument("--no-xray", action="store_true")
    parser.add_argument("--sbox-step", type=int, default=64)
    parser.add_argument("--entropy-threshold", type=float, default=7.5)
    parser.add_argument("--secret-entropy", type=float, default=4.5)
    parser.add_argument("--max-hits-per-pattern", type=int, default=32)
    parser.add_argument("--max-xrefs", type=int, default=4096)
    parser.add_argument("--xray-width", type=int, default=96)
    parser.add_argument("--algorithms", type=str, default=None)
    parser.add_argument("--render", choices=["json", "text", "markdown"], default=None)
    add_output_args(parser)
    args = parser.parse_args()
    run(args)
