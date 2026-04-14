"""cb cache - Dyld Shared Cache handler for macOS binary analysis."""
import argparse
import glob
import os
import re
import subprocess
import sys

from cb.output import add_output_args, make_formatter
from cb.macho import extract_from_shared_cache, list_shared_cache_images
from cb.config import load_config

EXPLOIT_TARGETS = {
    "WindowServer": "WindowServer",
    "SkyLight": "SkyLight",
    "libsystem_malloc": "libsystem_malloc.dylib",
    "ImageIO": "ImageIO",
    "libRadiance": "libRadiance",
}

TARGET_SETS = {"exploit": EXPLOIT_TARGETS}

_CACHE_DIRS = [
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld",
    "/System/Library/dyld",
]
DEFAULT_EXTRACT_DIR = os.path.expanduser("~/.cb/dsc_extract")


def find_shared_cache(arch="arm64e"):
    """Auto-detect dyld shared cache path for the given architecture."""
    for cache_dir in _CACHE_DIRS:
        if not os.path.isdir(cache_dir):
            continue
        pattern = os.path.join(cache_dir, f"dyld_shared_cache_{arch}*")
        hits = sorted(glob.glob(pattern))
        if hits:
            for h in hits:
                if os.path.basename(h) == f"dyld_shared_cache_{arch}":
                    return h
            return hits[0]
    return None


def extract_library(cache_path, library, output_dir=None, tool="auto"):
    """Extract a single library, caching results in ~/.cb/dsc_extract/."""
    if output_dir is None:
        output_dir = DEFAULT_EXTRACT_DIR
    os.makedirs(output_dir, exist_ok=True)

    existing = glob.glob(os.path.join(output_dir, "**", f"*{library}*"),
                         recursive=True)
    if existing:
        return {"library": library, "path": existing[0], "cached": True}

    extracted = extract_from_shared_cache(cache_path, library,
                                          output_dir=output_dir)
    if extracted is None:
        return {"library": library, "path": None, "cached": False,
                "error": f"Failed to extract '{library}' from cache"}
    return {"library": library, "path": extracted, "cached": False}


def extract_targets(cache_path, target_set, output_dir=None):
    """Extract all libraries in a predefined target set."""
    if target_set not in TARGET_SETS:
        return {"error": f"Unknown target set '{target_set}'. "
                         f"Available: {', '.join(sorted(TARGET_SETS))}"}

    targets = TARGET_SETS[target_set]
    results, extracted, failed, cached = [], 0, 0, 0

    for label, lib_name in targets.items():
        info = extract_library(cache_path, lib_name, output_dir=output_dir)
        info["label"] = label
        results.append(info)
        if info.get("error"):
            failed += 1
        elif info.get("cached"):
            cached += 1
        else:
            extracted += 1

    return {"target_set": target_set, "results": results,
            "extracted": extracted, "cached": cached,
            "failed": failed, "total": len(targets)}


def search_symbols(cache_path, library, pattern):
    """Extract library then search symbols with nm + regex."""
    lib_info = extract_library(cache_path, library)
    if lib_info.get("error") or lib_info.get("path") is None:
        return {"library": library, "pattern": pattern,
                "error": lib_info.get("error",
                                      f"Could not extract '{library}'")}

    lib_path = lib_info["path"]
    try:
        regex = re.compile(pattern)
    except re.error as e:
        return {"error": f"Invalid regex pattern: {e}"}

    # Try global+undefined first, fall back to full nm
    matches = []
    for nm_flags in (["-gUj"], []):
        if matches and nm_flags == []:
            break
        try:
            r = subprocess.run(["nm"] + nm_flags + [lib_path],
                               capture_output=True, text=True, timeout=60)
        except FileNotFoundError:
            return {"error": "nm not found. Install Xcode command-line tools."}
        except subprocess.TimeoutExpired:
            return {"error": "nm timed out (>60s)."}
        for line in r.stdout.splitlines():
            line = line.strip()
            if line and regex.search(line):
                matches.append(line)

    return {"library": library, "extracted_path": lib_path,
            "pattern": pattern, "total_matches": len(matches),
            "matches": matches}


# -- CLI registration -------------------------------------------------------

def register(subparsers):
    p = subparsers.add_parser("cache", help="Dyld shared cache handler")
    sub = p.add_subparsers(dest="cache_command", help="Cache subcommands")

    # list
    s = sub.add_parser("list", help="List images in cache")
    s.add_argument("cache_path", nargs="?", default=None,
                   help="Path to dyld_shared_cache (auto-detected if omitted)")
    s.add_argument("--arch", default="arm64e", help="Architecture (default: arm64e)")
    s.add_argument("--filter", default=None, help="Filter image paths by substring")
    add_output_args(s)

    # extract
    s = sub.add_parser("extract", help="Extract single library from cache")
    s.add_argument("library", help="Library name (e.g. libsystem_malloc.dylib)")
    s.add_argument("--cache-path", default=None, help="Path to dyld_shared_cache")
    s.add_argument("--arch", default="arm64e", help="Architecture (default: arm64e)")
    s.add_argument("--output-dir", default=None, help="Output directory")
    add_output_args(s)

    # extract-all
    s = sub.add_parser("extract-all", help="Extract a predefined set of libraries")
    s.add_argument("--targets", default="exploit",
                   choices=sorted(TARGET_SETS.keys()),
                   help="Target set (default: exploit)")
    s.add_argument("--cache-path", default=None, help="Path to dyld_shared_cache")
    s.add_argument("--arch", default="arm64e", help="Architecture (default: arm64e)")
    s.add_argument("--output-dir", default=None, help="Output directory")
    add_output_args(s)

    # symbols
    s = sub.add_parser("symbols", help="Search symbols in a cache image")
    s.add_argument("library", help="Library name (e.g. SkyLight)")
    s.add_argument("pattern", help="Regex pattern to match symbol names")
    s.add_argument("--cache-path", default=None, help="Path to dyld_shared_cache")
    s.add_argument("--arch", default="arm64e", help="Architecture (default: arm64e)")
    add_output_args(s)

    # results subcommands
    s = sub.add_parser("results", help="Manage analysis result cache")
    results_sub = s.add_subparsers(dest="results_command",
                                    help="Results cache subcommands")
    rs = results_sub.add_parser("stats", help="Show result cache stats")
    add_output_args(rs)
    rs = results_sub.add_parser("clear", help="Clear result cache")
    rs.add_argument("--binary", type=str, default=None,
                    help="Clear cache for specific binary only")
    add_output_args(rs)

    p.set_defaults(func=run)


def _resolve_cache(args):
    """Return cache path from args, auto-detecting if not provided."""
    path = getattr(args, "cache_path", None)
    if path:
        return path
    return find_shared_cache(arch=getattr(args, "arch", "arm64e"))


# -- Run dispatcher ----------------------------------------------------------

def run(args):
    out = make_formatter(args)
    cmd = getattr(args, "cache_command", None)
    if cmd is None:
        out.emit({"error": "No subcommand. Use: list, extract, "
                           "extract-all, symbols"}, "cache")
        return
    dispatch = {"list": _run_list, "extract": _run_extract,
                "extract-all": _run_extract_all, "symbols": _run_symbols,
                "results": _run_results}
    handler = dispatch.get(cmd)
    if handler is None:
        out.emit({"error": f"Unknown cache subcommand: {cmd}"}, "cache")
        return
    handler(args, out)


def _run_list(args, out):
    cache_path = _resolve_cache(args)
    if not cache_path:
        out.emit({"error": "Shared cache not found. Provide path or "
                           "check --arch."}, "cache.list")
        return
    out.status(f"Listing images in {cache_path}")
    images = list_shared_cache_images(cache_path)
    if images is None:
        out.emit({"error": "Failed to list images. Ensure "
                           "dyld_shared_cache_util or ipsw is installed."},
                 "cache.list")
        return
    filt = getattr(args, "filter", None)
    if filt:
        images = [i for i in images if filt.lower() in i.lower()]
    out.emit({"cache_path": cache_path, "total_images": len(images),
              "images": images}, "cache.list")


def _run_extract(args, out):
    cache_path = _resolve_cache(args)
    if not cache_path:
        out.emit({"error": "Shared cache not found. Provide --cache-path "
                           "or check --arch."}, "cache.extract")
        return
    out.status(f"Extracting {args.library} from {cache_path}")
    result = extract_library(cache_path, args.library,
                             output_dir=args.output_dir)
    if result.get("cached"):
        out.status(f"Using cached extraction: {result['path']}")
    elif result.get("path"):
        out.status(f"Extracted to: {result['path']}")
    result["cache_path"] = cache_path
    out.emit(result, "cache.extract")


def _run_extract_all(args, out):
    cache_path = _resolve_cache(args)
    if not cache_path:
        out.emit({"error": "Shared cache not found. Provide --cache-path "
                           "or check --arch."}, "cache.extract-all")
        return
    out.status(f"Extracting target set '{args.targets}' from {cache_path}")
    result = extract_targets(cache_path, args.targets,
                             output_dir=args.output_dir)
    result["cache_path"] = cache_path
    for entry in result.get("results", []):
        label = entry.get("label", entry.get("library", "?"))
        if entry.get("error"):
            out.status(f"  FAIL   {label}: {entry['error']}")
        elif entry.get("cached"):
            out.status(f"  CACHED {label}: {entry['path']}")
        else:
            out.status(f"  OK     {label}: {entry['path']}")
    out.emit(result, "cache.extract-all")


def _run_symbols(args, out):
    cache_path = _resolve_cache(args)
    if not cache_path:
        out.emit({"error": "Shared cache not found. Provide --cache-path "
                           "or check --arch."}, "cache.symbols")
        return
    out.status(f"Searching symbols in {args.library} for /{args.pattern}/")
    result = search_symbols(cache_path, args.library, args.pattern)
    result["cache_path"] = cache_path
    out.emit(result, "cache.symbols")


def _run_results(args, out):
    """Handle result cache subcommands (stats, clear)."""
    from cb.result_cache import ResultCache
    cache = ResultCache()

    results_cmd = getattr(args, "results_command", None)
    if results_cmd == "stats":
        stats = cache.stats()
        out.emit(stats, "cache.results.stats")
    elif results_cmd == "clear":
        binary = getattr(args, "binary", None)
        count = cache.clear(binary_path=binary)
        out.emit({"cleared": count, "binary": binary}, "cache.results.clear")
    else:
        out.emit({"error": "Use: cb cache results stats|clear"}, "cache.results")


# -- Standalone entry point --------------------------------------------------

def main():
    parser = argparse.ArgumentParser(prog="cbcache",
                                     description="Dyld shared cache handler")
    sub = parser.add_subparsers(dest="cache_command", help="Cache subcommands")

    s = sub.add_parser("list", help="List images in cache")
    s.add_argument("cache_path", nargs="?", default=None)
    s.add_argument("--arch", default="arm64e")
    s.add_argument("--filter", default=None)
    add_output_args(s)

    s = sub.add_parser("extract", help="Extract single library")
    s.add_argument("library")
    s.add_argument("--cache-path", default=None)
    s.add_argument("--arch", default="arm64e")
    s.add_argument("--output-dir", default=None)
    add_output_args(s)

    s = sub.add_parser("extract-all", help="Extract predefined target set")
    s.add_argument("--targets", default="exploit",
                   choices=sorted(TARGET_SETS.keys()))
    s.add_argument("--cache-path", default=None)
    s.add_argument("--arch", default="arm64e")
    s.add_argument("--output-dir", default=None)
    add_output_args(s)

    s = sub.add_parser("symbols", help="Search symbols in cache image")
    s.add_argument("library")
    s.add_argument("pattern")
    s.add_argument("--cache-path", default=None)
    s.add_argument("--arch", default="arm64e")
    add_output_args(s)

    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
