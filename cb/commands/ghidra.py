"""cb ghidra - Ghidra headless analysis bridge."""
import argparse
import sys

from cb.output import OutputFormatter, add_output_args, make_formatter
from cb.config import get_ghidra_home, load_config, save_config


def _ghidra_available_or_emit(out: OutputFormatter, tool_name: str) -> bool:
    """Check Ghidra availability; emit JSON error and return False if unavailable."""
    from cb.ghidra_bridge import is_available
    if not is_available():
        out.emit({
            "error": "Ghidra is not installed or not configured",
            "hint": "Install: 'brew install --cask ghidra' or 'cb ghidra setup --ghidra-home /path'",
        }, tool_name)
        return False
    return True


def register(subparsers):
    p = subparsers.add_parser("ghidra", help="Ghidra headless analysis")
    sub = p.add_subparsers(dest="ghidra_cmd", help="Ghidra subcommands")

    # setup
    s = sub.add_parser("setup", help="Configure Ghidra path")
    s.add_argument("--ghidra-home", required=True, help="Path to Ghidra installation")
    s.set_defaults(func=run_setup)

    # analyze
    s = sub.add_parser("analyze", help="Import and analyze a binary")
    s.add_argument("binary", help="Path to binary")
    s.add_argument("--timeout", type=int, default=600)
    s.add_argument("--force", action="store_true", help="Force re-analysis")
    add_output_args(s)
    s.set_defaults(func=run_analyze)

    # decompile
    s = sub.add_parser("decompile", help="Decompile a function")
    s.add_argument("binary", help="Path to binary")
    s.add_argument("function", help="Function name or 0xADDRESS")
    s.add_argument("--include-assembly", action="store_true")
    s.add_argument("--timeout", type=int, default=300)
    add_output_args(s)
    s.set_defaults(func=run_decompile)

    # functions
    s = sub.add_parser("functions", help="List functions with metrics")
    s.add_argument("binary", help="Path to binary")
    s.add_argument("--sort-by", choices=["size", "complexity", "name", "address"],
                   default="size")
    s.add_argument("--filter", type=str, default=None, help="Regex filter on names")
    s.add_argument("--min-size", type=int, default=0)
    s.add_argument("--timeout", type=int, default=300)
    add_output_args(s)
    s.set_defaults(func=run_functions)

    # xrefs
    s = sub.add_parser("xrefs", help="Cross-references to/from a function")
    s.add_argument("binary", help="Path to binary")
    s.add_argument("function", help="Function name or 0xADDRESS")
    s.add_argument("--direction", choices=["to", "from", "both"], default="both")
    s.add_argument("--depth", type=int, default=1)
    s.add_argument("--timeout", type=int, default=300)
    add_output_args(s)
    s.set_defaults(func=run_xrefs)

    # search
    s = sub.add_parser("search", help="Search decompiled code for patterns")
    s.add_argument("binary", help="Path to binary")
    s.add_argument("pattern", help="Regex pattern to search")
    s.add_argument("--timeout", type=int, default=300)
    add_output_args(s)
    s.set_defaults(func=run_search)

    # types
    s = sub.add_parser("types", help="Extract type/struct definitions")
    s.add_argument("binary", help="Path to binary")
    s.add_argument("--filter", type=str, default=None, help="Filter type names")
    s.add_argument("--timeout", type=int, default=300)
    add_output_args(s)
    s.set_defaults(func=run_types)

    p.set_defaults(func=lambda args: p.print_help())


def run_setup(args):
    import os
    path = os.path.expanduser(args.ghidra_home)
    if not os.path.isdir(path):
        print(f"Error: {path} is not a directory", file=sys.stderr)
        sys.exit(1)
    headless = os.path.join(path, "support", "analyzeHeadless")
    if not os.path.exists(headless):
        print(f"Warning: analyzeHeadless not found at {headless}", file=sys.stderr)

    cfg = load_config()
    cfg["ghidra_home"] = path
    save_config(cfg)
    print(f"Ghidra home set to: {path}")


def run_analyze(args):
    out = make_formatter(args)
    if not _ghidra_available_or_emit(out, "ghidra.analyze"):
        return
    try:
        from cb.ghidra_bridge import analyze, GhidraError
        result = analyze(args.binary, timeout=args.timeout, force=args.force)
        out.emit(result, "ghidra.analyze")
    except Exception as e:
        out.debug(f"Ghidra analyze failed: {e}", exc=e)
        out.emit({"error": str(e), "hint": "Run with --verbose for details"}, "ghidra.analyze")


def run_decompile(args):
    out = make_formatter(args)
    if not _ghidra_available_or_emit(out, "ghidra.decompile"):
        return
    try:
        from cb.ghidra_bridge import run_ghidra_script
        script_args = [args.function]
        if args.include_assembly:
            script_args.append("--assembly")
        result = run_ghidra_script(args.binary, "DecompileFunction.java",
                                   script_args, timeout=args.timeout)
        out.emit(result, "ghidra.decompile")
    except Exception as e:
        out.debug(f"Ghidra decompile failed: {e}", exc=e)
        out.emit({"error": str(e), "hint": "Run with --verbose for details"}, "ghidra.decompile")


def run_functions(args):
    out = make_formatter(args)
    if not _ghidra_available_or_emit(out, "ghidra.functions"):
        return
    try:
        from cb.ghidra_bridge import run_ghidra_script
        script_args = [
            args.sort_by,
            str(args.min_size),
            str(args.max_results),
        ]
        if args.filter:
            script_args.append(args.filter)
        result = run_ghidra_script(args.binary, "ListFunctions.java",
                                   script_args, timeout=args.timeout)
        out.emit(result, "ghidra.functions")
    except Exception as e:
        out.debug(f"Ghidra functions failed: {e}", exc=e)
        out.emit({"error": str(e), "hint": "Run with --verbose for details"}, "ghidra.functions")


def run_xrefs(args):
    out = make_formatter(args)
    if not _ghidra_available_or_emit(out, "ghidra.xrefs"):
        return
    try:
        from cb.ghidra_bridge import run_ghidra_script
        script_args = [args.function, args.direction, str(args.depth)]
        result = run_ghidra_script(args.binary, "FindXrefs.java",
                                   script_args, timeout=args.timeout)
        out.emit(result, "ghidra.xrefs")
    except Exception as e:
        out.debug(f"Ghidra xrefs failed: {e}", exc=e)
        out.emit({"error": str(e), "hint": "Run with --verbose for details"}, "ghidra.xrefs")


def run_search(args):
    out = make_formatter(args)
    if not _ghidra_available_or_emit(out, "ghidra.search"):
        return
    try:
        from cb.ghidra_bridge import run_ghidra_script
        script_args = [args.pattern, str(args.max_results)]
        result = run_ghidra_script(args.binary, "SearchDecompiled.java",
                                   script_args, timeout=args.timeout)
        out.emit(result, "ghidra.search")
    except Exception as e:
        out.debug(f"Ghidra search failed: {e}", exc=e)
        out.emit({"error": str(e), "hint": "Run with --verbose for details"}, "ghidra.search")


def run_types(args):
    out = make_formatter(args)
    if not _ghidra_available_or_emit(out, "ghidra.types"):
        return
    try:
        from cb.ghidra_bridge import run_ghidra_script
        script_args = [str(args.max_results)]
        if args.filter:
            script_args.append(args.filter)
        result = run_ghidra_script(args.binary, "ExtractTypes.java",
                                   script_args, timeout=args.timeout)
        out.emit(result, "ghidra.types")
    except Exception as e:
        out.debug(f"Ghidra types failed: {e}", exc=e)
        out.emit({"error": str(e), "hint": "Run with --verbose for details"}, "ghidra.types")


def main():
    parser = argparse.ArgumentParser(prog="cbghidra", description="Ghidra bridge")
    sub = parser.add_subparsers(dest="ghidra_cmd")

    s = sub.add_parser("setup")
    s.add_argument("--ghidra-home", required=True)
    s.set_defaults(func=run_setup)

    s = sub.add_parser("analyze")
    s.add_argument("binary")
    s.add_argument("--timeout", type=int, default=600)
    s.add_argument("--force", action="store_true")
    add_output_args(s)
    s.set_defaults(func=run_analyze)

    s = sub.add_parser("decompile")
    s.add_argument("binary")
    s.add_argument("function")
    s.add_argument("--include-assembly", action="store_true")
    s.add_argument("--timeout", type=int, default=300)
    add_output_args(s)
    s.set_defaults(func=run_decompile)

    s = sub.add_parser("functions")
    s.add_argument("binary")
    s.add_argument("--sort-by", choices=["size", "complexity", "name", "address"], default="size")
    s.add_argument("--filter", type=str, default=None)
    s.add_argument("--min-size", type=int, default=0)
    s.add_argument("--timeout", type=int, default=300)
    add_output_args(s)
    s.set_defaults(func=run_functions)

    s = sub.add_parser("xrefs")
    s.add_argument("binary")
    s.add_argument("function")
    s.add_argument("--direction", choices=["to", "from", "both"], default="both")
    s.add_argument("--depth", type=int, default=1)
    s.add_argument("--timeout", type=int, default=300)
    add_output_args(s)
    s.set_defaults(func=run_xrefs)

    s = sub.add_parser("search")
    s.add_argument("binary")
    s.add_argument("pattern")
    s.add_argument("--timeout", type=int, default=300)
    add_output_args(s)
    s.set_defaults(func=run_search)

    s = sub.add_parser("types")
    s.add_argument("binary")
    s.add_argument("--filter", type=str, default=None)
    s.add_argument("--timeout", type=int, default=300)
    add_output_args(s)
    s.set_defaults(func=run_types)

    args = parser.parse_args()
    if not args.ghidra_cmd:
        parser.print_help()
        sys.exit(1)
    args.func(args)
