"""cb triage - Quick binary overview for security analysis."""
import argparse
import sys

from cb.output import add_output_args, make_formatter
from cb.macho import (
    detect_format, get_file_info, get_architectures, get_protections,
    get_sections, get_imports, get_exports, get_libraries, get_strings,
)
from cb.elf_utils import categorize_imports


def register(subparsers):
    p = subparsers.add_parser("triage", help="Quick binary overview")
    p.add_argument("binary", help="Path to binary")
    p.add_argument("--no-sections", action="store_true")
    p.add_argument("--no-imports", action="store_true")
    p.add_argument("--no-exports", action="store_true")
    p.add_argument("--no-strings", action="store_true")
    p.add_argument("--checksec", action="store_true",
                   help="Security checks only")
    p.add_argument("--strings-min", type=int, default=6,
                   help="Min string length (default: 6)")
    p.add_argument("--strings-max", type=int, default=30,
                   help="Max strings per category (default: 30)")
    p.add_argument("--full", action="store_true",
                   help="Full output with higher limits")
    add_output_args(p)
    p.set_defaults(func=run)


def run(args):
    out = make_formatter(args)
    path = args.binary

    # Cache check
    cache_args = {
        "checksec": args.checksec,
        "no_sections": args.no_sections,
        "no_imports": args.no_imports,
        "no_exports": args.no_exports,
        "no_strings": args.no_strings,
        "full": args.full,
    }
    if not getattr(args, "no_cache", False):
        try:
            from cb.result_cache import ResultCache
            cache = ResultCache()
            cached = cache.get(path, "triage", cache_args)
            if cached:
                cached.setdefault("_meta", {})["cached"] = True
                out.emit(cached, "triage")
                return
        except Exception:
            pass

    fmt = detect_format(path)

    if fmt == "elf":
        result = _triage_elf(path, args, out)
    else:
        result = _triage_macho(path, args, out)

    # Cache store
    if not getattr(args, "no_cache", False):
        try:
            from cb.result_cache import ResultCache
            cache = ResultCache()
            cache.put(path, "triage", cache_args, result)
        except Exception:
            pass

    out.emit(result, "triage")


def _triage_macho(path, args, out):
    out.status(f"Analyzing Mach-O: {path}")
    result = {}

    # File info
    result["file_info"] = get_file_info(path)
    out.status("Getting architecture info...")
    result["architectures"] = get_architectures(path)

    # Protections
    out.status("Checking protections...")
    result["protections"] = get_protections(path)

    if args.checksec:
        return result

    # Sections
    if not args.no_sections:
        out.status("Parsing sections...")
        sections = get_sections(path)
        result["sections_summary"] = {
            "total_sections": len(sections),
            "sections": sections[:args.max_results],
        }

    # Imports
    if not args.no_imports:
        out.status("Analyzing imports...")
        imports = get_imports(path)
        categories = categorize_imports(imports)
        result["imports_summary"] = {
            "total_imports": len(imports),
            "libraries": get_libraries(path),
            "categories": categories,
        }

    # Exports
    if not args.no_exports:
        out.status("Getting exports...")
        exports = get_exports(path)
        limit = args.max_results if not args.full else 200
        result["exports_summary"] = {
            "total_exports": len(exports),
            "top_exports": exports[:limit],
        }

    # Strings
    if not args.no_strings:
        out.status("Extracting strings...")
        max_str = args.strings_max if not args.full else 100
        result["strings_interesting"] = get_strings(
            path, min_length=args.strings_min, max_count=max_str
        )

    return result


def _triage_elf(path, args, out):
    out.status(f"Analyzing ELF: {path}")
    from cb.elf_utils import get_elf_info
    info = get_elf_info(path)

    if args.checksec:
        return {
            "file_info": info["file_info"],
            "protections": info["protections"],
        }

    # Categorize imports
    if not args.no_imports:
        info["imports_summary"] = {
            "total_imports": len(info.get("imports", [])),
            "categories": categorize_imports(info.get("imports", [])),
        }

    if not args.no_strings:
        from cb.macho import get_strings
        info["strings_interesting"] = get_strings(
            path, min_length=args.strings_min,
            max_count=args.strings_max if not args.full else 100
        )

    return info


def main():
    parser = argparse.ArgumentParser(prog="cbtriage", description="Binary triage")
    parser.add_argument("binary", help="Path to binary")
    parser.add_argument("--no-sections", action="store_true")
    parser.add_argument("--no-imports", action="store_true")
    parser.add_argument("--no-exports", action="store_true")
    parser.add_argument("--no-strings", action="store_true")
    parser.add_argument("--checksec", action="store_true")
    parser.add_argument("--strings-min", type=int, default=6)
    parser.add_argument("--strings-max", type=int, default=30)
    parser.add_argument("--full", action="store_true")
    add_output_args(parser)
    args = parser.parse_args()
    run(args)
