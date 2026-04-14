"""cb variant - Find variant bugs from known vulnerability patterns."""
import argparse
import json
import re
import sys

from cb.output import add_output_args, make_formatter


# Known vulnerability patterns generalized from real CVEs
KNOWN_PATTERNS = {
    "oob_read_missing_length_check": {
        "description": "Out-of-bounds read due to missing length validation before buffer access",
        "ghidra_pattern": r"if\s*\(\s*\w+\s*[<>]=?\s*\w+\s*\).*?(?:memcpy|memmove|read)",
        "indicators": ["memcpy", "memmove"],
        "anti_indicators": ["if.*len", "if.*size", "if.*count"],
        "severity": "high",
        "cve_examples": ["CVE-2021-30860 (FORCEDENTRY)", "CVE-2019-8641"],
    },
    "integer_overflow_in_size": {
        "description": "Integer overflow in size calculation before allocation",
        "ghidra_pattern": r"(malloc|calloc|realloc)\s*\([^)]*\*[^)]*\)",
        "indicators": ["malloc", "calloc"],
        "severity": "high",
        "cve_examples": ["CVE-2021-1871", "CVE-2020-9839"],
    },
    "type_confusion_objc_unarchiver": {
        "description": "Type confusion via NSKeyedUnarchiver without class restriction",
        "ghidra_pattern": r"unarchiveObjectWithData|initWithCoder",
        "indicators": ["NSKeyedUnarchiver", "initWithCoder"],
        "anti_indicators": ["unarchivedObjectOfClasses:", "requiresSecureCoding"],
        "severity": "critical",
        "cve_examples": ["CVE-2019-8641", "CVE-2022-22616"],
    },
    "mach_msg_ool_descriptor_overflow": {
        "description": "Out-of-line descriptor size not validated in Mach message handler",
        "ghidra_pattern": r"mach_msg.*descriptor|ool_descriptor",
        "indicators": ["mach_msg", "MACH_MSG_OOL_DESCRIPTOR"],
        "severity": "critical",
        "cve_examples": ["CVE-2019-8635", "CVE-2020-9839"],
    },
    "xpc_dict_no_type_check": {
        "description": "XPC dictionary value used without type checking",
        "ghidra_pattern": r"xpc_dictionary_get_\w+\([^)]+\)(?:(?!xpc_get_type).)*?(memcpy|strcpy|strlen)",
        "indicators": ["xpc_dictionary_get_string", "xpc_dictionary_get_data"],
        "anti_indicators": ["xpc_get_type"],
        "severity": "high",
        "cve_examples": ["CVE-2020-9839"],
    },
    "format_string_from_ipc": {
        "description": "Format string from IPC message used in printf-family function",
        "ghidra_pattern": r"(xpc_dictionary_get_string|mach_msg).*?(printf|NSLog|syslog)",
        "indicators": ["printf", "NSLog"],
        "severity": "critical",
        "cve_examples": [],
    },
    "double_free_in_error_path": {
        "description": "Double free when error handling frees already-freed memory",
        "ghidra_pattern": r"free\s*\(\s*(\w+)\s*\).*?goto\s+\w+.*?free\s*\(\s*\1\s*\)",
        "indicators": ["free", "goto"],
        "severity": "high",
        "cve_examples": ["CVE-2021-30807"],
    },
    "heap_overflow_in_font_parser": {
        "description": "Heap buffer overflow in font/image parsing due to unchecked table size",
        "ghidra_pattern": r"(memcpy|memmove)\s*\([^,]+,\s*[^,]+,\s*\*\(",
        "indicators": ["font", "glyph", "table", "offset", "memcpy"],
        "severity": "critical",
        "cve_examples": ["CVE-2021-30860 (FORCEDENTRY)", "CVE-2023-41990"],
    },
    "sandbox_escape_via_mach_service": {
        "description": "Sandbox escape by sending crafted Mach message to privileged service",
        "ghidra_pattern": r"bootstrap_look_up|mach_msg_send",
        "indicators": ["bootstrap_look_up", "mach_msg_send"],
        "severity": "critical",
        "cve_examples": ["CVE-2020-9839"],
    },
    "toctou_symlink": {
        "description": "Time-of-check-to-time-of-use via symlink race",
        "ghidra_pattern": r"(lstat|access)\s*\([^)]+\)[\s\S]{1,500}(open|fopen|rename)\s*\(",
        "indicators": ["lstat", "access", "open"],
        "severity": "medium",
        "cve_examples": ["CVE-2022-26691"],
    },
    "xpc_integer_to_allocation": {
        "description": "XPC integer used as allocation size without overflow check",
        "ghidra_pattern": r"xpc_dictionary_get_(u?int64)\b.*?(mach_vm_allocate|mmap|malloc)",
        "indicators": ["xpc_dictionary_get_uint64", "mach_vm_allocate"],
        "anti_indicators": ["os_mul_overflow", "__builtin_mul_overflow"],
        "severity": "critical",
        "cve_examples": ["CVE-2021-30724"],
    },
    "xpc_data_to_memcpy": {
        "description": "XPC data used in memcpy without bounds check",
        "ghidra_pattern": r"xpc_dictionary_get_data.*?memcpy",
        "indicators": ["xpc_dictionary_get_data", "memcpy"],
        "anti_indicators": ["MIN(", "if.*size"],
        "severity": "critical",
        "cve_examples": ["CVE-2021-30724"],
    },
}


def register(subparsers):
    p = subparsers.add_parser("variant", help="Find variant bugs from known patterns")
    p.add_argument("binary", nargs="?", default=None, help="Path to binary")
    p.add_argument("--from-crash", type=str, default=None, metavar="FILE_OR_DASH",
                   help="Target crashing function from crash output (file or '-' for stdin)")
    p.add_argument("--heuristic", action="store_true",
                   help="Fast import-combo scan without Ghidra")
    p.add_argument("--pattern", type=str, default=None,
                   help="Specific pattern name to search for (see --list-patterns)")
    p.add_argument("--list-patterns", action="store_true",
                   help="List all known vulnerability patterns")
    p.add_argument("--custom-pattern", type=str, default=None,
                   help="Custom regex pattern to search in decompiled code")
    p.add_argument("--custom-description", type=str, default="Custom pattern match")
    p.add_argument("--from-cve", type=str, default=None,
                   help="Search for variants based on a CVE pattern")
    p.add_argument("--static", action="store_true",
                   help="Static analysis only (imports/strings, no Ghidra)")
    p.add_argument("--timeout", type=int, default=600)
    add_output_args(p)
    p.set_defaults(func=run)


def run(args):
    out = make_formatter(args)

    if args.list_patterns:
        patterns_list = []
        for name, info in KNOWN_PATTERNS.items():
            patterns_list.append({
                "name": name,
                "description": info["description"],
                "severity": info["severity"],
                "cve_examples": info.get("cve_examples", []),
            })
        out.emit({"patterns": patterns_list}, "variant")
        return

    # Pipeline mode: target crashing function
    if getattr(args, 'from_crash', None):
        from cb.output import load_piped_input
        if args.from_crash == "-":
            crash_data = load_piped_input()
        else:
            with open(args.from_crash) as f:
                crash_data = json.load(f)
        if crash_data:
            target_func = _extract_crash_target(crash_data)
            if target_func:
                out.status(f"Targeting crashing function: {target_func}")
                if not args.pattern:
                    args.custom_pattern = re.escape(target_func)
                    args.custom_description = f"Variants of crash in {target_func}"

    if not args.binary:
        if not getattr(args, 'from_crash', None):
            out.emit({"error": "Binary path required (or use --from-crash)"}, "variant")
            return

    # Determine which patterns to search
    if args.pattern:
        patterns = {args.pattern: KNOWN_PATTERNS[args.pattern]} \
            if args.pattern in KNOWN_PATTERNS else {}
        if not patterns:
            out.emit({"error": f"Unknown pattern: {args.pattern}"}, "variant")
            return
    elif args.custom_pattern:
        patterns = {
            "custom": {
                "description": args.custom_description,
                "ghidra_pattern": args.custom_pattern,
                "indicators": [],
                "severity": "medium",
            }
        }
    else:
        patterns = KNOWN_PATTERNS

    results = []

    if getattr(args, 'heuristic', False) or args.static:
        out.status("Running static variant detection...")
        results = static_variant_scan(args.binary, patterns, out)
    else:
        out.status("Running deep variant detection via Ghidra decompiled code...")
        results = ghidra_variant_scan(args.binary, patterns, args, out)

    # Sort by severity
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    results.sort(key=lambda r: sev_order.get(r.get("severity", "low"), 4))

    out.emit({
        "total_variants": len(results),
        "by_severity": {
            s: len([r for r in results if r["severity"] == s])
            for s in ["critical", "high", "medium", "low"]
            if any(r["severity"] == s for r in results)
        },
        "variants": results[:args.max_results],
    }, "variant")


def static_variant_scan(binary, patterns, out):
    """Fast static scan using imports and strings."""
    from cb.macho import get_imports, get_strings

    imports = get_imports(binary)
    import_set = {i.lstrip("_").lower() for i in imports}
    strings_data = get_strings(binary, min_length=4, max_count=2000)
    all_strings = []
    for cat in strings_data["categories"].values():
        all_strings.extend(cat)
    strings_lower = " ".join(all_strings).lower()

    results = []
    for name, info in patterns.items():
        indicators = [i.lower() for i in info.get("indicators", [])]
        anti_indicators = [i.lower() for i in info.get("anti_indicators", [])]

        # Check if indicators are present in imports/strings
        present = [i for i in indicators if i in import_set or i in strings_lower]
        absent_anti = [a for a in anti_indicators
                       if a not in import_set and a not in strings_lower]

        if len(present) >= max(1, len(indicators) // 2):
            # Pattern partially matches
            confidence = "high" if absent_anti and len(present) == len(indicators) \
                else "medium" if len(present) >= len(indicators) // 2 else "low"
            results.append({
                "pattern": name,
                "description": info["description"],
                "severity": info["severity"],
                "confidence": confidence,
                "evidence": {
                    "indicators_found": present,
                    "mitigations_absent": absent_anti,
                },
                "cve_examples": info.get("cve_examples", []),
                "note": "Static analysis - confirm with cb variant (without --static) "
                        "for decompiled code analysis",
            })

    return results


def ghidra_variant_scan(binary, patterns, args, out):
    """Deep variant scan using Ghidra decompiled code."""
    results = []

    try:
        from cb.ghidra_bridge import run_ghidra_script
    except ImportError:
        out.status("Warning: Ghidra bridge not available, falling back to static scan")
        return static_variant_scan(binary, patterns, out)

    for name, info in patterns.items():
        pattern_regex = info.get("ghidra_pattern", "")
        if not pattern_regex:
            continue

        out.status(f"Searching for pattern: {name}")
        try:
            search_result = run_ghidra_script(
                binary, "SearchDecompiled.java",
                [pattern_regex, str(min(args.max_results, 20))],
                timeout=args.timeout,
            )
            if search_result and search_result.get("matches"):
                for match in search_result["matches"]:
                    results.append({
                        "pattern": name,
                        "description": info["description"],
                        "severity": info["severity"],
                        "function": match.get("function", ""),
                        "address": match.get("address", ""),
                        "code_snippet": match.get("snippet", "")[:300],
                        "cve_examples": info.get("cve_examples", []),
                    })
        except Exception as e:
            out.status(f"Warning: Pattern '{name}' search failed: {e}")

    return results


def _extract_crash_target(crash_data):
    """Extract the crashing function name from crash report output."""
    bt = crash_data.get("backtrace", [])
    for frame in bt[:5]:
        sym = frame.get("symbol", frame.get("symbolicated", ""))
        if sym and not sym.startswith("0x") and sym != "???":
            # Clean up symbol name
            clean = sym.split("(")[0].split(" ")[-1].strip()
            if clean and len(clean) > 2:
                return clean
    return None


def main():
    parser = argparse.ArgumentParser(prog="cbvariant", description="Variant finder")
    parser.add_argument("binary", nargs="?", default=None)
    parser.add_argument("--from-crash", type=str, default=None)
    parser.add_argument("--heuristic", action="store_true")
    parser.add_argument("--pattern", type=str, default=None)
    parser.add_argument("--list-patterns", action="store_true")
    parser.add_argument("--custom-pattern", type=str, default=None)
    parser.add_argument("--custom-description", type=str, default="Custom pattern")
    parser.add_argument("--from-cve", type=str, default=None)
    parser.add_argument("--static", action="store_true")
    parser.add_argument("--timeout", type=int, default=600)
    add_output_args(parser)
    args = parser.parse_args()
    run(args)
