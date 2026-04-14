"""cb diff - Binary version diffing with fuzzy matching."""
import argparse
import hashlib
import re
import subprocess
import sys
from collections import defaultdict

from cb.output import add_output_args, make_formatter


def register(subparsers):
    p = subparsers.add_parser("diff", help="Diff two binary versions")
    p.add_argument("binary_old", help="Path to old binary")
    p.add_argument("binary_new", help="Path to new binary")
    p.add_argument("--mode", choices=["functions", "symbols", "strings", "imports",
                                       "security"],
                   default="functions", help="Diff mode (default: functions)")
    p.add_argument("--show-added", action="store_true")
    p.add_argument("--show-removed", action="store_true")
    p.add_argument("--show-changed", action="store_true")
    p.add_argument("--show-all", action="store_true", default=True)
    p.add_argument("--fuzzy", action="store_true",
                   help="Fuzzy match renamed/moved functions by instruction hash")
    p.add_argument("--decompile-changed", action="store_true",
                   help="Decompile changed functions for code diff (requires Ghidra)")
    add_output_args(p)
    p.set_defaults(func=run)


def run(args):
    out = make_formatter(args)

    if args.mode == "functions":
        result = diff_functions(args, out)
    elif args.mode == "symbols":
        result = diff_symbols(args, out)
    elif args.mode == "strings":
        result = diff_strings(args, out)
    elif args.mode == "imports":
        result = diff_imports(args, out)
    elif args.mode == "security":
        result = diff_security(args, out)
    else:
        result = {"error": f"Unknown mode: {args.mode}"}

    out.emit(result, "diff")


def _get_symbols(path):
    """Extract symbols with addresses and sizes from nm."""
    r = subprocess.run(["nm", "-defined-only", "-n", path],
                       capture_output=True, text=True, timeout=60)
    symbols = {}
    lines = r.stdout.splitlines()
    for i, line in enumerate(lines):
        parts = line.split()
        if len(parts) >= 3:
            addr = int(parts[0], 16)
            stype = parts[1]
            name = parts[2]
            # Estimate size from next symbol
            if i + 1 < len(lines):
                next_parts = lines[i + 1].split()
                if len(next_parts) >= 1:
                    try:
                        next_addr = int(next_parts[0], 16)
                        size = next_addr - addr
                    except ValueError:
                        size = 0
                else:
                    size = 0
            else:
                size = 0
            symbols[name] = {"address": hex(addr), "size": size, "type": stype}
    return symbols


def diff_functions(args, out):
    """Function-level diff using symbol tables."""
    out.status("Extracting symbols from old binary...")
    old_syms = _get_symbols(args.binary_old)
    out.status("Extracting symbols from new binary...")
    new_syms = _get_symbols(args.binary_new)

    old_names = set(old_syms.keys())
    new_names = set(new_syms.keys())

    added = new_names - old_names
    removed = old_names - new_names
    common = old_names & new_names

    # Find changed functions (different size)
    changed = []
    unchanged = 0
    for name in common:
        old_size = old_syms[name]["size"]
        new_size = new_syms[name]["size"]
        if old_size != new_size and old_size > 0:
            delta = new_size - old_size
            changed.append({
                "name": name,
                "old_address": old_syms[name]["address"],
                "new_address": new_syms[name]["address"],
                "old_size": old_size,
                "new_size": new_size,
                "size_delta": f"+{delta}" if delta > 0 else str(delta),
            })
        else:
            unchanged += 1

    # Sort changed by absolute delta
    changed.sort(key=lambda c: abs(c["new_size"] - c["old_size"]), reverse=True)

    # Fuzzy matching: try to match removed functions with added functions
    fuzzy_matches = []
    if getattr(args, "fuzzy", False) and added and removed:
        out.status("Running fuzzy function matching...")
        fuzzy_matches = _fuzzy_match_functions(
            args.binary_old, args.binary_new,
            sorted(removed)[:100], sorted(added)[:100], old_syms, new_syms
        )

    # Decompile changed functions if requested
    if args.decompile_changed and changed:
        out.status("Decompiling changed functions (this may take a while)...")
        _add_decompiled_diffs(changed[:10], args)

    # Build result
    show_all = args.show_all and not (args.show_added or args.show_removed or args.show_changed)

    result = {
        "summary": {
            "functions_added": len(added),
            "functions_removed": len(removed),
            "functions_changed": len(changed),
            "functions_unchanged": unchanged,
            "fuzzy_renamed": len(fuzzy_matches),
            "total_old": len(old_syms),
            "total_new": len(new_syms),
        },
        "changes": [],
    }

    if fuzzy_matches:
        result["fuzzy_renamed"] = fuzzy_matches[:args.max_results]

    if show_all or args.show_added:
        for name in sorted(added)[:args.max_results]:
            result["changes"].append({
                "type": "added",
                "name": name,
                "new_address": new_syms[name]["address"],
                "new_size": new_syms[name]["size"],
            })

    if show_all or args.show_removed:
        for name in sorted(removed)[:args.max_results]:
            result["changes"].append({
                "type": "removed",
                "name": name,
                "old_address": old_syms[name]["address"],
                "old_size": old_syms[name]["size"],
            })

    if show_all or args.show_changed:
        for c in changed[:args.max_results]:
            c["type"] = "changed"
            result["changes"].append(c)

    return result


def _add_decompiled_diffs(changed_list, args):
    """Add decompiled code diffs to changed functions."""
    try:
        from cb.ghidra_bridge import run_ghidra_script
    except ImportError:
        return

    for change in changed_list:
        try:
            old_result = run_ghidra_script(
                args.binary_old, "DecompileFunction.java",
                [change["name"]], timeout=60
            )
            new_result = run_ghidra_script(
                args.binary_new, "DecompileFunction.java",
                [change["name"]], timeout=60
            )
            old_code = old_result.get("decompiled_c", "")
            new_code = new_result.get("decompiled_c", "")

            if old_code and new_code:
                import difflib
                diff = difflib.unified_diff(
                    old_code.splitlines(), new_code.splitlines(),
                    fromfile="old", tofile="new", lineterm=""
                )
                change["decompiled_diff"] = "\n".join(list(diff)[:100])
        except Exception:
            pass


def diff_symbols(args, out):
    """Symbol table diff."""
    out.status("Comparing symbol tables...")
    old_syms = _get_symbols(args.binary_old)
    new_syms = _get_symbols(args.binary_new)

    old_names = set(old_syms.keys())
    new_names = set(new_syms.keys())

    return {
        "summary": {
            "symbols_added": len(new_names - old_names),
            "symbols_removed": len(old_names - new_names),
            "symbols_common": len(old_names & new_names),
        },
        "added": sorted(new_names - old_names)[:args.max_results],
        "removed": sorted(old_names - new_names)[:args.max_results],
    }


def diff_strings(args, out):
    """String table diff."""
    out.status("Comparing strings...")

    def get_strings(path):
        r = subprocess.run(["strings", "-n", "6", path],
                           capture_output=True, text=True, timeout=60)
        return set(r.stdout.splitlines())

    old = get_strings(args.binary_old)
    new = get_strings(args.binary_new)

    return {
        "summary": {
            "strings_added": len(new - old),
            "strings_removed": len(old - new),
            "strings_common": len(old & new),
        },
        "added": sorted(new - old)[:args.max_results],
        "removed": sorted(old - new)[:args.max_results],
    }


def diff_imports(args, out):
    """Import diff."""
    out.status("Comparing imports...")
    from cb.macho import get_imports

    old_imports = set(get_imports(args.binary_old))
    new_imports = set(get_imports(args.binary_new))

    return {
        "summary": {
            "imports_added": len(new_imports - old_imports),
            "imports_removed": len(old_imports - new_imports),
            "imports_common": len(old_imports & new_imports),
        },
        "added": sorted(new_imports - old_imports),
        "removed": sorted(old_imports - new_imports),
    }


def diff_security(args, out):
    """Security-focused diff: what changed from an attacker's perspective."""
    out.status("Running security-focused diff...")
    from cb.macho import get_imports, get_entitlements

    result = {"changes": []}

    # Import changes (new dangerous imports = new attack surface)
    old_imports = set(i.lstrip("_") for i in get_imports(args.binary_old))
    new_imports = set(i.lstrip("_") for i in get_imports(args.binary_new))
    from cb.patterns.dangerous_functions import DANGEROUS_IMPORTS
    all_dangerous = set()
    for sev_funcs in DANGEROUS_IMPORTS.values():
        for funcs in sev_funcs.values():
            all_dangerous.update(funcs)

    new_dangerous = (new_imports - old_imports) & all_dangerous
    removed_dangerous = (old_imports - new_imports) & all_dangerous
    if new_dangerous:
        result["changes"].append({
            "type": "new_dangerous_imports",
            "severity": "high",
            "description": "New dangerous functions imported",
            "functions": sorted(new_dangerous),
        })
    if removed_dangerous:
        result["changes"].append({
            "type": "removed_dangerous_imports",
            "severity": "info",
            "description": "Dangerous functions removed (hardening)",
            "functions": sorted(removed_dangerous),
        })

    # Entitlement changes
    old_ents = get_entitlements(args.binary_old)
    new_ents = get_entitlements(args.binary_new)
    added_ents = set(new_ents.keys()) - set(old_ents.keys())
    removed_ents = set(old_ents.keys()) - set(new_ents.keys())
    if added_ents:
        result["changes"].append({
            "type": "new_entitlements",
            "severity": "medium",
            "description": "New entitlements added",
            "entitlements": sorted(added_ents),
        })
    if removed_ents:
        result["changes"].append({
            "type": "removed_entitlements",
            "severity": "info",
            "description": "Entitlements removed (hardening)",
            "entitlements": sorted(removed_ents),
        })

    # Function changes (size-based, focus on large changes)
    old_syms = _get_symbols(args.binary_old)
    new_syms = _get_symbols(args.binary_new)
    common = set(old_syms.keys()) & set(new_syms.keys())
    big_changes = []
    for name in common:
        old_size = old_syms[name]["size"]
        new_size = new_syms[name]["size"]
        if old_size > 0 and new_size > 0:
            ratio = new_size / old_size
            # Flag functions that grew significantly (potential new code paths)
            if ratio > 1.5 and (new_size - old_size) > 50:
                big_changes.append({
                    "name": name,
                    "old_size": old_size,
                    "new_size": new_size,
                    "growth": f"{ratio:.1f}x",
                })
    big_changes.sort(key=lambda c: c["new_size"] - c["old_size"], reverse=True)
    if big_changes:
        result["changes"].append({
            "type": "significantly_changed_functions",
            "severity": "medium",
            "description": "Functions that grew significantly (new code paths to audit)",
            "functions": big_changes[:20],
        })

    # New functions (potential new attack surface)
    added_funcs = set(new_syms.keys()) - set(old_syms.keys())
    interesting_added = [f for f in added_funcs
                         if any(x in f.lower() for x in
                                ["parse", "handle", "process", "decode", "deserial",
                                 "unpack", "read", "recv", "xpc", "mach", "ipc"])]
    if interesting_added:
        result["changes"].append({
            "type": "new_interesting_functions",
            "severity": "high",
            "description": "New functions with parser/handler/IPC names (attack surface)",
            "functions": sorted(interesting_added)[:30],
        })

    # === Enhanced hardening detection ===

    # Hardening added: new safe arithmetic / bounds checking
    hardening_funcs = {
        "os_mul_overflow", "__builtin_mul_overflow", "os_add_overflow",
        "__builtin_add_overflow", "SecTaskCreateWithAuditToken",
        "SecTaskCopyValueForEntitlement", "strlcpy", "strlcat",
        "xpc_connection_get_audit_token",
    }
    new_hardening = (new_imports - old_imports) & hardening_funcs
    if new_hardening:
        result["changes"].append({
            "type": "hardening_added",
            "severity": "info",
            "description": "New hardening / safe functions added",
            "functions": sorted(new_hardening),
        })

    # Dangerous functions removed (replaced by safer variants)
    dangerous_to_safe = {
        "strcpy": "strlcpy", "strcat": "strlcat",
        "sprintf": "snprintf", "vsprintf": "vsnprintf",
        "gets": "fgets",
    }
    replacements = []
    for dangerous, safe in dangerous_to_safe.items():
        if dangerous in old_imports and dangerous not in new_imports:
            if safe in new_imports:
                replacements.append({"removed": dangerous, "replaced_by": safe})
    if replacements:
        result["changes"].append({
            "type": "dangerous_removed",
            "severity": "info",
            "description": "Dangerous functions replaced by safer variants",
            "replacements": replacements,
        })

    # Audit token / auth checks added
    auth_funcs = {
        "xpc_connection_get_audit_token", "SecTaskCreateWithAuditToken",
        "SecTaskCopyValueForEntitlement", "audit_token_to_pid",
        "audit_token_to_euid",
    }
    new_auth = (new_imports - old_imports) & auth_funcs
    if new_auth:
        result["changes"].append({
            "type": "audit_token_added",
            "severity": "info",
            "description": "New authentication / audit token checks added",
            "functions": sorted(new_auth),
        })

    # Functions that gained bounds checks (grew AND have new safe imports)
    if new_hardening and big_changes:
        hardened_funcs = [
            bc for bc in big_changes[:10]
            if float(bc["growth"].rstrip("x")) >= 1.2
        ]
        if hardened_funcs:
            result["changes"].append({
                "type": "bounds_checks_added",
                "severity": "info",
                "description": "Functions that grew significantly (likely gained bounds checks)",
                "functions": [f["name"] for f in hardened_funcs[:10]],
            })

    result["summary"] = {
        "total_security_changes": len(result["changes"]),
        "new_dangerous_imports": len(new_dangerous),
        "removed_dangerous_imports": len(removed_dangerous),
        "new_entitlements": len(added_ents),
        "removed_entitlements": len(removed_ents),
        "significantly_changed_functions": len(big_changes),
        "new_attack_surface_functions": len(interesting_added),
        "hardening_added": len(new_hardening) if 'new_hardening' in dir() else 0,
        "auth_checks_added": len(new_auth) if 'new_auth' in dir() else 0,
    }

    return result


def _fuzzy_match_functions(old_path, new_path, removed, added, old_syms, new_syms):
    """BinDiff-style fuzzy matching of renamed/moved functions.

    Uses instruction count + size similarity to match removed functions
    to added functions that might be renamed versions of the same code.
    """
    matches = []

    # Build size profiles for removed and added
    removed_profiles = {}
    for name in removed:
        info = old_syms.get(name, {})
        size = info.get("size", 0)
        if size > 16:  # Skip tiny functions
            removed_profiles[name] = size

    added_profiles = {}
    for name in added:
        info = new_syms.get(name, {})
        size = info.get("size", 0)
        if size > 16:
            added_profiles[name] = size

    # Match by exact size first (strongest signal)
    used_removed = set()
    used_added = set()

    # Group by size for exact matching
    added_by_size = defaultdict(list)
    for name, size in added_profiles.items():
        added_by_size[size].append(name)

    for rname, rsize in removed_profiles.items():
        if rname in used_removed:
            continue
        candidates = added_by_size.get(rsize, [])
        candidates = [c for c in candidates if c not in used_added]
        if len(candidates) == 1:
            # Unique size match — high confidence
            matches.append({
                "old_name": rname,
                "new_name": candidates[0],
                "confidence": "high",
                "reason": f"exact size match ({rsize} bytes)",
            })
            used_removed.add(rname)
            used_added.add(candidates[0])

    # Fuzzy size match for remaining (within 10% size tolerance)
    for rname, rsize in removed_profiles.items():
        if rname in used_removed:
            continue
        best_match = None
        best_ratio = 0
        for aname, asize in added_profiles.items():
            if aname in used_added:
                continue
            if asize == 0 or rsize == 0:
                continue
            ratio = min(rsize, asize) / max(rsize, asize)
            if ratio > 0.9 and ratio > best_ratio:
                # Also check name similarity
                name_sim = _name_similarity(rname, aname)
                if name_sim > 0.3:
                    best_ratio = ratio
                    best_match = aname

        if best_match:
            matches.append({
                "old_name": rname,
                "new_name": best_match,
                "confidence": "medium",
                "reason": f"size {removed_profiles[rname]}→{added_profiles[best_match]} "
                          f"({best_ratio:.0%} match), name similarity",
            })
            used_removed.add(rname)
            used_added.add(best_match)

    return matches


def _name_similarity(name1, name2):
    """Simple name similarity score between two symbol names."""
    # Strip common prefixes/suffixes
    for prefix in ["_", "__", "___"]:
        name1 = name1.lstrip(prefix) if name1.startswith(prefix) else name1
        name2 = name2.lstrip(prefix) if name2.startswith(prefix) else name2

    # Split into tokens (camelCase, underscore_case)
    def tokenize(s):
        tokens = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)|[0-9]+", s)
        return set(t.lower() for t in tokens)

    tokens1 = tokenize(name1)
    tokens2 = tokenize(name2)
    if not tokens1 or not tokens2:
        return 0.0
    intersection = tokens1 & tokens2
    union = tokens1 | tokens2
    return len(intersection) / len(union) if union else 0.0


def main():
    parser = argparse.ArgumentParser(prog="cbdiff", description="Binary diff")
    parser.add_argument("binary_old")
    parser.add_argument("binary_new")
    parser.add_argument("--mode", choices=["functions", "symbols", "strings", "imports", "security"],
                        default="functions")
    parser.add_argument("--show-added", action="store_true")
    parser.add_argument("--show-removed", action="store_true")
    parser.add_argument("--show-changed", action="store_true")
    parser.add_argument("--show-all", action="store_true", default=True)
    parser.add_argument("--decompile-changed", action="store_true")
    add_output_args(parser)
    args = parser.parse_args()
    run(args)
