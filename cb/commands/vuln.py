"""cb vuln - Vulnerability pattern scanner."""
import argparse
import os
import re
import sys

from cb.output import add_output_args, make_formatter
from cb.macho import detect_format, get_imports, get_strings
from cb.elf_utils import categorize_imports
from cb.patterns.dangerous_functions import DANGEROUS_IMPORTS


# Patterns for decompiled code analysis
DECOMPILED_PATTERNS = {
    "format_string_variable": {
        "pattern": r"(printf|fprintf|syslog|NSLog|CFStringCreateWithFormat)\s*\(\s*[a-zA-Z_]\w*\s*[,)]",
        "severity": "high",
        "category": "format",
        "description": "Format function called with variable format string",
    },
    "unbounded_copy": {
        "pattern": r"(strcpy|strcat|sprintf|gets)\s*\(",
        "severity": "high",
        "category": "overflow",
        "description": "Unbounded string/memory operation",
    },
    "malloc_multiplication": {
        "pattern": r"malloc\s*\([^)]*\*[^)]*\)",
        "severity": "medium",
        "category": "integer",
        "description": "Multiplication in malloc argument (potential integer overflow)",
    },
    "realloc_to_zero": {
        "pattern": r"realloc\s*\([^,]+,\s*0\s*\)",
        "severity": "medium",
        "category": "memory",
        "description": "realloc with size 0 (implementation-defined behavior)",
    },
    "signed_comparison": {
        "pattern": r"if\s*\(\s*\(int\)\w+\s*[<>]=?\s*0\s*\)",
        "severity": "medium",
        "category": "integer",
        "description": "Signed comparison after cast (potential sign confusion)",
    },
    "memcpy_from_param": {
        "pattern": r"memcpy\s*\([^,]+,\s*param_\d+\s*,\s*param_\d+\s*\)",
        "severity": "high",
        "category": "overflow",
        "description": "memcpy with size from function parameter (may be user-controlled)",
    },
    "free_then_use": {
        "pattern": r"free\s*\(\s*(\w+)\s*\)(?:(?!(?:\1\s*=))[\s\S]){1,200}\1\s*[^=]",
        "severity": "high",
        "category": "uaf",
        "description": "Variable used after free without reassignment",
        "multiline": True,
    },
    "double_free": {
        "pattern": r"free\s*\(\s*(\w+)\s*\)(?:(?!\1\s*=)[\s\S]){1,500}free\s*\(\s*\1\s*\)",
        "severity": "high",
        "category": "uaf",
        "description": "Same variable freed twice without reassignment",
        "multiline": True,
    },
    "system_call": {
        "pattern": r"system\s*\([^)]*\+[^)]*\)",
        "severity": "high",
        "category": "injection",
        "description": "system() called with concatenated string (command injection)",
    },
    "toctou": {
        "pattern": r"(access|stat|lstat)\s*\([^)]+\)[\s\S]{1,300}(open|fopen)\s*\(",
        "severity": "medium",
        "category": "race",
        "description": "TOCTOU: file check then use pattern",
        "multiline": True,
    },
    # Logic bug patterns
    "unchecked_return": {
        "pattern": r"(?:^|[;{}\n])\s*(?:malloc|calloc|realloc|mmap|open|fopen|socket|read|recv)\s*\([^)]*\)\s*;",
        "severity": "medium",
        "category": "logic",
        "description": "Return value from critical function not checked (may be NULL/-1)",
    },
    "signed_unsigned_comparison": {
        "pattern": r"if\s*\(\s*(?:int|long|ssize_t)\s+\w+\s*[<>]=?\s*(?:unsigned|size_t|uint)",
        "severity": "medium",
        "category": "logic",
        "description": "Signed/unsigned comparison (sign extension may bypass check)",
    },
    "missing_break_in_switch": {
        "pattern": r"case\s+\w+:(?:(?!break|return|goto|case|default)[\s\S]){1,300}case\s+",
        "severity": "low",
        "category": "logic",
        "description": "Switch case without break (potential fallthrough bug)",
        "multiline": True,
    },
    "unchecked_arithmetic_before_alloc": {
        "pattern": r"(\w+)\s*=\s*\w+\s*[+*]\s*\w+\s*;[\s\S]{0,100}(?:malloc|calloc)\s*\(\s*\1\s*\)",
        "severity": "high",
        "category": "integer",
        "description": "Arithmetic result used in allocation without overflow check",
        "multiline": True,
    },
    "null_deref_after_check": {
        "pattern": r"if\s*\(\s*(\w+)\s*==\s*NULL\s*\)[\s\S]{0,100}\1->",
        "severity": "high",
        "category": "logic",
        "description": "Pointer used after NULL check without return (null deref in error path)",
        "multiline": True,
    },
    "missing_length_before_memcpy": {
        "pattern": r"memcpy\s*\([^,]+,\s*[^,]+,\s*(\w+)\s*\)(?:(?!if\s*\(\s*\1)[\s\S]){0,0}",
        "severity": "medium",
        "category": "overflow",
        "description": "memcpy with size variable not validated in visible scope",
    },
}


def register(subparsers):
    p = subparsers.add_parser("vuln", help="Scan for vulnerability patterns")
    p.add_argument("binary", nargs="?", default=None, help="Path to binary")
    p.add_argument("--from-triage", type=str, default=None, metavar="FILE_OR_DASH",
                   help="Use pre-parsed triage output (file path or '-' for stdin)")
    p.add_argument("--static", action="store_true", default=True,
                   help="Static analysis (imports + strings, fast)")
    p.add_argument("--decompiled", action="store_true",
                   help="Analyze Ghidra decompiled output (slow)")
    p.add_argument("--chrome", action="store_true",
                   help="Chrome/Chromium-specific vulnerability scanning (Mojo IPC, V8, sandbox)")
    p.add_argument("--category", type=str, default="all",
                   choices=["overflow", "format", "integer", "uaf", "race",
                            "type", "heap", "injection", "logic", "info_leak",
                            "chrome", "mojo", "v8", "all"],
                   help="Filter by vulnerability category")
    p.add_argument("--severity", type=str, default="all",
                   choices=["high", "medium", "low", "all"],
                   help="Filter by severity")
    p.add_argument("--compact", action="store_true",
                   help="Compact output: consolidate import findings, size-aware severity, Chrome dedup")
    p.add_argument("--context", type=int, default=3)
    add_output_args(p)
    p.set_defaults(func=run)


# Common imports that are expected in large binaries (>50MB) and should be
# downgraded from medium → low severity to reduce noise
_LARGE_BINARY_EXPECTED_IMPORTS = {
    "memcpy", "memmove", "malloc", "free", "realloc", "calloc",
    "strlen", "memset", "memcmp", "mmap", "munmap",
}


def _compact_findings(findings):
    """Group import-based findings by (category, severity) into consolidated entries."""
    import_findings = []
    non_import = []

    for f in findings:
        if f.get("evidence", {}).get("type") == "import":
            import_findings.append(f)
        else:
            non_import.append(f)

    # Group by (category, severity)
    groups = {}
    for f in import_findings:
        key = (f["category"], f["severity"])
        groups.setdefault(key, []).append(f)

    compacted = []
    for (cat, sev), group in sorted(groups.items()):
        symbols = [f["evidence"]["symbol"] for f in group]
        compacted.append({
            "id": group[0]["id"],
            "category": cat,
            "severity": sev,
            "title": f"Dangerous imports ({cat}): {', '.join(symbols)}",
            "description": f"{len(symbols)} potentially dangerous {cat}-related "
                           f"function(s) imported",
            "evidence": {
                "type": "import_group",
                "symbols": symbols,
                "count": len(symbols),
            },
            "recommendation": group[0].get("recommendation", ""),
        })

    return compacted + non_import


def run(args):
    out = make_formatter(args)
    findings = []

    # Pipeline mode: use pre-parsed triage output
    triage_data = None
    if getattr(args, 'from_triage', None):
        from cb.output import load_piped_input
        if args.from_triage == "-":
            triage_data = load_piped_input()
        else:
            import json as json_mod
            with open(args.from_triage) as f:
                triage_data = json_mod.load(f)
        if triage_data:
            out.status("Using pre-parsed triage data...")
            findings.extend(_scan_from_triage(triage_data, args, out))

    if not triage_data:
        if not args.binary:
            out.emit({"error": "Binary path required (or use --from-triage)"}, "vuln")
            return

        # Check cache for static analysis
        cache_args = {
            "category": args.category,
            "severity": args.severity,
            "decompiled": args.decompiled,
            "chrome": getattr(args, "chrome", False),
        }
        if not getattr(args, "no_cache", False):
            try:
                from cb.result_cache import ResultCache
                cache = ResultCache()
                cached = cache.get(args.binary, "vuln", cache_args)
                if cached:
                    cached.setdefault("_meta", {})["cached"] = True
                    out.emit(cached, "vuln")
                    return
            except Exception:
                pass

        # Static analysis (always run unless --decompiled-only)
        out.status("Running static vulnerability scan...")
        findings.extend(scan_static(args.binary, args, out))

    # Chrome/Chromium-specific analysis
    if getattr(args, 'chrome', False) and args.binary:
        out.status("Running Chrome/Chromium-specific vulnerability scan...")
        findings.extend(scan_chrome_static(args.binary, args, out))

    # Decompiled analysis (if requested)
    if args.decompiled:
        out.status("Running decompiled code analysis (requires Ghidra)...")
        findings.extend(scan_decompiled(args.binary, args, out))

    # Chrome dedup: when --chrome + --compact, remove generic import findings
    # that overlap with Chrome-specific checks
    if getattr(args, 'compact', False) and getattr(args, 'chrome', False):
        chrome_ids = {f["id"] for f in findings if f["id"].startswith("CHROME-")}
        chrome_symbols = set()
        for f in findings:
            if f["id"].startswith("CHROME-"):
                matched = f.get("evidence", {}).get("matched_symbols", [])
                chrome_symbols.update(matched)
        # Remove STATIC findings whose symbol is already covered by Chrome findings
        findings = [
            f for f in findings
            if not (f["id"].startswith("STATIC-")
                    and f.get("evidence", {}).get("type") == "import"
                    and f.get("evidence", {}).get("symbol") in chrome_symbols)
        ]

    # Filter by category and severity
    if args.category != "all":
        findings = [f for f in findings if f.get("category") == args.category]
    if args.severity != "all":
        findings = [f for f in findings if f.get("severity") == args.severity]

    # Compact mode: consolidate import findings
    if getattr(args, 'compact', False):
        findings = _compact_findings(findings)

    # Sort by severity
    sev_order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: sev_order.get(f.get("severity", "low"), 3))

    # Build summary
    summary = {
        "total_findings": len(findings),
        "by_severity": {},
        "by_category": {},
    }
    for f in findings:
        sev = f.get("severity", "unknown")
        cat = f.get("category", "unknown")
        summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1
        summary["by_category"][cat] = summary["by_category"].get(cat, 0) + 1

    result = {
        "summary": summary,
        "findings": findings[:args.max_results],
    }

    # Cache store
    if args.binary and not triage_data and not getattr(args, "no_cache", False):
        try:
            from cb.result_cache import ResultCache
            cache = ResultCache()
            cache.put(args.binary, "vuln", cache_args, result)
        except Exception:
            pass

    out.emit(result, "vuln")


def scan_static(binary_path, args, out):
    """Static analysis based on imports and strings."""
    findings = []
    finding_id = 0

    # Check binary size for severity adjustments
    try:
        binary_size = os.path.getsize(binary_path)
    except OSError:
        binary_size = 0
    is_large_binary = binary_size > 50_000_000  # >50MB
    compact = getattr(args, 'compact', False)

    # Analyze imports
    imports = get_imports(binary_path)
    import_set = {i.lstrip("_") for i in imports}

    for severity, categories in DANGEROUS_IMPORTS.items():
        for category, funcs in categories.items():
            for func in funcs:
                if func in import_set:
                    finding_id += 1
                    effective_severity = severity
                    # Large binaries: downgrade expected standard-lib imports
                    if is_large_binary and compact and \
                       func in _LARGE_BINARY_EXPECTED_IMPORTS and \
                       severity == "medium":
                        effective_severity = "low"
                    findings.append({
                        "id": f"STATIC-{finding_id:03d}",
                        "category": category,
                        "severity": effective_severity,
                        "title": f"Dangerous function imported: {func}",
                        "description": f"Binary imports {func} which is known to be "
                                       f"potentially dangerous ({category} risk)",
                        "evidence": {
                            "type": "import",
                            "symbol": func,
                        },
                        "recommendation": _get_recommendation(func),
                    })

    # String-based indicators
    strings_data = get_strings(binary_path, min_length=4, max_count=500)

    # Check for format strings with %n (write-what-where)
    for s in strings_data["categories"].get("format_strings", []):
        if "%n" in s:
            finding_id += 1
            findings.append({
                "id": f"STATIC-{finding_id:03d}",
                "category": "format",
                "severity": "high",
                "title": "Format string with %n specifier found",
                "description": f"String containing %n: \"{s[:80]}\"",
                "evidence": {"type": "string", "value": s[:100]},
                "recommendation": "Investigate all uses of this format string",
            })

    # Check for hardcoded credentials/keys
    cred_patterns = [
        (r"password\s*=\s*['\"][^'\"]+", "Hardcoded password"),
        (r"api[_-]?key\s*=\s*['\"][^'\"]+", "Hardcoded API key"),
        (r"secret\s*=\s*['\"][^'\"]+", "Hardcoded secret"),
        (r"-----BEGIN (?:RSA )?PRIVATE KEY-----", "Embedded private key"),
    ]
    all_strings_flat = []
    for cat_strings in strings_data["categories"].values():
        all_strings_flat.extend(cat_strings)

    for pattern, title in cred_patterns:
        for s in all_strings_flat:
            if re.search(pattern, s, re.IGNORECASE):
                finding_id += 1
                findings.append({
                    "id": f"STATIC-{finding_id:03d}",
                    "category": "info_leak",
                    "severity": "medium",
                    "title": title,
                    "description": f"Found in binary strings: \"{s[:60]}...\"",
                    "evidence": {"type": "string", "value": s[:100]},
                    "recommendation": "Remove hardcoded credentials",
                })
                break  # One finding per pattern type

    # Logic bug indicators via import analysis
    # Check for memory allocation without overflow checks
    alloc_funcs = {"malloc", "calloc", "realloc", "mmap"} & import_set
    overflow_checks = {"__builtin_mul_overflow", "__builtin_add_overflow",
                       "os_mul_overflow", "os_add_overflow",
                       "safe_math", "checked_multiply"} & import_set
    if alloc_funcs and not overflow_checks:
        finding_id += 1
        findings.append({
            "id": f"STATIC-{finding_id:03d}",
            "category": "logic",
            "severity": "medium",
            "title": "Memory allocation without safe integer arithmetic",
            "description": f"Uses {', '.join(sorted(alloc_funcs))} but no overflow-safe "
                           f"arithmetic (os_mul_overflow, __builtin_mul_overflow, etc.)",
            "evidence": {"type": "import_pattern", "present": sorted(alloc_funcs),
                         "missing": ["overflow-safe arithmetic"]},
            "recommendation": "Use os_mul_overflow / __builtin_mul_overflow before allocation",
        })

    # Check for mach_msg without audit_token validation
    mach_funcs = {"mach_msg", "mach_msg_send", "mach_msg_receive"} & import_set
    audit_funcs = {"audit_token_to_pid", "audit_token_to_euid",
                   "SecTaskCreateWithAuditToken"} & import_set
    if mach_funcs and not audit_funcs:
        finding_id += 1
        findings.append({
            "id": f"STATIC-{finding_id:03d}",
            "category": "logic",
            "severity": "high",
            "title": "Mach IPC without sender validation",
            "description": "Uses mach_msg but no audit token validation detected. "
                           "Any process may be able to send messages.",
            "evidence": {"type": "import_pattern", "present": sorted(mach_funcs),
                         "missing": ["audit_token validation"]},
            "recommendation": "Validate sender identity via audit token before "
                              "processing Mach messages",
        })

    # Check for NSKeyedUnarchiver without NSSecureCoding
    all_strings_text = " ".join(all_strings_flat)
    if "NSKeyedUnarchiver" in all_strings_text:
        if "NSSecureCoding" not in all_strings_text and \
           "unarchivedObjectOfClasses" not in all_strings_text:
            finding_id += 1
            findings.append({
                "id": f"STATIC-{finding_id:03d}",
                "category": "logic",
                "severity": "high",
                "title": "NSKeyedUnarchiver without NSSecureCoding",
                "description": "Uses NSKeyedUnarchiver but NSSecureCoding / "
                               "unarchivedObjectOfClasses not detected. "
                               "Vulnerable to deserialization type confusion.",
                "evidence": {"type": "string_pattern",
                             "present": ["NSKeyedUnarchiver"],
                             "missing": ["NSSecureCoding"]},
                "recommendation": "Use unarchivedObjectOfClasses:fromData:error: "
                                  "with restricted class allowlist",
            })

    return findings


def scan_chrome_static(binary_path, args, out):
    """Chrome/Chromium-specific static vulnerability analysis.

    Detects Mojo IPC lifetime issues, V8 JIT attack surface, sandbox
    escape indicators, and Chrome-specific pattern misuse.
    Based on CVE analysis: CVE-2025-2783, CVE-2024-9369, CVE-2024-1284, etc.
    """
    findings = []
    finding_id = 0

    try:
        from cb.patterns.chrome_patterns import (
            CHROME_DANGEROUS_SYMBOLS, SANDBOX_ESCAPE_INDICATORS,
        )
    except ImportError:
        out.status("Warning: chrome_patterns not available")
        return findings

    imports = get_imports(binary_path)
    import_set = {i.lstrip("_") for i in imports}
    strings_data = get_strings(binary_path, min_length=4, max_count=1000)
    all_strings_flat = []
    for cat_strings in strings_data["categories"].values():
        all_strings_flat.extend(cat_strings)
    all_strings_text = " ".join(all_strings_flat)

    # Check for Chrome dangerous symbol categories
    for component, info in CHROME_DANGEROUS_SYMBOLS.items():
        matched = [s for s in info["symbols"] if s in import_set or s in all_strings_text]
        if matched:
            finding_id += 1
            findings.append({
                "id": f"CHROME-{finding_id:03d}",
                "category": "chrome",
                "severity": info["risk"],
                "title": f"Chrome {component} attack surface detected",
                "description": info["description"],
                "evidence": {
                    "type": "chrome_symbols",
                    "component": component,
                    "matched_symbols": matched[:10],
                },
                "recommendation": f"Review {component} usage for known vulnerability patterns",
            })

    # Mojo IPC: MakeSelfOwnedReceiver without FrameServiceBase
    mojo_self_owned = any(s in all_strings_text for s in
                          ["MakeSelfOwnedReceiver", "SelfOwnedReceiver"])
    mojo_safe_base = any(s in all_strings_text for s in
                         ["FrameServiceBase", "DocumentService", "WebContentsObserver"])
    if mojo_self_owned and not mojo_safe_base:
        finding_id += 1
        findings.append({
            "id": f"CHROME-{finding_id:03d}",
            "category": "mojo",
            "severity": "high",
            "title": "MakeSelfOwnedReceiver without safe lifecycle base class",
            "description": "Mojo SelfOwnedReceiver detected without FrameServiceBase or "
                           "DocumentService inheritance. Raw pointer stored in receiver may "
                           "outlive the referenced object (UAF risk). "
                           "See: CVE-2024-1284, CVE-2019-13688.",
            "evidence": {
                "type": "chrome_pattern",
                "present": ["MakeSelfOwnedReceiver"],
                "missing": ["FrameServiceBase", "DocumentService"],
            },
            "recommendation": "Inherit from FrameServiceBase or DocumentService to tie "
                              "receiver lifetime to the frame. Or use weak pointers.",
        })

    # Mojo IPC: base::Unretained usage
    unretained_present = "Unretained" in all_strings_text
    if unretained_present:
        finding_id += 1
        findings.append({
            "id": f"CHROME-{finding_id:03d}",
            "category": "mojo",
            "severity": "high",
            "title": "base::Unretained callback pattern detected",
            "description": "base::Unretained captures raw pointer in async callback. "
                           "If the callback executes after the object is freed, UAF occurs. "
                           "37.5%% of Chrome UAFs attributed to this pattern.",
            "evidence": {
                "type": "chrome_pattern",
                "matched": ["base::Unretained"],
            },
            "recommendation": "Use base::WeakPtr or ref-counted pointers instead of "
                              "base::Unretained. Check cross-thread callback posting.",
        })

    # Mojo IPC: Missing ReportBadMessage
    has_mojo_handlers = any(s in all_strings_text for s in
                            ["Stub::Accept", "mojo::Receiver", "PendingReceiver"])
    has_report_bad = any(s in all_strings_text for s in
                         ["ReportBadMessage", "GetBadMessageCallback"])
    if has_mojo_handlers and not has_report_bad:
        finding_id += 1
        findings.append({
            "id": f"CHROME-{finding_id:03d}",
            "category": "mojo",
            "severity": "medium",
            "title": "Mojo handlers without ReportBadMessage",
            "description": "Mojo interface handlers detected but no ReportBadMessage calls. "
                           "Invalid IPC input may not be properly rejected, leading to "
                           "memory corruption or logic errors. See: CVE-2024-9369, CVE-2022-3075.",
            "evidence": {
                "type": "chrome_pattern",
                "present": ["Mojo handlers"],
                "missing": ["ReportBadMessage"],
            },
            "recommendation": "Call mojo::ReportBadMessage() on all invalid IPC input paths. "
                              "Never use CHECK/DCHECK for IPC input validation.",
        })

    # V8: JIT compilation attack surface
    v8_indicators = [s for s in ["TurboFan", "Maglev", "Turboshaft", "CompileLazy",
                                  "v8::Isolate", "v8::Context"]
                     if s in all_strings_text]
    if v8_indicators:
        finding_id += 1
        findings.append({
            "id": f"CHROME-{finding_id:03d}",
            "category": "v8",
            "severity": "medium",
            "title": "V8 JIT compilation surface detected",
            "description": f"V8 JIT components present: {', '.join(v8_indicators)}. "
                           "JIT compilers are the primary source of type confusion bugs "
                           "(CVE-2024-5274, CVE-2024-7971).",
            "evidence": {
                "type": "chrome_symbols",
                "component": "v8_engine",
                "matched_symbols": v8_indicators,
            },
            "recommendation": "Audit JIT compiler optimizations for type confusion. "
                              "Check bounds check elimination and type guard correctness.",
        })

    # Sandbox escape indicators
    for indicator_name, indicator_data in SANDBOX_ESCAPE_INDICATORS.items():
        matched = [s for s in indicator_data["symbols"]
                   if s in import_set or s in all_strings_text]
        if matched and len(matched) >= indicator_data.get("min_matches", 1):
            finding_id += 1
            severity = indicator_data.get("severity",
                                          indicator_data.get("risk", "medium"))
            findings.append({
                "id": f"CHROME-{finding_id:03d}",
                "category": "chrome",
                "severity": severity,
                "title": f"Sandbox escape indicator: {indicator_name}",
                "description": indicator_data["description"],
                "evidence": {
                    "type": "sandbox_escape",
                    "indicator": indicator_name,
                    "matched_symbols": matched[:10],
                },
                "recommendation": indicator_data.get("recommendation",
                    "Review sandbox boundary for escape vectors"),
            })

    # Chrome-specific entitlement checks
    try:
        from cb.macho import get_entitlements
        ents = get_entitlements(binary_path)
        chrome_ents = {
            "com.apple.security.cs.allow-jit": {
                "severity": "medium",
                "desc": "JIT compilation allowed — V8 needs W^X exception, widens attack surface",
            },
            "com.apple.security.cs.allow-unsigned-executable-memory": {
                "severity": "high",
                "desc": "Unsigned executable memory — enables shellcode execution post-compromise",
            },
            "com.apple.security.cs.disable-library-validation": {
                "severity": "high",
                "desc": "Library validation disabled — dylib injection possible in Chrome helper",
            },
        }
        for ent, info in chrome_ents.items():
            if ent in ents:
                finding_id += 1
                findings.append({
                    "id": f"CHROME-{finding_id:03d}",
                    "category": "chrome",
                    "severity": info["severity"],
                    "title": f"Chrome entitlement: {ent}",
                    "description": info["desc"],
                    "evidence": {"type": "entitlement", "entitlement": ent},
                    "recommendation": "Verify this entitlement is minimally scoped and required",
                })
    except Exception:
        pass

    return findings


def scan_decompiled(binary_path, args, out):
    """Scan Ghidra decompiled output for vulnerability patterns."""
    findings = []

    try:
        from cb.ghidra_bridge import run_ghidra_script
    except ImportError:
        out.status("Warning: Ghidra bridge not available")
        return findings

    # Use Ghidra search to find vulnerability patterns
    for name, pattern_info in DECOMPILED_PATTERNS.items():
        if args.category != "all" and pattern_info["category"] != args.category:
            continue

        try:
            result = run_ghidra_script(
                binary_path, "SearchDecompiled.java",
                [pattern_info["pattern"], str(args.max_results)]
            )
            if result and result.get("matches"):
                for match in result["matches"][:10]:
                    findings.append({
                        "id": f"DECOMP-{len(findings)+1:03d}",
                        "category": pattern_info["category"],
                        "severity": pattern_info["severity"],
                        "title": pattern_info["description"],
                        "description": f"Pattern '{name}' matched in {match.get('function', 'unknown')}",
                        "evidence": {
                            "type": "decompiled",
                            "function": match.get("function", ""),
                            "address": match.get("address", ""),
                            "snippet": match.get("snippet", "")[:200],
                        },
                        "recommendation": f"Review {match.get('function', 'this function')} "
                                           f"for {pattern_info['category']} vulnerability",
                    })
        except Exception as e:
            out.status(f"Warning: Ghidra search for '{name}' failed: {e}")

    return findings


def _get_recommendation(func):
    recs = {
        "strcpy": "Replace with strlcpy or strncpy with proper bounds",
        "strcat": "Replace with strlcat or strncat with proper bounds",
        "gets": "Replace with fgets with explicit buffer size",
        "sprintf": "Replace with snprintf with buffer size limit",
        "scanf": "Use width specifiers (e.g., %255s) to limit input",
        "printf": "Ensure format string is constant, not user-controlled",
        "system": "Avoid system() - use execve() with explicit argv",
        "popen": "Avoid popen() - use fork+exec with explicit argv",
        "memcpy": "Verify size argument is validated against buffer capacity",
        "free": "Set pointer to NULL after free to prevent use-after-free",
        "access": "Use fstat on opened fd instead (TOCTOU prevention)",
        "tmpnam": "Use mkstemp() instead for safe temp file creation",
    }
    return recs.get(func, f"Review all call sites of {func} for proper usage")


def _scan_from_triage(triage_data, args, out):
    """Scan using pre-parsed triage data (piped from cb triage)."""
    findings = []
    finding_id = 0

    # Extract imports from triage data
    imports_data = triage_data.get("imports", [])
    if isinstance(imports_data, dict):
        imports_data = imports_data.get("symbols", imports_data.get("imports", []))
    import_set = {i.lstrip("_") for i in imports_data if isinstance(i, str)}

    # Extract strings
    strings_data = triage_data.get("strings", {})
    if isinstance(strings_data, dict):
        categories = strings_data.get("categories", {})
    else:
        categories = {}

    # Run the same dangerous import checks
    for severity, cat_funcs in DANGEROUS_IMPORTS.items():
        for category, funcs in cat_funcs.items():
            for func in funcs:
                if func in import_set:
                    finding_id += 1
                    findings.append({
                        "id": f"PIPE-{finding_id:03d}",
                        "category": category,
                        "severity": severity,
                        "title": f"Dangerous function imported: {func}",
                        "description": f"Binary imports {func} ({category} risk)",
                        "evidence": {"type": "import", "symbol": func},
                        "recommendation": _get_recommendation(func),
                        "source": "piped_triage",
                    })

    # Check for allocation without overflow checks
    alloc_funcs = {"malloc", "calloc", "realloc", "mmap"} & import_set
    overflow_checks = {"__builtin_mul_overflow", "__builtin_add_overflow",
                       "os_mul_overflow", "os_add_overflow"} & import_set
    if alloc_funcs and not overflow_checks:
        finding_id += 1
        findings.append({
            "id": f"PIPE-{finding_id:03d}",
            "category": "logic",
            "severity": "medium",
            "title": "Memory allocation without safe integer arithmetic",
            "description": f"Uses {', '.join(sorted(alloc_funcs))} without overflow checks",
            "evidence": {"type": "import_pattern", "present": sorted(alloc_funcs)},
            "recommendation": "Use os_mul_overflow before allocation",
            "source": "piped_triage",
        })

    return findings


def main():
    parser = argparse.ArgumentParser(prog="cbvuln", description="Vulnerability scanner")
    parser.add_argument("binary", nargs="?", default=None, help="Path to binary")
    parser.add_argument("--from-triage", type=str, default=None)
    parser.add_argument("--static", action="store_true", default=True)
    parser.add_argument("--decompiled", action="store_true")
    parser.add_argument("--chrome", action="store_true",
                        help="Chrome/Chromium-specific vulnerability scanning")
    parser.add_argument("--compact", action="store_true",
                        help="Compact output: consolidate, size-aware severity, Chrome dedup")
    parser.add_argument("--category", type=str, default="all",
                        choices=["overflow", "format", "integer", "uaf", "race",
                                 "type", "heap", "injection", "logic", "info_leak",
                                 "chrome", "mojo", "v8", "all"])
    parser.add_argument("--severity", type=str, default="all",
                        choices=["high", "medium", "low", "all"])
    parser.add_argument("--context", type=int, default=3)
    add_output_args(parser)
    args = parser.parse_args()
    run(args)
