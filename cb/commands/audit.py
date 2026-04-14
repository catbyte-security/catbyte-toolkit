"""cb audit - Consolidated security audit pipeline."""
import argparse
import os
import sys
import time

from cb.output import add_output_args, make_formatter


def register(subparsers):
    p = subparsers.add_parser("audit", help="Full security audit (runs all analysis)")
    p.add_argument("binary", help="Path to binary or .app bundle")
    p.add_argument("--skip", nargs="*", default=[],
                   choices=["triage", "attack", "vuln", "objc", "ipc",
                            "sandbox", "variant"],
                   help="Skip specific analyses")
    p.add_argument("--deep", action="store_true",
                   help="Also run Ghidra-based analysis (taint, callgraph)")
    p.add_argument("--timeout", type=int, default=120,
                   help="Per-command timeout in seconds")
    add_output_args(p)
    p.set_defaults(func=run)


def run(args):
    out = make_formatter(args)
    binary = args.binary
    skip = set(args.skip)

    # Resolve app bundle
    actual_binary = binary
    bundle_path = None
    if binary.endswith(".app"):
        bundle_path = binary
        import plistlib
        info_plist = os.path.join(binary, "Contents", "Info.plist")
        if os.path.exists(info_plist):
            with open(info_plist, "rb") as f:
                plist = plistlib.load(f)
            exec_name = plist.get("CFBundleExecutable", "")
            if exec_name:
                actual_binary = os.path.join(binary, "Contents", "MacOS", exec_name)

    report = {
        "target": binary,
        "binary": actual_binary,
        "sections": {},
    }

    # Phase 1: Quick static analysis
    analyses = [
        ("triage", _run_triage),
        ("attack", _run_attack),
        ("vuln", _run_vuln),
        ("objc", _run_objc),
        ("ipc", _run_ipc),
        ("sandbox", _run_sandbox),
        ("variant", _run_variant),
    ]

    risk_scores = []
    total_findings = 0

    for name, func in analyses:
        if name in skip:
            continue
        out.status(f"Running {name} analysis...")
        t0 = time.time()
        try:
            section = func(binary, actual_binary, args)
            elapsed = round(time.time() - t0, 2)
            section["_time"] = elapsed
            report["sections"][name] = section

            # Collect risk indicators
            findings = _count_findings(name, section)
            total_findings += findings
            risk = section.get("risk_level") or section.get("summary", {}).get("risk_level")
            if risk:
                risk_scores.append(risk)
        except Exception as e:
            report["sections"][name] = {"error": str(e)}

    # Phase 2: Deep analysis (optional)
    if args.deep:
        for name, func in [("taint", _run_taint), ("callgraph", _run_callgraph)]:
            if name in skip:
                continue
            out.status(f"Running {name} deep analysis (Ghidra required)...")
            t0 = time.time()
            try:
                section = func(actual_binary, args)
                section["_time"] = round(time.time() - t0, 2)
                report["sections"][name] = section
            except Exception as e:
                report["sections"][name] = {"error": str(e)}

    # Consolidated risk assessment
    report["risk_assessment"] = _compute_overall_risk(report, risk_scores, total_findings)

    # Executive summary
    report["executive_summary"] = _build_summary(report)

    out.emit(report, "audit")


def _run_triage(binary, actual_binary, args):
    from cb.commands.triage import _triage_macho, _triage_elf
    from cb.macho import detect_format
    from cb.output import OutputFormatter
    out = OutputFormatter(quiet=True)

    class TriageArgs:
        checksec = False
        no_sections = False
        no_imports = False
        no_exports = True  # skip exports to save space in audit
        no_strings = False
        strings_min = 6
        strings_max = 15
        full = False
        max_results = args.max_results

    ta = TriageArgs()
    fmt = detect_format(actual_binary)
    if fmt.startswith("macho") or fmt == "fat":
        return _triage_macho(actual_binary, ta, out)
    elif fmt == "elf":
        return _triage_elf(actual_binary, ta, out)
    return {"format": fmt, "note": "Unsupported format for triage"}


def _run_attack(binary, actual_binary, args):
    from cb.macho import get_imports
    from cb.commands.attack import (discover_bundle, analyze_entitlements,
                                     analyze_ipc, analyze_parsers,
                                     analyze_network, compute_attack_surface_score)
    from cb.output import OutputFormatter

    is_bundle = binary.endswith(".app")
    out = OutputFormatter(quiet=True)

    if is_bundle:
        binaries, bundle_info = discover_bundle(binary, out)
    else:
        binaries = [actual_binary]
        bundle_info = None

    all_imports = set()
    for b in binaries:
        try:
            all_imports.update(get_imports(b))
        except Exception:
            pass

    result = {}
    if bundle_info:
        result["bundle_info"] = bundle_info
    result["entitlements"] = analyze_entitlements(binaries[0] if binaries else actual_binary)
    result["ipc"] = analyze_ipc(all_imports, binary if is_bundle else None)
    result["parsers"] = analyze_parsers(all_imports)
    result["network"] = analyze_network(all_imports)
    result["summary"] = compute_attack_surface_score(result)

    return result


def _run_vuln(binary, actual_binary, args):
    from cb.commands.vuln import scan_static
    from cb.output import OutputFormatter
    out = OutputFormatter(quiet=True)

    class VulnArgs:
        pass
    va = VulnArgs()
    va.binary = actual_binary
    va.max_results = args.max_results
    va.category = "all"
    findings = scan_static(actual_binary, va, out)

    sev_counts = {}
    cat_counts = {}
    for f in findings:
        sev = f.get("severity", "unknown")
        cat = f.get("category", "unknown")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    return {
        "total_findings": len(findings),
        "by_severity": sev_counts,
        "by_category": cat_counts,
        "top_findings": findings[:15],
    }


def _run_objc(binary, actual_binary, args):
    from cb.macho import get_objc_classes, get_objc_selectors
    from cb.commands.objc import DANGEROUS_SELECTORS, _categorize_selector

    classes = get_objc_classes(actual_binary)
    selectors = get_objc_selectors(actual_binary)
    selector_set = set(selectors)

    dangerous = []
    for sel in DANGEROUS_SELECTORS:
        if sel in selector_set:
            cat = _categorize_selector(sel)
            dangerous.append({"selector": sel, **cat})

    return {
        "total_classes": len(classes),
        "total_selectors": len(selectors),
        "dangerous_patterns": dangerous,
        "total_dangerous": len(dangerous),
    }


def _run_ipc(binary, actual_binary, args):
    from cb.macho import get_imports, get_strings, get_objc_selectors
    from cb.commands.ipc import (analyze_xpc, analyze_mach, analyze_mig,
                                  find_handlers, assess_ipc_security,
                                  analyze_app_bundle_ipc)
    from cb.output import OutputFormatter

    imports = get_imports(actual_binary)
    import_set = {i.lstrip("_") for i in imports}
    selectors = get_objc_selectors(actual_binary)
    strings_data = get_strings(actual_binary, min_length=4, max_count=2000)
    out = OutputFormatter(quiet=True)

    result = {}
    if binary.endswith(".app"):
        result["bundle"] = analyze_app_bundle_ipc(binary, out)

    result["xpc"] = analyze_xpc(actual_binary, import_set, selectors, strings_data)
    result["mach"] = analyze_mach(actual_binary, import_set, strings_data)
    result["mig"] = analyze_mig(actual_binary, import_set)
    result["handlers"] = find_handlers(actual_binary, import_set, selectors)
    result["security"] = assess_ipc_security(result, import_set, selectors)

    return {
        "handler_count": result["handlers"]["total"],
        "xpc_services": len(result.get("bundle", {}).get("xpc_services", [])),
        "security_issues": result["security"]["total_issues"],
        "risk_level": result["security"]["risk_level"],
        "has_auth": result["security"]["has_auth_checks"],
        "issues": result["security"]["issues"],
    }


def _run_sandbox(binary, actual_binary, args):
    from cb.macho import get_entitlements
    from cb.commands.sandbox import ESCAPE_VECTORS, _compute_risk

    entitlements = get_entitlements(actual_binary)
    sandboxed = entitlements.get("com.apple.security.app-sandbox", False)

    escapes = []
    for ent_key, ent_val in entitlements.items():
        if not ent_val:
            continue
        for pattern, info in ESCAPE_VECTORS.items():
            if pattern in ent_key:
                escapes.append({"entitlement": ent_key, **info})

    temp_exceptions = [k for k in entitlements if "temporary-exception" in k]

    result = {
        "entitlements": {"sandboxed": sandboxed, "total": len(entitlements),
                         "raw": entitlements},
        "escape_vectors": {"total": len(escapes), "findings": escapes},
    }
    result["risk_level"] = _compute_risk(result)

    return {
        "sandboxed": sandboxed,
        "total_entitlements": len(entitlements),
        "escape_vectors": len(escapes),
        "critical_escapes": len([e for e in escapes if e.get("severity") == "critical"]),
        "temp_exceptions": len(temp_exceptions),
        "risk_level": result["risk_level"],
        "escapes": escapes,
    }


def _run_variant(binary, actual_binary, args):
    from cb.commands.variant import static_variant_scan, KNOWN_PATTERNS
    from cb.output import OutputFormatter
    out = OutputFormatter(quiet=True)
    variants = static_variant_scan(actual_binary, KNOWN_PATTERNS, out)
    sev_counts = {}
    for v in variants:
        sev = v.get("severity", "unknown")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    return {
        "total_variants": len(variants),
        "by_severity": sev_counts,
        "top_variants": variants[:10],
    }


def _run_taint(actual_binary, args):
    from cb.ghidra_bridge import run_ghidra_script
    return run_ghidra_script(
        actual_binary, "TaintAnalysis.java",
        ["auto", "5", "20"], timeout=args.timeout,
    )


def _run_callgraph(actual_binary, args):
    from cb.ghidra_bridge import run_ghidra_script
    return run_ghidra_script(
        actual_binary, "CallGraph.java",
        ["sinks", "5", "20"], timeout=args.timeout,
    )


def _count_findings(name, section):
    """Count security-relevant findings from a section."""
    if name == "vuln":
        return section.get("total_findings", 0)
    if name == "variant":
        return section.get("total_variants", 0)
    if name == "objc":
        return section.get("total_dangerous", 0)
    if name == "ipc":
        return section.get("security_issues", 0)
    if name == "sandbox":
        return section.get("escape_vectors", 0)
    return 0


def _compute_overall_risk(report, risk_scores, total_findings):
    """Compute overall risk from all sections."""
    if "critical" in risk_scores:
        overall = "critical"
    elif "high" in risk_scores or total_findings > 15:
        overall = "high"
    elif "medium" in risk_scores or total_findings > 5:
        overall = "medium"
    else:
        overall = "low"

    return {
        "overall_risk": overall,
        "total_findings": total_findings,
        "section_risks": {s: d.get("risk_level", "unknown")
                          for s, d in report["sections"].items()
                          if isinstance(d, dict) and "risk_level" in d},
    }


def _build_summary(report):
    """Build executive summary of key findings."""
    lines = []
    sections = report["sections"]

    # Triage
    t = sections.get("triage", {})
    prot = t.get("protections", {})
    if prot:
        missing = [k for k, v in prot.items() if v is False]
        if missing:
            lines.append(f"Missing protections: {', '.join(missing)}")

    # Sandbox
    sb = sections.get("sandbox", {})
    if sb and not sb.get("error"):
        if not sb.get("sandboxed"):
            lines.append("NOT SANDBOXED - full system access")
        if sb.get("critical_escapes", 0) > 0:
            lines.append(f"{sb['critical_escapes']} critical sandbox escape vectors")

    # IPC
    ipc = sections.get("ipc", {})
    if ipc and not ipc.get("error"):
        if ipc.get("security_issues", 0) > 0 and not ipc.get("has_auth"):
            lines.append(f"IPC: {ipc['security_issues']} issues, NO auth checks")

    # Vuln
    vuln = sections.get("vuln", {})
    if vuln and not vuln.get("error"):
        high = vuln.get("by_severity", {}).get("high", 0)
        if high > 0:
            lines.append(f"Vuln scanner: {high} high-severity findings")

    # Variant
    var = sections.get("variant", {})
    if var and not var.get("error"):
        crit = var.get("by_severity", {}).get("critical", 0)
        if crit > 0:
            lines.append(f"Variant scanner: {crit} critical CVE-pattern matches")

    # ObjC
    objc = sections.get("objc", {})
    if objc and not objc.get("error"):
        if objc.get("total_dangerous", 0) > 0:
            lines.append(f"ObjC: {objc['total_dangerous']} dangerous patterns")

    risk = report.get("risk_assessment", {}).get("overall_risk", "unknown")
    lines.insert(0, f"Overall risk: {risk.upper()}")

    return lines


def main():
    parser = argparse.ArgumentParser(prog="cbaudit", description="Full security audit")
    parser.add_argument("binary")
    parser.add_argument("--skip", nargs="*", default=[],
                        choices=["triage", "attack", "vuln", "objc", "ipc",
                                 "sandbox", "variant"])
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--timeout", type=int, default=120)
    add_output_args(parser)
    args = parser.parse_args()
    run(args)
