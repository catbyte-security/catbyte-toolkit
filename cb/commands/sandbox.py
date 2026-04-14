"""cb sandbox - macOS sandbox profile and entitlement deep analysis."""
import argparse
import os
import re
import subprocess
import sys

from cb.output import add_output_args, make_formatter
from cb.macho import get_entitlements, get_imports, _run
from cb.patterns.dangerous_functions import DANGEROUS_ENTITLEMENTS, IMPORT_CATEGORIES


# Sandbox operations and what they allow
SANDBOX_OPERATIONS = {
    "file-read*": "Read any file",
    "file-write*": "Write any file",
    "file-read-data": "Read file data",
    "file-write-data": "Write file data",
    "file-read-metadata": "Read file metadata",
    "file-write-create": "Create new files",
    "file-write-unlink": "Delete files",
    "process-exec": "Execute programs",
    "process-fork": "Fork processes",
    "signal": "Send signals to processes",
    "sysctl-read": "Read sysctl values",
    "sysctl-write": "Write sysctl values",
    "mach-lookup": "Look up Mach services",
    "mach-register": "Register Mach services",
    "ipc-posix-shm-read*": "Read POSIX shared memory",
    "ipc-posix-shm-write*": "Write POSIX shared memory",
    "network-outbound": "Make outbound connections",
    "network-inbound": "Accept inbound connections",
    "network-bind": "Bind to network ports",
    "system-socket": "Create sockets",
    "iokit-open": "Open IOKit connections",
    "iokit-get-properties": "Read IOKit properties",
    "iokit-set-properties": "Set IOKit properties",
    "user-preference-read": "Read user preferences",
    "user-preference-write": "Write user preferences",
    "lsopen": "Open URLs via Launch Services",
    "distributed-notification-post": "Post distributed notifications",
}

# Escape vectors: entitlements/capabilities that weaken sandbox
ESCAPE_VECTORS = {
    "com.apple.security.cs.disable-library-validation": {
        "vector": "DYLIB injection via unsigned library loading",
        "severity": "critical",
    },
    "com.apple.security.cs.allow-dyld-environment-variables": {
        "vector": "DYLD_INSERT_LIBRARIES injection",
        "severity": "critical",
    },
    "com.apple.security.cs.allow-unsigned-executable-memory": {
        "vector": "JIT spraying / shellcode in RWX memory",
        "severity": "high",
    },
    "com.apple.security.cs.debugger": {
        "vector": "Attach to other processes via task_for_pid",
        "severity": "critical",
    },
    "com.apple.private.security.no-sandbox": {
        "vector": "No sandbox at all - full system access",
        "severity": "critical",
    },
    "com.apple.security.temporary-exception.mach-lookup.global-name": {
        "vector": "Can look up arbitrary Mach services (sandbox exception)",
        "severity": "high",
    },
    "com.apple.security.temporary-exception.files.absolute-path.read-write": {
        "vector": "Can read/write arbitrary paths (sandbox exception)",
        "severity": "high",
    },
}


# IOKit user client class → known CVE/risk mapping
IOKIT_CVE_MAP = {
    "IOSurfaceRootUserClient": {
        "cves": ["CVE-2019-8836", "CVE-2020-9839"],
        "risk": "high",
        "note": "Frequently targeted from sandboxed contexts for kernel r/w primitives",
    },
    "IOHIDLibUserClient": {
        "cves": ["CVE-2017-7153", "CVE-2020-9771"],
        "risk": "high",
        "note": "HID driver attack surface, sandbox-reachable on some configs",
    },
    "AGXCommandQueue": {
        "cves": ["CVE-2023-32434", "CVE-2022-32947"],
        "risk": "high",
        "note": "Apple GPU driver, complex attack surface accessible from GPU process",
    },
    "AppleAVE2UserClient": {
        "cves": ["CVE-2020-9907"],
        "risk": "medium",
        "note": "Video encoder, reachable from media sandbox profiles",
    },
    "IOAccelerator": {
        "cves": ["CVE-2023-38611"],
        "risk": "high",
        "note": "GPU accelerator, common kernel exploitation target",
    },
    "AppleSPUProfileDriver": {
        "cves": [],
        "risk": "medium",
        "note": "Signal processing unit driver, limited public research",
    },
    "IOBluetoothHCIUserClient": {
        "cves": ["CVE-2020-3892"],
        "risk": "medium",
        "note": "Bluetooth stack, requires network.bluetooth entitlement",
    },
}


def extract_security_findings(profile_text):
    """Extract security-relevant findings from a sandbox profile.

    Detects:
    - file-issue-extension rules (especially subpath "/" = CRITICAL)
    - iokit-user-client-class names cross-referenced with CVE map
    - Overly broad rules: unrestricted mach-lookup, file-read*/file-write* with subpath "/"
    """
    findings = []

    # 1. file-issue-extension rules
    for m in re.finditer(
        r'\(\s*allow\s+file-issue-extension\s+(.*?)\)', profile_text, re.DOTALL
    ):
        rule_body = m.group(1)
        scope_type = "unknown"
        scope_value = ""

        subpath_m = re.search(r'subpath\s+"([^"]*)"', rule_body)
        literal_m = re.search(r'literal\s+"([^"]*)"', rule_body)
        regex_m = re.search(r'regex\s+"([^"]*)"', rule_body)

        if subpath_m:
            scope_type = "subpath"
            scope_value = subpath_m.group(1)
        elif literal_m:
            scope_type = "literal"
            scope_value = literal_m.group(1)
        elif regex_m:
            scope_type = "regex"
            scope_value = regex_m.group(1)

        severity = "critical" if scope_value == "/" else "medium"
        finding = {
            "type": "file-issue-extension",
            "severity": severity,
            "scope_type": scope_type,
            "scope_value": scope_value,
            "rule": rule_body.strip()[:200],
        }
        if scope_value == "/":
            finding["detail"] = (
                "file-issue-extension with subpath \"/\" allows issuing file extensions "
                "to ANY path on the filesystem. A compromised process can grant read/write "
                "access to arbitrary files to other sandboxed processes."
            )
        findings.append(finding)

    # 2. iokit-user-client-class names
    for m in re.finditer(
        r'iokit-user-client-class\s+"([^"]+)"', profile_text
    ):
        class_name = m.group(1)
        cve_info = IOKIT_CVE_MAP.get(class_name)
        finding = {
            "type": "iokit-user-client-class",
            "class_name": class_name,
        }
        if cve_info:
            finding["severity"] = cve_info["risk"]
            finding["known_cves"] = cve_info["cves"]
            finding["note"] = cve_info["note"]
        else:
            finding["severity"] = "low"
            finding["note"] = "No known CVEs mapped for this IOKit class"
        findings.append(finding)

    # 3. Overly broad mach-lookup (unrestricted)
    if re.search(r'\(\s*allow\s+mach-lookup\s*\)', profile_text):
        findings.append({
            "type": "broad-mach-lookup",
            "severity": "high",
            "detail": "Unrestricted mach-lookup allows connecting to ANY Mach service. "
                      "This effectively negates sandbox IPC restrictions.",
        })

    # 4. Overly broad file-read*/file-write* with subpath "/"
    for op in ["file-read\\*", "file-write\\*", "file-read-data", "file-write-data"]:
        pattern = rf'\(\s*allow\s+{op}\s+[^)]*subpath\s+"/"\s*[^)]*\)'
        if re.search(pattern, profile_text):
            clean_op = op.replace("\\", "")
            findings.append({
                "type": f"broad-{clean_op}",
                "severity": "high",
                "detail": f"{clean_op} with subpath \"/\" grants {clean_op} access "
                          "to the entire filesystem, making the sandbox ineffective "
                          "for file access control.",
            })

    return findings


def register(subparsers):
    p = subparsers.add_parser("sandbox", help="Sandbox profile and entitlement analysis")
    p.add_argument("binary", help="Path to binary or .app bundle")
    p.add_argument("--profile", type=str, default=None,
                   help="Path to .sb sandbox profile (auto-detected for apps)")
    p.add_argument("--escape-vectors", action="store_true", default=True,
                   help="Identify sandbox escape vectors")
    p.add_argument("--capability-map", action="store_true",
                   help="Map entitlements to actual capabilities")
    p.add_argument("--compare-apis", action="store_true",
                   help="Compare used APIs against sandbox restrictions")
    p.add_argument("--reachable-from", type=str, default=None, metavar="BINARY",
                   help="Show root services reachable from a sandboxed binary")
    p.add_argument("--chain", type=str, default=None, metavar="TARGET_SERVICE",
                   help="Analyze attack chain to a target service")
    p.add_argument("--extract-profile", action="store_true",
                   help="Extract embedded sandbox profile from binary")
    add_output_args(p)
    p.set_defaults(func=run)


def run(args):
    out = make_formatter(args)
    result = {}
    binary = args.binary

    # If it's an app bundle, find the binary
    if binary.endswith(".app"):
        import plistlib
        info_plist = os.path.join(binary, "Contents", "Info.plist")
        if os.path.exists(info_plist):
            with open(info_plist, "rb") as f:
                plist = plistlib.load(f)
            exec_name = plist.get("CFBundleExecutable", "")
            if exec_name:
                binary = os.path.join(binary, "Contents", "MacOS", exec_name)

    # Extract embedded sandbox profile
    if getattr(args, 'extract_profile', False):
        from cb.macho import get_embedded_sandbox_profile
        profile = get_embedded_sandbox_profile(binary)
        if profile:
            result["embedded_profile"] = profile
            result["embedded_profile_parsed"] = parse_sandbox_profile_text(profile)

    # Reachability analysis
    if getattr(args, 'reachable_from', None):
        out.status("Analyzing reachable services...")
        result["reachable_services"] = analyze_reachable_services(
            args.reachable_from, out)
        out.emit(result, "sandbox")
        return

    # Chain analysis
    if getattr(args, 'chain', None):
        out.status(f"Analyzing attack chain to {args.chain}...")
        result["chain_analysis"] = analyze_chain(binary, args.chain, out)
        out.emit(result, "sandbox")
        return

    # 1. Entitlements deep analysis
    out.status("Analyzing entitlements...")
    entitlements = get_entitlements(binary)
    result["entitlements"] = {
        "raw": entitlements,
        "total": len(entitlements),
        "sandboxed": entitlements.get("com.apple.security.app-sandbox", False),
    }

    # 2. Escape vector analysis
    out.status("Checking sandbox escape vectors...")
    escape_findings = []
    for ent_key, ent_val in entitlements.items():
        if not ent_val:
            continue
        for pattern, info in ESCAPE_VECTORS.items():
            if pattern in ent_key:
                escape_findings.append({
                    "entitlement": ent_key,
                    "vector": info["vector"],
                    "severity": info["severity"],
                })

    # Check for temporary exceptions (sandbox holes)
    temp_exceptions = [k for k in entitlements.keys()
                       if "temporary-exception" in k]
    for exc in temp_exceptions:
        if exc not in [e["entitlement"] for e in escape_findings]:
            escape_findings.append({
                "entitlement": exc,
                "vector": "Sandbox temporary exception - weakens sandbox restrictions",
                "severity": "medium",
            })

    result["escape_vectors"] = {
        "total": len(escape_findings),
        "findings": escape_findings,
    }

    # 3. Capability mapping
    if args.capability_map:
        out.status("Mapping capabilities...")
        capabilities = []
        for ent_key, ent_val in entitlements.items():
            if not ent_val:
                continue
            cap = _map_capability(ent_key)
            if cap:
                capabilities.append(cap)
        result["capabilities"] = capabilities

    # 4. API vs sandbox comparison
    if args.compare_apis:
        out.status("Comparing used APIs against sandbox profile...")
        imports = get_imports(binary)
        import_set = {i.lstrip("_") for i in imports}

        violations = []
        # Check for APIs that require specific entitlements
        api_entitlement_map = {
            "IOConnectCallMethod": "iokit-open (or com.apple.security.device.*)",
            "IOServiceGetMatchingService": "iokit-open",
            "task_for_pid": "com.apple.security.cs.debugger",
            "ptrace": "com.apple.security.cs.debugger",
            "posix_spawn": "process-exec*",
            "fork": "process-fork",
            "bind": "network-bind / com.apple.security.network.server",
            "accept": "network-inbound / com.apple.security.network.server",
            "connect": "network-outbound / com.apple.security.network.client",
            "dlopen": "com.apple.security.cs.disable-library-validation (for unsigned)",
        }

        for api, needed in api_entitlement_map.items():
            if api in import_set:
                # Check if the corresponding entitlement exists
                has_permission = False
                for ent_key in entitlements:
                    if any(x in ent_key.lower() for x in
                           needed.lower().split(" / ")[0].split(".")):
                        has_permission = True
                        break
                violations.append({
                    "api": api,
                    "requires": needed,
                    "has_entitlement": has_permission,
                    "note": "May fail at runtime" if not has_permission else "Permitted",
                })

        result["api_sandbox_comparison"] = {
            "apis_checked": len(violations),
            "potential_violations": [v for v in violations if not v["has_entitlement"]],
            "permitted_apis": [v for v in violations if v["has_entitlement"]],
        }

    # 5. Sandbox profile analysis (if provided or found)
    profile_path = args.profile
    if not profile_path and args.binary.endswith(".app"):
        # Try to find embedded sandbox profile
        candidate = os.path.join(args.binary, "Contents", "Resources", "*.sb")
        import glob
        profiles = glob.glob(candidate)
        if profiles:
            profile_path = profiles[0]

    if profile_path and os.path.exists(profile_path):
        out.status(f"Parsing sandbox profile: {profile_path}")
        result["sandbox_profile"] = parse_sandbox_profile(profile_path)
        # Extract security findings from the profile
        with open(profile_path) as f:
            profile_content = f.read()
        sec_findings = extract_security_findings(profile_content)
        if sec_findings:
            result["sandbox_security_findings"] = sec_findings

    # Also extract security findings from embedded profile if present
    if "embedded_profile" in result and result["embedded_profile"]:
        sec_findings = extract_security_findings(result["embedded_profile"])
        if sec_findings:
            result.setdefault("sandbox_security_findings", []).extend(sec_findings)

    # Summary
    result["summary"] = {
        "sandboxed": result["entitlements"]["sandboxed"],
        "total_entitlements": result["entitlements"]["total"],
        "escape_vectors": len(escape_findings),
        "critical_escapes": len([e for e in escape_findings
                                 if e["severity"] == "critical"]),
        "temporary_exceptions": len(temp_exceptions),
        "risk_level": _compute_risk(result),
    }

    out.emit(result, "sandbox")


def parse_sandbox_profile(path):
    """Parse a .sb sandbox profile."""
    with open(path) as f:
        content = f.read()

    allows = re.findall(r"\(allow\s+([^\)]+)\)", content)
    denies = re.findall(r"\(deny\s+([^\)]+)\)", content)

    allowed_ops = []
    for allow in allows:
        op = allow.split()[0] if allow.split() else allow
        desc = SANDBOX_OPERATIONS.get(op, "")
        allowed_ops.append({"operation": op, "description": desc, "full": allow[:100]})

    denied_ops = []
    for deny in denies:
        op = deny.split()[0] if deny.split() else deny
        denied_ops.append({"operation": op, "full": deny[:100]})

    return {
        "path": path,
        "allowed_operations": allowed_ops,
        "denied_operations": denied_ops,
        "total_allows": len(allows),
        "total_denies": len(denies),
    }


def _map_capability(entitlement):
    """Map an entitlement to a human-readable capability."""
    mappings = {
        "com.apple.security.network.client": "Make outbound network connections",
        "com.apple.security.network.server": "Accept inbound network connections",
        "com.apple.security.device.camera": "Access camera",
        "com.apple.security.device.microphone": "Access microphone",
        "com.apple.security.device.usb": "Access USB devices",
        "com.apple.security.personal-information.location": "Access location",
        "com.apple.security.personal-information.addressbook": "Access contacts",
        "com.apple.security.personal-information.calendars": "Access calendars",
        "com.apple.security.personal-information.photos-library": "Access photos",
        "com.apple.security.files.user-selected.read-only": "Read user-selected files",
        "com.apple.security.files.user-selected.read-write": "Read/write user-selected files",
        "com.apple.security.files.downloads.read-write": "Access Downloads folder",
        "com.apple.security.automation.apple-events": "Send Apple Events (automation)",
        "com.apple.security.print": "Print documents",
    }
    for key, desc in mappings.items():
        if key in entitlement:
            return {"entitlement": entitlement, "capability": desc}
    if "com.apple.private" in entitlement:
        return {"entitlement": entitlement,
                "capability": "Private Apple entitlement (elevated privileges)"}
    return None


def _compute_risk(result):
    if not result["entitlements"]["sandboxed"]:
        return "critical"
    critical = len([e for e in result["escape_vectors"]["findings"]
                    if e["severity"] == "critical"])
    if critical > 0:
        return "critical"
    high = len([e for e in result["escape_vectors"]["findings"]
                if e["severity"] == "high"])
    if high > 0:
        return "high"
    if result["escape_vectors"]["total"] > 0:
        return "medium"
    return "low"


def parse_sandbox_profile_text(profile_text):
    """Parse sandbox profile from text (not file path)."""
    allows = re.findall(r"\(allow\s+([^\)]+)\)", profile_text)
    denies = re.findall(r"\(deny\s+([^\)]+)\)", profile_text)

    allowed_ops = []
    for allow in allows:
        op = allow.split()[0] if allow.split() else allow
        desc = SANDBOX_OPERATIONS.get(op, "")
        allowed_ops.append({"operation": op, "description": desc, "full": allow[:100]})

    denied_ops = []
    for deny in denies:
        op = deny.split()[0] if deny.split() else deny
        denied_ops.append({"operation": op, "full": deny[:100]})

    parsed = {
        "allowed_operations": allowed_ops,
        "denied_operations": denied_ops,
        "total_allows": len(allows),
        "total_denies": len(denies),
    }

    # Enrich with security findings
    sec_findings = extract_security_findings(profile_text)
    if sec_findings:
        parsed["security_findings"] = sec_findings

    return parsed


def extract_mach_lookup_allows(profile_text):
    """Extract allowed mach-lookup service names from SBPL profile."""
    allows = []
    # Literal global-name matches
    for m in re.finditer(
        r'\(allow\s+mach-lookup[^)]*\(global-name\s+"([^"]+)"\)', profile_text
    ):
        allows.append({"service": m.group(1), "type": "literal"})

    # Regex pattern matches
    for m in re.finditer(
        r'\(allow\s+mach-lookup[^)]*\(global-name-regex\s+"([^"]+)"\)', profile_text
    ):
        allows.append({"pattern": m.group(1), "type": "regex"})

    # Broader allow mach-lookup (no filter)
    if re.search(r'\(allow\s+mach-lookup\s*\)', profile_text):
        allows.append({"service": "*", "type": "unrestricted"})

    return allows


def extract_mach_lookup_from_entitlements(entitlements):
    """Extract Mach service exceptions from entitlements."""
    services = []
    for key, val in entitlements.items():
        if "temporary-exception.mach-lookup.global-name" in key:
            if isinstance(val, list):
                services.extend(val)
            elif isinstance(val, str):
                services.append(val)
            elif isinstance(val, bool) and val:
                services.append(key)
    return services


def analyze_reachable_services(binary_path, out):
    """Analyze which root services are reachable from a sandboxed binary."""
    from cb.macho import get_entitlements, get_embedded_sandbox_profile

    # 1. Get sandbox profile (embedded or from entitlements)
    entitlements = get_entitlements(binary_path)
    profile_text = get_embedded_sandbox_profile(binary_path) or ""

    # Also check for profile in standard locations
    if not profile_text:
        bundle_id = None
        for key, val in entitlements.items():
            if "bundle-identifier" in key.lower() or key == "application-identifier":
                bundle_id = val
                break
        if bundle_id:
            for sb_dir in ["/System/Library/Sandbox/Profiles", "/usr/share/sandbox"]:
                sb_path = os.path.join(sb_dir, f"{bundle_id}.sb")
                if os.path.exists(sb_path):
                    with open(sb_path) as f:
                        profile_text = f.read()
                    break

    # 2. Extract allowed mach-lookup services
    allowed = []
    if profile_text:
        allowed = extract_mach_lookup_allows(profile_text)
    ent_services = extract_mach_lookup_from_entitlements(entitlements)
    for svc in ent_services:
        allowed.append({"service": svc, "type": "entitlement_exception"})

    # Check if unsandboxed
    is_sandboxed = entitlements.get("com.apple.security.app-sandbox", False)
    if not is_sandboxed:
        allowed.append({"service": "*", "type": "not_sandboxed"})

    # 3. Cross-reference with system services
    from cb.services import enumerate_launchd_services
    all_services = enumerate_launchd_services()

    reachable = []
    for svc in all_services:
        for mach_name in svc.get("mach_services", []):
            is_reachable = False
            match_reason = ""
            for rule in allowed:
                if rule.get("type") == "unrestricted" or rule.get("type") == "not_sandboxed":
                    is_reachable = True
                    match_reason = rule["type"]
                    break
                if rule.get("type") == "literal" and rule.get("service") == mach_name:
                    is_reachable = True
                    match_reason = "sandbox_allow"
                    break
                if rule.get("type") == "entitlement_exception" and rule.get("service") == mach_name:
                    is_reachable = True
                    match_reason = "entitlement_exception"
                    break
                if rule.get("type") == "regex":
                    try:
                        if re.match(rule["pattern"], mach_name):
                            is_reachable = True
                            match_reason = f"regex:{rule['pattern']}"
                            break
                    except re.error:
                        pass

            if is_reachable:
                svc_info = {
                    "service": mach_name,
                    "label": svc.get("label", ""),
                    "binary": svc.get("binary_path", ""),
                    "match_reason": match_reason,
                    "runs_as": svc.get("user_name", "root") or "root",
                }
                # Get entitlements of target service if binary exists
                binary = svc.get("binary_path", "")
                if binary and os.path.exists(binary):
                    try:
                        svc_ents = get_entitlements(binary)
                        svc_info["target_sandboxed"] = svc_ents.get(
                            "com.apple.security.app-sandbox", False)
                        svc_info["target_entitlements_count"] = len(svc_ents)
                    except Exception:
                        pass
                reachable.append(svc_info)

    return {
        "source_binary": binary_path,
        "source_sandboxed": is_sandboxed,
        "allowed_lookups": allowed,
        "reachable_services": reachable,
        "total_reachable": len(reachable),
    }


def analyze_chain(source_binary, target_service, out):
    """Analyze if source can reach target and what the attack surface looks like."""
    from cb.services import resolve_service_binary
    from cb.macho import get_entitlements, get_imports

    result = {
        "source": source_binary,
        "target_service": target_service,
        "reachable": False,
    }

    # Check reachability
    reachability = analyze_reachable_services(source_binary, out)
    for svc in reachability.get("reachable_services", []):
        if svc.get("service") == target_service or svc.get("label") == target_service:
            result["reachable"] = True
            result["match_reason"] = svc.get("match_reason", "")
            break

    # Analyze target
    target_binary = resolve_service_binary(target_service)
    if target_binary and os.path.exists(target_binary):
        result["target_binary"] = target_binary

        target_ents = get_entitlements(target_binary)
        result["target_entitlements"] = {
            "total": len(target_ents),
            "sandboxed": target_ents.get("com.apple.security.app-sandbox", False),
        }

        target_imports = get_imports(target_binary)
        import_set = {i.lstrip("_") for i in target_imports}

        # IPC surface
        xpc_funcs = {i for i in import_set if i.startswith("xpc_")}
        mach_funcs = {i for i in import_set if "mach_" in i}
        result["target_ipc_surface"] = {
            "xpc_functions": sorted(xpc_funcs)[:20],
            "mach_functions": sorted(mach_funcs)[:10],
            "has_auth_checks": bool({"SecTaskCreateWithAuditToken",
                                     "xpc_connection_get_audit_token"} & import_set),
        }

        # Dangerous imports
        dangerous = {"strcpy", "sprintf", "memcpy", "gets", "system"} & import_set
        if dangerous:
            result["target_dangerous_imports"] = sorted(dangerous)

    return result


def main():
    parser = argparse.ArgumentParser(prog="cbsandbox", description="Sandbox analysis")
    parser.add_argument("binary")
    parser.add_argument("--profile", type=str, default=None)
    parser.add_argument("--escape-vectors", action="store_true", default=True)
    parser.add_argument("--capability-map", action="store_true")
    parser.add_argument("--compare-apis", action="store_true")
    parser.add_argument("--reachable-from", type=str, default=None)
    parser.add_argument("--chain", type=str, default=None)
    parser.add_argument("--extract-profile", action="store_true")
    add_output_args(parser)
    args = parser.parse_args()
    run(args)
