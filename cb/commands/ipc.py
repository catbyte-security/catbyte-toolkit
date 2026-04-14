"""cb ipc - Deep IPC/XPC handler analysis for macOS."""
import argparse
import os
import plistlib
import re
import subprocess
import sys

from cb.output import add_output_args, make_formatter
from cb.macho import get_imports, get_strings, get_objc_selectors, _run


def register(subparsers):
    p = subparsers.add_parser("ipc", help="Deep IPC/XPC handler analysis")
    p.add_argument("binary", help="Path to binary or .app bundle")
    p.add_argument("--xpc", action="store_true", help="XPC service analysis")
    p.add_argument("--mach", action="store_true", help="Mach port analysis")
    p.add_argument("--mig", action="store_true", help="MIG stub analysis")
    p.add_argument("--handlers", action="store_true",
                   help="Find message handler functions")
    p.add_argument("--xpc-deep", action="store_true",
                   help="Deep XPC security audit: auth gap detection, root service check, SMAuthorizedClients")
    p.add_argument("--mojo", action="store_true",
                   help="Extract Mojo IPC interface names and classify by process type")
    p.add_argument("--all", action="store_true", default=True,
                   help="All IPC analysis (default)")
    p.add_argument("--protocol", action="store_true",
                   help="Extract XPC protocol spec via Ghidra (requires Ghidra)")
    p.add_argument("--protocol-func", type=str, default=None,
                   help="Specific dispatch function to analyze")
    p.add_argument("--timeout", type=int, default=600,
                   help="Ghidra analysis timeout in seconds")
    add_output_args(p)
    p.set_defaults(func=run)


def run(args):
    out = make_formatter(args)
    binary = args.binary
    result = {}

    analyze_all = args.all and not (args.xpc or args.mach or args.mig or args.handlers
                                     or getattr(args, 'xpc_deep', False)
                                     or getattr(args, 'mojo', False))

    # Resolve app bundle to binary
    if binary.endswith(".app"):
        result["bundle_analysis"] = analyze_app_bundle_ipc(binary, out)
        import plistlib
        info_plist = os.path.join(binary, "Contents", "Info.plist")
        if os.path.exists(info_plist):
            with open(info_plist, "rb") as f:
                plist = plistlib.load(f)
            exec_name = plist.get("CFBundleExecutable", "")
            if exec_name:
                binary = os.path.join(binary, "Contents", "MacOS", exec_name)

    imports = get_imports(binary)
    import_set = {i.lstrip("_") for i in imports}
    selectors = get_objc_selectors(binary)
    strings_data = get_strings(binary, min_length=4, max_count=2000)

    if analyze_all or args.xpc:
        out.status("Analyzing XPC services...")
        result["xpc"] = analyze_xpc(binary, import_set, selectors, strings_data)

    if analyze_all or args.mach:
        out.status("Analyzing Mach ports...")
        result["mach"] = analyze_mach(binary, import_set, strings_data)

    if analyze_all or args.mig:
        out.status("Analyzing MIG stubs...")
        result["mig"] = analyze_mig(binary, import_set)

    if analyze_all or args.handlers:
        out.status("Finding message handlers...")
        result["handlers"] = find_handlers(binary, import_set, selectors)

    # Deep XPC security audit
    if getattr(args, 'xpc_deep', False):
        out.status("Running deep XPC security audit...")
        bundle_info = result.get("bundle_analysis")
        result["xpc_deep"] = analyze_xpc_deep(
            binary, import_set, selectors, strings_data, bundle_info, out)

    # Mojo interface extraction
    if getattr(args, 'mojo', False):
        out.status("Extracting Mojo IPC interfaces...")
        result["mojo"] = analyze_mojo_interfaces(binary, strings_data, out)

    # Security assessment
    result["security_assessment"] = assess_ipc_security(result, import_set, selectors)

    # XPC Protocol extraction (opt-in, requires Ghidra)
    if getattr(args, 'protocol', False):
        out.status("Extracting XPC protocol specification via Ghidra...")
        result["protocol"] = extract_protocol(binary, args, out)

    out.emit(result, "ipc")


def analyze_app_bundle_ipc(app_path, out):
    """Analyze IPC configuration in an app bundle."""
    info = {"xpc_services": [], "mach_services": [], "launchd_plists": []}

    # XPC services
    xpc_dir = os.path.join(app_path, "Contents", "XPCServices")
    if os.path.isdir(xpc_dir):
        for svc in os.listdir(xpc_dir):
            if svc.endswith(".xpc"):
                svc_path = os.path.join(xpc_dir, svc)
                svc_info = {"name": svc, "path": svc_path}
                svc_plist = os.path.join(svc_path, "Contents", "Info.plist")
                if os.path.exists(svc_plist):
                    try:
                        with open(svc_plist, "rb") as f:
                            sp = plistlib.load(f)
                        svc_info["bundle_id"] = sp.get("CFBundleIdentifier", "")
                        xpc_cfg = sp.get("XPCService", {})
                        svc_info["service_type"] = xpc_cfg.get("ServiceType", "Application")
                        svc_info["run_loop_type"] = xpc_cfg.get("RunLoopType", "dispatch_main")

                        # MachServices dict - defines what services are exposed
                        mach_services = sp.get("MachServices", {})
                        if mach_services:
                            svc_info["mach_services"] = list(mach_services.keys())
                            info["mach_services"].extend(mach_services.keys())
                    except Exception:
                        pass
                info["xpc_services"].append(svc_info)

    # LaunchAgents/LaunchDaemons
    for subdir in ["Contents/Library/LaunchAgents",
                    "Contents/Library/LaunchDaemons"]:
        ld_dir = os.path.join(app_path, subdir)
        if os.path.isdir(ld_dir):
            for pfile in os.listdir(ld_dir):
                if pfile.endswith(".plist"):
                    ppath = os.path.join(ld_dir, pfile)
                    try:
                        with open(ppath, "rb") as f:
                            lp = plistlib.load(f)
                        info["launchd_plists"].append({
                            "path": ppath,
                            "label": lp.get("Label", ""),
                            "program": lp.get("Program", lp.get("ProgramArguments", [""])[0]),
                            "mach_services": list(lp.get("MachServices", {}).keys()),
                        })
                    except Exception:
                        pass

    return info


def analyze_xpc(binary, import_set, selectors, strings_data):
    """Analyze XPC usage patterns."""
    result = {
        "connection_creation": [],
        "message_handling": [],
        "security_checks": [],
    }

    # XPC connection APIs
    xpc_create = {"xpc_connection_create", "xpc_connection_create_mach_service",
                   "xpc_connection_create_from_endpoint"}
    for func in xpc_create & import_set:
        result["connection_creation"].append(func)

    # XPC message handling
    xpc_msg = {"xpc_connection_set_event_handler",
               "xpc_dictionary_get_string", "xpc_dictionary_get_data",
               "xpc_dictionary_get_value", "xpc_dictionary_get_int64",
               "xpc_dictionary_get_uint64", "xpc_dictionary_get_bool",
               "xpc_dictionary_get_fd", "xpc_dictionary_get_array",
               "xpc_dictionary_get_dictionary"}
    for func in xpc_msg & import_set:
        result["message_handling"].append(func)

    # Security checks present?
    xpc_security = {"xpc_connection_get_pid", "xpc_connection_get_euid",
                     "xpc_connection_get_egid", "xpc_connection_get_audit_token",
                     "SecTaskCreateWithAuditToken", "SecTaskCopyValueForEntitlement"}
    for func in xpc_security & import_set:
        result["security_checks"].append(func)

    # NSXPCConnection usage
    nsxpc_selectors = [s for s in selectors
                       if "NSXPCConnection" in s or "NSXPCInterface" in s
                       or "NSXPCListener" in s]
    if nsxpc_selectors:
        result["nsxpc_usage"] = nsxpc_selectors[:20]

    # Extract service names from strings
    all_strings = []
    for cat in strings_data["categories"].values():
        all_strings.extend(cat)
    service_names = [s for s in all_strings
                     if re.match(r"^com\.[a-z]+\.[a-z]", s) and len(s) < 100]
    if service_names:
        result["referenced_services"] = list(set(service_names))[:20]

    return result


def analyze_mach(binary, import_set, strings_data):
    """Analyze Mach IPC usage."""
    result = {
        "port_operations": [],
        "message_operations": [],
        "bootstrap_services": [],
    }

    port_ops = {"mach_port_allocate", "mach_port_deallocate",
                "mach_port_insert_right", "mach_port_extract_right",
                "mach_port_mod_refs", "mach_port_request_notification",
                "mach_port_construct", "mach_port_destruct"}
    for func in port_ops & import_set:
        result["port_operations"].append(func)

    msg_ops = {"mach_msg", "mach_msg_send", "mach_msg_receive",
               "mach_msg_overwrite", "mach_msg_destroy",
               "mach_voucher_attr_command"}
    for func in msg_ops & import_set:
        result["message_operations"].append(func)

    bootstrap = {"bootstrap_look_up", "bootstrap_register",
                  "bootstrap_check_in", "bootstrap_create_service"}
    for func in bootstrap & import_set:
        result["bootstrap_services"].append(func)

    return result


def analyze_mig(binary, import_set):
    """Detect and analyze MIG (Mach Interface Generator) stubs."""
    result = {"mig_detected": False, "subsystems": []}

    # MIG generates functions with specific naming patterns
    mig_indicators = {"mig_get_reply_port", "mig_dealloc_reply_port",
                       "mig_put_reply_port", "mig_strncpy"}
    if mig_indicators & import_set:
        result["mig_detected"] = True

    # Look for MIG subsystem routines via nm
    stdout, _ = _run(["nm", "-defined-only", binary])
    mig_routines = []
    for line in stdout.splitlines():
        # MIG server routines typically end with "_server" or contain "Subsystem"
        if "server_routine" in line.lower() or "subsystem" in line.lower():
            parts = line.split()
            if len(parts) >= 3:
                mig_routines.append(parts[-1].lstrip("_"))

    # Also look for MIG dispatch tables (arrays of routine descriptors)
    # These have message ID ranges
    for line in stdout.splitlines():
        if re.search(r"_\w+_subsystem", line):
            parts = line.split()
            if parts:
                result["subsystems"].append(parts[-1].lstrip("_"))

    if mig_routines:
        result["mig_detected"] = True
        result["server_routines"] = mig_routines[:50]

    return result


def find_handlers(binary, import_set, selectors):
    """Find IPC message handler functions."""
    handlers = []

    # ObjC delegate methods for XPC
    xpc_handler_sels = [
        s for s in selectors
        if any(x in s for x in [
            "listener:shouldAcceptNewConnection:",
            "connection:handleInvocation:",
            "handleMessage:", "handleRequest:",
            "processMessage:", "processRequest:",
            "dispatchMessage:", "routeMessage:",
            "handleXPCMessage:", "handleMachMessage:",
        ])
    ]
    for sel in xpc_handler_sels:
        handlers.append({
            "type": "objc_handler",
            "selector": sel,
            "severity": "high",
            "note": "XPC/IPC message handler - prime target for fuzzing",
        })

    # C-style handler functions from symbols
    stdout, _ = _run(["nm", "-defined-only", binary])
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        name = parts[-1].lstrip("_")
        name_lower = name.lower()
        if any(x in name_lower for x in [
            "handle_message", "handle_request", "process_message",
            "dispatch_message", "mig_server", "server_routine",
            "message_handler", "ipc_handler", "xpc_handler",
        ]):
            handlers.append({
                "type": "c_handler",
                "function": name,
                "address": f"0x{parts[0]}",
                "severity": "high",
                "note": "IPC handler function",
            })

    return {"total": len(handlers), "handlers": handlers}


def analyze_xpc_deep(binary, import_set, selectors, strings_data, bundle_info, out):
    """Deep XPC security audit: auth gaps, root services, SMAuthorizedClients."""
    findings = []

    # Detect XPC listener/handler presence
    has_xpc_handler = any(
        "shouldAcceptNewConnection:" in s or "listener:shouldAcceptNewConnection:" in s
        for s in selectors
    )
    has_xpc_event_handler = "xpc_connection_set_event_handler" in import_set
    has_xpc_listener = has_xpc_handler or has_xpc_event_handler

    # Check for modern ProcessRequirement API (macOS 13+)
    all_strings = []
    for cat in strings_data["categories"].values():
        all_strings.extend(cat)
    all_strings_text = " ".join(all_strings)
    has_process_requirement = "ProcessRequirement" in all_strings_text

    # Check for audit_token-based authentication
    audit_token_funcs = {
        "xpc_connection_get_audit_token",
        "SecTaskCreateWithAuditToken",
        "SecTaskCopyValueForEntitlement",
        "audit_token_to_euid",
        "audit_token_to_pid",
    }
    found_audit_funcs = audit_token_funcs & import_set
    has_audit_auth = bool(found_audit_funcs)

    # Detect PID-only auth (bypassable via PID reuse)
    has_pid_only = "xpc_connection_get_pid" in import_set and not has_audit_auth

    # Check for code signing verification
    codesign_funcs = {"SecCodeCheckValidity", "SecCodeCopySigningInformation",
                      "SecStaticCodeCheckValidity"}
    has_codesign_check = bool(codesign_funcs & import_set)

    # Determine if binary runs as root (from LaunchDaemon plists)
    runs_as_root = False
    daemon_label = None
    if bundle_info:
        for plist_info in bundle_info.get("launchd_plists", []):
            plist_path = plist_info.get("path", "")
            program = plist_info.get("program", "")
            if "LaunchDaemons" in plist_path:
                # LaunchDaemons run as root by default
                if os.path.basename(binary) in program or \
                   os.path.basename(program) == os.path.basename(binary):
                    runs_as_root = True
                    daemon_label = plist_info.get("label", "")
    else:
        # Check if binary itself is in a LaunchDaemons path
        if "LaunchDaemons" in binary:
            runs_as_root = True

    # Generate findings
    auth_methods = []
    if has_audit_auth:
        auth_methods.append("audit_token")
    if has_codesign_check:
        auth_methods.append("code_signature")
    if has_process_requirement:
        auth_methods.append("ProcessRequirement")

    if has_xpc_listener and not has_audit_auth and not has_process_requirement:
        severity = "critical" if runs_as_root else "high"
        finding = {
            "severity": severity,
            "issue": "XPC service accepts connections without audit_token or ProcessRequirement validation",
            "detail": "Any process can connect to this XPC service and send messages",
        }
        if runs_as_root:
            finding["detail"] = (
                f"Privileged XPC service (LaunchDaemon: {daemon_label or 'unknown'}) "
                "runs as root with no client authentication. Any local process can "
                "connect and send commands that execute with root privileges."
            )
        if has_pid_only:
            finding["note"] = (
                "PID-based auth detected but no audit_token. PID checks are bypassable "
                "via PID reuse race conditions."
            )
        findings.append(finding)

    if has_pid_only:
        findings.append({
            "severity": "medium",
            "issue": "PID-only authentication (bypassable via PID reuse)",
            "detail": "xpc_connection_get_pid used without audit_token. An attacker can "
                      "race the PID check by spawning a legitimately-signed process, then "
                      "replacing it with a malicious one before the PID is validated.",
            "recommendation": "Use xpc_connection_get_audit_token or ProcessRequirement instead",
        })

    if has_process_requirement and not has_audit_auth:
        findings.append({
            "severity": "info",
            "issue": "Uses modern ProcessRequirement API (macOS 13+)",
            "detail": "ProcessRequirement provides declarative connection validation. "
                      "Verify the requirement string is sufficiently restrictive.",
        })

    # SMAuthorizedClients analysis
    sm_clients = _extract_sm_authorized_clients(binary)

    result = {
        "has_xpc_listener": has_xpc_listener,
        "runs_as_root": runs_as_root,
        "daemon_label": daemon_label,
        "auth_methods": auth_methods,
        "has_pid_only_auth": has_pid_only,
        "audit_token_functions": sorted(found_audit_funcs),
        "findings": findings,
        "total_findings": len(findings),
    }

    if sm_clients:
        result["sm_authorized_clients"] = sm_clients
        result["sm_note"] = (
            "SMAuthorizedClients restricts which apps can INSTALL this helper via "
            "SMJobBless, but does NOT restrict which processes can CONNECT to the "
            "XPC service once it's running. Connection auth must be checked separately."
        )

    return result


def _extract_sm_authorized_clients(binary):
    """Extract SMAuthorizedClients from embedded Info.plist."""
    # Look for Info.plist in the same bundle
    binary_dir = os.path.dirname(binary)
    candidates = [
        os.path.join(binary_dir, "..", "Info.plist"),
        os.path.join(binary_dir, "Info.plist"),
    ]
    for plist_path in candidates:
        plist_path = os.path.normpath(plist_path)
        if os.path.exists(plist_path):
            try:
                with open(plist_path, "rb") as f:
                    plist = plistlib.load(f)
                clients = plist.get("SMAuthorizedClients", [])
                if clients:
                    return clients
            except Exception:
                pass

    # Also try extracting from __TEXT,__info_plist section via strings
    try:
        stdout, _ = _run(["strings", binary])
        if "SMAuthorizedClients" in stdout:
            return ["(embedded — extract with plutil for full details)"]
    except Exception:
        pass

    return []


# Mojo namespace → process type mapping
MOJO_NAMESPACE_PROCESS = {
    "blink.mojom": "renderer",
    "content.mojom": "renderer",
    "third_party.blink.mojom": "renderer",
    "network.mojom": "network",
    "viz.mojom": "gpu",
    "gpu.mojom": "gpu",
    "media.mojom": "utility",
    "audio.mojom": "utility",
    "printing.mojom": "utility",
    "device.mojom": "browser",
    "chrome.mojom": "browser",
    "extensions.mojom": "browser",
    "storage.mojom": "browser",
    "downloads.mojom": "browser",
    "autofill.mojom": "browser",
    "payments.mojom": "browser",
    "ax.mojom": "browser",
    "page_load_metrics.mojom": "browser",
    "data_decoder.mojom": "utility",
    "proxy_resolver.mojom": "utility",
}


def analyze_mojo_interfaces(binary, strings_data, out):
    """Extract Mojo interface names from binary strings and classify by process type."""
    all_strings = []
    for cat in strings_data["categories"].values():
        all_strings.extend(cat)

    # Match mojom interface patterns: namespace.mojom.InterfaceName
    mojo_pattern = re.compile(r'(\w+(?:\.\w+)*\.mojom\.\w+)')
    interfaces = set()
    for s in all_strings:
        for match in mojo_pattern.findall(s):
            interfaces.add(match)

    if not interfaces:
        return {
            "total": 0,
            "interfaces": [],
            "by_process_type": {},
        }

    # Classify by process type
    by_process = {}
    classified = []
    for iface in sorted(interfaces):
        # Find matching namespace
        process_type = "unknown"
        parts = iface.split(".mojom.")
        if len(parts) == 2:
            namespace = parts[0] + ".mojom"
            for ns, ptype in MOJO_NAMESPACE_PROCESS.items():
                if namespace.startswith(ns) or namespace.endswith(ns):
                    process_type = ptype
                    break

        classified.append({
            "interface": iface,
            "process_type": process_type,
        })
        by_process.setdefault(process_type, []).append(iface)

    return {
        "total": len(interfaces),
        "interfaces": classified,
        "by_process_type": {k: len(v) for k, v in by_process.items()},
        "renderer_accessible": len(by_process.get("renderer", [])),
        "detail_by_process": {k: sorted(v) for k, v in by_process.items()},
    }


def assess_ipc_security(result, import_set, selectors):
    """Assess overall IPC security posture."""
    issues = []

    # Check: XPC accepts connections without auth checks
    xpc = result.get("xpc", {})
    if xpc.get("connection_creation") and not xpc.get("security_checks"):
        issues.append({
            "severity": "high",
            "issue": "XPC connections created but no audit token / entitlement checks detected",
            "recommendation": "Verify shouldAcceptNewConnection: checks client entitlements "
                              "via SecTaskCreateWithAuditToken",
        })

    # Check: mach_msg without validation
    mach = result.get("mach", {})
    if mach.get("message_operations") and "mach_msg" in import_set:
        issues.append({
            "severity": "medium",
            "issue": "Raw mach_msg usage detected - messages may not be validated",
            "recommendation": "Ensure message size, port rights, and content are validated",
        })

    # Check: MIG subsystem without auth
    mig = result.get("mig", {})
    if mig.get("mig_detected"):
        auth_funcs = {"audit_token_to_pid", "audit_token_to_euid",
                       "SecTaskCreateWithAuditToken", "SecTaskCopyValueForEntitlement"}
        has_auth = bool(auth_funcs & import_set)
        if not has_auth:
            issues.append({
                "severity": "high",
                "issue": "MIG subsystem detected without audit token validation",
                "recommendation": "MIG handlers should validate sender via audit token",
            })

    # Check: deserialization of IPC data
    if "NSKeyedUnarchiver" in " ".join(selectors):
        issues.append({
            "severity": "high",
            "issue": "NSKeyedUnarchiver used - potential deserialization attack vector",
            "recommendation": "Ensure NSSecureCoding with strict allowedClasses",
        })

    # Count handler functions
    handlers = result.get("handlers", {})
    handler_count = handlers.get("total", 0)

    return {
        "issues": issues,
        "total_issues": len(issues),
        "handler_count": handler_count,
        "has_auth_checks": bool(xpc.get("security_checks")),
        "uses_mig": mig.get("mig_detected", False),
        "risk_level": "high" if any(i["severity"] == "high" for i in issues) else
                      "medium" if issues else "low",
    }


def extract_protocol(binary, args, out):
    """Extract XPC protocol specification using Ghidra."""
    try:
        from cb.ghidra_bridge import run_ghidra_script
    except ImportError:
        return {"error": "Ghidra bridge not available"}

    try:
        timeout = getattr(args, 'timeout', 600)
        script_result = run_ghidra_script(
            binary, "XPCProtocol.java",
            [str(getattr(args, 'max_results', 50))],
            timeout=timeout,
        )
        if not script_result:
            return {"error": "No results from XPC protocol analysis"}

        # Format the protocol spec
        result = {
            "dispatch_function": script_result.get("dispatch_function", ""),
            "message_count": len(script_result.get("message_ids", [])),
            "messages": [],
        }

        for msg in script_result.get("message_ids", []):
            msg_info = {
                "id": msg.get("id", ""),
                "handler": msg.get("handler", ""),
            }
            # Find args for this handler
            for spec in script_result.get("handler_specs", []):
                if spec.get("handler") == msg.get("handler"):
                    msg_info["args"] = spec.get("args", [])
                    break
            result["messages"].append(msg_info)

        # Format as readable spec
        result["formatted_spec"] = _format_protocol_spec(result)

        # NSXPC methods
        nsxpc = script_result.get("nsxpc_protocol_methods", [])
        if nsxpc:
            result["nsxpc_methods"] = nsxpc

        return result

    except Exception as e:
        return {"error": f"XPC protocol analysis failed: {e}"}


def _format_protocol_spec(protocol):
    """Format protocol spec as readable strings."""
    lines = []
    for msg in protocol.get("messages", []):
        msg_id = msg.get("id", "?")
        handler = msg.get("handler", "unknown")
        args = msg.get("args", [])
        arg_str = ", ".join(f"{a['key']}: {a['type']}" for a in args) if args else "unknown"
        lines.append(f"msg={msg_id} ({handler}): {{{arg_str}}}")
    return lines


def main():
    parser = argparse.ArgumentParser(prog="cbipc", description="IPC analysis")
    parser.add_argument("binary")
    parser.add_argument("--xpc", action="store_true")
    parser.add_argument("--mach", action="store_true")
    parser.add_argument("--mig", action="store_true")
    parser.add_argument("--handlers", action="store_true")
    parser.add_argument("--xpc-deep", action="store_true")
    parser.add_argument("--mojo", action="store_true")
    parser.add_argument("--all", action="store_true", default=True)
    parser.add_argument("--protocol", action="store_true")
    parser.add_argument("--protocol-func", type=str, default=None)
    parser.add_argument("--timeout", type=int, default=600)
    add_output_args(parser)
    args = parser.parse_args()
    run(args)
