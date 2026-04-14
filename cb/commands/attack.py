"""cb attack - Attack surface mapper for macOS binaries and app bundles."""
import argparse
import os
import plistlib
import re
import subprocess
import sys

from cb.output import add_output_args, make_formatter
from cb.macho import get_imports, get_libraries, get_entitlements, _run
from cb.patterns.dangerous_functions import (
    DANGEROUS_ENTITLEMENTS, PARSER_INDICATORS, IMPORT_CATEGORIES,
)


def register(subparsers):
    p = subparsers.add_parser("attack", help="Map attack surface")
    p.add_argument("binary", help="Path to binary or .app bundle")
    p.add_argument("--app-bundle", action="store_true",
                   help="Analyze entire .app bundle")
    p.add_argument("--ipc", action="store_true", help="IPC endpoints only")
    p.add_argument("--parsers", action="store_true", help="File parsers only")
    p.add_argument("--network", action="store_true", help="Network handlers only")
    p.add_argument("--entitlements", action="store_true", help="Entitlements only")
    p.add_argument("--syscalls", action="store_true", help="Syscall usage only")
    p.add_argument("--depth", choices=["shallow", "deep"], default="shallow")
    p.add_argument("--services-from", type=str, default=None, metavar="BINARY",
                   help="Enumerate and rank services reachable from sandboxed binary")
    p.add_argument("--rank-by", choices=["risk", "attack_surface", "privilege"],
                   default="risk", help="Ranking criterion for service prioritization")
    add_output_args(p)
    p.set_defaults(func=run)


def run(args):
    out = make_formatter(args)
    path = args.binary

    # Determine if we should analyze a single binary or app bundle
    is_bundle = args.app_bundle or path.endswith(".app")
    analyze_all = not (args.ipc or args.parsers or args.network
                       or args.entitlements or args.syscalls)

    # Cache check (skip for service enumeration and bundles)
    cache_args = {
        "app_bundle": args.app_bundle,
        "ipc": args.ipc, "parsers": args.parsers,
        "network": args.network, "entitlements": args.entitlements,
        "syscalls": args.syscalls, "depth": args.depth,
    }
    if (not getattr(args, "no_cache", False)
            and not getattr(args, "services_from", None)
            and not is_bundle):
        try:
            from cb.result_cache import ResultCache
            cache = ResultCache()
            cached = cache.get(path, "attack", cache_args)
            if cached:
                cached.setdefault("_meta", {})["cached"] = True
                out.emit(cached, "attack")
                return
        except Exception:
            pass

    # Service enumeration and ranking mode
    if getattr(args, 'services_from', None):
        out.status("Enumerating and ranking reachable services...")
        result = enumerate_and_rank_services(args.services_from,
                                             getattr(args, 'rank_by', 'risk'), out)
        out.emit(result, "attack")
        return

    if is_bundle:
        binaries, bundle_info = discover_bundle(path, out)
    else:
        binaries = [path]
        bundle_info = None

    # Collect all imports across binaries
    all_imports = set()
    for b in binaries:
        try:
            all_imports.update(get_imports(b))
        except Exception:
            pass

    result = {}
    if bundle_info:
        result["bundle_info"] = bundle_info

    if analyze_all or args.entitlements:
        out.status("Analyzing entitlements...")
        result["entitlements"] = analyze_entitlements(binaries[0] if binaries else path)

    if analyze_all or args.ipc:
        out.status("Mapping IPC endpoints...")
        result["ipc"] = analyze_ipc(all_imports, path if is_bundle else None)

    if analyze_all or args.parsers:
        out.status("Detecting file format parsers...")
        result["parsers"] = analyze_parsers(all_imports)

    if analyze_all or args.network:
        out.status("Analyzing network surface...")
        result["network"] = analyze_network(all_imports)

    if analyze_all or args.syscalls:
        out.status("Analyzing syscall usage...")
        result["syscalls"] = analyze_syscall_patterns(all_imports)

    # Summary score
    result["summary"] = compute_attack_surface_score(result)

    # Cache store
    if (not getattr(args, "no_cache", False)
            and not getattr(args, "services_from", None)
            and not is_bundle):
        try:
            from cb.result_cache import ResultCache
            cache = ResultCache()
            cache.put(path, "attack", cache_args, result)
        except Exception:
            pass

    out.emit(result, "attack")


def discover_bundle(app_path, out):
    """Discover binaries and metadata in an .app bundle."""
    info = {"app_path": app_path, "binaries": [], "xpc_services": []}

    # Find main binary from Info.plist
    info_plist = os.path.join(app_path, "Contents", "Info.plist")
    if os.path.exists(info_plist):
        try:
            with open(info_plist, "rb") as f:
                plist = plistlib.load(f)
            info["bundle_id"] = plist.get("CFBundleIdentifier", "")
            info["bundle_name"] = plist.get("CFBundleName", "")
            info["version"] = plist.get("CFBundleShortVersionString", "")
            main_exec = plist.get("CFBundleExecutable", "")
            if main_exec:
                main_path = os.path.join(app_path, "Contents", "MacOS", main_exec)
                if os.path.exists(main_path):
                    info["binaries"].append(main_path)
        except Exception as e:
            out.status(f"Warning: Failed to parse Info.plist: {e}")

    # Find XPC services
    xpc_dir = os.path.join(app_path, "Contents", "XPCServices")
    if os.path.isdir(xpc_dir):
        for svc in os.listdir(xpc_dir):
            if svc.endswith(".xpc"):
                svc_path = os.path.join(xpc_dir, svc)
                svc_plist = os.path.join(svc_path, "Contents", "Info.plist")
                svc_info = {"name": svc, "path": svc_path}
                if os.path.exists(svc_plist):
                    try:
                        with open(svc_plist, "rb") as f:
                            sp = plistlib.load(f)
                        svc_info["bundle_id"] = sp.get("CFBundleIdentifier", "")
                        svc_info["mach_service"] = bool(
                            sp.get("XPCService", {}).get("ServiceType", "") == "Application"
                            or sp.get("MachServices", {})
                        )
                    except Exception:
                        pass
                info["xpc_services"].append(svc_info)
                # Find binary inside XPC service
                svc_macos = os.path.join(svc_path, "Contents", "MacOS")
                if os.path.isdir(svc_macos):
                    for f in os.listdir(svc_macos):
                        fp = os.path.join(svc_macos, f)
                        if os.path.isfile(fp) and os.access(fp, os.X_OK):
                            info["binaries"].append(fp)

    # Find frameworks
    fw_dir = os.path.join(app_path, "Contents", "Frameworks")
    if os.path.isdir(fw_dir):
        for fw in os.listdir(fw_dir):
            if fw.endswith(".framework"):
                fw_path = os.path.join(fw_dir, fw)
                # Find binary inside framework
                fw_name = fw.replace(".framework", "")
                fw_bin = os.path.join(fw_path, "Versions", "Current", fw_name)
                if not os.path.exists(fw_bin):
                    fw_bin = os.path.join(fw_path, fw_name)
                if os.path.exists(fw_bin):
                    info["binaries"].append(fw_bin)

    # Find helpers
    helpers_dir = os.path.join(app_path, "Contents", "Helpers")
    if os.path.isdir(helpers_dir):
        for h in os.listdir(helpers_dir):
            hp = os.path.join(helpers_dir, h)
            if os.path.isfile(hp) and os.access(hp, os.X_OK):
                info["binaries"].append(hp)

    out.status(f"Found {len(info['binaries'])} binaries, "
               f"{len(info['xpc_services'])} XPC services")

    return info["binaries"], info


def analyze_entitlements(binary_path):
    """Analyze entitlements and flag dangerous ones."""
    # Get raw entitlements
    stdout, stderr = _run(["codesign", "-d", "--entitlements", "-", binary_path])
    combined = stdout + stderr

    raw = {}
    keys = re.findall(r"<key>([^<]+)</key>", combined)
    for key in keys:
        raw[key] = True

    # Flag dangerous ones
    dangerous = []
    for key in raw:
        for pattern, info in DANGEROUS_ENTITLEMENTS.items():
            if pattern in key:
                dangerous.append({
                    "entitlement": key,
                    "risk": info["risk"],
                    "description": info["description"],
                })

    # Check for sandbox
    sandboxed = "com.apple.security.app-sandbox" in raw

    return {
        "raw": raw,
        "dangerous": dangerous,
        "sandboxed": sandboxed,
        "total_entitlements": len(raw),
    }


def analyze_ipc(imports, bundle_path=None):
    """Analyze IPC mechanisms used."""
    result = {
        "mach_ports": {"indicators": [], "count": 0},
        "xpc": {"indicators": [], "count": 0},
        "unix_sockets": {"indicators": [], "count": 0},
        "nsxpc": {"indicators": [], "count": 0},
    }

    mach_funcs = {"mach_msg", "mach_port_allocate", "mach_port_deallocate",
                  "mach_port_insert_right", "bootstrap_look_up",
                  "bootstrap_register", "mig_get_reply_port"}
    xpc_funcs = {"xpc_connection_create", "xpc_connection_send_message",
                 "xpc_connection_create_mach_service", "xpc_dictionary_create",
                 "xpc_pipe_routine"}
    nsxpc_indicators = {"NSXPCConnection", "NSXPCInterface", "NSXPCListener"}
    socket_funcs = {"bind", "connect", "accept", "listen"}

    for imp in imports:
        name = imp.lstrip("_")
        if name in mach_funcs:
            result["mach_ports"]["indicators"].append(name)
            result["mach_ports"]["count"] += 1
        if name in xpc_funcs or "xpc_" in name:
            result["xpc"]["indicators"].append(name)
            result["xpc"]["count"] += 1
        if name in nsxpc_indicators:
            result["nsxpc"]["indicators"].append(name)
            result["nsxpc"]["count"] += 1
        if name in socket_funcs:
            result["unix_sockets"]["indicators"].append(name)
            result["unix_sockets"]["count"] += 1

    return result


def analyze_parsers(imports):
    """Detect file format parsers from imports."""
    result = {}

    for category, patterns in PARSER_INDICATORS.items():
        detected = {}
        for pattern, formats in patterns.items():
            for imp in imports:
                name = imp.lstrip("_")
                if pattern.lower() in name.lower():
                    if pattern not in detected:
                        detected[pattern] = {
                            "import_matches": [],
                            "likely_formats": formats,
                        }
                    detected[pattern]["import_matches"].append(name)

        if detected:
            result[category] = detected

    return result


def analyze_network(imports):
    """Analyze network attack surface."""
    result = {
        "socket_layer": [],
        "tls_layer": [],
        "high_level": [],
        "protocols_likely": [],
    }

    for imp in imports:
        name = imp.lstrip("_")
        if name in {"socket", "connect", "bind", "listen", "accept",
                     "send", "recv", "sendto", "recvfrom", "sendmsg", "recvmsg"}:
            result["socket_layer"].append(name)
        elif "SSL" in name or "ssl" in name or "SecureTransport" in name:
            result["tls_layer"].append(name)
        elif name in {"NSURLSession", "CFURLConnection", "NSURLRequest",
                      "WKWebView", "nw_connection"} or "curl_" in name:
            result["high_level"].append(name)

    # Infer protocols
    if result["tls_layer"]:
        result["protocols_likely"].append("TLS/HTTPS")
    if result["socket_layer"]:
        result["protocols_likely"].append("TCP/UDP")
    if any("http" in i.lower() for i in imports):
        result["protocols_likely"].append("HTTP")
    if any("websocket" in i.lower() for i in imports):
        result["protocols_likely"].append("WebSocket")
    if any("dns" in i.lower() for i in imports):
        result["protocols_likely"].append("DNS")

    # Deduplicate
    result["socket_layer"] = list(set(result["socket_layer"]))
    result["tls_layer"] = list(set(result["tls_layer"]))
    result["high_level"] = list(set(result["high_level"]))
    result["protocols_likely"] = list(set(result["protocols_likely"]))

    return result


def analyze_syscall_patterns(imports):
    """Categorize syscall-level imports."""
    categorized = {}
    for cat, funcs in IMPORT_CATEGORIES.items():
        found = [imp.lstrip("_") for imp in imports if imp.lstrip("_") in funcs]
        if found:
            categorized[cat] = sorted(set(found))
    return categorized


def compute_attack_surface_score(result):
    """Compute overall attack surface risk score."""
    score = 0
    notes = []

    # Entitlements
    ents = result.get("entitlements", {})
    dangerous_ents = ents.get("dangerous", [])
    for d in dangerous_ents:
        if d["risk"] == "critical":
            score += 30
        elif d["risk"] == "high":
            score += 15
        elif d["risk"] == "medium":
            score += 5
    if not ents.get("sandboxed", True):
        score += 20
        notes.append("NOT sandboxed")

    # IPC
    ipc = result.get("ipc", {})
    if ipc.get("mach_ports", {}).get("count", 0) > 0:
        score += 10
        notes.append("Uses Mach ports")
    if ipc.get("xpc", {}).get("count", 0) > 0:
        score += 5

    # Parsers
    parsers = result.get("parsers", {})
    parser_count = sum(len(v) for v in parsers.values())
    score += min(parser_count * 5, 25)
    if parser_count > 3:
        notes.append(f"Handles {parser_count} parser categories")

    # Network
    net = result.get("network", {})
    if net.get("socket_layer"):
        score += 10
        notes.append("Raw socket access")

    # Classify
    if score >= 60:
        level = "critical"
    elif score >= 40:
        level = "high"
    elif score >= 20:
        level = "medium"
    else:
        level = "low"

    return {
        "attack_surface_score": score,
        "risk_level": level,
        "notes": notes,
        "dangerous_entitlements": len(dangerous_ents),
        "parser_categories": len(parsers),
        "ipc_types": sum(1 for v in ipc.values()
                         if isinstance(v, dict) and v.get("count", 0) > 0),
    }


def enumerate_and_rank_services(source_binary, rank_by, out):
    """Enumerate reachable services from a sandbox and rank by attack potential."""
    from cb.commands.sandbox import analyze_reachable_services
    from cb.patterns.dangerous_functions import HIGH_VALUE_SERVICES, COMPLEX_INPUT_INDICATORS

    reachability = analyze_reachable_services(source_binary, out)
    reachable = reachability.get("reachable_services", [])

    ranked = []
    for svc in reachable:
        score = 0
        notes = []
        binary = svc.get("binary", "")

        # Privilege scoring
        runs_as = svc.get("runs_as", "")
        if runs_as == "root" or not runs_as:
            score += 25
            notes.append("runs as root")

        # High-value service
        if svc.get("service") in HIGH_VALUE_SERVICES:
            score += 15
            notes.append("high-value service")

        # Analyze binary if available
        if binary and os.path.exists(binary):
            try:
                ents = get_entitlements(binary)
                imports = get_imports(binary)
                import_set = {i.lstrip("_") for i in imports}

                # No sandbox on target
                if not ents.get("com.apple.security.app-sandbox", False):
                    score += 20
                    notes.append("target not sandboxed")

                # Critical entitlements
                for ent_key in ents:
                    for pattern, info in DANGEROUS_ENTITLEMENTS.items():
                        if pattern in ent_key and info["risk"] in ("critical", "high"):
                            score += 20
                            notes.append(f"critical entitlement: {ent_key[:60]}")
                            break
                    if score >= 90:
                        break

                # No auth checks
                auth_funcs = {"SecTaskCreateWithAuditToken",
                              "xpc_connection_get_audit_token",
                              "audit_token_to_pid"}
                if not (auth_funcs & import_set):
                    score += 15
                    notes.append("no auth checks detected")

                # Complex input handling
                complex_inputs = COMPLEX_INPUT_INDICATORS & import_set
                if complex_inputs:
                    score += 10
                    notes.append(f"complex input: {len(complex_inputs)} indicators")

                # Parser categories
                parsers_found = 0
                for cat, patterns in PARSER_INDICATORS.items():
                    for pattern in patterns:
                        if any(pattern.lower() in imp.lower() for imp in import_set):
                            parsers_found += 1
                            break
                if parsers_found > 0:
                    score += min(parsers_found * 5, 10)
                    notes.append(f"{parsers_found} parser categories")

            except Exception:
                pass

        # Tier classification
        if score >= 70:
            tier = "critical"
        elif score >= 45:
            tier = "high"
        elif score >= 20:
            tier = "medium"
        else:
            tier = "low"

        ranked.append({
            "service": svc.get("service", ""),
            "label": svc.get("label", ""),
            "binary": binary,
            "score": score,
            "tier": tier,
            "runs_as": svc.get("runs_as", ""),
            "notes": notes,
        })

    # Sort by score descending
    ranked.sort(key=lambda r: r["score"], reverse=True)

    # Build result
    result = {
        "source_binary": source_binary,
        "total_reachable": len(ranked),
        "by_tier": {
            "critical": len([r for r in ranked if r["tier"] == "critical"]),
            "high": len([r for r in ranked if r["tier"] == "high"]),
            "medium": len([r for r in ranked if r["tier"] == "medium"]),
            "low": len([r for r in ranked if r["tier"] == "low"]),
        },
        "ranked_services": ranked,
    }

    if ranked:
        result["top_recommendation"] = {
            "service": ranked[0]["service"],
            "score": ranked[0]["score"],
            "tier": ranked[0]["tier"],
            "reason": "; ".join(ranked[0]["notes"][:3]),
        }

    return result


def main():
    parser = argparse.ArgumentParser(prog="cbattack", description="Attack surface mapper")
    parser.add_argument("binary", help="Path to binary or .app")
    parser.add_argument("--app-bundle", action="store_true")
    parser.add_argument("--ipc", action="store_true")
    parser.add_argument("--parsers", action="store_true")
    parser.add_argument("--network", action="store_true")
    parser.add_argument("--entitlements", action="store_true")
    parser.add_argument("--syscalls", action="store_true")
    parser.add_argument("--depth", choices=["shallow", "deep"], default="shallow")
    parser.add_argument("--services-from", type=str, default=None)
    parser.add_argument("--rank-by", choices=["risk", "attack_surface", "privilege"], default="risk")
    add_output_args(parser)
    args = parser.parse_args()
    run(args)
