"""cb bundle - Scan .app/.framework bundles for security posture."""
import os
import struct

from cb.output import add_output_args, make_formatter
from cb.macho import (
    get_file_info, get_architectures, get_entitlements,
    get_protections, get_imports, detect_format,
)


# Mach-O magic values (big-endian representation)
_MACHO_MAGICS = {
    0xFEEDFACE,  # MH_MAGIC (32-bit)
    0xFEEDFACF,  # MH_MAGIC_64
    0xCFFAEDFE,  # MH_CIGAM_64 (little-endian 64)
    0xCEFAEDFE,  # MH_CIGAM (little-endian 32)
    0xCAFEBABE,  # FAT_MAGIC
    0xBEBAFECA,  # FAT_CIGAM
}

_DANGEROUS_ENTITLEMENTS = {
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.allow-jit",
    "com.apple.security.get-task-allow",
}


def _is_macho(path):
    """Check if a file is a Mach-O binary by reading magic bytes."""
    try:
        with open(path, "rb") as f:
            data = f.read(4)
        if len(data) < 4:
            return False
        magic = int.from_bytes(data, "big")
        return magic in _MACHO_MAGICS
    except (OSError, IOError):
        return False


def _find_bundle_binaries(bundle_path):
    """Walk an .app or .framework bundle and find all Mach-O binaries."""
    bundle_path = os.path.abspath(bundle_path)
    results = []
    seen = set()

    def _add(path, binary_type):
        real = os.path.realpath(path)
        if real in seen:
            return
        seen.add(real)
        rel = os.path.relpath(path, bundle_path)
        results.append({
            "path": path,
            "relative_path": rel,
            "type": binary_type,
        })

    def _scan_dir(directory, binary_type):
        """Scan a directory for Mach-O files, recursing into .app/.framework dirs."""
        if not os.path.isdir(directory):
            return
        for entry in os.listdir(directory):
            full = os.path.join(directory, entry)
            if entry.endswith(".app"):
                # Recurse into nested .app bundles
                _find_in_bundle(full, "helper")
            elif entry.endswith(".framework"):
                _find_in_bundle(full, "framework")
            elif os.path.isfile(full) and _is_macho(full):
                _add(full, binary_type)
            elif os.path.isdir(full):
                _scan_dir(full, binary_type)

    def _find_in_bundle(bpath, default_type):
        """Find binaries inside a bundle (.app or .framework)."""
        contents = os.path.join(bpath, "Contents")
        has_contents = os.path.isdir(contents)
        base = contents if has_contents else bpath

        # Main executable in MacOS/
        macos_dir = os.path.join(base, "MacOS")
        if os.path.isdir(macos_dir):
            for entry in os.listdir(macos_dir):
                full = os.path.join(macos_dir, entry)
                if os.path.isfile(full) and _is_macho(full):
                    _add(full, default_type if default_type != "helper" or bpath != bundle_path else "main")

        # Helpers/
        for helpers_name in ("Helpers", "XPCServices"):
            helpers_dir = os.path.join(base, helpers_name)
            _scan_dir(helpers_dir, "helper")

        # Frameworks/
        frameworks_dir = os.path.join(base, "Frameworks")
        if os.path.isdir(frameworks_dir):
            for entry in os.listdir(frameworks_dir):
                full = os.path.join(frameworks_dir, entry)
                if entry.endswith(".framework"):
                    _find_in_bundle(full, "framework")
                elif os.path.isfile(full) and _is_macho(full):
                    _add(full, "framework")

        # PlugIns/
        plugins_dir = os.path.join(base, "PlugIns")
        _scan_dir(plugins_dir, "plugin")

        # Frameworks may have Helpers/ directly (Chrome does this)
        if not has_contents:
            helpers_dir = os.path.join(bpath, "Helpers")
            _scan_dir(helpers_dir, "helper")

    # Top-level: detect main executable
    contents = os.path.join(bundle_path, "Contents")
    has_contents = os.path.isdir(contents)
    base = contents if has_contents else bundle_path

    # Main executable
    macos_dir = os.path.join(base, "MacOS")
    if os.path.isdir(macos_dir):
        for entry in os.listdir(macos_dir):
            full = os.path.join(macos_dir, entry)
            if os.path.isfile(full) and _is_macho(full):
                _add(full, "main")

    # Helpers/
    for helpers_name in ("Helpers", "XPCServices"):
        helpers_dir = os.path.join(base, helpers_name)
        _scan_dir(helpers_dir, "helper")

    # Frameworks/
    frameworks_dir = os.path.join(base, "Frameworks")
    if os.path.isdir(frameworks_dir):
        for entry in os.listdir(frameworks_dir):
            full = os.path.join(frameworks_dir, entry)
            if entry.endswith(".framework"):
                _find_in_bundle(full, "framework")
            elif os.path.isfile(full) and _is_macho(full):
                _add(full, "framework")

    # PlugIns/
    plugins_dir = os.path.join(base, "PlugIns")
    _scan_dir(plugins_dir, "plugin")

    # Frameworks may have Helpers/ directly (Chrome-style)
    if not has_contents:
        helpers_dir = os.path.join(bundle_path, "Helpers")
        _scan_dir(helpers_dir, "helper")

    return results


def _scan_binary_quick(path):
    """Quick per-binary security scan."""
    result = {"path": path}

    try:
        info = get_file_info(path)
        result["size_bytes"] = info.get("size_bytes", 0)
        result["size_human"] = info.get("size_human", "")
        result["format"] = info.get("format", "unknown")
    except Exception:
        result["size_bytes"] = 0
        result["format"] = "unknown"

    try:
        archs = get_architectures(path)
        result["architectures"] = [a.get("arch", "unknown") for a in archs]
    except Exception:
        result["architectures"] = []

    try:
        ents = get_entitlements(path)
        result["entitlements"] = ents
        dangerous = [e for e in ents if e in _DANGEROUS_ENTITLEMENTS]
        result["dangerous_entitlements"] = dangerous
    except Exception:
        result["entitlements"] = {}
        result["dangerous_entitlements"] = []

    try:
        prots = get_protections(path)
        cs = prots.get("code_signing", {})
        result["signed"] = cs.get("signed", False)
        result["hardened_runtime"] = cs.get("hardened_runtime", False)
        result["authority"] = cs.get("authority", "")
        result["team_id"] = cs.get("team_id", "")
    except Exception:
        result["signed"] = False
        result["hardened_runtime"] = False
        result["authority"] = ""
        result["team_id"] = ""

    try:
        imports = get_imports(path)
        result["import_count"] = len(imports)
    except Exception:
        result["import_count"] = 0

    return result


def _scan_binary_deep(path, bundle_path):
    """Deep per-binary security scan: sandbox profile + privilege level + findings."""
    result = _scan_binary_quick(path)

    # Extract embedded sandbox profile
    try:
        from cb.macho import get_embedded_sandbox_profile
        profile = get_embedded_sandbox_profile(path)
        if profile:
            result["has_sandbox_profile"] = True
            result["sandbox_profile_size"] = len(profile)
            # Extract security findings from profile
            try:
                from cb.commands.sandbox import extract_security_findings
                sec_findings = extract_security_findings(profile)
                if sec_findings:
                    result["sandbox_findings"] = sec_findings
                    result["sandbox_findings_count"] = len(sec_findings)
            except ImportError:
                pass
        else:
            result["has_sandbox_profile"] = False
    except Exception:
        result["has_sandbox_profile"] = False

    # Detect privilege level
    result["privilege"] = _detect_privilege_level(path, bundle_path)

    return result


def _detect_privilege_level(binary_path, bundle_path):
    """Detect the privilege level of a binary."""
    privilege = {
        "level": "standard",
        "runs_as_root": False,
        "is_setuid": False,
        "is_launch_daemon": False,
        "has_sandbox": True,
    }

    # Check setuid bit
    try:
        st = os.stat(binary_path)
        if st.st_mode & 0o4000:
            privilege["is_setuid"] = True
            privilege["runs_as_root"] = True
            privilege["level"] = "root"
    except OSError:
        pass

    # Check entitlements for sandbox status
    try:
        ents = get_entitlements(binary_path)
        if not ents.get("com.apple.security.app-sandbox", False):
            privilege["has_sandbox"] = False
            if privilege["level"] == "standard":
                privilege["level"] = "unsandboxed"
    except Exception:
        pass

    # Check if referenced by a LaunchDaemon
    if _check_launch_daemon(binary_path, bundle_path):
        privilege["is_launch_daemon"] = True
        privilege["runs_as_root"] = True
        privilege["level"] = "root"

    return privilege


def _check_launch_daemon(binary_path, bundle_path):
    """Check if binary is referenced in Contents/Library/LaunchDaemons/."""
    import plistlib as pl
    daemon_dirs = [
        os.path.join(bundle_path, "Contents", "Library", "LaunchDaemons"),
    ]
    binary_name = os.path.basename(binary_path)

    for daemon_dir in daemon_dirs:
        if not os.path.isdir(daemon_dir):
            continue
        for entry in os.listdir(daemon_dir):
            if not entry.endswith(".plist"):
                continue
            try:
                with open(os.path.join(daemon_dir, entry), "rb") as f:
                    plist = pl.load(f)
                program = plist.get("Program", "")
                prog_args = plist.get("ProgramArguments", [])
                all_progs = [program] + prog_args
                if any(binary_name in p for p in all_progs if p):
                    return True
            except Exception:
                pass
    return False


def _build_security_comparison(binaries_results):
    """Build a comparative security table sorted by risk (unsandboxed root first)."""
    def _risk_score(b):
        score = 0
        priv = b.get("privilege", {})
        if priv.get("runs_as_root"):
            score += 100
        if not priv.get("has_sandbox", True):
            score += 50
        if priv.get("is_setuid"):
            score += 30
        score += len(b.get("dangerous_entitlements", []) or []) * 10
        score += len(b.get("sandbox_findings", []) or []) * 5
        return score

    sorted_bins = sorted(binaries_results, key=_risk_score, reverse=True)

    comparison = []
    for b in sorted_bins:
        priv = b.get("privilege", {})
        entry = {
            "binary": b.get("relative_path", b.get("path", "")),
            "type": b.get("type", "unknown"),
            "privilege_level": priv.get("level", "unknown"),
            "runs_as_root": priv.get("runs_as_root", False),
            "sandboxed": priv.get("has_sandbox", True),
            "has_sandbox_profile": b.get("has_sandbox_profile", False),
            "sandbox_findings": b.get("sandbox_findings_count", 0),
            "dangerous_entitlements": len(b.get("dangerous_entitlements", []) or []),
            "signed": b.get("signed", False),
            "risk_score": _risk_score(b),
        }
        comparison.append(entry)

    return comparison


def _assess_bundle_security(binaries_results):
    """Assess overall bundle security posture."""
    signed_count = sum(1 for b in binaries_results if b.get("signed"))
    unsigned_count = len(binaries_results) - signed_count
    all_dangerous = {}
    weakest_link = None
    max_danger = -1

    for b in binaries_results:
        danger = b.get("dangerous_entitlements", [])
        if danger:
            all_dangerous[b["path"]] = danger
        score = len(danger)
        if not b.get("signed"):
            score += 10
        if score > max_danger:
            max_danger = score
            weakest_link = {
                "path": b.get("path", ""),
                "signed": b.get("signed", False),
                "dangerous_entitlements": danger,
            }

    has_disable_lib_val = any(
        "com.apple.security.cs.disable-library-validation" in b.get("dangerous_entitlements", [])
        for b in binaries_results
    )
    all_signed = unsigned_count == 0
    any_dangerous = len(all_dangerous) > 0
    all_hardened = all(b.get("hardened_runtime") for b in binaries_results)

    if all_signed and all_hardened and not any_dangerous:
        rating = "hardened"
        summary = "All binaries signed with hardened runtime, no dangerous entitlements."
    elif all_signed and not has_disable_lib_val:
        rating = "standard"
        summary = f"All binaries signed. {len(all_dangerous)} binary(ies) have dangerous entitlements."
    else:
        reasons = []
        if unsigned_count:
            reasons.append(f"{unsigned_count} unsigned binary(ies)")
        if has_disable_lib_val:
            reasons.append("library validation disabled")
        rating = "weak"
        summary = "Weak security posture: " + ", ".join(reasons) + "."

    return {
        "rating": rating,
        "weakest_link": weakest_link,
        "signed_count": signed_count,
        "unsigned_count": unsigned_count,
        "summary": summary,
    }


def register(subparsers):
    p = subparsers.add_parser("bundle", help="Scan .app/.framework bundle security")
    p.add_argument("bundle_path", help="Path to .app or .framework bundle")
    p.add_argument("--entitlements-only", action="store_true",
                   help="Only show entitlements for each binary")
    p.add_argument("--helpers-only", action="store_true",
                   help="Only scan helper binaries")
    p.add_argument("--deep", action="store_true",
                   help="Deep scan: sandbox profiles, privilege levels, security comparison")
    add_output_args(p)
    p.set_defaults(func=run)


def run(args):
    fmt = make_formatter(args)
    bundle_path = os.path.abspath(args.bundle_path)

    if not os.path.isdir(bundle_path):
        fmt.status(f"Error: {bundle_path} is not a directory")
        fmt.emit({"error": f"Not a directory: {bundle_path}"}, "bundle")
        return

    fmt.status(f"Scanning bundle: {bundle_path}")

    # Discover binaries
    fmt.status("Finding Mach-O binaries in bundle...")
    binaries = _find_bundle_binaries(bundle_path)
    fmt.status(f"Found {len(binaries)} Mach-O binary(ies)")

    if not binaries:
        fmt.emit({
            "bundle_path": bundle_path,
            "binaries_found": 0,
            "binaries": [],
            "error": "No Mach-O binaries found in bundle",
        }, "bundle")
        return

    # Filter if --helpers-only
    if args.helpers_only:
        binaries = [b for b in binaries if b["type"] == "helper"]
        fmt.status(f"Filtered to {len(binaries)} helper binary(ies)")

    # Scan each binary
    deep = getattr(args, 'deep', False)
    binaries_results = []
    for i, b in enumerate(binaries):
        label = "Deep scanning" if deep else "Scanning"
        fmt.status(f"{label} [{i+1}/{len(binaries)}]: {b['relative_path']}")
        try:
            if deep:
                scan = _scan_binary_deep(b["path"], bundle_path)
            else:
                scan = _scan_binary_quick(b["path"])
            scan["relative_path"] = b["relative_path"]
            scan["type"] = b["type"]
            binaries_results.append(scan)
        except Exception as exc:
            binaries_results.append({
                "path": b["path"],
                "relative_path": b["relative_path"],
                "type": b["type"],
                "error": str(exc),
            })

    # Build output
    data = {
        "bundle_path": bundle_path,
        "binaries_found": len(binaries_results),
    }

    if args.entitlements_only:
        # Slim output: just entitlements per binary
        ent_list = []
        for b in binaries_results:
            entry = {
                "relative_path": b.get("relative_path", ""),
                "type": b.get("type", ""),
                "entitlements": b.get("entitlements", {}),
                "dangerous_entitlements": b.get("dangerous_entitlements", []),
            }
            ent_list.append(entry)
        data["entitlements"] = ent_list
    else:
        data["binaries"] = binaries_results
        # Security assessment
        fmt.status("Assessing bundle security...")
        data["security"] = _assess_bundle_security(binaries_results)

        # Deep mode: add security comparison table
        if deep:
            fmt.status("Building security comparison...")
            data["security_comparison"] = _build_security_comparison(binaries_results)

    fmt.emit(data, "bundle")
