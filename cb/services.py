"""Shared service enumeration for macOS launchd services."""
import glob
import os
import plistlib
import re
import subprocess


def enumerate_launchd_services():
    """Parse launchd plists to enumerate system services.

    Scans LaunchDaemons and LaunchAgents directories for service definitions.
    """
    services = []
    search_dirs = [
        "/System/Library/LaunchDaemons",
        "/Library/LaunchDaemons",
        "/System/Library/LaunchAgents",
        "/Library/LaunchAgents",
        os.path.expanduser("~/Library/LaunchAgents"),
    ]

    for svc_dir in search_dirs:
        if not os.path.isdir(svc_dir):
            continue
        for pfile in os.listdir(svc_dir):
            if not pfile.endswith(".plist"):
                continue
            ppath = os.path.join(svc_dir, pfile)
            try:
                with open(ppath, "rb") as f:
                    plist = plistlib.load(f)
                svc = {
                    "label": plist.get("Label", pfile.replace(".plist", "")),
                    "plist_path": ppath,
                    "program": plist.get("Program", ""),
                    "program_arguments": plist.get("ProgramArguments", []),
                    "mach_services": list(plist.get("MachServices", {}).keys()),
                    "sandbox_profile": plist.get("SandboxProfile", ""),
                    "user_name": plist.get("UserName", ""),
                    "group_name": plist.get("GroupName", ""),
                    "source_dir": svc_dir,
                }
                # Determine binary path
                if svc["program"]:
                    svc["binary_path"] = svc["program"]
                elif svc["program_arguments"]:
                    svc["binary_path"] = svc["program_arguments"][0]
                else:
                    svc["binary_path"] = ""
                services.append(svc)
            except Exception:
                continue

    return services


def get_running_services():
    """Get currently running launchd services via launchctl."""
    services = []
    try:
        r = subprocess.run(["launchctl", "list"], capture_output=True,
                          text=True, timeout=10)
        for line in r.stdout.splitlines()[1:]:  # skip header
            parts = line.split("\t")
            if len(parts) >= 3:
                services.append({
                    "pid": parts[0].strip() if parts[0].strip() != "-" else None,
                    "status": parts[1].strip(),
                    "label": parts[2].strip(),
                })
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return services


def resolve_service_binary(service_name):
    """Find the backing binary for a Mach service name."""
    all_services = enumerate_launchd_services()
    for svc in all_services:
        if service_name in svc.get("mach_services", []):
            binary = svc.get("binary_path", "")
            if binary and os.path.exists(binary):
                return binary
        if svc.get("label") == service_name:
            binary = svc.get("binary_path", "")
            if binary and os.path.exists(binary):
                return binary
    return None


def resolve_service_sandbox_profile(svc):
    """Resolve sandbox profile for a service.

    Checks: plist SandboxProfile key, embedded profile in binary, convention.
    """
    # 1. Plist key
    profile_name = svc.get("sandbox_profile", "")
    if profile_name:
        # Look for .sb file
        for sb_dir in ["/System/Library/Sandbox/Profiles",
                       "/usr/share/sandbox"]:
            sb_path = os.path.join(sb_dir, profile_name)
            if not sb_path.endswith(".sb"):
                sb_path += ".sb"
            if os.path.exists(sb_path):
                return sb_path

    # 2. Convention: service label as profile name
    label = svc.get("label", "")
    if label:
        for sb_dir in ["/System/Library/Sandbox/Profiles",
                       "/usr/share/sandbox"]:
            sb_path = os.path.join(sb_dir, f"{label}.sb")
            if os.path.exists(sb_path):
                return sb_path

    return None
