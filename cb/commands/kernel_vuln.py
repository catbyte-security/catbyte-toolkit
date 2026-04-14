"""cb kernel-vuln - Linux kernel source vulnerability scanner."""
import argparse
import os
import re
import sys
from pathlib import Path
from collections import defaultdict

from cb.output import add_output_args, make_formatter
from cb.patterns.kernel_patterns import KERNEL_VULN_PATTERNS, KERNEL_SUBSYSTEMS


def register(subparsers):
    p = subparsers.add_parser(
        "kernel-vuln",
        help="Scan Linux kernel source for vulnerability patterns",
        description="Pattern-based vulnerability scanner for Linux kernel C source code.",
    )
    p.add_argument("path", help="Source file or directory to scan")
    p.add_argument(
        "--category",
        choices=[
            "overflow", "integer", "uaf", "race", "info_leak",
            "null_deref", "privilege", "logic", "all",
        ],
        default="all",
        help="Filter by vulnerability category",
    )
    p.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "all"],
        default="all",
        help="Filter by minimum severity",
    )
    p.add_argument(
        "--subsystem",
        choices=list(KERNEL_SUBSYSTEMS.keys()) + ["auto", "all"],
        default="auto",
        help="Target subsystem (auto-detect from path)",
    )
    p.add_argument(
        "--context", type=int, default=3,
        help="Lines of context around matches",
    )
    p.add_argument(
        "--exclude", type=str, default="",
        help="Comma-separated patterns to exclude (e.g., test,tools,Documentation)",
    )
    p.add_argument(
        "--max-file-size", type=int, default=500000,
        help="Skip files larger than this (bytes)",
    )
    p.add_argument(
        "--focus-entry-points", action="store_true",
        help="Only scan functions reachable from syscall/ioctl entry points",
    )
    p.add_argument(
        "--summary-only", action="store_true",
        help="Only show summary statistics, not individual matches",
    )
    add_output_args(p)
    p.set_defaults(func=run)


SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def should_scan_file(filepath, excludes):
    """Check if a file should be scanned."""
    if not filepath.endswith((".c", ".h")):
        return False
    for exc in excludes:
        if exc and exc in filepath:
            return False
    return True


def detect_subsystem(filepath):
    """Auto-detect kernel subsystem from file path."""
    for name, info in KERNEL_SUBSYSTEMS.items():
        if info["path"] in filepath:
            return name
    return "unknown"


def scan_file(filepath, patterns, category_filter, severity_filter, context_lines):
    """Scan a single file for vulnerability patterns."""
    try:
        with open(filepath, "r", errors="replace") as f:
            content = f.read()
            lines = content.split("\n")
    except (OSError, UnicodeDecodeError):
        return []

    findings = []

    for pattern_name, pattern_info in patterns.items():
        # Filter by category
        if category_filter != "all" and pattern_info["category"] != category_filter:
            continue

        # Filter by severity
        if severity_filter != "all":
            if SEVERITY_RANK.get(pattern_info["severity"], 0) < SEVERITY_RANK.get(severity_filter, 0):
                continue

        flags = re.IGNORECASE if pattern_info.get("flags") == "IGNORECASE" else 0
        if pattern_info.get("multiline"):
            flags |= re.DOTALL

        try:
            for match in re.finditer(pattern_info["pattern"], content, flags):
                # Find line number
                line_start = content[:match.start()].count("\n") + 1
                line_end = content[:match.end()].count("\n") + 1

                # Extract context
                ctx_start = max(0, line_start - context_lines - 1)
                ctx_end = min(len(lines), line_end + context_lines)
                context = []
                for i in range(ctx_start, ctx_end):
                    prefix = ">>>" if line_start - 1 <= i <= line_end - 1 else "   "
                    context.append(f"{prefix} {i+1:5d} | {lines[i]}")

                # Extract the matched text (truncated)
                matched_text = match.group(0)
                if len(matched_text) > 200:
                    matched_text = matched_text[:200] + "..."

                findings.append({
                    "pattern": pattern_name,
                    "severity": pattern_info["severity"],
                    "category": pattern_info["category"],
                    "description": pattern_info["description"],
                    "file": filepath,
                    "line": line_start,
                    "line_end": line_end,
                    "matched": matched_text,
                    "context": "\n".join(context),
                    "check_context": pattern_info.get("check_context", ""),
                })
        except re.error:
            continue

    return findings


def scan_for_entry_points(filepath, content):
    """Find syscall and ioctl entry points in a file."""
    entry_points = []

    # SYSCALL_DEFINE
    for m in re.finditer(r"SYSCALL_DEFINE\d\s*\(\s*(\w+)", content):
        entry_points.append({
            "type": "syscall",
            "name": m.group(1),
            "line": content[:m.start()].count("\n") + 1,
            "file": filepath,
        })

    # ioctl handlers
    for m in re.finditer(r"\.(?:unlocked_ioctl|compat_ioctl)\s*=\s*(\w+)", content):
        entry_points.append({
            "type": "ioctl",
            "name": m.group(1),
            "line": content[:m.start()].count("\n") + 1,
            "file": filepath,
        })

    # file_operations
    for m in re.finditer(r"static\s+(?:const\s+)?struct\s+file_operations\s+(\w+)", content):
        entry_points.append({
            "type": "file_ops",
            "name": m.group(1),
            "line": content[:m.start()].count("\n") + 1,
            "file": filepath,
        })

    # proc entries
    for m in re.finditer(r"proc_create\w*\s*\(\s*\"([^\"]+)\"", content):
        entry_points.append({
            "type": "proc",
            "name": m.group(1),
            "line": content[:m.start()].count("\n") + 1,
            "file": filepath,
        })

    # netlink handlers
    for m in re.finditer(r"\.doit\s*=\s*(\w+)|genl_register_family", content):
        entry_points.append({
            "type": "netlink",
            "name": m.group(1) if m.group(1) else "genl_family",
            "line": content[:m.start()].count("\n") + 1,
            "file": filepath,
        })

    return entry_points


def run(args):
    fmt = make_formatter(args)
    path = os.path.expanduser(args.path)
    excludes = [e.strip() for e in args.exclude.split(",") if e.strip()]

    # Collect files to scan
    files_to_scan = []
    if os.path.isfile(path):
        files_to_scan = [path]
    elif os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in (
                ".git", "tools", "Documentation", "samples",
                "scripts", "usr", "certs",
            )]
            for f in files:
                fp = os.path.join(root, f)
                if should_scan_file(fp, excludes):
                    if os.path.getsize(fp) <= args.max_file_size:
                        files_to_scan.append(fp)
    else:
        print(f"Error: {path} not found", file=sys.stderr)
        sys.exit(1)

    if not files_to_scan:
        print("No C/H files found to scan", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Scanning {len(files_to_scan)} files...", file=sys.stderr)

    all_findings = []
    all_entry_points = []
    files_scanned = 0
    subsystem_stats = defaultdict(int)

    for filepath in files_to_scan:
        # Auto-detect subsystem
        subsystem = detect_subsystem(filepath)
        if args.subsystem not in ("auto", "all") and subsystem != args.subsystem:
            continue

        subsystem_stats[subsystem] += 1

        # Scan for entry points
        try:
            with open(filepath, "r", errors="replace") as f:
                content = f.read()
            entry_points = scan_for_entry_points(filepath, content)
            all_entry_points.extend(entry_points)
        except OSError:
            continue

        # Scan for vulnerability patterns
        findings = scan_file(
            filepath, KERNEL_VULN_PATTERNS,
            args.category, args.severity, args.context,
        )
        all_findings.extend(findings)
        files_scanned += 1

        if files_scanned % 500 == 0:
            print(f"[*] Scanned {files_scanned}/{len(files_to_scan)} files, "
                  f"{len(all_findings)} findings so far...", file=sys.stderr)

    # Sort by severity
    all_findings.sort(
        key=lambda f: SEVERITY_RANK.get(f["severity"], 0),
        reverse=True,
    )

    # Build output
    result = {
        "scan_path": path,
        "files_scanned": files_scanned,
        "total_findings": len(all_findings),
        "entry_points_found": len(all_entry_points),
        "subsystem_coverage": dict(subsystem_stats),
        "severity_breakdown": {
            sev: len([f for f in all_findings if f["severity"] == sev])
            for sev in ("critical", "high", "medium", "low")
        },
        "category_breakdown": {},
    }

    # Category breakdown
    categories = set(f["category"] for f in all_findings)
    for cat in sorted(categories):
        result["category_breakdown"][cat] = len(
            [f for f in all_findings if f["category"] == cat]
        )

    # Entry points summary
    result["entry_points"] = {
        "syscalls": [e for e in all_entry_points if e["type"] == "syscall"],
        "ioctls": [e for e in all_entry_points if e["type"] == "ioctl"],
        "proc": [e for e in all_entry_points if e["type"] == "proc"],
        "file_ops": [e for e in all_entry_points if e["type"] == "file_ops"],
        "netlink": [e for e in all_entry_points if e["type"] == "netlink"],
    }

    if not args.summary_only:
        # Limit findings in output
        max_results = getattr(args, "max_results", 50)
        result["findings"] = all_findings[:max_results]
        if len(all_findings) > max_results:
            result["truncated"] = True
            result["total_findings_available"] = len(all_findings)

    fmt.emit(result, "kernel_vuln")
