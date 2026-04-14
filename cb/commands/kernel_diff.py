"""cb kernel-diff - Analyze kernel git commits for security patches and variant opportunities."""
import argparse
import os
import re
import subprocess
import sys
from collections import defaultdict

from cb.output import add_output_args, make_formatter
from cb.patterns.kernel_patterns import KERNEL_PATCH_PATTERNS, KERNEL_SUBSYSTEMS


def register(subparsers):
    p = subparsers.add_parser(
        "kernel-diff",
        help="Analyze kernel git diffs for security patches and variant bugs",
        description="Find security-relevant kernel patches and suggest variant opportunities.",
    )
    p.add_argument("range", nargs="?", default="HEAD~50..HEAD",
                   help="Git commit range (default: HEAD~50..HEAD)")
    p.add_argument("--repo", default=".", help="Path to kernel git repo")
    p.add_argument("--subsystem", default="all",
                   help="Filter by subsystem path (e.g., net/netfilter)")
    p.add_argument("--security-only", action="store_true",
                   help="Only show commits that look like security fixes")
    p.add_argument("--find-variants", action="store_true",
                   help="For each security fix, search for unfixed variant patterns")
    p.add_argument("--cve", type=str, default="",
                   help="Search for commits related to a specific CVE")
    p.add_argument("--since", type=str, default="",
                   help="Only show commits since date (e.g., '2025-01-01')")
    p.add_argument("--author", type=str, default="",
                   help="Filter by author")
    add_output_args(p)
    p.set_defaults(func=run)


# Indicators that a commit is security-relevant
SECURITY_INDICATORS = [
    (r"fix.*(?:overflow|underflow|oob|out.of.bound)", "overflow_fix", "high"),
    (r"fix.*(?:uaf|use.after.free|dangling|double.free)", "uaf_fix", "critical"),
    (r"fix.*(?:null.ptr|null.deref|nullptr|null pointer)", "null_fix", "medium"),
    (r"fix.*(?:race|deadlock|locking|concurrent)", "race_fix", "high"),
    (r"fix.*(?:leak|info.leak|uninit|uninitialized)", "leak_fix", "medium"),
    (r"fix.*(?:inject|escape|bypass|privilege)", "security_fix", "critical"),
    (r"(?:add|check).*(?:bounds|range|limit|valid|sanit)", "bounds_added", "high"),
    (r"(?:add|missing).*(?:lock|mutex|synchroniz)", "lock_added", "high"),
    (r"(?:add|missing).*(?:null.check|error.check)", "null_check_added", "medium"),
    (r"(?:add|missing).*(?:capable|permission|access)", "access_check", "high"),
    (r"CVE-\d{4}-\d+", "cve_reference", "critical"),
    (r"Fixes:\s+[0-9a-f]{12}", "fixes_tag", "high"),
    (r"Cc:\s+stable@", "stable_backport", "high"),
]


def git_cmd(repo, *args):
    """Run a git command in the repo."""
    try:
        result = subprocess.run(
            ["git", "-C", repo] + list(args),
            capture_output=True, text=True, timeout=30,
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def analyze_commit(repo, commit_hash):
    """Analyze a single commit for security relevance."""
    # Get commit message
    msg = git_cmd(repo, "log", "-1", "--format=%B", commit_hash)
    author = git_cmd(repo, "log", "-1", "--format=%an", commit_hash)
    date = git_cmd(repo, "log", "-1", "--format=%ai", commit_hash)
    subject = git_cmd(repo, "log", "-1", "--format=%s", commit_hash)

    # Check security indicators
    indicators = []
    max_severity = "low"
    for pattern, indicator_type, severity in SECURITY_INDICATORS:
        if re.search(pattern, msg, re.IGNORECASE):
            indicators.append(indicator_type)
            if {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(severity, 0) > \
               {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(max_severity, 0):
                max_severity = severity

    if not indicators:
        return None

    # Get diff stats
    diff_stat = git_cmd(repo, "diff", "--stat", f"{commit_hash}~1..{commit_hash}")
    diff = git_cmd(repo, "diff", "-U3", f"{commit_hash}~1..{commit_hash}")

    # Get changed files
    files_changed = git_cmd(repo, "diff", "--name-only", f"{commit_hash}~1..{commit_hash}")
    file_list = [f for f in files_changed.split("\n") if f]

    # Detect subsystem
    subsystems = set()
    for f in file_list:
        for name, info in KERNEL_SUBSYSTEMS.items():
            if info["path"] in f:
                subsystems.add(name)

    # Analyze the diff for specific patch patterns
    patch_patterns_found = []
    for line in diff.split("\n"):
        for pattern_name, pattern_info in KERNEL_PATCH_PATTERNS.items():
            if re.search(pattern_info["pattern"], line):
                patch_patterns_found.append({
                    "type": pattern_name,
                    "description": pattern_info["description"],
                    "line": line.strip(),
                })

    # Extract CVE references
    cves = re.findall(r"CVE-\d{4}-\d+", msg)

    # Extract Fixes: tags
    fixes = re.findall(r"Fixes:\s+([0-9a-f]{12,})", msg)

    return {
        "hash": commit_hash[:12],
        "subject": subject,
        "author": author,
        "date": date,
        "severity": max_severity,
        "indicators": indicators,
        "cves": cves,
        "fixes_commits": fixes,
        "files_changed": file_list,
        "subsystems": list(subsystems),
        "patch_patterns": patch_patterns_found,
        "diff_stat": diff_stat,
    }


def find_variants(repo, commit_info):
    """Search for unfixed variants of a security fix."""
    variants = []

    # For each changed file, look for similar patterns in sibling files
    for filepath in commit_info.get("files_changed", []):
        dir_path = os.path.dirname(filepath)
        if not dir_path:
            continue

        # Get the added lines (the fix)
        diff = git_cmd(repo, "diff", "-U0", f"{commit_info['hash']}~1..{commit_info['hash']}",
                       "--", filepath)

        # Extract the fix pattern
        added_lines = [line[1:] for line in diff.split("\n") if line.startswith("+") and not line.startswith("+++")]

        if not added_lines:
            continue

        # Look for the removed pattern (the bug) in other files
        removed_lines = [line[1:] for line in diff.split("\n") if line.startswith("-") and not line.startswith("---")]

        for removed_line in removed_lines:
            # Skip trivial lines
            stripped = removed_line.strip()
            if not stripped or len(stripped) < 10:
                continue

            # Search for similar patterns in the same directory
            try:
                search_result = subprocess.run(
                    ["grep", "-rn", "--include=*.c", "--include=*.h",
                     stripped[:50], os.path.join(repo, dir_path)],
                    capture_output=True, text=True, timeout=10,
                )
                for match_line in search_result.stdout.split("\n")[:5]:
                    if match_line and filepath not in match_line:
                        variants.append({
                            "original_fix": filepath,
                            "variant_location": match_line.split(":")[0] if ":" in match_line else match_line,
                            "pattern": stripped[:80],
                            "match": match_line[:200],
                        })
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

    return variants


def run(args):
    fmt = make_formatter(args)
    repo = os.path.expanduser(args.repo)

    if not os.path.isdir(os.path.join(repo, ".git")):
        print(f"Error: {repo} is not a git repository", file=sys.stderr)
        sys.exit(1)

    # Build git log command
    log_args = ["log", "--format=%H", args.range]
    if args.since:
        log_args.extend(["--since", args.since])
    if args.author:
        log_args.extend(["--author", args.author])
    if args.subsystem != "all" and args.subsystem in KERNEL_SUBSYSTEMS:
        log_args.extend(["--", KERNEL_SUBSYSTEMS[args.subsystem]["path"]])
    elif args.subsystem != "all":
        log_args.extend(["--", args.subsystem])
    if args.cve:
        log_args = ["log", "--format=%H", "--all", f"--grep={args.cve}"]

    commits = git_cmd(repo, *log_args).split("\n")
    commits = [c for c in commits if c and len(c) >= 7]

    if not commits:
        print("No commits found in range", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Analyzing {len(commits)} commits...", file=sys.stderr)

    security_commits = []
    all_variants = []

    for i, commit_hash in enumerate(commits):
        result = analyze_commit(repo, commit_hash)
        if result:
            if not args.security_only or result["severity"] in ("critical", "high"):
                security_commits.append(result)

            if args.find_variants:
                variants = find_variants(repo, result)
                if variants:
                    result["variants"] = variants
                    all_variants.extend(variants)

        if (i + 1) % 100 == 0:
            print(f"[*] Analyzed {i+1}/{len(commits)} commits, "
                  f"{len(security_commits)} security-relevant...", file=sys.stderr)

    # Sort by severity
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    security_commits.sort(key=lambda c: sev_rank.get(c["severity"], 0), reverse=True)

    output = {
        "repo": repo,
        "range": args.range,
        "total_commits": len(commits),
        "security_commits": len(security_commits),
        "severity_breakdown": {
            sev: len([c for c in security_commits if c["severity"] == sev])
            for sev in ("critical", "high", "medium", "low")
        },
        "commits": security_commits[:getattr(args, "max_results", 50)],
    }

    if args.find_variants:
        output["variants_found"] = len(all_variants)
        output["variants"] = all_variants[:20]

    fmt.emit(output, "kernel_diff")
