"""cb plan - AI audit planner with deterministic rule engine."""
import argparse
import json
import os
import sys
import time

from cb.output import add_output_args, make_formatter, load_piped_input


def register(subparsers):
    p = subparsers.add_parser("plan", help="Generate audit plan for binary")
    p.add_argument("binary", help="Path to binary")
    p.add_argument("--from-triage", type=str, default=None, metavar="FILE_OR_DASH",
                   help="Use pre-parsed triage data (file path or '-' for stdin)")
    p.add_argument("--deep", action="store_true",
                   help="Include Ghidra/LLDB steps")
    p.add_argument("--quick", action="store_true",
                   help="Only priority=1 steps")
    p.add_argument("--crash-dir", type=str, default=None,
                   help="Include crash report processing from directory")
    add_output_args(p)
    p.set_defaults(func=run)


def run(args):
    out = make_formatter(args)
    binary = args.binary

    # Get triage data
    triage_data = _get_triage_data(args, out)

    # Build plan
    steps = _build_plan(binary, triage_data, args)

    # Filter by priority if --quick
    if args.quick:
        steps = [s for s in steps if s["priority"] == 1]

    # Renumber steps
    for i, step in enumerate(steps, 1):
        step["step"] = i

    # Build pipeline command
    pipeline = _build_pipeline_command(steps)

    total_time = sum(s.get("estimated_seconds", 5) for s in steps)
    requires_ghidra = any("ghidra" in s["command"] for s in steps)

    result = {
        "target": binary,
        "total_steps": len(steps),
        "estimated_time_minutes": round(total_time / 60, 1),
        "requires_ghidra": requires_ghidra,
        "steps": steps,
        "pipeline_command": pipeline,
    }

    out.emit(result, "plan")


def _get_triage_data(args, out):
    """Get triage data from cache, pipe, file, or run triage."""
    # From file or stdin
    from_triage = getattr(args, "from_triage", None)
    if from_triage:
        if from_triage == "-":
            data = load_piped_input()
            if data:
                return data
        else:
            try:
                with open(from_triage) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                out.status(f"Warning: Failed to load triage data: {e}")

    # Try cache
    if not getattr(args, "no_cache", False):
        try:
            from cb.result_cache import ResultCache
            cache = ResultCache()
            cached = cache.get(args.binary, "triage", {})
            if cached:
                out.status("Using cached triage data for planning")
                return cached
        except Exception:
            pass

    # Run lightweight triage internally
    out.status("Running quick triage for planning...")
    try:
        from cb.macho import detect_format, get_file_info, get_imports, get_protections
        from cb.elf_utils import categorize_imports

        path = args.binary
        fmt = detect_format(path)

        if fmt == "elf":
            from cb.elf_utils import get_elf_info
            info = get_elf_info(path)
            imports = info.get("imports", [])
            info["imports_summary"] = {
                "total_imports": len(imports),
                "categories": categorize_imports(imports),
            }
            return info
        else:
            imports = get_imports(path)
            categories = categorize_imports(imports)
            return {
                "file_info": get_file_info(path),
                "protections": get_protections(path),
                "imports_summary": {
                    "total_imports": len(imports),
                    "categories": categories,
                },
            }
    except Exception as e:
        out.status(f"Warning: Quick triage failed: {e}")
        return {}


def _has_ipc(triage_data):
    """Check if binary uses IPC mechanisms."""
    cats = triage_data.get("imports_summary", {}).get("categories", {})
    if "ipc" in cats or "xpc" in cats:
        return True
    # Check raw imports if available
    imports = triage_data.get("imports_summary", {})
    ipc_patterns = {"xpc_connection", "mach_msg", "bootstrap_look_up"}
    for key in ("imports", "top_imports"):
        for imp in imports.get(key, []):
            name = imp if isinstance(imp, str) else imp.get("name", "")
            if any(p in name for p in ipc_patterns):
                return True
    return False


def _has_objc(triage_data):
    """Check if binary uses ObjC runtime."""
    imports = triage_data.get("imports_summary", {})
    cats = imports.get("categories", {})
    if "objc" in cats:
        return True
    for key in ("imports", "top_imports"):
        for imp in imports.get(key, []):
            name = imp if isinstance(imp, str) else imp.get("name", "")
            if "objc_msgSend" in name:
                return True
    return False


def _has_parsers(triage_data):
    """Check if binary handles file format parsing."""
    cats = triage_data.get("imports_summary", {}).get("categories", {})
    return any(c in cats for c in ("image", "compression", "xml", "parsing"))


def _has_network(triage_data):
    """Check if binary has network functionality."""
    cats = triage_data.get("imports_summary", {}).get("categories", {})
    return "network" in cats


def _ghidra_available():
    """Check if Ghidra is available."""
    try:
        from cb.ghidra_bridge import is_available
        return is_available()
    except Exception:
        return False


def _binary_size_mb(binary):
    """Get binary size in MB."""
    try:
        return os.path.getsize(binary) / (1024 * 1024)
    except OSError:
        return 0


def _build_plan(binary, triage_data, args):
    """Build analysis plan based on triage data."""
    steps = []

    # Step: Triage (always, unless provided via --from-triage)
    if not getattr(args, "from_triage", None):
        steps.append({
            "step": 0,
            "command": f"cb triage {binary} --full",
            "rationale": "Establish baseline: format, protections, imports, strings",
            "priority": 1,
            "depends_on": [],
            "estimated_seconds": 5,
        })

    # Step: Attack surface (always)
    steps.append({
        "step": 0,
        "command": f"cb attack {binary}",
        "rationale": "Map attack surface: entitlements, IPC, parsers, network",
        "priority": 1,
        "depends_on": [1] if not getattr(args, "from_triage", None) else [],
        "estimated_seconds": 10,
    })

    # Step: Vuln scan (always)
    steps.append({
        "step": 0,
        "command": f"cb vuln {binary}",
        "rationale": "Scan for dangerous imports and vulnerability patterns",
        "priority": 1,
        "depends_on": [],
        "estimated_seconds": 8,
    })

    # Conditional: IPC analysis
    if _has_ipc(triage_data):
        steps.append({
            "step": 0,
            "command": f"cb ipc {binary}",
            "rationale": "IPC imports detected — analyze XPC/Mach port endpoints",
            "priority": 2,
            "depends_on": [],
            "estimated_seconds": 10,
        })
        steps.append({
            "step": 0,
            "command": f"cb sandbox {binary}",
            "rationale": "IPC target — check sandbox profile and restrictions",
            "priority": 2,
            "depends_on": [],
            "estimated_seconds": 8,
        })

    # Conditional: ObjC analysis
    if _has_objc(triage_data):
        steps.append({
            "step": 0,
            "command": f"cb objc {binary} --dangerous",
            "rationale": "ObjC runtime detected — find dangerous method patterns",
            "priority": 2,
            "depends_on": [],
            "estimated_seconds": 15,
        })

    # Conditional: Fuzzing
    if _has_parsers(triage_data):
        steps.append({
            "step": 0,
            "command": f"cb fuzz {binary} --auto",
            "rationale": "Parser imports detected — generate fuzzing harness",
            "priority": 2,
            "depends_on": [],
            "estimated_seconds": 20,
        })

    # Conditional: Ghidra deep analysis
    if getattr(args, "deep", False) and _ghidra_available() and _binary_size_mb(binary) < 50:
        steps.append({
            "step": 0,
            "command": f"cb ghidra analyze {binary}",
            "rationale": "Deep analysis: decompile and analyze with Ghidra",
            "priority": 3,
            "depends_on": [],
            "estimated_seconds": 120,
        })
        steps.append({
            "step": 0,
            "command": f"cb taint {binary}",
            "rationale": "Taint analysis on decompiled code",
            "priority": 3,
            "depends_on": [],
            "estimated_seconds": 60,
        })

    # Conditional: Crash directory
    crash_dir = getattr(args, "crash_dir", None)
    if crash_dir and os.path.isdir(crash_dir):
        steps.append({
            "step": 0,
            "command": f"cb crash {crash_dir} --batch --dedup",
            "rationale": "Process existing crash reports for known issues",
            "priority": 2,
            "depends_on": [],
            "estimated_seconds": 15,
        })

    # Conditional: Verify (if any high-priority findings likely)
    has_high = _has_ipc(triage_data) or _has_parsers(triage_data)
    if has_high:
        steps.append({
            "step": 0,
            "command": f"cb verify {binary} /dev/null",
            "rationale": "Verify crash behavior under memory guards",
            "priority": 2,
            "depends_on": [],
            "estimated_seconds": 15,
        })

    # Always last: Report
    steps.append({
        "step": 0,
        "command": f"cb report {binary}",
        "rationale": "Generate structured vulnerability report",
        "priority": 1,
        "depends_on": [],
        "estimated_seconds": 5,
    })

    return steps


def _build_pipeline_command(steps):
    """Build a single pipeline command from steps."""
    commands = [s["command"] for s in steps]
    return " && ".join(commands)


def main():
    parser = argparse.ArgumentParser(prog="cbplan",
                                     description="AI audit planner")
    parser.add_argument("binary", help="Path to binary")
    parser.add_argument("--from-triage", type=str, default=None)
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--crash-dir", type=str, default=None)
    add_output_args(parser)
    args = parser.parse_args()
    run(args)
