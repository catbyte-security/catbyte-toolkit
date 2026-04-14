"""cb taint - Inter-procedural data flow / taint analysis via Ghidra."""
import argparse
import sys

from cb.output import add_output_args, make_formatter


def register(subparsers):
    p = subparsers.add_parser("taint", help="Trace tainted data from sources to sinks")
    p.add_argument("binary", help="Path to binary")
    p.add_argument("--source", type=str, default="auto",
                   help="Source function or 'auto' to detect all (default: auto)")
    p.add_argument("--depth", type=int, default=5,
                   help="Max interprocedural depth (default: 5)")
    p.add_argument("--severity", choices=["critical", "high", "medium", "all"],
                   default="all", help="Filter by severity")
    p.add_argument("--timeout", type=int, default=600)
    add_output_args(p)
    p.set_defaults(func=run)


def run(args):
    from cb.ghidra_bridge import run_ghidra_script
    out = make_formatter(args)

    out.status(f"Running taint analysis (source={args.source}, depth={args.depth})...")
    out.status("This traces data from input sources (read/recv/xpc/mach_msg) to "
               "dangerous sinks (memcpy/system/exec)...")

    try:
        result = run_ghidra_script(
            args.binary, "TaintAnalysis.java",
            [args.source, str(args.depth), str(args.max_results)],
            timeout=args.timeout,
        )
    except Exception as e:
        result = {"error": str(e)}

    # Filter by severity
    if args.severity != "all" and "flows" in result:
        result["flows"] = [
            f for f in result["flows"]
            if severity_rank(f.get("severity", "")) <= severity_rank(args.severity)
        ]
        result["total_flows"] = len(result["flows"])

    out.emit(result, "taint")


def severity_rank(s):
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(s, 4)


def main():
    parser = argparse.ArgumentParser(prog="cbtaint", description="Taint analysis")
    parser.add_argument("binary")
    parser.add_argument("--source", type=str, default="auto")
    parser.add_argument("--depth", type=int, default=5)
    parser.add_argument("--severity", choices=["critical", "high", "medium", "all"],
                        default="all")
    parser.add_argument("--timeout", type=int, default=600)
    add_output_args(parser)
    args = parser.parse_args()
    run(args)
