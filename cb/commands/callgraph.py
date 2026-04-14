"""cb callgraph - Call graph recovery and sink reachability analysis."""
import argparse
import sys

from cb.output import add_output_args, make_formatter


def register(subparsers):
    p = subparsers.add_parser("callgraph", help="Build call graphs, find paths to sinks")
    p.add_argument("binary", help="Path to binary")
    p.add_argument("--mode", choices=["sinks", "from", "stats"],
                   default="sinks",
                   help="sinks=paths to dangerous functions, from=graph from function, "
                        "stats=hotspot analysis")
    p.add_argument("--function", type=str, default="",
                   help="Function name (required for --mode from)")
    p.add_argument("--depth", type=int, default=8,
                   help="Max call chain depth (default: 8)")
    p.add_argument("--timeout", type=int, default=600)
    add_output_args(p)
    p.set_defaults(func=run)


def run(args):
    from cb.ghidra_bridge import run_ghidra_script
    out = make_formatter(args)

    mode = args.mode
    target = args.function

    if mode == "sinks":
        out.status("Finding all paths from code to dangerous sinks "
                   "(memcpy, system, execve, mach_msg_send, IOConnect...)...")
    elif mode == "from":
        if not target:
            out.emit({"error": "--function required for --mode from"}, "callgraph")
            return
        out.status(f"Building call graph from {target}...")
    else:
        out.status("Analyzing call graph statistics and hotspots...")

    try:
        result = run_ghidra_script(
            args.binary, "CallGraph.java",
            [mode, target, str(args.depth), str(args.max_results)],
            timeout=args.timeout,
        )
    except Exception as e:
        result = {"error": str(e)}

    out.emit(result, "callgraph")


def main():
    parser = argparse.ArgumentParser(prog="cbcallgraph", description="Call graph analysis")
    parser.add_argument("binary")
    parser.add_argument("--mode", choices=["sinks", "from", "stats"], default="sinks")
    parser.add_argument("--function", type=str, default="")
    parser.add_argument("--depth", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=600)
    add_output_args(parser)
    args = parser.parse_args()
    run(args)
