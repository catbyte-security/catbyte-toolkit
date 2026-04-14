"""cb lldb - LLDB dynamic analysis bridge."""
import argparse
import sys

from cb.output import OutputFormatter, add_output_args, make_formatter


def _lldb_available_or_emit(out: OutputFormatter, tool_name: str) -> bool:
    """Check LLDB availability; emit JSON error and return False if unavailable."""
    from cb.lldb_bridge import is_available
    if not is_available():
        out.emit({
            "error": "LLDB Python bindings not available",
            "hint": "Install Xcode/CLT or set lldb_pythonpath in ~/.cbconfig.json",
        }, tool_name)
        return False
    return True


def register(subparsers):
    p = subparsers.add_parser("lldb", help="LLDB dynamic analysis bridge")
    sub = p.add_subparsers(dest="lldb_cmd", help="LLDB subcommands")

    # info
    s = sub.add_parser("info", help="Static target info (arch, UUID, sections)")
    s.add_argument("binary", help="Path to binary")
    s.add_argument("--timeout", type=int, default=30)
    add_output_args(s)
    s.set_defaults(func=run_info)

    # modules
    s = sub.add_parser("modules", help="List loaded dylibs/modules")
    s.add_argument("binary", nargs="?", help="Path to binary")
    s.add_argument("--pid", type=int, default=None, help="Attach to running process")
    s.add_argument("--timeout", type=int, default=30)
    add_output_args(s)
    s.set_defaults(func=run_modules)

    # symbols
    s = sub.add_parser("symbols", help="Find symbols by name/regex")
    s.add_argument("binary", help="Path to binary")
    s.add_argument("pattern", help="Symbol name or regex pattern")
    s.add_argument("--timeout", type=int, default=30)
    add_output_args(s)
    s.set_defaults(func=run_symbols)

    # disasm
    s = sub.add_parser("disasm", help="Disassemble function or address")
    s.add_argument("binary", help="Path to binary")
    s.add_argument("target", help="Function name or 0xADDRESS")
    s.add_argument("--pid", type=int, default=None, help="Attach for ASLR-resolved addresses")
    s.add_argument("--count", type=int, default=50, help="Max instructions")
    s.add_argument("--timeout", type=int, default=30)
    add_output_args(s)
    s.set_defaults(func=run_disasm)

    # memory
    s = sub.add_parser("memory", help="Read process memory")
    s.add_argument("--pid", type=int, required=True, help="Process ID")
    s.add_argument("address", help="Memory address (0x...)")
    s.add_argument("size", nargs="?", type=int, default=256, help="Bytes to read (default: 256)")
    s.add_argument("--timeout", type=int, default=30)
    add_output_args(s)
    s.set_defaults(func=run_memory)

    # backtrace
    s = sub.add_parser("backtrace", help="Thread backtraces")
    s.add_argument("--pid", type=int, required=True, help="Process ID")
    s.add_argument("--timeout", type=int, default=30)
    add_output_args(s)
    s.set_defaults(func=run_backtrace)

    # registers
    s = sub.add_parser("registers", help="Thread registers")
    s.add_argument("--pid", type=int, required=True, help="Process ID")
    s.add_argument("--timeout", type=int, default=30)
    add_output_args(s)
    s.set_defaults(func=run_registers)

    # breakpoint
    s = sub.add_parser("breakpoint", help="Launch with breakpoints, collect data")
    s.add_argument("binary", help="Path to binary")
    s.add_argument("functions", nargs="+", help="Function names to break on")
    s.add_argument("--args", nargs="*", dest="proc_args", help="Arguments for the binary")
    s.add_argument("--collect", type=str, default="args,backtrace",
                   help="Data to collect: args,backtrace,registers (comma-separated)")
    s.add_argument("--count", type=int, default=10, help="Max breakpoint hits")
    s.add_argument("--timeout", type=int, default=60)
    add_output_args(s)
    s.set_defaults(func=run_breakpoint)

    # eval
    s = sub.add_parser("eval", help="Evaluate expression in process context")
    s.add_argument("--pid", type=int, required=True, help="Process ID")
    s.add_argument("expression", help="LLDB expression to evaluate")
    s.add_argument("--timeout", type=int, default=30)
    add_output_args(s)
    s.set_defaults(func=run_eval)

    p.set_defaults(func=lambda args: p.print_help())


def run_info(args):
    out = make_formatter(args)
    if not _lldb_available_or_emit(out, "lldb.info"):
        return
    try:
        from cb.lldb_bridge import get_info
        result = get_info(args.binary, timeout=args.timeout)
        out.emit(result, "lldb.info")
    except Exception as e:
        out.debug(f"LLDB info failed: {e}", exc=e)
        out.emit({"error": str(e), "hint": "Run with --verbose for details"}, "lldb.info")


def run_modules(args):
    if not args.binary and args.pid is None:
        print("Error: provide a binary path or --pid", file=sys.stderr)
        sys.exit(1)
    out = make_formatter(args)
    if not _lldb_available_or_emit(out, "lldb.modules"):
        return
    try:
        from cb.lldb_bridge import get_modules
        result = get_modules(binary=args.binary, pid=args.pid, timeout=args.timeout)
        out.emit(result, "lldb.modules")
    except Exception as e:
        out.debug(f"LLDB modules failed: {e}", exc=e)
        out.emit({"error": str(e), "hint": "Run with --verbose for details"}, "lldb.modules")


def run_symbols(args):
    out = make_formatter(args)
    if not _lldb_available_or_emit(out, "lldb.symbols"):
        return
    try:
        from cb.lldb_bridge import find_symbols
        result = find_symbols(args.binary, args.pattern,
                              max_results=args.max_results, timeout=args.timeout)
        out.emit(result, "lldb.symbols")
    except Exception as e:
        out.debug(f"LLDB symbols failed: {e}", exc=e)
        out.emit({"error": str(e), "hint": "Run with --verbose for details"}, "lldb.symbols")


def run_disasm(args):
    out = make_formatter(args)
    if not _lldb_available_or_emit(out, "lldb.disasm"):
        return
    try:
        from cb.lldb_bridge import disassemble
        result = disassemble(args.binary, args.target, pid=args.pid,
                             count=args.count, timeout=args.timeout)
        out.emit(result, "lldb.disasm")
    except Exception as e:
        out.debug(f"LLDB disasm failed: {e}", exc=e)
        out.emit({"error": str(e), "hint": "Run with --verbose for details"}, "lldb.disasm")


def run_memory(args):
    out = make_formatter(args)
    if not _lldb_available_or_emit(out, "lldb.memory"):
        return
    try:
        from cb.lldb_bridge import read_memory
        result = read_memory(args.pid, args.address, size=args.size,
                             timeout=args.timeout)
        out.emit(result, "lldb.memory")
    except Exception as e:
        out.debug(f"LLDB memory failed: {e}", exc=e)
        out.emit({"error": str(e), "hint": "Run with --verbose for details"}, "lldb.memory")


def run_backtrace(args):
    out = make_formatter(args)
    if not _lldb_available_or_emit(out, "lldb.backtrace"):
        return
    try:
        from cb.lldb_bridge import get_backtrace
        result = get_backtrace(args.pid, timeout=args.timeout)
        out.emit(result, "lldb.backtrace")
    except Exception as e:
        out.debug(f"LLDB backtrace failed: {e}", exc=e)
        out.emit({"error": str(e), "hint": "Run with --verbose for details"}, "lldb.backtrace")


def run_registers(args):
    out = make_formatter(args)
    if not _lldb_available_or_emit(out, "lldb.registers"):
        return
    try:
        from cb.lldb_bridge import get_registers
        result = get_registers(args.pid, timeout=args.timeout)
        out.emit(result, "lldb.registers")
    except Exception as e:
        out.debug(f"LLDB registers failed: {e}", exc=e)
        out.emit({"error": str(e), "hint": "Run with --verbose for details"}, "lldb.registers")


def run_breakpoint(args):
    out = make_formatter(args)
    if not _lldb_available_or_emit(out, "lldb.breakpoint"):
        return
    try:
        from cb.lldb_bridge import run_with_breakpoints
        collect = [c.strip() for c in args.collect.split(",")]
        result = run_with_breakpoints(
            args.binary, args.functions,
            args=args.proc_args, collect=collect,
            count=args.count, timeout=args.timeout,
        )
        out.emit(result, "lldb.breakpoint")
    except Exception as e:
        out.debug(f"LLDB breakpoint failed: {e}", exc=e)
        out.emit({"error": str(e), "hint": "Run with --verbose for details"}, "lldb.breakpoint")


def run_eval(args):
    out = make_formatter(args)
    if not _lldb_available_or_emit(out, "lldb.eval"):
        return
    try:
        from cb.lldb_bridge import evaluate
        result = evaluate(args.pid, args.expression, timeout=args.timeout)
        out.emit(result, "lldb.eval")
    except Exception as e:
        out.debug(f"LLDB eval failed: {e}", exc=e)
        out.emit({"error": str(e), "hint": "Run with --verbose for details"}, "lldb.eval")


def main():
    parser = argparse.ArgumentParser(prog="cblldb", description="LLDB bridge")
    sub = parser.add_subparsers(dest="lldb_cmd")

    s = sub.add_parser("info")
    s.add_argument("binary")
    s.add_argument("--timeout", type=int, default=30)
    add_output_args(s)
    s.set_defaults(func=run_info)

    s = sub.add_parser("modules")
    s.add_argument("binary", nargs="?")
    s.add_argument("--pid", type=int, default=None)
    s.add_argument("--timeout", type=int, default=30)
    add_output_args(s)
    s.set_defaults(func=run_modules)

    s = sub.add_parser("symbols")
    s.add_argument("binary")
    s.add_argument("pattern")
    s.add_argument("--timeout", type=int, default=30)
    add_output_args(s)
    s.set_defaults(func=run_symbols)

    s = sub.add_parser("disasm")
    s.add_argument("binary")
    s.add_argument("target")
    s.add_argument("--pid", type=int, default=None)
    s.add_argument("--count", type=int, default=50)
    s.add_argument("--timeout", type=int, default=30)
    add_output_args(s)
    s.set_defaults(func=run_disasm)

    s = sub.add_parser("memory")
    s.add_argument("--pid", type=int, required=True)
    s.add_argument("address")
    s.add_argument("size", nargs="?", type=int, default=256)
    s.add_argument("--timeout", type=int, default=30)
    add_output_args(s)
    s.set_defaults(func=run_memory)

    s = sub.add_parser("backtrace")
    s.add_argument("--pid", type=int, required=True)
    s.add_argument("--timeout", type=int, default=30)
    add_output_args(s)
    s.set_defaults(func=run_backtrace)

    s = sub.add_parser("registers")
    s.add_argument("--pid", type=int, required=True)
    s.add_argument("--timeout", type=int, default=30)
    add_output_args(s)
    s.set_defaults(func=run_registers)

    s = sub.add_parser("breakpoint")
    s.add_argument("binary")
    s.add_argument("functions", nargs="+")
    s.add_argument("--args", nargs="*", dest="proc_args")
    s.add_argument("--collect", type=str, default="args,backtrace")
    s.add_argument("--count", type=int, default=10)
    s.add_argument("--timeout", type=int, default=60)
    add_output_args(s)
    s.set_defaults(func=run_breakpoint)

    s = sub.add_parser("eval")
    s.add_argument("--pid", type=int, required=True)
    s.add_argument("expression")
    s.add_argument("--timeout", type=int, default=30)
    add_output_args(s)
    s.set_defaults(func=run_eval)

    args = parser.parse_args()
    if not args.lldb_cmd:
        parser.print_help()
        sys.exit(1)
    args.func(args)
