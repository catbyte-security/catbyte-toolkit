"""cb grep - Binary search (disasm, bytes, strings, gadgets)."""
import argparse
import mmap
import re
import subprocess
import sys

from cb.output import add_output_args, make_formatter


def register(subparsers):
    p = subparsers.add_parser("grep", help="Search binary content")
    p.add_argument("binary", help="Path to binary")
    p.add_argument("pattern", help="Search pattern")
    p.add_argument("--mode", choices=["disasm", "bytes", "strings", "gadgets"],
                   default="disasm", help="Search mode (default: disasm)")
    p.add_argument("--case-sensitive", action="store_true")
    p.add_argument("--context", "-C", type=int, default=3,
                   help="Context lines (default: 3)")
    p.add_argument("--function", type=str, default=None,
                   help="Limit search to function name")
    p.add_argument("--section", type=str, default=None,
                   help="Limit search to section")
    # Gadget options
    p.add_argument("--gadget-type", choices=["rop", "jop", "all"],
                   default="rop")
    p.add_argument("--gadget-depth", type=int, default=5)
    p.add_argument("--no-duplicates", action="store_true")
    add_output_args(p)
    p.set_defaults(func=run)


def run(args):
    out = make_formatter(args)
    mode = args.mode

    if mode == "disasm":
        result = search_disasm(args, out)
    elif mode == "bytes":
        result = search_bytes(args, out)
    elif mode == "strings":
        result = search_strings(args, out)
    elif mode == "gadgets":
        result = search_gadgets(args, out)
    else:
        result = {"error": f"Unknown mode: {mode}"}

    out.emit(result, "grep")


def search_disasm(args, out):
    """Search disassembly output for pattern."""
    out.status(f"Disassembling and searching for: {args.pattern}")

    cmd = ["objdump", "-d", args.binary]
    if args.section:
        cmd.extend([f"-j{args.section}"])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return {"error": "Disassembly timed out (>120s). Try --section to narrow scope."}

    lines = result.stdout.splitlines()
    flags = 0 if args.case_sensitive else re.IGNORECASE
    try:
        regex = re.compile(args.pattern, flags)
    except re.error as e:
        return {"error": f"Invalid regex: {e}"}

    matches = []
    current_func = ""
    ctx = args.context

    # If filtering by function, find function boundaries
    func_filter = args.function
    in_target_func = func_filter is None

    for i, line in enumerate(lines):
        # Track current function
        if line and not line.startswith(" ") and line.endswith(":"):
            fn = line.rstrip(":").strip()
            if fn.startswith("<") or ">" in fn:
                current_func = fn
            else:
                current_func = fn
            if func_filter:
                in_target_func = func_filter.lower() in current_func.lower()

        if not in_target_func:
            continue

        if regex.search(line):
            before = [lines[j] for j in range(max(0, i - ctx), i)]
            after = [lines[j] for j in range(i + 1, min(len(lines), i + ctx + 1))]

            # Extract address if present
            addr = ""
            stripped = line.strip()
            if ":" in stripped:
                addr = stripped.split(":")[0].strip()

            matches.append({
                "line_number": i + 1,
                "address": addr,
                "match": stripped,
                "function": current_func,
                "context_before": [l.strip() for l in before],
                "context_after": [l.strip() for l in after],
            })

            if len(matches) >= args.max_results:
                break

    total = len(matches)
    return {
        "_meta": {"mode": "disasm", "pattern": args.pattern},
        "total_matches": total,
        "matches": matches[:args.max_results],
    }


def search_bytes(args, out):
    """Search for byte pattern in binary."""
    out.status(f"Searching for byte pattern: {args.pattern}")

    try:
        pattern_bytes = bytes.fromhex(args.pattern.replace(" ", "").replace("0x", ""))
    except ValueError as e:
        return {"error": f"Invalid hex pattern: {e}"}

    matches = []
    try:
        with open(args.binary, "rb") as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            offset = 0
            while len(matches) < args.max_results:
                pos = mm.find(pattern_bytes, offset)
                if pos == -1:
                    break
                # Get surrounding bytes for context
                ctx_start = max(0, pos - 16)
                ctx_end = min(len(mm), pos + len(pattern_bytes) + 16)
                context_hex = mm[ctx_start:ctx_end].hex()

                matches.append({
                    "offset": hex(pos),
                    "context_hex": context_hex,
                    "context_offset": hex(ctx_start),
                })
                offset = pos + 1
            mm.close()
    except Exception as e:
        return {"error": f"Failed to search: {e}"}

    return {
        "_meta": {"mode": "bytes", "pattern": args.pattern},
        "total_matches": len(matches),
        "matches": matches,
    }


def search_strings(args, out):
    """Search through binary strings."""
    out.status(f"Searching strings for: {args.pattern}")

    cmd = ["strings", "-n", "4", args.binary]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return {"error": "strings command timed out"}

    flags = 0 if args.case_sensitive else re.IGNORECASE
    try:
        regex = re.compile(args.pattern, flags)
    except re.error as e:
        return {"error": f"Invalid regex: {e}"}

    matches = []
    for line in result.stdout.splitlines():
        if regex.search(line):
            matches.append(line.strip())
            if len(matches) >= args.max_results:
                break

    return {
        "_meta": {"mode": "strings", "pattern": args.pattern},
        "total_matches": len(matches),
        "matches": matches,
    }


def search_gadgets(args, out):
    """Search ROP/JOP gadgets using ROPgadget."""
    out.status(f"Searching gadgets matching: {args.pattern}")

    cmd = ["ROPgadget", "--binary", args.binary,
           "--depth", str(args.gadget_depth)]
    if args.gadget_type == "jop":
        cmd.append("--jop")
    elif args.gadget_type == "all":
        cmd.extend(["--all"])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return {"error": "ROPgadget timed out (>300s)"}
    except FileNotFoundError:
        return {"error": "ROPgadget not installed. Run: pip install ROPgadget"}

    # Parse ROPgadget output
    flags = 0 if args.case_sensitive else re.IGNORECASE
    try:
        regex = re.compile(args.pattern, flags)
    except re.error as e:
        return {"error": f"Invalid regex: {e}"}

    gadgets = []
    seen = set()

    for line in result.stdout.splitlines():
        # ROPgadget format: "0xaddress : instruction ; instruction ; ret"
        if " : " not in line:
            continue
        parts = line.split(" : ", 1)
        if len(parts) != 2:
            continue
        addr, instructions = parts[0].strip(), parts[1].strip()

        if not regex.search(instructions):
            continue

        if args.no_duplicates:
            if instructions in seen:
                continue
            seen.add(instructions)

        gadgets.append({
            "address": addr,
            "instructions": instructions,
        })

        if len(gadgets) >= args.max_results:
            break

    return {
        "_meta": {"mode": "gadgets", "pattern": args.pattern,
                  "gadget_type": args.gadget_type},
        "total_gadgets": len(gadgets),
        "gadgets": gadgets,
    }


def main():
    parser = argparse.ArgumentParser(prog="cbgrep", description="Binary search")
    parser.add_argument("binary", help="Path to binary")
    parser.add_argument("pattern", help="Search pattern")
    parser.add_argument("--mode", choices=["disasm", "bytes", "strings", "gadgets"],
                        default="disasm")
    parser.add_argument("--case-sensitive", action="store_true")
    parser.add_argument("--context", "-C", type=int, default=3)
    parser.add_argument("--function", type=str, default=None)
    parser.add_argument("--section", type=str, default=None)
    parser.add_argument("--gadget-type", choices=["rop", "jop", "all"], default="rop")
    parser.add_argument("--gadget-depth", type=int, default=5)
    parser.add_argument("--no-duplicates", action="store_true")
    add_output_args(parser)
    args = parser.parse_args()
    run(args)
