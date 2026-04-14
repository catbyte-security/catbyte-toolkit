"""cb struct - Struct Layout Recovery via ARM64 disassembly analysis."""
import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

from cb.output import add_output_args, make_formatter

FIELD_HINTS = {
    "SetWindowLevel": "level", "SetWindowAlpha": "alpha",
    "SetWindowTags": "tags", "MoveWindow": "position",
    "ReleaseWindow": "refcount", "OrderWindow": "z_order_next",
    "NewWindow": "window_id", "SetWindowProperty": "properties",
    "GetWindowBounds": "bounds", "SetWindowShape": "shape",
    "SetWindowOpacity": "opacity", "SetWindowOwner": "owner_pid",
    "SetWindowTitle": "title_ptr", "SetSurfaceColorSpace": "color_space",
    "SetSurfaceResolution": "resolution", "AddSurface": "surface_id",
    "RemoveSurface": "surface_count", "BindSurface": "surface_binding",
    "SetWindowListProperties": "list_props",
}

_REG_WIDTH = {"x": 8, "w": 4}
_C_TYPES = {
    (8, "ptr"): "void *", (8, "uint64"): "uint64_t", (8, "int64"): "int64_t",
    (4, "uint32"): "uint32_t", (4, "int32"): "int32_t", (4, "float"): "float",
    (2, "uint16"): "uint16_t", (1, "uint8"): "uint8_t",
}


def register(subparsers):
    p = subparsers.add_parser("struct", help="Recover struct layouts from ARM64 disassembly")
    sub = p.add_subparsers(dest="struct_command")

    s = sub.add_parser("recover", help="Recover struct layout from function disassembly")
    s.add_argument("binary", help="Path to extracted Mach-O binary")
    s.add_argument("--functions", "-f", type=str, required=True,
                   help="Comma-separated list of function names to analyze")
    s.add_argument("--arch", type=str, default="arm64",
                   choices=["arm64", "x86_64"], help="Target architecture (default: arm64)")
    s.add_argument("--max-insns", type=int, default=200,
                   help="Max instructions to disassemble per function (default: 200)")
    s.add_argument("--struct-name", type=str, default=None,
                   help="Name for the recovered struct (default: auto-detect)")
    add_output_args(s)
    s.set_defaults(func=run_recover)

    s = sub.add_parser("from-lldb", help="Recover struct from live process memory")
    s.add_argument("--pid", type=int, required=True, help="Process ID")
    s.add_argument("--address", type=str, required=True,
                   help="Memory address of struct instance (0x...)")
    s.add_argument("--size", type=int, default=256, help="Bytes to read (default: 256)")
    add_output_args(s)
    s.set_defaults(func=run_from_lldb)

    s = sub.add_parser("format", help="Format a saved layout JSON as C struct")
    s.add_argument("layout_file", help="Path to layout JSON file")
    s.add_argument("--struct-name", type=str, default=None, help="Override struct name")
    add_output_args(s)
    s.set_defaults(func=run_format)

    p.set_defaults(func=lambda args: p.print_help())


def run_recover(args):
    out = make_formatter(args)
    binary = args.binary
    func_names = [f.strip() for f in args.functions.split(",") if f.strip()]
    if not os.path.isfile(binary):
        out.emit({"error": f"Binary not found: {binary}"}, "struct")
        return

    out.status(f"Analyzing {len(func_names)} functions in {os.path.basename(binary)}...")
    access_results = []
    for fname in func_names:
        out.status(f"  Disassembling {fname}...")
        try:
            result = analyze_function_accesses(
                binary, fname, arch=args.arch, max_insns=args.max_insns)
            access_results.append(result)
            n = len(result.get("accesses", []))
            out.status(f"    Found {n} memory accesses (base={result.get('base_register', '?')})")
        except Exception as e:
            access_results.append({"function": fname, "error": str(e), "accesses": []})
            out.status(f"    Error: {e}")

    out.status("Merging layouts from all functions...")
    layout = merge_layouts(access_results)
    layout["fields"] = infer_field_names(layout.get("fields", []), access_results)

    struct_name = args.struct_name or _guess_struct_name(func_names)
    layout["struct_name"] = struct_name
    layout["c_struct"] = format_as_c_struct(layout, struct_name=struct_name)

    layout["function_analysis"] = []
    for ar in access_results:
        entry = {"function": ar.get("function", "?"), "address": ar.get("address", "?"),
                 "base_register": ar.get("base_register", "?"),
                 "num_accesses": len(ar.get("accesses", []))}
        if "error" in ar:
            entry["error"] = ar["error"]
        layout["function_analysis"].append(entry)

    out.emit(layout, "struct")


def run_from_lldb(args):
    out = make_formatter(args)
    out.status(f"Reading {args.size} bytes from pid {args.pid} at {args.address}...")
    out.emit(recover_from_memory(args.pid, args.address, args.size), "struct")


def run_format(args):
    out = make_formatter(args)
    out.emit(format_layout_from_file(args.layout_file, struct_name=args.struct_name), "struct")


# -- Core analysis -----------------------------------------------------------

def analyze_function_accesses(binary, func_name, arch="arm64", max_insns=200):
    """Disassemble a function and extract struct memory access patterns."""
    from cb.disasm import capstone_disasm, _read_code_bytes

    # Try ELF symbol lookup for x86_64/ELF binaries
    addr = None
    if arch == "x86_64":
        addr = _find_elf_function_address(binary, func_name)
    if addr is None:
        addr = _find_function_address(binary, func_name)
    if addr is None:
        return {"function": func_name, "address": None,
                "error": f"Symbol '{func_name}' not found in {binary}",
                "base_register": None, "accesses": []}

    code = _read_code_bytes(binary, addr, max_insns * 4)
    if not code:
        return {"function": func_name, "address": hex(addr),
                "error": "Could not read code bytes",
                "base_register": None, "accesses": []}

    instructions = capstone_disasm(code, addr, arch, max_insns=max_insns)
    if not instructions:
        return {"function": func_name, "address": hex(addr),
                "error": "Disassembly produced no instructions",
                "base_register": None, "accesses": []}

    if arch == "x86_64":
        base_reg = _detect_base_register_x86_64(instructions)
        accesses = _extract_x86_64_accesses(instructions, base_reg=base_reg)
    else:
        base_reg = detect_base_register(instructions)
        accesses = extract_memory_accesses(instructions, base_reg=base_reg)
    return {"function": func_name, "address": hex(addr),
            "base_register": base_reg, "accesses": accesses}


def extract_memory_accesses(instructions, base_reg=None):
    """Parse ARM64 ldr/str/ldp/stp for [base, #offset] patterns."""
    accesses, seen = [], set()
    pat_single = re.compile(
        r'([wx]\d+),\s*\[([wx]\d+)(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]')
    pat_pair = re.compile(
        r'([wx]\d+),\s*([wx]\d+),\s*\[([wx]\d+)(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]')

    load_mn = {"ldr", "ldur", "ldrb", "ldrh", "ldrsw", "ldrsh", "ldrsb", "ldp"}
    store_mn = {"str", "stur", "strb", "strh", "stp"}
    mem_mn = load_mn | store_mn

    for insn in instructions:
        mnemonic = insn.get("mnemonic", "").lower()
        if mnemonic not in mem_mn:
            continue
        op_str = insn.get("op_str", "")
        operation = "load" if mnemonic in load_mn else "store"

        # Pair pattern (ldp/stp)
        m_pair = pat_pair.search(op_str)
        if m_pair and mnemonic in ("ldp", "stp"):
            reg1, reg2, base, off_str = m_pair.groups()
            if base_reg and base != base_reg:
                continue
            offset = _parse_offset(off_str)
            w1, w2 = _reg_width(reg1, mnemonic), _reg_width(reg2, mnemonic)
            for r, o, w in [(reg1, offset, w1), (reg2, offset + w1, w2)]:
                key = (o, w, operation)
                if key not in seen:
                    seen.add(key)
                    accesses.append({"offset": o, "width": w, "operation": operation,
                                     "register": r, "base": base})
            continue

        # Single register pattern
        m = pat_single.search(op_str)
        if m:
            reg, base, off_str = m.groups()
            if base_reg and base != base_reg:
                continue
            offset = _parse_offset(off_str)
            width = _reg_width(reg, mnemonic)
            key = (offset, width, operation)
            if key not in seen:
                seen.add(key)
                accesses.append({"offset": offset, "width": width, "operation": operation,
                                 "register": reg, "base": base})

    return sorted(accesses, key=lambda a: a["offset"])


def detect_base_register(instructions):
    """Return the most frequently used base register in memory ops."""
    counter = Counter()
    pat = re.compile(r'\[([wx]\d+)(?:,\s*#(?:0x[0-9a-fA-F]+|\d+))?\]')
    mem_mn = {"ldr", "ldur", "ldrb", "ldrh", "ldrsw", "ldrsh", "ldrsb", "ldp",
              "str", "stur", "strb", "strh", "stp"}
    for insn in instructions:
        if insn.get("mnemonic", "").lower() not in mem_mn:
            continue
        m = pat.search(insn.get("op_str", ""))
        if m:
            base = m.group(1)
            if base not in ("sp", "x31"):
                counter[base] += 1
    return counter.most_common(1)[0][0] if counter else "x19"


def merge_layouts(access_results):
    """Combine accesses from multiple functions into a unified struct layout."""
    field_map = {}
    for ar in access_results:
        func_name = ar.get("function", "unknown")
        for acc in ar.get("accesses", []):
            off, width = acc["offset"], acc["width"]
            if off not in field_map:
                field_map[off] = {"offset": off, "offset_hex": hex(off), "width": width,
                                  "operations": set(), "source_functions": set()}
            entry = field_map[off]
            entry["operations"].add(acc["operation"])
            entry["source_functions"].add(func_name)
            if width > entry["width"]:
                entry["width"] = width

    fields = []
    for off in sorted(field_map):
        e = field_map[off]
        fields.append({"offset": e["offset_hex"], "offset_int": e["offset"],
                        "width": e["width"], "operations": sorted(e["operations"]),
                        "source_functions": sorted(e["source_functions"])})

    min_size = (fields[-1]["offset_int"] + fields[-1]["width"]) if fields else 0
    return {"fields": fields, "min_size": min_size, "num_fields": len(fields),
            "gaps": _detect_gaps(fields)}


def infer_field_names(fields, function_accesses):
    """Assign human-readable names using FIELD_HINTS, else field_0xNN."""
    offset_funcs = defaultdict(set)
    for ar in function_accesses:
        fn = ar.get("function", "")
        for acc in ar.get("accesses", []):
            offset_funcs[acc["offset"]].add(fn)

    named, used = [], set()
    for field in fields:
        off = field.get("offset_int", 0)
        width = field.get("width", 8)
        funcs = offset_funcs.get(off, set())
        name = None
        for func in funcs:
            for hint_key, hint_name in FIELD_HINTS.items():
                if hint_key in func and hint_name not in used:
                    name = hint_name
                    break
            if name:
                break
        if not name:
            name = f"field_{field.get('offset', hex(off))}"
        used.add(name)
        ctype = _infer_type(off, width, name, field.get("operations", []))
        entry = dict(field)
        entry.update({"name": name, "type": ctype, "offset": field.get("offset", hex(off))})
        named.append(entry)
    return named


def recover_from_memory(pid, address, size):
    """Run lldb to dump memory at address, return raw hex and pointers."""
    addr_int = int(address, 16) if isinstance(address, str) and address.startswith("0x") \
        else int(address) if isinstance(address, str) else address
    count = size // 8
    lldb_cmd = f"lldb -p {pid} -o 'memory read --size 8 --format x --count {count} {hex(addr_int)}' -o quit"
    result = {"pid": pid, "address": hex(addr_int), "size": size,
              "lldb_command": lldb_cmd,
              "note": "Run the lldb_command to dump raw memory, or use 'cb lldb memory'"}
    try:
        proc = subprocess.run(
            ["lldb", "-p", str(pid), "-o",
             f"memory read --size 8 --format x --count {count} {hex(addr_int)}",
             "-o", "quit"], capture_output=True, text=True, timeout=15)
        if proc.returncode == 0 and proc.stdout.strip():
            raw_lines, pointers = [], []
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line.startswith("0x"):
                    continue
                raw_lines.append(line)
                for part in line.split()[1:]:
                    if part.startswith("0x"):
                        try:
                            pointers.append(hex(int(part, 16)))
                        except ValueError:
                            pass
            result["raw_dump"] = raw_lines
            result["pointers"] = pointers
        else:
            result["error"] = (proc.stderr.strip()[:500] if proc.stderr
                               else "lldb returned no output")
    except FileNotFoundError:
        result["error"] = "lldb not found in PATH"
    except subprocess.TimeoutExpired:
        result["error"] = "lldb timed out (process may require sudo or entitlements)"
    return result


def format_as_c_struct(layout, struct_name="recovered_struct"):
    """Render a recovered layout as a C struct definition with comments."""
    fields = layout.get("fields", [])
    if not fields:
        return f"struct {struct_name} {{\n    /* no fields recovered */\n}};"

    lines = [f"struct {struct_name} {{"]
    prev_end = 0
    for field in fields:
        off = field.get("offset_int", 0)
        width = field.get("width", 8)
        name = field.get("name", f"field_{hex(off)}")
        ftype = field.get("type", "uint64")

        if off > prev_end:
            gap = off - prev_end
            pad = f"    uint8_t _pad_{hex(prev_end)}[{gap}];"
            lines.append(f"{pad}{' ' * max(1, 40 - len(pad))}// {hex(prev_end)}")

        c_type = _C_TYPES.get((width, ftype))
        if c_type is None:
            c_type = {8: "uint64_t", 4: "uint32_t", 2: "uint16_t"}.get(width, "uint8_t")

        decl = f"    {c_type} {name};"
        comment = f"// {hex(off)}"
        ops = field.get("operations", [])
        if ops:
            comment += f"  ({'/'.join(ops)})"
        srcs = field.get("source_functions", [])
        if srcs and len(srcs) <= 3:
            comment += f"  via {', '.join(srcs)}"
        elif srcs:
            comment += f"  via {', '.join(srcs[:2])}+{len(srcs)-2}"
        lines.append(f"{decl}{' ' * max(1, 40 - len(decl))}{comment}")
        prev_end = off + width

    lines.append("};")
    lines.append(f"// min size: {layout.get('min_size', '?')} bytes ({hex(layout.get('min_size', 0))})")
    return "\n".join(lines)


def format_layout_from_file(path, struct_name=None):
    """Load a JSON layout file and render it as a C struct."""
    if not os.path.isfile(path):
        return {"error": f"File not found: {path}"}
    with open(path, "r") as f:
        try:
            layout = json.load(f)
        except json.JSONDecodeError as e:
            return {"error": f"Invalid JSON: {e}"}
    name = struct_name or layout.get("struct_name", "recovered_struct")
    layout["c_struct"] = format_as_c_struct(layout, struct_name=name)
    layout["struct_name"] = name
    return layout


# -- Internal helpers --------------------------------------------------------

def _find_function_address(binary, func_name):
    """Look up a function's virtual address using nm."""
    try:
        proc = subprocess.run(["nm", "-defined-only", binary],
                              capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        sym = parts[2]
        if sym == func_name or sym == f"_{func_name}":
            try:
                return int(parts[0], 16)
            except ValueError:
                continue
    return None


def _parse_offset(off_str):
    """Parse an immediate offset string to int."""
    if off_str is None:
        return 0
    off_str = off_str.strip()
    return int(off_str, 16) if off_str.lower().startswith("0x") else int(off_str)


def _reg_width(reg, mnemonic):
    """Determine access width from register name and mnemonic."""
    if mnemonic in ("ldrb", "ldrsb", "strb"):
        return 1
    if mnemonic in ("ldrh", "ldrsh", "strh"):
        return 2
    if mnemonic in ("ldrsw",):
        return 4
    return _REG_WIDTH.get(reg[0].lower() if reg else "x", 8)


def _infer_type(offset, width, name, operations):
    """Heuristic type inference from offset, width, and name."""
    if offset == 0 and width == 8:
        return "ptr"
    float_hints = {"alpha", "opacity", "scale", "level", "resolution", "aspect"}
    if any(h in name.lower() for h in float_hints) and width == 4:
        return "float"
    ptr_hints = {"ptr", "pointer", "ref", "vtable", "isa", "callback", "handler"}
    if any(h in name.lower() for h in ptr_hints) and width == 8:
        return "ptr"
    return {1: "uint8", 2: "uint16", 4: "int32", 8: "uint64"}.get(width, "uint64")


def _detect_gaps(fields):
    """Find unreferenced regions between known fields."""
    gaps, prev_end = [], 0
    for field in fields:
        off = field.get("offset_int", 0)
        if off > prev_end:
            gaps.append({"start": hex(prev_end), "end": hex(off), "size": off - prev_end})
        prev_end = off + field.get("width", 8)
    return gaps


def _find_elf_function_address(binary, func_name):
    """Look up a function's virtual address in an ELF binary via pwntools."""
    try:
        from cb.elf_utils import find_elf_function_address
        return find_elf_function_address(binary, func_name)
    except (ImportError, Exception):
        return None


def _reg_width_x86_64(reg):
    """Determine register width for x86_64 registers.

    Returns width in bytes: rax=8, eax=4, ax=2, al/ah=1.
    """
    reg = reg.lower().strip()
    # 64-bit registers
    if reg.startswith("r") and (reg[1:].isdigit() or len(reg) == 3):
        if reg.endswith("d"):
            return 4
        if reg.endswith("w"):
            return 2
        if reg.endswith("b"):
            return 1
        return 8
    # Named 64-bit
    if reg in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
               "rip"):
        return 8
    # Named 32-bit
    if reg in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
               "eip"):
        return 4
    # Named 16-bit
    if reg in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp"):
        return 2
    # Named 8-bit
    if reg in ("al", "ah", "bl", "bh", "cl", "ch", "dl", "dh",
               "sil", "dil", "bpl", "spl"):
        return 1
    return 8


def _detect_base_register_x86_64(instructions):
    """Return the most frequently used base register in x86_64 memory ops."""
    counter = Counter()
    # Match [reg+offset] or [reg]
    pat = re.compile(r'\[(\w+)(?:\s*[+\-]\s*(?:0x[0-9a-fA-F]+|\d+))?\]')
    mem_mn = {"mov", "lea", "movzx", "movsx", "cmp", "test", "add", "sub",
              "and", "or", "xor"}
    for insn in instructions:
        mnemonic = insn.get("mnemonic", "").lower()
        if mnemonic not in mem_mn:
            continue
        op_str = insn.get("op_str", "")
        if "[" not in op_str:
            continue
        m = pat.search(op_str)
        if m:
            base = m.group(1).lower()
            if base not in ("rsp", "rip", "esp", "eip"):
                counter[base] += 1
    return counter.most_common(1)[0][0] if counter else "rdi"


def _extract_x86_64_accesses(instructions, base_reg=None):
    """Parse x86_64 mov/lea [reg+offset] patterns for struct access recovery."""
    accesses, seen = [], set()
    # Match patterns like [reg+0x10], [reg-0x8], [reg]
    pat = re.compile(
        r'\[(\w+)\s*([+\-])\s*(0x[0-9a-fA-F]+|\d+)\]'
    )
    pat_no_off = re.compile(r'\[(\w+)\]')

    load_mn = {"mov", "movzx", "movsx", "lea", "cmp", "test"}
    store_mn = {"mov"}  # mov [mem], reg is a store
    mem_mn = load_mn | store_mn

    for insn in instructions:
        mnemonic = insn.get("mnemonic", "").lower()
        if mnemonic not in mem_mn:
            continue
        op_str = insn.get("op_str", "")
        if "[" not in op_str:
            continue

        # Determine if load or store based on operand order
        # Store: mov [mem], reg  -- destination is memory
        # Load: mov reg, [mem]  -- source is memory
        parts = op_str.split(",", 1)
        if len(parts) < 2:
            continue

        dest, src = parts[0].strip(), parts[1].strip()
        if "[" in dest:
            operation = "store"
            mem_part = dest
            reg_part = src
        elif "[" in src:
            operation = "load"
            mem_part = src
            reg_part = dest
        else:
            continue

        # Extract base and offset
        m = pat.search(mem_part)
        if m:
            base, sign, off_str = m.groups()
            if base_reg and base.lower() != base_reg.lower():
                continue
            offset = int(off_str, 16) if off_str.lower().startswith("0x") else int(off_str)
            if sign == "-":
                offset = -offset
        else:
            m2 = pat_no_off.search(mem_part)
            if not m2:
                continue
            base = m2.group(1)
            if base_reg and base.lower() != base_reg.lower():
                continue
            offset = 0

        # Determine width from the register operand
        reg_clean = reg_part.strip().split()[0]  # handle "rax" from "rax, ..."
        width = _reg_width_x86_64(reg_clean)

        key = (offset, width, operation)
        if key not in seen:
            seen.add(key)
            accesses.append({
                "offset": offset,
                "width": width,
                "operation": operation,
                "register": reg_clean,
                "base": base,
            })

    return sorted(accesses, key=lambda a: a["offset"])


def _guess_struct_name(func_names):
    """Derive struct name from function names (e.g. SLSSetWindow* -> CGSWindow)."""
    for fn in func_names:
        if "Window" in fn:
            return "CGSWindow" if fn[:3] in ("SLS", "CGS") else "Window"
        if "Surface" in fn:
            return "CGSSurface"
        if "Display" in fn:
            return "CGSDisplay"
        if "Connection" in fn:
            return "CGSConnection"
        if "Session" in fn:
            return "CGSSession"
        if "Space" in fn:
            return "CGSSpace"
    if len(func_names) >= 2:
        prefix = os.path.commonprefix(func_names)
        prefix = re.sub(r'[A-Z][a-z]*$', '', prefix)
        if len(prefix) > 2:
            return f"{prefix}Struct"
    return "recovered_struct"


# -- Standalone entry point --------------------------------------------------

def main():
    parser = argparse.ArgumentParser(prog="cbstruct",
                                     description="Struct Layout Recovery via ARM64 disassembly")
    sub = parser.add_subparsers(dest="struct_command")

    s = sub.add_parser("recover")
    s.add_argument("binary")
    s.add_argument("--functions", "-f", type=str, required=True)
    s.add_argument("--arch", type=str, default="arm64", choices=["arm64", "x86_64"])
    s.add_argument("--max-insns", type=int, default=200)
    s.add_argument("--struct-name", type=str, default=None)
    add_output_args(s)
    s.set_defaults(func=run_recover)

    s = sub.add_parser("from-lldb")
    s.add_argument("--pid", type=int, required=True)
    s.add_argument("--address", type=str, required=True)
    s.add_argument("--size", type=int, default=256)
    add_output_args(s)
    s.set_defaults(func=run_from_lldb)

    s = sub.add_parser("format")
    s.add_argument("layout_file")
    s.add_argument("--struct-name", type=str, default=None)
    add_output_args(s)
    s.set_defaults(func=run_format)

    args = parser.parse_args()
    if not args.struct_command:
        parser.print_help()
        sys.exit(1)
    args.func(args)
