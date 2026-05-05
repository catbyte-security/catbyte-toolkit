"""Cross-reference resolver: find which functions reference each crypto hit.

Strategy:
  1. Load executable code section(s).
  2. Disassemble with capstone, tracking PC-relative loads.
       - ARM64: ADRP base + ADD/LDR follow-up gives target VA.
       - ARM64: ADR (small range) is one-shot.
       - x86-64: LEA reg, [rip+disp] / MOV reg, [rip+disp] one-shot.
  3. Recover function boundaries from Mach-O LC_FUNCTION_STARTS / ELF .symtab,
     fall back to a heuristic over branch targets.
  4. Attribute each PC-relative load that targets a crypto hit's address range
     to the function containing the load instruction.

Output is a map: hit_index -> list of FunctionRef.
"""
from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass, field

from cb.crypto.scanner import Hit, ScanResult, SectionInfo


@dataclass
class FunctionRef:
    """A reference from a function to a crypto hit's address range."""
    function_va: int
    function_name: str
    ref_va: int            # VA of the loading instruction
    target_va: int         # VA of the target (inside a hit's bytes)

    def to_dict(self) -> dict:
        return {
            "function_va": f"0x{self.function_va:x}",
            "function_name": self.function_name,
            "ref_va": f"0x{self.ref_va:x}",
            "target_va": f"0x{self.target_va:x}",
        }


@dataclass
class FunctionInfo:
    va: int
    size: int
    name: str

    @property
    def end_va(self) -> int:
        return self.va + self.size


# ──────────────────────────────────────────────────────────────────────
# Function recovery
# ──────────────────────────────────────────────────────────────────────

def recover_functions(binary_path: str) -> list[FunctionInfo]:
    """Recover function start VAs and names from the binary.

    Uses LIEF where available. Mach-O LC_FUNCTION_STARTS gives compact
    function starts even in stripped binaries; ELF uses .symtab/.dynsym.
    """
    funcs: list[FunctionInfo] = []
    try:
        import lief  # type: ignore
        binary = lief.parse(binary_path)
        if binary is None:
            return funcs

        # Walk Mach-O FatBinary to first slice
        if hasattr(binary, "at") and not hasattr(binary, "sections"):
            try:
                if binary.size > 0:
                    binary = binary.at(0)
            except Exception:
                pass

        # LIEF exposes "functions" iter for Mach-O (synthesized from
        # LC_FUNCTION_STARTS + symbols) and for ELF (from symtab).
        try:
            iter_funcs = list(binary.functions)
        except Exception:
            iter_funcs = []

        # Build name lookup from symbol table for nicer naming
        name_by_va: dict[int, str] = {}
        try:
            for sym in binary.symbols:
                addr = int(getattr(sym, "value", 0) or 0)
                name = sym.name or ""
                if addr and name and addr not in name_by_va:
                    # Strip leading underscore (Mach-O convention)
                    if name.startswith("_"):
                        name = name[1:]
                    name_by_va[addr] = name
        except Exception:
            pass

        for f in iter_funcs:
            va = int(getattr(f, "address", 0) or 0)
            size = int(getattr(f, "size", 0) or 0)
            name = getattr(f, "name", "") or name_by_va.get(va, "")
            if name and name.startswith("_"):
                name = name[1:]
            if not name:
                name = f"sub_{va:x}"
            funcs.append(FunctionInfo(va=va, size=size, name=name))
    except ImportError:
        return funcs
    except Exception:
        return funcs

    funcs.sort(key=lambda f: f.va)

    # If sizes are zero (LC_FUNCTION_STARTS only gives starts), infer them
    # from the next function's start.
    for i, f in enumerate(funcs):
        if f.size == 0:
            if i + 1 < len(funcs):
                funcs[i] = FunctionInfo(va=f.va, size=funcs[i + 1].va - f.va, name=f.name)
            else:
                funcs[i] = FunctionInfo(va=f.va, size=0x1000, name=f.name)  # rough guess

    return funcs


def find_function(funcs: list[FunctionInfo], va: int) -> FunctionInfo | None:
    """Binary-search the function containing a VA."""
    if not funcs:
        return None
    starts = [f.va for f in funcs]
    idx = bisect_right(starts, va) - 1
    if idx < 0:
        return None
    f = funcs[idx]
    if f.size and f.va <= va < f.va + f.size:
        return f
    if not f.size and f.va <= va:
        return f
    return None


# ──────────────────────────────────────────────────────────────────────
# Hit lookup by VA
# ──────────────────────────────────────────────────────────────────────

@dataclass
class _HitRange:
    start: int
    end: int
    index: int


def _build_hit_index(hits: list[Hit]) -> list[_HitRange]:
    """Create sorted list of (va_start, va_end, hit_index) for fast containment check."""
    ranges: list[_HitRange] = []
    for i, h in enumerate(hits):
        if h.virtual_address is None:
            continue
        size = len(h.fingerprint.bytes)
        ranges.append(_HitRange(h.virtual_address, h.virtual_address + size, i))
    ranges.sort(key=lambda r: r.start)
    return ranges


def _find_hit(ranges: list[_HitRange], va: int) -> int | None:
    """Find the hit whose [start, end) contains va. -1 if none."""
    if not ranges:
        return None
    starts = [r.start for r in ranges]
    idx = bisect_right(starts, va) - 1
    if idx < 0:
        return None
    r = ranges[idx]
    if r.start <= va < r.end:
        return r.index
    return None


# ──────────────────────────────────────────────────────────────────────
# Capstone walker
# ──────────────────────────────────────────────────────────────────────

def _arch_to_capstone(arch: str):
    """Map our architecture string to capstone (cs_arch, cs_mode)."""
    import capstone
    a = arch.lower()
    if "arm64" in a or "aarch64" in a:
        try:
            return capstone.CS_ARCH_AARCH64, capstone.CS_MODE_ARM
        except AttributeError:
            return capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM
    if "x86_64" in a or "x64" in a or "amd64" in a:
        return capstone.CS_ARCH_X86, capstone.CS_MODE_64
    if "x86" in a or "i386" in a:
        return capstone.CS_ARCH_X86, capstone.CS_MODE_32
    raise ValueError(f"Unsupported arch for xref resolution: {arch}")


def _walk_arm64(code: bytes, base_va: int,
                 hit_ranges: list[_HitRange],
                 funcs: list[FunctionInfo],
                 max_xrefs: int = 4096) -> list[tuple[int, FunctionRef]]:
    """Walk ARM64 code and yield (hit_index, FunctionRef) for crypto refs.

    Mach-O __text frequently interleaves code with literal/constant pools
    (especially for SIMD AES/SHA assembly). We enable skipdata so capstone
    advances past undecodable bytes instead of bailing out.
    """
    import capstone
    cs_arch, cs_mode = _arch_to_capstone("arm64")
    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = False
    md.skipdata = True  # critical: skip non-instruction bytes (literal pools)

    # Track ADRP register state: last ADRP page per register (and the address).
    # The page's lifetime is short — anything that overwrites the register
    # invalidates it. We forget on conditional branches too.
    adrp_state: dict[str, int] = {}  # reg name -> page va

    out: list[tuple[int, FunctionRef]] = []

    for insn in md.disasm(code, base_va):
        mnem = insn.mnemonic
        ops = insn.op_str

        if mnem == "adrp":
            # "adrp x0, #0xffff" — ops is "x0, #0xffff"
            try:
                reg, target = [s.strip() for s in ops.split(",", 1)]
                page = int(target.lstrip("#"), 0)
                adrp_state[reg] = page
            except Exception:
                pass
            continue

        target_va: int | None = None

        if mnem == "adr":
            # "adr x0, #0xffff" — direct PC-relative target
            try:
                reg, target = [s.strip() for s in ops.split(",", 1)]
                target_va = int(target.lstrip("#"), 0)
            except Exception:
                pass

        elif mnem == "add" and adrp_state:
            # "add x0, x0, #0x123" — combine with prior ADRP
            try:
                parts = [s.strip() for s in ops.split(",")]
                if len(parts) == 3 and parts[0] == parts[1] and parts[2].startswith("#"):
                    reg = parts[0]
                    if reg in adrp_state:
                        offset = int(parts[2].lstrip("#"), 0)
                        target_va = adrp_state[reg] + offset
                        # ADRP+ADD pair "uses" the ADRP — clear it
                        adrp_state.pop(reg, None)
            except Exception:
                pass

        elif mnem in ("ldr", "ldrb", "ldrh", "ldrsw", "str", "strb", "strh") and adrp_state:
            # "ldr x1, [x0, #0x123]" — combine with prior ADRP for x0
            try:
                # find "[reg, #imm]" or "[reg]"
                bracket = ops.find("[")
                if bracket != -1:
                    inner = ops[bracket + 1:ops.find("]", bracket)]
                    parts = [s.strip() for s in inner.split(",")]
                    base_reg = parts[0]
                    if base_reg in adrp_state:
                        offset = 0
                        if len(parts) >= 2 and parts[1].startswith("#"):
                            offset = int(parts[1].lstrip("#"), 0)
                        target_va = adrp_state[base_reg] + offset
                        # LDR using an ADRP usually uses it once; clear it
                        adrp_state.pop(base_reg, None)
            except Exception:
                pass

        elif mnem in ("br", "blr", "ret", "b", "bl") or mnem.startswith("b."):
            # Branches invalidate register state — we lose track on
            # control flow joins. (A real dataflow analysis would track
            # this properly.)
            adrp_state.clear()

        elif mnem == "mov":
            # mov reg, #imm clears the ADRP for that reg
            try:
                reg = ops.split(",", 1)[0].strip()
                adrp_state.pop(reg, None)
            except Exception:
                pass

        if target_va is None:
            continue

        hit_idx = _find_hit(hit_ranges, target_va)
        if hit_idx is None:
            continue

        f = find_function(funcs, insn.address)
        out.append((hit_idx, FunctionRef(
            function_va=f.va if f else insn.address,
            function_name=f.name if f else f"sub_{insn.address:x}",
            ref_va=insn.address,
            target_va=target_va,
        )))
        if len(out) >= max_xrefs:
            break

    return out


def _walk_x86_64(code: bytes, base_va: int,
                  hit_ranges: list[_HitRange],
                  funcs: list[FunctionInfo],
                  max_xrefs: int = 4096) -> list[tuple[int, FunctionRef]]:
    """Walk x86-64 code looking for RIP-relative refs to crypto hit ranges."""
    import capstone
    cs_arch, cs_mode = _arch_to_capstone("x86_64")
    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = True
    md.skipdata = True

    out: list[tuple[int, FunctionRef]] = []
    for insn in md.disasm(code, base_va):
        # Use detail to find RIP-relative memory operands.
        try:
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_MEM:
                    if op.mem.base == capstone.x86.X86_REG_RIP:
                        target_va = insn.address + insn.size + op.mem.disp
                        hit_idx = _find_hit(hit_ranges, target_va)
                        if hit_idx is None:
                            continue
                        f = find_function(funcs, insn.address)
                        out.append((hit_idx, FunctionRef(
                            function_va=f.va if f else insn.address,
                            function_name=f.name if f else f"sub_{insn.address:x}",
                            ref_va=insn.address,
                            target_va=target_va,
                        )))
                        if len(out) >= max_xrefs:
                            return out
        except Exception:
            continue
    return out


# ──────────────────────────────────────────────────────────────────────
# Top-level resolver
# ──────────────────────────────────────────────────────────────────────

def resolve_xrefs(binary_path: str, result: ScanResult,
                   max_xrefs: int = 4096,
                   max_text_size: int = 64 * 1024 * 1024) -> dict[int, list[FunctionRef]]:
    """Resolve function-level cross-references for each crypto hit.

    Returns {hit_index: [FunctionRef, ...]}. Hits without VAs are skipped.
    Capped by ``max_xrefs`` total references and ``max_text_size`` bytes
    of code disassembly to keep the runtime bounded on large binaries.
    """
    if not result.hits or not result.sections:
        return {}

    arch = result.architecture or "arm64"
    text_secs = _executable_sections(result.sections, result.format)
    if not text_secs:
        return {}

    hit_ranges = _build_hit_index(result.hits)
    if not hit_ranges:
        return {}

    funcs = recover_functions(binary_path)

    refs_by_hit: dict[int, list[FunctionRef]] = {}
    walked = 0
    with open(binary_path, "rb") as f:
        for sec in text_secs:
            if walked >= max_text_size:
                break
            f.seek(sec.file_offset)
            chunk_size = min(sec.file_size, max_text_size - walked)
            if chunk_size <= 0:
                break
            code = f.read(chunk_size)
            walked += len(code)

            if any(a in arch.lower() for a in ("arm64", "aarch64")):
                walker = _walk_arm64
            elif "x86" in arch.lower() or "x64" in arch.lower() or "amd64" in arch.lower():
                walker = _walk_x86_64
            else:
                continue

            try:
                pairs = walker(code, sec.virtual_address, hit_ranges, funcs,
                                max_xrefs=max_xrefs - sum(len(v) for v in refs_by_hit.values()))
            except Exception:
                continue
            for hit_idx, ref in pairs:
                refs_by_hit.setdefault(hit_idx, []).append(ref)

    return refs_by_hit


def _executable_sections(sections: list[SectionInfo], fmt: str) -> list[SectionInfo]:
    """Pick the executable / code sections from a section list.

    Mach-O: __TEXT.__text (sometimes __TEXT.__stubs / __text_exec).
    ELF:    .text.
    PE:     .text.
    """
    out: list[SectionInfo] = []
    for s in sections:
        nm = (s.name or "").lower()
        sg = (s.segment or "").lower()
        if fmt == "macho":
            if sg == "__text" and nm in ("__text", "__stubs"):
                out.append(s)
            elif nm == "__text" and "text" in sg:
                out.append(s)
        elif fmt == "elf":
            if nm in (".text", ".init", ".plt", ".plt.sec"):
                out.append(s)
        elif fmt == "pe":
            if nm in (".text",):
                out.append(s)
    # If we found nothing, fall back to anything that smells like code
    if not out:
        for s in sections:
            if "text" in (s.name or "").lower():
                out.append(s)
    return out
