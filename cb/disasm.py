"""Capstone-native disassembly with objdump fallback."""
from __future__ import annotations

import os
import re
import struct
import subprocess
from typing import Any


def disassemble_function(binary_path: str, start_addr: int, size: int, arch: str = "arm64") -> list[dict[str, Any]]:
    """Disassemble a function - tries Capstone first, falls back to objdump."""
    # Try Capstone native first
    code = _read_code_bytes(binary_path, start_addr, size)
    if code:
        try:
            return capstone_disasm(code, start_addr, arch)
        except Exception:
            pass

    # Fallback to objdump
    end_addr = start_addr + size
    cmd = [
        "objdump", "-d",
        f"--start-address={hex(start_addr)}",
        f"--stop-address={hex(end_addr)}",
        binary_path,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return parse_objdump(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def disassemble_section(binary_path: str, section: str = "__TEXT,__text", max_lines: int = 10000) -> tuple[list[str], int]:
    """Disassemble a section, streaming with line limit."""
    cmd = ["objdump", "-d", f"-j{section}", binary_path]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        lines = result.stdout.splitlines()
        return lines[:max_lines], len(lines)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return [], 0


def parse_objdump(text: str) -> list[dict[str, str]]:
    """Parse objdump -d output into structured instructions."""
    instructions = []
    for line in text.splitlines():
        line = line.strip()
        if not line or (line.endswith(":") and not line[0].isdigit()):
            continue
        if ":" in line and len(line) > 10:
            parts = line.split(":", 1)
            if len(parts) == 2:
                addr = parts[0].strip()
                rest = parts[1].strip()
                instructions.append({
                    "address": addr,
                    "raw": rest,
                })
    return instructions


def capstone_disasm(code_bytes: bytes, base_addr: int = 0, arch: str = "arm64", max_insns: int = 500) -> list[dict[str, Any]]:
    """Disassemble raw bytes using Capstone."""
    import capstone

    if arch == "arm64":
        try:
            cs_arch = capstone.CS_ARCH_AARCH64
        except AttributeError:
            cs_arch = capstone.CS_ARCH_ARM64
        cs_mode = capstone.CS_MODE_ARM
    elif arch == "x86_64":
        cs_arch = capstone.CS_ARCH_X86
        cs_mode = capstone.CS_MODE_64
    elif arch == "x86":
        cs_arch = capstone.CS_ARCH_X86
        cs_mode = capstone.CS_MODE_32
    else:
        raise ValueError(f"Unsupported arch: {arch}")

    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = True
    instructions = []
    for insn in md.disasm(code_bytes, base_addr):
        entry = {
            "address": hex(insn.address),
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
            "bytes": insn.bytes.hex(),
            "size": insn.size,
        }
        # Extract instruction groups for pattern matching
        if insn.groups:
            entry["groups"] = [insn.group_name(g) for g in insn.groups
                               if insn.group_name(g)]
        instructions.append(entry)
        if len(instructions) >= max_insns:
            break
    return instructions


def capstone_search(code_bytes: bytes, base_addr: int, pattern: str, arch: str = "arm64", max_matches: int = 50) -> list[dict[str, str]]:
    """Search for instruction patterns using Capstone (semantic, not regex on text).

    Patterns:
        "bl *"       - branch-link to any target
        "str *,[sp*" - store to stack
        "ldr x0,*"   - load into x0
        "ret"        - return instruction
    """
    import capstone

    if arch == "arm64":
        try:
            cs_arch = capstone.CS_ARCH_AARCH64
        except AttributeError:
            cs_arch = capstone.CS_ARCH_ARM64
        cs_mode = capstone.CS_MODE_ARM
    elif arch == "x86_64":
        cs_arch = capstone.CS_ARCH_X86
        cs_mode = capstone.CS_MODE_64
    else:
        cs_arch = capstone.CS_ARCH_X86
        cs_mode = capstone.CS_MODE_32

    md = capstone.Cs(cs_arch, cs_mode)
    matches = []

    # Convert glob pattern to regex
    regex_pat = pattern.replace("*", ".*")
    regex = re.compile(regex_pat, re.IGNORECASE)

    for insn in md.disasm(code_bytes, base_addr):
        full = f"{insn.mnemonic} {insn.op_str}".strip()
        if regex.search(full):
            matches.append({
                "address": hex(insn.address),
                "instruction": full,
                "bytes": insn.bytes.hex(),
            })
            if len(matches) >= max_matches:
                break

    return matches


def _read_code_bytes(binary_path: str, addr: int, size: int) -> bytes | None:
    """Read raw bytes from a binary at a given virtual address."""
    try:
        import lief
        binary = lief.parse(binary_path)
        if binary is None:
            return None
        # Convert VA to file offset
        for section in binary.sections:
            sec_start = section.virtual_address
            sec_end = sec_start + section.size
            if sec_start <= addr < sec_end:
                offset = section.offset + (addr - sec_start)
                with open(binary_path, "rb") as f:
                    f.seek(offset)
                    return f.read(min(size, section.size))
        return None
    except Exception:
        pass

    # Fallback: try otool to get raw section data
    try:
        r = subprocess.run(
            ["otool", "-l", binary_path],
            capture_output=True, text=True, timeout=10
        )
        # Parse load commands to find the right segment/section
        # This is complex - just return None and let objdump handle it
        return None
    except Exception:
        return None


def capstone_disasm_detailed(code_bytes: bytes, base_addr: int = 0, arch: str = "arm64", max_insns: int = 500) -> list[dict[str, Any]]:
    """Disassemble raw bytes with full operand detail (memory offsets, registers, widths).

    Like capstone_disasm() but includes parsed operand information for each
    instruction, useful for struct layout recovery.
    """
    import capstone

    if arch == "arm64":
        try:
            cs_arch = capstone.CS_ARCH_AARCH64
        except AttributeError:
            cs_arch = capstone.CS_ARCH_ARM64
        cs_mode = capstone.CS_MODE_ARM
    elif arch == "x86_64":
        cs_arch = capstone.CS_ARCH_X86
        cs_mode = capstone.CS_MODE_64
    elif arch == "x86":
        cs_arch = capstone.CS_ARCH_X86
        cs_mode = capstone.CS_MODE_32
    else:
        raise ValueError(f"Unsupported arch: {arch}")

    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = True
    instructions = []
    for insn in md.disasm(code_bytes, base_addr):
        entry = {
            "address": hex(insn.address),
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
            "bytes": insn.bytes.hex(),
            "size": insn.size,
        }
        if insn.groups:
            entry["groups"] = [insn.group_name(g) for g in insn.groups
                               if insn.group_name(g)]
        # Parse operands for memory access detail
        operands = []
        for op in insn.operands:
            op_info = {"type": op.type}
            if op.type == capstone.CS_OP_REG:
                op_info["reg"] = insn.reg_name(op.reg)
            elif op.type == capstone.CS_OP_IMM:
                op_info["imm"] = op.imm
            elif op.type == capstone.CS_OP_MEM:
                mem = op.mem
                op_info["mem"] = {
                    "base": insn.reg_name(mem.base) if mem.base else None,
                    "index": insn.reg_name(mem.index) if mem.index else None,
                    "disp": mem.disp,
                }
            operands.append(op_info)
        entry["operands"] = operands
        instructions.append(entry)
        if len(instructions) >= max_insns:
            break
    return instructions


def detect_arch(binary_path: str) -> str:
    """Detect architecture of a binary."""
    try:
        r = subprocess.run(["file", "-b", binary_path],
                           capture_output=True, text=True, timeout=10)
        output = r.stdout.lower()
        if "arm64" in output or "aarch64" in output:
            return "arm64"
        elif "x86_64" in output or "x86-64" in output:
            return "x86_64"
        elif "i386" in output or "i686" in output:
            return "x86"
        return "unknown"
    except Exception:
        return "unknown"
