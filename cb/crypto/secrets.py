"""Hardcoded key and static IV detection.

Heuristic: a function that references AES tables likely also references
its key and IV. We follow ADRP+ADD/LDR pairs from any AES-touching function
and look for:

  - 16/24/32-byte high-entropy runs in __const / __data / __DATA_CONST →
    key candidates. Entropy threshold rejects easy false positives like
    repeated bytes or English text.
  - 16-byte aligned non-zero non-textual constants in same data regions →
    IV candidates. We don't filter as aggressively because IVs may have
    structure (nonce + counter pattern).

This isn't a guarantee — some real implementations derive keys at runtime,
in which case nothing static will be found and that's the correct answer.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from cb.crypto.heuristics import shannon_entropy
from cb.crypto.scanner import Hit, ScanResult, SectionInfo
from cb.crypto.xref import (FunctionRef, _executable_sections,
                              _walk_arm64, _walk_x86_64,
                              _build_hit_index, recover_functions,
                              find_function)


# ──────────────────────────────────────────────────────────────────────
# Findings
# ──────────────────────────────────────────────────────────────────────

@dataclass
class SecretCandidate:
    kind: str               # "key" | "iv" | "nonce"
    function_name: str      # function that references the candidate
    function_va: int
    target_va: int          # VA of the candidate bytes
    file_offset: int
    size: int               # 16, 24, 32 bytes
    entropy: float
    bytes_hex: str          # short prefix for human display
    severity: str           # "critical" | "warn" | "info"
    confidence: float
    rationale: str

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "function_name": self.function_name,
            "function_va": f"0x{self.function_va:x}",
            "target_va": f"0x{self.target_va:x}",
            "file_offset": self.file_offset,
            "size": self.size,
            "entropy": round(self.entropy, 3),
            "bytes_hex": self.bytes_hex,
            "severity": self.severity,
            "confidence": round(self.confidence, 2),
            "rationale": self.rationale,
        }


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def _va_to_offset(sections: list[SectionInfo], va: int, size: int) -> tuple[int, SectionInfo] | None:
    """Resolve a VA range to a file offset and the containing section."""
    for s in sections:
        if s.file_size <= 0:
            continue
        sec_end_va = s.virtual_address + s.file_size
        if s.virtual_address <= va < sec_end_va and va + size <= sec_end_va:
            return s.file_offset + (va - s.virtual_address), s
    return None


def _is_data_section(s: SectionInfo, fmt: str) -> bool:
    nm = (s.name or "").lower()
    sg = (s.segment or "").lower()
    if fmt == "macho":
        return sg in ("__data", "__data_const") or nm in ("__const", "__const_coal")
    if fmt == "elf":
        return nm in (".rodata", ".data", ".data.rel.ro")
    if fmt == "pe":
        return nm in (".data", ".rdata")
    return False


def _looks_textual(data: bytes) -> bool:
    """Cheap check — is this likely ASCII text or another well-known structure?"""
    if not data:
        return False
    printable = sum(1 for b in data if 0x20 <= b < 0x7f or b in (0x09, 0x0a, 0x0d))
    return printable >= len(data) * 0.85


def _all_zero(data: bytes) -> bool:
    return all(b == 0 for b in data)


def _all_same_byte(data: bytes) -> bool:
    return len(set(data)) <= 1


# ──────────────────────────────────────────────────────────────────────
# Candidate scanner
# ──────────────────────────────────────────────────────────────────────

def find_secret_candidates(binary_path: str,
                            result: ScanResult,
                            xrefs_by_hit: dict[int, list[FunctionRef]],
                            *,
                            entropy_threshold: float = 3.5,
                            max_candidates: int = 100) -> list[SecretCandidate]:
    """Scan data sections referenced by AES functions for key/IV candidates.

    We don't try to brute-force every load in the binary — only the loads
    inside functions that we already know touch AES code.
    """
    if not result.hits or not xrefs_by_hit:
        return []

    # Identify functions that reference any AES hit.
    aes_funcs: dict[int, str] = {}  # function_va -> name
    iv_eligible_funcs: dict[int, str] = {}  # any cipher-touching function

    for hit_idx, refs in xrefs_by_hit.items():
        algo = result.hits[hit_idx].fingerprint.algorithm
        for r in refs:
            if algo in ("aes", "aes-gcm"):
                aes_funcs[r.function_va] = r.function_name
            if algo in ("aes", "aes-gcm", "des", "blowfish", "chacha20", "rc2", "rc4"):
                iv_eligible_funcs[r.function_va] = r.function_name

    if not aes_funcs and not iv_eligible_funcs:
        return []

    # Walk the entire __text once and capture every PC-relative target
    # whose referencing instruction lies inside an interesting function.
    text_secs = _executable_sections(result.sections, result.format)
    if not text_secs:
        return []

    # Functions list (so xref walker can attribute correctly)
    funcs = recover_functions(binary_path)
    hit_ranges = _build_hit_index(result.hits)

    # We use the same walker but capture *all* PC-relative targets,
    # not only ones that hit existing crypto. We do this by giving
    # the walker an empty hit_ranges and iterating its own target_va
    # detection — but the walker only reports when the target matches.
    # Instead: walk manually with a custom inner loop.
    candidates: list[SecretCandidate] = []
    seen_targets: set[tuple[int, int]] = set()  # (target_va, size)

    arch = result.architecture or "arm64"
    for sec in text_secs:
        with open(binary_path, "rb") as f:
            f.seek(sec.file_offset)
            code = f.read(sec.file_size)
        targets = _collect_pc_relative_targets(code, sec.virtual_address, arch, funcs,
                                                 max_targets=8000)
        for target_va, ref_va, fn_va, fn_name in targets:
            # Skip targets that already correspond to a known crypto hit
            if any(r.start <= target_va < r.end for r in hit_ranges):
                continue

            # Try each candidate size
            for size in (32, 24, 16):
                key = (target_va, size)
                if key in seen_targets:
                    continue

                resolved = _va_to_offset(result.sections, target_va, size)
                if resolved is None:
                    continue
                file_off, sec_info = resolved
                if not _is_data_section(sec_info, result.format):
                    continue

                with open(binary_path, "rb") as f:
                    f.seek(file_off)
                    data = f.read(size)

                if len(data) != size:
                    continue
                if _all_zero(data) or _all_same_byte(data):
                    continue
                if _looks_textual(data):
                    continue

                ent = shannon_entropy(data)

                # Key candidates need high entropy + must be in an AES function.
                # Real random N-byte data has entropy capped at log2(N), so the
                # bar scales with size: 16-byte keys top out at 4.0, 32-byte at 5.0.
                # We require entropy >= log2(size) - 0.5 to allow small variance.
                import math as _math
                key_min_entropy = max(entropy_threshold, _math.log2(size) - 0.5)
                if size in (16, 24, 32) and fn_va in aes_funcs and ent >= key_min_entropy:
                    seen_targets.add(key)
                    candidates.append(SecretCandidate(
                        kind="key",
                        function_name=fn_name,
                        function_va=fn_va,
                        target_va=target_va,
                        file_offset=file_off,
                        size=size,
                        entropy=ent,
                        bytes_hex=data.hex()[:32] + ("…" if len(data) > 16 else ""),
                        severity="critical",
                        confidence=min(0.95, ent / 8.0),
                        rationale=f"AES-{size*8}-bit key candidate referenced by AES "
                                  f"function {fn_name} (entropy {ent:.2f}/8.0)",
                    ))
                    break  # one candidate per target

                # IV candidates: 16 bytes, lower entropy bar (IVs may be structured)
                if size == 16 and fn_va in iv_eligible_funcs and ent >= entropy_threshold:
                    seen_targets.add(key)
                    candidates.append(SecretCandidate(
                        kind="iv",
                        function_name=fn_name,
                        function_va=fn_va,
                        target_va=target_va,
                        file_offset=file_off,
                        size=size,
                        entropy=ent,
                        bytes_hex=data.hex(),
                        severity="warn",
                        confidence=min(0.7, ent / 8.0),
                        rationale=f"Static 16-byte IV/nonce candidate referenced by "
                                  f"cipher function {fn_name} (entropy {ent:.2f})",
                    ))

            if len(candidates) >= max_candidates:
                return candidates

    return candidates


def _collect_pc_relative_targets(code: bytes, base_va: int, arch: str,
                                   funcs, max_targets: int = 8000) -> list[tuple[int, int, int, str]]:
    """Return [(target_va, ref_va, function_va, function_name), ...] for every
    PC-relative load in the code section. Used to find data references from
    crypto-touching functions.
    """
    out: list[tuple[int, int, int, str]] = []
    arch_l = arch.lower()
    if "arm64" in arch_l or "aarch64" in arch_l:
        out = _arm64_targets(code, base_va, funcs, max_targets)
    elif "x86" in arch_l or "x64" in arch_l or "amd64" in arch_l:
        out = _x86_targets(code, base_va, funcs, max_targets)
    return out


def _arm64_targets(code: bytes, base_va: int, funcs, max_targets: int) -> list[tuple[int, int, int, str]]:
    import capstone
    try:
        cs_arch = capstone.CS_ARCH_AARCH64
    except AttributeError:
        cs_arch = capstone.CS_ARCH_ARM64
    md = capstone.Cs(cs_arch, capstone.CS_MODE_ARM)
    md.detail = False
    md.skipdata = True

    out: list[tuple[int, int, int, str]] = []
    adrp_state: dict[str, int] = {}

    for insn in md.disasm(code, base_va):
        mnem = insn.mnemonic
        ops = insn.op_str

        if mnem == "adrp":
            try:
                reg, target = [s.strip() for s in ops.split(",", 1)]
                adrp_state[reg] = int(target.lstrip("#"), 0)
            except Exception:
                pass
            continue

        target_va: int | None = None

        if mnem == "adr":
            try:
                reg, target = [s.strip() for s in ops.split(",", 1)]
                target_va = int(target.lstrip("#"), 0)
            except Exception:
                pass
        elif mnem == "add" and adrp_state:
            try:
                parts = [s.strip() for s in ops.split(",")]
                if len(parts) == 3 and parts[0] == parts[1] and parts[2].startswith("#"):
                    if parts[0] in adrp_state:
                        target_va = adrp_state[parts[0]] + int(parts[2].lstrip("#"), 0)
                        adrp_state.pop(parts[0], None)
            except Exception:
                pass
        elif mnem in ("ldr", "ldrb", "ldrh", "ldrsw") and adrp_state:
            try:
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
                        adrp_state.pop(base_reg, None)
            except Exception:
                pass
        elif mnem in ("br", "blr", "ret", "b", "bl") or mnem.startswith("b."):
            adrp_state.clear()

        if target_va is None:
            continue

        f = find_function(funcs, insn.address)
        out.append((target_va, insn.address,
                    f.va if f else insn.address,
                    f.name if f else f"sub_{insn.address:x}"))
        if len(out) >= max_targets:
            break

    return out


def _x86_targets(code: bytes, base_va: int, funcs, max_targets: int) -> list[tuple[int, int, int, str]]:
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    md.skipdata = True

    out: list[tuple[int, int, int, str]] = []
    for insn in md.disasm(code, base_va):
        try:
            for op in insn.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    target_va = insn.address + insn.size + op.mem.disp
                    f = find_function(funcs, insn.address)
                    out.append((target_va, insn.address,
                                f.va if f else insn.address,
                                f.name if f else f"sub_{insn.address:x}"))
                    if len(out) >= max_targets:
                        return out
        except Exception:
            continue
    return out
