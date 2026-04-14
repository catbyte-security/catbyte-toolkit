"""Tests for disassembly module."""
import pytest

from cb.disasm import parse_objdump, detect_arch, capstone_disasm


class TestParseObjdump:
    def test_parse_arm64(self):
        text = """
_main:
100003f48: d10083ff  sub sp, sp, #0x20
100003f4c: a9017bfd  stp x29, x30, [sp, #0x10]
100003f50: 910043fd  add x29, sp, #0x10
"""
        insns = parse_objdump(text)
        assert len(insns) == 3
        assert insns[0]["address"] == "100003f48"

    def test_parse_empty(self):
        assert parse_objdump("") == []
        assert parse_objdump("no instructions here") == []


class TestCapstone:
    def test_arm64_nop(self):
        # ARM64 NOP = 0xd503201f
        nop_bytes = bytes.fromhex("1f2003d5")
        insns = capstone_disasm(nop_bytes, 0, "arm64")
        assert len(insns) == 1
        assert insns[0]["mnemonic"] == "nop"

    def test_x86_nop(self):
        nop_bytes = b"\x90\x90\x90"
        insns = capstone_disasm(nop_bytes, 0, "x86_64")
        assert len(insns) == 3
        assert all(i["mnemonic"] == "nop" for i in insns)

    def test_max_insns(self):
        nops = b"\x90" * 100
        insns = capstone_disasm(nops, 0, "x86_64", max_insns=10)
        assert len(insns) == 10


class TestDetectArch:
    def test_system_binary(self):
        arch = detect_arch("/usr/bin/file")
        assert arch in ("arm64", "x86_64", "unknown")
