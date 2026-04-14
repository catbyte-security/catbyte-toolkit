"""Tests for cross-platform x86_64 support."""
import pytest

from cb.patterns.gadget_patterns import X86_64_CLASSIFIERS, CHAIN_TEMPLATES_X86_64
from cb.commands.gadget import classify_gadget
from cb.commands.struct import (
    _reg_width_x86_64, _detect_base_register_x86_64,
    _extract_x86_64_accesses,
)


class TestX86_64Classifiers:
    def test_all_six_categories_exist(self):
        expected = {"stack_pivot", "register_control", "memory_write",
                    "memory_read", "syscall", "function_call"}
        assert set(X86_64_CLASSIFIERS.keys()) == expected

    def test_each_category_has_patterns(self):
        for cat, patterns in X86_64_CLASSIFIERS.items():
            assert len(patterns) > 0, f"{cat} has no patterns"

    def test_chain_templates_x86_64_exist(self):
        assert "execve" in CHAIN_TEMPLATES_X86_64
        assert "mprotect_shellcode" in CHAIN_TEMPLATES_X86_64


class TestClassifyGadgetX86_64:
    def test_pop_rdi_ret(self):
        cats = classify_gadget("pop rdi ; ret", arch="x86_64")
        assert "register_control" in cats

    def test_syscall(self):
        cats = classify_gadget("syscall", arch="x86_64")
        assert "syscall" in cats

    def test_int_0x80(self):
        cats = classify_gadget("int 0x80", arch="x86_64")
        assert "syscall" in cats

    def test_xchg_rsp(self):
        cats = classify_gadget("xchg rax, rsp ; ret", arch="x86_64")
        assert "stack_pivot" in cats

    def test_leave(self):
        cats = classify_gadget("leave ; ret", arch="x86_64")
        assert "stack_pivot" in cats

    def test_mov_memory_write(self):
        cats = classify_gadget("mov [rdi], rax ; ret", arch="x86_64")
        assert "memory_write" in cats

    def test_mov_memory_read(self):
        cats = classify_gadget("mov rax, [rdi] ; ret", arch="x86_64")
        assert "memory_read" in cats

    def test_call_rax(self):
        cats = classify_gadget("call rax", arch="x86_64")
        assert "function_call" in cats

    def test_jmp_rax(self):
        cats = classify_gadget("jmp rax", arch="x86_64")
        assert "function_call" in cats

    def test_pop_rsi(self):
        cats = classify_gadget("pop rsi ; ret", arch="x86_64")
        assert "register_control" in cats

    def test_arm64_not_matched_on_x86_64(self):
        """ARM64 instructions should not match x86_64 classifiers."""
        cats = classify_gadget("svc #0x80", arch="x86_64")
        assert "syscall" not in cats

    def test_x86_64_not_matched_on_arm64(self):
        """x86_64 instructions should not match ARM64 classifiers."""
        cats = classify_gadget("syscall", arch="arm64")
        assert "syscall" not in cats


class TestRegWidthX86_64:
    def test_rax_is_8(self):
        assert _reg_width_x86_64("rax") == 8

    def test_eax_is_4(self):
        assert _reg_width_x86_64("eax") == 4

    def test_ax_is_2(self):
        assert _reg_width_x86_64("ax") == 2

    def test_al_is_1(self):
        assert _reg_width_x86_64("al") == 1

    def test_rbx(self):
        assert _reg_width_x86_64("rbx") == 8

    def test_rdi(self):
        assert _reg_width_x86_64("rdi") == 8

    def test_esi(self):
        assert _reg_width_x86_64("esi") == 4

    def test_r8(self):
        assert _reg_width_x86_64("r8") == 8

    def test_r8d(self):
        assert _reg_width_x86_64("r8d") == 4

    def test_r8w(self):
        assert _reg_width_x86_64("r8w") == 2

    def test_r8b(self):
        assert _reg_width_x86_64("r8b") == 1


class TestDetectBaseRegisterX86_64:
    def test_finds_most_common_base(self):
        instructions = [
            {"mnemonic": "mov", "op_str": "rax, [rdi+0x10]"},
            {"mnemonic": "mov", "op_str": "rbx, [rdi+0x18]"},
            {"mnemonic": "mov", "op_str": "rcx, [rsi+0x20]"},
        ]
        assert _detect_base_register_x86_64(instructions) == "rdi"

    def test_excludes_rsp(self):
        instructions = [
            {"mnemonic": "mov", "op_str": "rax, [rsp+0x10]"},
            {"mnemonic": "mov", "op_str": "rbx, [rsp+0x18]"},
            {"mnemonic": "mov", "op_str": "rcx, [rdi+0x20]"},
        ]
        assert _detect_base_register_x86_64(instructions) == "rdi"

    def test_empty_instructions(self):
        assert _detect_base_register_x86_64([]) == "rdi"


class TestExtractX86_64Accesses:
    def test_basic_load(self):
        instructions = [
            {"mnemonic": "mov", "op_str": "rax, [rdi+0x10]"},
        ]
        accesses = _extract_x86_64_accesses(instructions, base_reg="rdi")
        assert len(accesses) == 1
        assert accesses[0]["offset"] == 0x10
        assert accesses[0]["width"] == 8
        assert accesses[0]["operation"] == "load"

    def test_basic_store(self):
        instructions = [
            {"mnemonic": "mov", "op_str": "[rdi+0x20], eax"},
        ]
        accesses = _extract_x86_64_accesses(instructions, base_reg="rdi")
        assert len(accesses) == 1
        assert accesses[0]["offset"] == 0x20
        assert accesses[0]["width"] == 4
        assert accesses[0]["operation"] == "store"

    def test_filters_by_base_reg(self):
        instructions = [
            {"mnemonic": "mov", "op_str": "rax, [rdi+0x10]"},
            {"mnemonic": "mov", "op_str": "rbx, [rsi+0x20]"},
        ]
        accesses = _extract_x86_64_accesses(instructions, base_reg="rdi")
        assert len(accesses) == 1
        assert accesses[0]["offset"] == 0x10

    def test_zero_offset(self):
        instructions = [
            {"mnemonic": "mov", "op_str": "rax, [rdi]"},
        ]
        accesses = _extract_x86_64_accesses(instructions, base_reg="rdi")
        assert len(accesses) == 1
        assert accesses[0]["offset"] == 0

    def test_sorted_by_offset(self):
        instructions = [
            {"mnemonic": "mov", "op_str": "rax, [rdi+0x20]"},
            {"mnemonic": "mov", "op_str": "rbx, [rdi+0x8]"},
            {"mnemonic": "mov", "op_str": "rcx, [rdi+0x10]"},
        ]
        accesses = _extract_x86_64_accesses(instructions, base_reg="rdi")
        offsets = [a["offset"] for a in accesses]
        assert offsets == sorted(offsets)
