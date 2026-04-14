"""Tests for Ghidra/LLDB graceful degradation when tools are unavailable."""
import argparse
import json
import sys
from io import StringIO
from unittest.mock import patch, MagicMock

import pytest


def _make_args(**kwargs):
    """Create a minimal argparse.Namespace for command handlers."""
    defaults = {
        "format": "json",
        "max_results": 50,
        "quiet": True,
        "output": None,
        "verbose": False,
        "timeout": 30,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


class TestGhidraGracefulDegradation:
    @patch("cb.ghidra_bridge.is_available", return_value=False)
    def test_analyze_unavailable(self, mock_avail, capsys):
        from cb.commands.ghidra import run_analyze
        args = _make_args(binary="/usr/bin/file", force=False, timeout=600)
        run_analyze(args)
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "error" in result
        assert "not installed" in result["error"].lower() or "not configured" in result["error"].lower()
        assert "hint" in result

    @patch("cb.ghidra_bridge.is_available", return_value=False)
    def test_decompile_unavailable(self, mock_avail, capsys):
        from cb.commands.ghidra import run_decompile
        args = _make_args(binary="/usr/bin/file", function="main",
                          include_assembly=False)
        run_decompile(args)
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "error" in result
        assert "hint" in result

    @patch("cb.ghidra_bridge.is_available", return_value=False)
    def test_functions_unavailable(self, mock_avail, capsys):
        from cb.commands.ghidra import run_functions
        args = _make_args(binary="/usr/bin/file", sort_by="size",
                          min_size=0, filter=None)
        run_functions(args)
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "error" in result

    @patch("cb.ghidra_bridge.is_available", return_value=False)
    def test_xrefs_unavailable(self, mock_avail, capsys):
        from cb.commands.ghidra import run_xrefs
        args = _make_args(binary="/usr/bin/file", function="main",
                          direction="both", depth=1)
        run_xrefs(args)
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "error" in result

    @patch("cb.ghidra_bridge.is_available", return_value=False)
    def test_search_unavailable(self, mock_avail, capsys):
        from cb.commands.ghidra import run_search
        args = _make_args(binary="/usr/bin/file", pattern="malloc")
        run_search(args)
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "error" in result

    @patch("cb.ghidra_bridge.is_available", return_value=True)
    @patch("cb.ghidra_bridge.analyze", side_effect=Exception("Ghidra crashed"))
    def test_analyze_exception_caught(self, mock_analyze, mock_avail, capsys):
        from cb.commands.ghidra import run_analyze
        args = _make_args(binary="/usr/bin/file", force=False, timeout=600)
        run_analyze(args)
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "error" in result
        assert "Ghidra crashed" in result["error"]


class TestLLDBGracefulDegradation:
    @patch("cb.lldb_bridge.is_available", return_value=False)
    def test_info_unavailable(self, mock_avail, capsys):
        from cb.commands.lldb import run_info
        args = _make_args(binary="/usr/bin/file")
        run_info(args)
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "error" in result
        assert "not available" in result["error"].lower()
        assert "hint" in result

    @patch("cb.lldb_bridge.is_available", return_value=False)
    def test_symbols_unavailable(self, mock_avail, capsys):
        from cb.commands.lldb import run_symbols
        args = _make_args(binary="/usr/bin/file", pattern="main")
        run_symbols(args)
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "error" in result

    @patch("cb.lldb_bridge.is_available", return_value=False)
    def test_disasm_unavailable(self, mock_avail, capsys):
        from cb.commands.lldb import run_disasm
        args = _make_args(binary="/usr/bin/file", target="main",
                          pid=None, count=50)
        run_disasm(args)
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "error" in result

    @patch("cb.lldb_bridge.is_available", return_value=False)
    def test_memory_unavailable(self, mock_avail, capsys):
        from cb.commands.lldb import run_memory
        args = _make_args(pid=1234, address="0x1000", size=256)
        run_memory(args)
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "error" in result

    @patch("cb.lldb_bridge.is_available", return_value=False)
    def test_backtrace_unavailable(self, mock_avail, capsys):
        from cb.commands.lldb import run_backtrace
        args = _make_args(pid=1234)
        run_backtrace(args)
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "error" in result

    @patch("cb.lldb_bridge.is_available", return_value=False)
    def test_registers_unavailable(self, mock_avail, capsys):
        from cb.commands.lldb import run_registers
        args = _make_args(pid=1234)
        run_registers(args)
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "error" in result

    @patch("cb.lldb_bridge.is_available", return_value=False)
    def test_breakpoint_unavailable(self, mock_avail, capsys):
        from cb.commands.lldb import run_breakpoint
        args = _make_args(binary="/usr/bin/file", functions=["main"],
                          proc_args=None, collect="args,backtrace", count=10,
                          timeout=60)
        run_breakpoint(args)
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "error" in result

    @patch("cb.lldb_bridge.is_available", return_value=False)
    def test_eval_unavailable(self, mock_avail, capsys):
        from cb.commands.lldb import run_eval
        args = _make_args(pid=1234, expression="(int)getpid()")
        run_eval(args)
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "error" in result

    @patch("cb.lldb_bridge.is_available", return_value=True)
    @patch("cb.lldb_bridge.get_info", side_effect=Exception("LLDB segfault"))
    def test_info_exception_caught(self, mock_info, mock_avail, capsys):
        from cb.commands.lldb import run_info
        args = _make_args(binary="/usr/bin/file")
        run_info(args)
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert "error" in result
        assert "LLDB segfault" in result["error"]
