"""Tests for output formatting and truncation."""
import json
import sys
from io import StringIO

import pytest

from cb.output import OutputFormatter, add_output_args


class TestOutputFormatter:
    def test_truncate_list(self):
        fmt = OutputFormatter(max_results=3)
        data = {"items": [1, 2, 3, 4, 5], "_meta": {}}
        result = fmt._truncate(data)
        assert len(result["items"]) == 3
        assert result["_meta"]["truncated"] is True
        assert result["_meta"]["items_total"] == 5

    def test_no_truncate_small_list(self):
        fmt = OutputFormatter(max_results=10)
        data = {"items": [1, 2, 3], "_meta": {}}
        result = fmt._truncate(data)
        assert len(result["items"]) == 3
        assert "truncated" not in result["_meta"]

    def test_truncate_nested(self):
        fmt = OutputFormatter(max_results=2)
        data = {"outer": {"inner": [1, 2, 3, 4]}, "_meta": {}}
        result = fmt._truncate(data)
        assert len(result["outer"]["inner"]) == 2

    def test_meta_preserved(self):
        fmt = OutputFormatter(max_results=1)
        data = {"_meta": {"tool": "test"}, "items": [1, 2]}
        result = fmt._truncate(data)
        assert result["_meta"]["tool"] == "test"

    def test_emit_json(self, capsys):
        fmt = OutputFormatter(fmt="json", max_results=50, quiet=True)
        fmt.emit({"key": "value"}, "test")
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert parsed["key"] == "value"
        assert parsed["_meta"]["tool"] == "test"

    def test_emit_summary(self, capsys):
        fmt = OutputFormatter(fmt="summary", max_results=50, quiet=True)
        fmt.emit({"summary": {"count": 5}, "details": [1, 2, 3]}, "test")
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert "summary" in parsed
        assert parsed["summary"]["count"] == 5

    def test_status_quiet(self, capsys):
        fmt = OutputFormatter(quiet=True)
        fmt.status("test message")
        captured = capsys.readouterr()
        assert captured.err == ""

    def test_status_verbose(self, capsys):
        fmt = OutputFormatter(quiet=False)
        fmt.status("test message")
        captured = capsys.readouterr()
        assert "[*] test message" in captured.err


class TestDebugMethod:
    def test_debug_verbose_prints(self, capsys):
        fmt = OutputFormatter(verbose=True)
        fmt.debug("test debug message")
        captured = capsys.readouterr()
        assert "[DEBUG" in captured.err
        assert "test debug message" in captured.err

    def test_debug_silent_when_not_verbose(self, capsys):
        fmt = OutputFormatter(verbose=False)
        fmt.debug("should not appear")
        captured = capsys.readouterr()
        assert captured.err == ""

    def test_debug_with_exception(self, capsys):
        fmt = OutputFormatter(verbose=True)
        try:
            raise ValueError("test error")
        except ValueError as e:
            fmt.debug("caught error", exc=e)
        captured = capsys.readouterr()
        assert "test error" in captured.err
        assert "ValueError" in captured.err

    def test_debug_elapsed_time(self, capsys):
        fmt = OutputFormatter(verbose=True)
        fmt.debug("timing check")
        captured = capsys.readouterr()
        # Should contain elapsed time like [DEBUG +0.0s]
        assert "+0." in captured.err or "+0s" in captured.err


class TestOutputToFile:
    def test_output_to_file(self, tmp_path):
        """Verify -o writes valid JSON and file is populated."""
        import argparse
        outfile = tmp_path / "test_out.json"

        # Save original stdout to restore after test
        original_stdout = sys.stdout

        args = argparse.Namespace(
            format="json", max_results=50, quiet=True,
            output=str(outfile), verbose=False,
        )

        from cb.output import make_formatter
        fmt = make_formatter(args)
        fmt.emit({"key": "value"}, "test")

        # Flush and restore stdout so we can read the file
        sys.stdout.flush()
        sys.stdout = original_stdout

        content = outfile.read_text()
        parsed = json.loads(content)
        assert parsed["key"] == "value"
        assert parsed["_meta"]["tool"] == "test"
