"""Tests for LLDB bridge JSON parsing and bridge functions."""
import json
import os
import pytest
from unittest.mock import patch, MagicMock

from cb.lldb_bridge import JSON_START, JSON_END, LLDBError, _run_lldb_script


class TestJsonMarkerParsing:
    def test_extract_json(self):
        output = f"""
some debug output
{JSON_START}
{{"arch": "arm64", "uuid": "ABC-123"}}
{JSON_END}
more output
"""
        start = output.find(JSON_START)
        end = output.find(JSON_END)
        assert start != -1
        assert end != -1
        json_str = output[start + len(JSON_START):end].strip()
        data = json.loads(json_str)
        assert data["arch"] == "arm64"
        assert data["uuid"] == "ABC-123"

    def test_no_markers(self):
        output = "no json here"
        assert output.find(JSON_START) == -1

    def test_markers_are_unique(self):
        assert JSON_START != JSON_END
        assert "###" in JSON_START
        assert "CB_JSON" in JSON_START

    def test_markers_match_common(self):
        """Bridge markers must match the ones in lldb_common.py."""
        from cb.lldb_scripts.lldb_common import JSON_START as COMMON_START
        from cb.lldb_scripts.lldb_common import JSON_END as COMMON_END
        assert JSON_START == COMMON_START
        assert JSON_END == COMMON_END


class TestDetectLldbPython:
    def test_detect_returns_path_or_none(self):
        from cb.lldb_bridge import _detect_lldb_python
        result = _detect_lldb_python()
        # Should return a string path or None
        assert result is None or isinstance(result, str)

    def test_detect_with_config(self):
        from cb.lldb_bridge import _detect_lldb_python
        with patch("cb.lldb_bridge.load_config",
                   return_value={"lldb_pythonpath": "/nonexistent/path"}):
            # Should fall through since path doesn't exist
            result = _detect_lldb_python()
            # May still find via lldb -P or known locations
            assert result is None or isinstance(result, str)


class TestGetLldbPython:
    def test_default_system_python(self):
        from cb.lldb_bridge import _get_lldb_python
        with patch("cb.lldb_bridge.load_config", return_value={"lldb_python": ""}):
            result = _get_lldb_python()
            assert result in ("/usr/bin/python3", "python3")

    def test_explicit_config(self):
        from cb.lldb_bridge import _get_lldb_python
        with patch("cb.lldb_bridge.load_config",
                   return_value={"lldb_python": "/usr/bin/python3"}):
            result = _get_lldb_python()
            assert result == "/usr/bin/python3"


class TestRunLldbScript:
    def test_successful_json_output(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = f"debug\n{JSON_START}\n{{\"key\": \"value\"}}\n{JSON_END}\nend"
        mock_result.stderr = ""

        with patch("cb.lldb_bridge._detect_lldb_python", return_value="/fake/path"), \
             patch("cb.lldb_bridge._get_lldb_python", return_value="/usr/bin/python3"), \
             patch("subprocess.run", return_value=mock_result):
            result = _run_lldb_script("lldb_info.py", ["test"])
            assert result == {"key": "value"}

    def test_error_in_json(self):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = f"{JSON_START}\n{{\"error\": \"something broke\"}}\n{JSON_END}"
        mock_result.stderr = ""

        with patch("cb.lldb_bridge._detect_lldb_python", return_value="/fake/path"), \
             patch("cb.lldb_bridge._get_lldb_python", return_value="/usr/bin/python3"), \
             patch("subprocess.run", return_value=mock_result):
            with pytest.raises(LLDBError, match="something broke"):
                _run_lldb_script("lldb_info.py", ["test"])

    def test_no_json_output(self):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = "no markers here"
        mock_result.stderr = "error details"

        with patch("cb.lldb_bridge._detect_lldb_python", return_value="/fake/path"), \
             patch("cb.lldb_bridge._get_lldb_python", return_value="/usr/bin/python3"), \
             patch("subprocess.run", return_value=mock_result):
            with pytest.raises(LLDBError, match="Script failed"):
                _run_lldb_script("lldb_info.py", ["test"])

    def test_timeout(self):
        import subprocess
        with patch("cb.lldb_bridge._detect_lldb_python", return_value="/fake/path"), \
             patch("cb.lldb_bridge._get_lldb_python", return_value="/usr/bin/python3"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 30)):
            with pytest.raises(LLDBError, match="timed out"):
                _run_lldb_script("lldb_info.py", ["test"], timeout=30)

    def test_no_pythonpath(self):
        with patch("cb.lldb_bridge._detect_lldb_python", return_value=None):
            with pytest.raises(LLDBError, match="LLDB Python framework not found"):
                _run_lldb_script("lldb_info.py", ["test"])

    def test_invalid_json(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = f"{JSON_START}\nnot valid json\n{JSON_END}"
        mock_result.stderr = ""

        with patch("cb.lldb_bridge._detect_lldb_python", return_value="/fake/path"), \
             patch("cb.lldb_bridge._get_lldb_python", return_value="/usr/bin/python3"), \
             patch("subprocess.run", return_value=mock_result):
            with pytest.raises(LLDBError, match="Invalid JSON"):
                _run_lldb_script("lldb_info.py", ["test"])


class TestPublicAPI:
    """Test that public API functions correctly build script args."""

    def _mock_run(self, expected_script, expected_args_contains=None):
        """Helper to mock _run_lldb_script and verify calls."""
        with patch("cb.lldb_bridge._run_lldb_script", return_value={"ok": True}) as mock:
            yield mock
            mock.assert_called_once()
            call_args = mock.call_args
            assert call_args[0][0] == expected_script
            if expected_args_contains:
                for item in expected_args_contains:
                    assert item in call_args[0][1] or item in call_args[1].get("args", [])

    def test_get_info(self):
        from cb.lldb_bridge import get_info
        with patch("cb.lldb_bridge._run_lldb_script", return_value={"ok": True}) as mock:
            result = get_info("/bin/echo")
            assert result == {"ok": True}
            mock.assert_called_once_with("lldb_info.py", ["/bin/echo"], timeout=30)

    def test_get_modules_binary(self):
        from cb.lldb_bridge import get_modules
        with patch("cb.lldb_bridge._run_lldb_script", return_value={"ok": True}) as mock:
            result = get_modules(binary="/bin/echo")
            assert result == {"ok": True}
            args = mock.call_args[0][1]
            assert "--binary" in args
            assert "/bin/echo" in args

    def test_get_modules_pid(self):
        from cb.lldb_bridge import get_modules
        with patch("cb.lldb_bridge._run_lldb_script", return_value={"ok": True}) as mock:
            result = get_modules(pid=1234)
            assert result == {"ok": True}
            args = mock.call_args[0][1]
            assert "--pid" in args
            assert "1234" in args

    def test_find_symbols(self):
        from cb.lldb_bridge import find_symbols
        with patch("cb.lldb_bridge._run_lldb_script", return_value={"ok": True}) as mock:
            result = find_symbols("/bin/echo", "main", max_results=10)
            assert result == {"ok": True}
            args = mock.call_args[0][1]
            assert "/bin/echo" in args
            assert "main" in args
            assert "--max-results" in args
            assert "10" in args

    def test_disassemble(self):
        from cb.lldb_bridge import disassemble
        with patch("cb.lldb_bridge._run_lldb_script", return_value={"ok": True}) as mock:
            result = disassemble("/bin/echo", "main", count=20)
            assert result == {"ok": True}
            args = mock.call_args[0][1]
            assert "/bin/echo" in args
            assert "main" in args
            assert "--count" in args

    def test_run_with_breakpoints(self):
        from cb.lldb_bridge import run_with_breakpoints
        with patch("cb.lldb_bridge._run_lldb_script", return_value={"ok": True}) as mock:
            result = run_with_breakpoints(
                "/bin/echo", ["malloc"], args=["hello"],
                collect=["args", "backtrace"], count=5, timeout=30,
            )
            assert result == {"ok": True}
            args = mock.call_args[0][1]
            assert "/bin/echo" in args
            assert "malloc" in args
            assert "--args" in args
            assert "hello" in args
            assert "--collect" in args
            assert "--count" in args

    def test_evaluate(self):
        from cb.lldb_bridge import evaluate
        with patch("cb.lldb_bridge._run_lldb_script", return_value={"ok": True}) as mock:
            result = evaluate(1234, "(int)getpid()")
            assert result == {"ok": True}
            args = mock.call_args[0][1]
            assert "1234" in args
            assert "(int)getpid()" in args


class TestLldbCommon:
    """Test the shared utilities module (importable from venv Python)."""

    def test_emit_json_format(self, capsys):
        # We can import the module since it doesn't require lldb at import time
        from cb.lldb_scripts.lldb_common import emit_json, JSON_START, JSON_END
        emit_json({"test": 123})
        captured = capsys.readouterr()
        assert JSON_START in captured.out
        assert JSON_END in captured.out
        # Parse the JSON between markers
        start = captured.out.find(JSON_START)
        end = captured.out.find(JSON_END)
        json_str = captured.out[start + len(JSON_START):end].strip()
        data = json.loads(json_str)
        assert data["test"] == 123

    def test_emit_error_format(self, capsys):
        from cb.lldb_scripts.lldb_common import emit_error, JSON_START, JSON_END
        emit_error("test error")
        captured = capsys.readouterr()
        start = captured.out.find(JSON_START)
        end = captured.out.find(JSON_END)
        json_str = captured.out[start + len(JSON_START):end].strip()
        data = json.loads(json_str)
        assert data["error"] == "test error"


class TestConfigDefaults:
    def test_lldb_config_keys(self):
        from cb.config import DEFAULT_CONFIG
        assert "lldb_python" in DEFAULT_CONFIG
        assert "lldb_pythonpath" in DEFAULT_CONFIG


class TestScriptFilesExist:
    """Verify all expected LLDB script files exist."""

    EXPECTED_SCRIPTS = [
        "lldb_common.py",
        "lldb_info.py",
        "lldb_modules.py",
        "lldb_symbols.py",
        "lldb_disasm.py",
        "lldb_memory.py",
        "lldb_threads.py",
        "lldb_breakpoint.py",
        "lldb_eval.py",
    ]

    def test_all_scripts_exist(self):
        from cb.lldb_bridge import SCRIPT_DIR
        for script in self.EXPECTED_SCRIPTS:
            path = os.path.join(SCRIPT_DIR, script)
            assert os.path.exists(path), f"Missing script: {script}"

    def test_script_dir_exists(self):
        from cb.lldb_bridge import SCRIPT_DIR
        assert os.path.isdir(SCRIPT_DIR)
