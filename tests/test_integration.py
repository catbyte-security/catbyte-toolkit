"""Integration tests using real system binaries."""
import json
import os
import subprocess
import sys

import pytest

# Use /usr/bin/file as a test binary — always present on macOS
SYSTEM_BINARY = "/usr/bin/file"
CB_CMD = [sys.executable, "-m", "cb"]


def run_cb(*args, input_data=None, expect_fail=False):
    """Run cb command and return (stdout, stderr, returncode)."""
    cmd = CB_CMD + list(args)
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=60,
        input=input_data,
    )
    if not expect_fail:
        assert result.returncode == 0, (
            f"cb {' '.join(args)} failed (rc={result.returncode}):\n"
            f"stdout: {result.stdout[:500]}\n"
            f"stderr: {result.stderr[:500]}"
        )
    return result.stdout, result.stderr, result.returncode


class TestTriageIntegration:
    def test_triage_system_binary(self):
        """Verify triage produces valid JSON with expected structure."""
        stdout, stderr, _ = run_cb("triage", SYSTEM_BINARY)
        data = json.loads(stdout)
        assert "_meta" in data
        assert data["_meta"]["tool"] == "triage"
        assert "file_info" in data
        assert data["file_info"]["path"] == SYSTEM_BINARY

    def test_triage_nonexistent(self):
        """Verify clean error for missing file."""
        stdout, stderr, rc = run_cb("triage", "/nonexistent/binary",
                                     expect_fail=True)
        assert rc != 0
        assert "not found" in stderr.lower() or "error" in stderr.lower()

    def test_triage_verbose(self):
        """Verify --verbose still produces valid JSON output."""
        stdout, stderr, _ = run_cb("--verbose", "triage", SYSTEM_BINARY)
        data = json.loads(stdout)
        assert "_meta" in data
        assert data["_meta"]["tool"] == "triage"


class TestGhidraIntegration:
    def test_ghidra_graceful_output(self):
        """Verify ghidra analyze produces valid JSON (error or result)."""
        stdout, stderr, _ = run_cb("ghidra", "analyze", SYSTEM_BINARY)
        data = json.loads(stdout)
        # Either an error dict (Ghidra not installed) or a valid result
        assert "_meta" in data or "error" in data
        if "error" in data:
            assert "hint" in data


class TestFormatFlags:
    def test_summary_format(self):
        stdout, stderr, _ = run_cb("triage", SYSTEM_BINARY, "--summary")
        data = json.loads(stdout)
        assert "_meta" in data

    def test_text_format(self):
        stdout, stderr, _ = run_cb("triage", SYSTEM_BINARY, "--format", "text")
        # Text format is not JSON — just verify it doesn't crash
        assert len(stdout) > 0


class TestOutputFile:
    def test_output_to_file(self, tmp_path):
        """Verify -o flag writes correct JSON."""
        outfile = tmp_path / "out.json"
        run_cb("triage", SYSTEM_BINARY, "-o", str(outfile))
        content = outfile.read_text()
        data = json.loads(content)
        assert data["_meta"]["tool"] == "triage"
        assert data["file_info"]["path"] == SYSTEM_BINARY


class TestPipelineChaining:
    def test_triage_to_vuln_pipeline(self):
        """Verify pipeline chaining: triage output fed to vuln."""
        triage_out, _, _ = run_cb("triage", SYSTEM_BINARY)
        # Feed triage output to vuln via stdin
        stdout, stderr, rc = run_cb(
            "vuln", "--from-triage", "-",
            input_data=triage_out,
        )
        # vuln should accept the input (may find 0 vulns, that's fine)
        if rc == 0:
            data = json.loads(stdout)
            assert "_meta" in data

    def test_pipeline_bad_json(self):
        """Verify pipeline error message for invalid JSON."""
        stdout, stderr, rc = run_cb(
            "vuln", "--from-triage", "-",
            input_data='{"bad": "json"',
            expect_fail=True,
        )
        # Should mention invalid JSON somewhere
        assert "json" in stderr.lower() or "error" in stderr.lower() or rc != 0
