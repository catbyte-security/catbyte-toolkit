"""Tests for parallel batch crash processing."""
import argparse
import json
import os

import pytest

from cb.commands.crash import _process_single_crash


@pytest.fixture
def sample_ips(tmp_path):
    """Create a sample IPS crash report."""
    data = {
        "procName": "test_process",
        "pid": 1234,
        "parentProc": "launchd",
        "captureTime": "2024-01-01 00:00:00",
        "exception": {
            "type": "EXC_BAD_ACCESS",
            "signal": "SIGSEGV",
            "codes": "KERN_INVALID_ADDRESS at 0x0000000000000000",
        },
        "faultingThread": 0,
        "threads": [
            {"frames": [{"imageOffset": "0x1234", "symbol": "test_func"}]}
        ],
    }
    f = tmp_path / "test.ips"
    f.write_text(json.dumps(data))
    return str(f)


class TestProcessSingleCrash:
    def test_ips_parsing(self, sample_ips):
        result = _process_single_crash(sample_ips)
        assert result["_file"] == sample_ips
        assert "error" not in result
        assert "crash_summary" in result
        assert result["crash_summary"]["process"] == "test_process"

    def test_bad_file(self, tmp_path):
        bad = tmp_path / "bad.ips"
        bad.write_text("this is not valid json or crash format")
        result = _process_single_crash(str(bad))
        assert result["_file"] == str(bad)
        # Should not raise, should handle gracefully
        assert "crash_summary" in result or "error" in result

    def test_nonexistent_file(self, tmp_path):
        missing = str(tmp_path / "missing.ips")
        result = _process_single_crash(missing)
        assert "error" in result

    def test_parallel_flag_accepted(self):
        """Verify --parallel flag is accepted by argparse."""
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()
        from cb.commands.crash import register
        register(sub)
        args = parser.parse_args(["crash", "/tmp/test.ips", "--parallel", "4"])
        assert args.parallel == 4
