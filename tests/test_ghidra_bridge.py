"""Tests for Ghidra bridge JSON parsing."""
import pytest

from cb.ghidra_bridge import JSON_START, JSON_END


class TestJsonMarkerParsing:
    def test_extract_json(self):
        output = f"""
INFO: Loading binary...
INFO: Analysis complete
{JSON_START}
{{"function": "main", "address": "0x1000"}}
{JSON_END}
INFO: Done
"""
        start = output.find(JSON_START)
        end = output.find(JSON_END)
        assert start != -1
        assert end != -1
        import json
        json_str = output[start + len(JSON_START):end].strip()
        data = json.loads(json_str)
        assert data["function"] == "main"
        assert data["address"] == "0x1000"

    def test_no_markers(self):
        output = "INFO: No output produced"
        assert output.find(JSON_START) == -1

    def test_markers_are_unique(self):
        assert JSON_START != JSON_END
        assert "###" in JSON_START
        assert "CB_JSON" in JSON_START


class TestProjectNaming:
    def test_project_name_deterministic(self):
        from cb.ghidra_bridge import _project_name
        name1 = _project_name("/usr/bin/file")
        name2 = _project_name("/usr/bin/file")
        assert name1 == name2

    def test_project_name_different(self):
        from cb.ghidra_bridge import _project_name
        name1 = _project_name("/usr/bin/file")
        name2 = _project_name("/usr/bin/ls")
        assert name1 != name2
