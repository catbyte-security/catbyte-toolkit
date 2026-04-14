"""Tests for SQLite analysis store and cb db command."""
import json
import os
import sqlite3

import pytest

from cb.store import AnalysisStore


@pytest.fixture
def store(tmp_path):
    """Create a fresh AnalysisStore with a temp database."""
    db_path = str(tmp_path / "test_analysis.db")
    return AnalysisStore(db_path=db_path)


@pytest.fixture
def sample_data():
    """Sample emit() data with findings."""
    return {
        "findings": [
            {
                "id": "STATIC-001",
                "category": "overflow",
                "severity": "high",
                "title": "Buffer overflow in parse_header",
                "description": "Unbounded memcpy from user input",
                "evidence": {"function": "parse_header", "offset": "0x1234"},
                "recommendation": "Use bounded copy",
            },
            {
                "id": "STATIC-002",
                "category": "format",
                "severity": "medium",
                "title": "Format string vulnerability",
                "description": "User-controlled format string in log_message",
                "evidence": {"function": "log_message"},
                "recommendation": "Use fixed format string",
            },
            {
                "id": "CHROME-003",
                "category": "chrome",
                "severity": "high",
                "title": "Mojo interface exposed to renderer",
                "description": "Unsafe Mojo binding",
                "evidence": None,
                "recommendation": "Add browser process check",
            },
        ],
        "protections": {
            "pie": True,
            "nx": True,
            "canary": False,
        },
        "file_info": {
            "sha256": "abc123def456",
            "size": 102400,
        },
        "_meta": {"time_seconds": 1.5},
    }


class TestAnalysisStoreSchema:
    def test_creates_tables(self, store):
        conn = sqlite3.connect(store.db_path)
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = {t[0] for t in tables}
        assert "runs" in table_names
        assert "findings" in table_names
        assert "properties" in table_names
        conn.close()

    def test_creates_indexes(self, store):
        conn = sqlite3.connect(store.db_path)
        indexes = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()
        idx_names = {i[0] for i in indexes}
        assert "idx_findings_severity" in idx_names
        assert "idx_findings_category" in idx_names
        assert "idx_runs_tool" in idx_names
        conn.close()

    def test_wal_mode(self, store):
        conn = store._get_conn()
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"


class TestRecordRun:
    def test_basic_record(self, store, sample_data):
        run_id = store.record_run(sample_data, "vuln")
        assert len(run_id) == 16
        run = store.get_run(run_id)
        assert run is not None
        assert run["tool_name"] == "vuln"

    def test_binary_path_stored(self, store, sample_data, tmp_path):
        # Create a temp binary to hash
        bin_file = tmp_path / "test_bin"
        bin_file.write_bytes(b"\x00" * 100)
        run_id = store.record_run(sample_data, "vuln", binary_path=str(bin_file))
        run = store.get_run(run_id)
        assert run["binary_path"] == str(bin_file)
        assert run["binary_name"] == "test_bin"
        assert run["binary_sha256"] is not None

    def test_sha256_from_data(self, store, sample_data):
        run_id = store.record_run(sample_data, "triage")
        run = store.get_run(run_id)
        # Should pick up sha256 from file_info
        assert run["binary_sha256"] == "abc123def456"

    def test_result_json_stored(self, store, sample_data):
        run_id = store.record_run(sample_data, "vuln")
        run = store.get_run(run_id)
        assert "result_data" in run
        assert run["result_data"]["findings"][0]["id"] == "STATIC-001"

    def test_elapsed_stored(self, store, sample_data):
        run_id = store.record_run(sample_data, "vuln")
        run = store.get_run(run_id)
        assert run["elapsed_sec"] == 1.5


class TestFindingExtraction:
    def test_findings_extracted(self, store, sample_data):
        store.record_run(sample_data, "vuln")
        findings = store.query_findings()
        assert len(findings) == 3

    def test_finding_fields(self, store, sample_data):
        store.record_run(sample_data, "vuln")
        findings = store.query_findings(severity="high")
        assert len(findings) == 2
        titles = {f["title"] for f in findings}
        assert "Buffer overflow in parse_header" in titles
        assert "Mojo interface exposed to renderer" in titles

    def test_finding_category_filter(self, store, sample_data):
        store.record_run(sample_data, "vuln")
        findings = store.query_findings(category="overflow")
        assert len(findings) == 1
        assert findings[0]["finding_id"] == "STATIC-001"

    def test_finding_evidence_json(self, store, sample_data):
        store.record_run(sample_data, "vuln")
        findings = store.query_findings(category="overflow")
        evidence = json.loads(findings[0]["evidence_json"])
        assert evidence["function"] == "parse_header"

    def test_no_findings_graceful(self, store):
        data = {"summary": "nothing here", "_meta": {}}
        store.record_run(data, "triage")
        findings = store.query_findings()
        assert findings == []


class TestPropertyExtraction:
    def test_properties_extracted(self, store, sample_data):
        store.record_run(sample_data, "triage")
        props = store.query_properties()
        keys = {p["key"] for p in props}
        assert "protections.pie" in keys
        assert "protections.canary" in keys
        assert "file_info.sha256" in keys

    def test_property_values(self, store, sample_data):
        store.record_run(sample_data, "triage")
        props = store.query_properties(key_pattern="protections.%")
        prop_map = {p["key"]: p["value"] for p in props}
        assert prop_map["protections.pie"] == "True"
        assert prop_map["protections.canary"] == "False"

    def test_property_binary_filter(self, store, sample_data):
        store.record_run(sample_data, "triage")
        props = store.query_properties(binary_sha256="abc123def456")
        assert len(props) > 0
        props_other = store.query_properties(binary_sha256="nonexistent")
        assert len(props_other) == 0


class TestQueryRuns:
    def test_list_runs(self, store, sample_data):
        store.record_run(sample_data, "vuln")
        store.record_run({"_meta": {}}, "triage")
        runs = store.query_runs()
        assert len(runs) == 2

    def test_filter_by_tool(self, store, sample_data):
        store.record_run(sample_data, "vuln")
        store.record_run({"_meta": {}}, "triage")
        runs = store.query_runs(tool_name="vuln")
        assert len(runs) == 1
        assert runs[0]["tool_name"] == "vuln"

    def test_run_not_found(self, store):
        assert store.get_run("nonexistent") is None


class TestQueryFindings:
    def test_fields_filter(self, store, sample_data):
        store.record_run(sample_data, "vuln")
        findings = store.query_findings(fields=["title", "severity"])
        assert len(findings) == 3
        for f in findings:
            assert set(f.keys()) == {"title", "severity"}

    def test_limit(self, store, sample_data):
        store.record_run(sample_data, "vuln")
        findings = store.query_findings(limit=1)
        assert len(findings) == 1

    def test_tool_name_filter(self, store, sample_data):
        store.record_run(sample_data, "vuln")
        store.record_run({"findings": [{"id": "X", "severity": "low"}], "_meta": {}}, "grep")
        findings = store.query_findings(tool_name="vuln")
        assert len(findings) == 3
        findings = store.query_findings(tool_name="grep")
        assert len(findings) == 1


class TestStats:
    def test_stats(self, store, sample_data):
        store.record_run(sample_data, "vuln")
        stats = store.get_stats()
        assert stats["total_runs"] == 1
        assert stats["total_findings"] == 3
        assert stats["findings_by_severity"]["high"] == 2
        assert stats["runs_by_tool"]["vuln"] == 1
        assert stats["db_path"] == store.db_path


class TestRawQuery:
    def test_select_allowed(self, store, sample_data):
        store.record_run(sample_data, "vuln")
        rows = store.execute_raw("SELECT COUNT(*) as cnt FROM findings")
        assert rows[0]["cnt"] == 3

    def test_non_select_rejected(self, store):
        with pytest.raises(ValueError, match="Only SELECT"):
            store.execute_raw("DELETE FROM findings")

    def test_insert_rejected(self, store):
        with pytest.raises(ValueError, match="Only SELECT"):
            store.execute_raw("INSERT INTO runs VALUES (1,2,3,4,5,6,7,8,9,10)")


class TestDbCommand:
    """Test the cb db command handler."""

    def test_findings_subcommand(self, store, sample_data, capsys, monkeypatch):
        import argparse
        from cb.commands.db import run as db_run

        store.record_run(sample_data, "vuln")
        monkeypatch.setattr("cb.store.get_store", lambda: store)

        args = argparse.Namespace(
            format="json", max_results=50, quiet=True, output=None,
            verbose=False, budget=None, no_store=True,
            db_command="findings", severity="high", category=None,
            binary=None, tool=None, limit=50, fields=None,
        )
        db_run(args)
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["count"] == 2

    def test_stats_subcommand(self, store, sample_data, capsys, monkeypatch):
        import argparse
        from cb.commands.db import run as db_run

        store.record_run(sample_data, "vuln")
        monkeypatch.setattr("cb.store.get_store", lambda: store)

        args = argparse.Namespace(
            format="json", max_results=50, quiet=True, output=None,
            verbose=False, budget=None, no_store=True,
            db_command="stats",
        )
        db_run(args)
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        assert result["total_runs"] == 1

    def test_fields_slim_output(self, store, sample_data, capsys, monkeypatch):
        import argparse
        from cb.commands.db import run as db_run

        store.record_run(sample_data, "vuln")
        monkeypatch.setattr("cb.store.get_store", lambda: store)

        args = argparse.Namespace(
            format="json", max_results=50, quiet=True, output=None,
            verbose=False, budget=None, no_store=True,
            db_command="findings", severity=None, category=None,
            binary=None, tool=None, limit=50, fields="title,severity",
        )
        db_run(args)
        captured = capsys.readouterr()
        result = json.loads(captured.out)
        for f in result["findings"]:
            assert set(f.keys()) == {"title", "severity"}
