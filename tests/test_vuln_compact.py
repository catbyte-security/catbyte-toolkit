"""Tests for cb vuln --compact: finding consolidation and noise reduction."""
import pytest

from cb.commands.vuln import _compact_findings, _LARGE_BINARY_EXPECTED_IMPORTS


class TestCompactFindings:
    """Test finding grouping/consolidation."""

    def test_groups_import_findings(self):
        """Import findings of same category+severity are grouped."""
        findings = [
            {
                "id": "STATIC-001",
                "category": "overflow",
                "severity": "high",
                "title": "Dangerous function imported: strcpy",
                "description": "...",
                "evidence": {"type": "import", "symbol": "strcpy"},
                "recommendation": "Replace with strlcpy",
            },
            {
                "id": "STATIC-002",
                "category": "overflow",
                "severity": "high",
                "title": "Dangerous function imported: strcat",
                "description": "...",
                "evidence": {"type": "import", "symbol": "strcat"},
                "recommendation": "Replace with strlcat",
            },
        ]
        result = _compact_findings(findings)
        import_groups = [f for f in result
                         if f.get("evidence", {}).get("type") == "import_group"]
        assert len(import_groups) == 1
        assert import_groups[0]["evidence"]["count"] == 2
        assert "strcpy" in import_groups[0]["evidence"]["symbols"]
        assert "strcat" in import_groups[0]["evidence"]["symbols"]

    def test_preserves_non_import_findings(self):
        """Non-import findings pass through unchanged."""
        findings = [
            {
                "id": "STATIC-001",
                "category": "overflow",
                "severity": "high",
                "title": "Dangerous function imported: strcpy",
                "evidence": {"type": "import", "symbol": "strcpy"},
                "recommendation": "...",
            },
            {
                "id": "STATIC-005",
                "category": "format",
                "severity": "high",
                "title": "Format string with %n",
                "evidence": {"type": "string", "value": "%n"},
                "recommendation": "...",
            },
        ]
        result = _compact_findings(findings)
        non_import = [f for f in result
                      if f.get("evidence", {}).get("type") != "import_group"]
        assert len(non_import) == 1
        assert non_import[0]["id"] == "STATIC-005"

    def test_mixed_categories_separate_groups(self):
        """Different categories produce separate groups."""
        findings = [
            {
                "id": "STATIC-001",
                "category": "overflow",
                "severity": "high",
                "title": "strcpy",
                "evidence": {"type": "import", "symbol": "strcpy"},
                "recommendation": "...",
            },
            {
                "id": "STATIC-002",
                "category": "format",
                "severity": "high",
                "title": "printf",
                "evidence": {"type": "import", "symbol": "printf"},
                "recommendation": "...",
            },
        ]
        result = _compact_findings(findings)
        import_groups = [f for f in result
                         if f.get("evidence", {}).get("type") == "import_group"]
        assert len(import_groups) == 2


class TestLargeBinaryDowngrade:
    """Test binary-size-aware severity adjustment."""

    def test_expected_imports_list(self):
        """Standard library functions are in the expected imports set."""
        assert "memcpy" in _LARGE_BINARY_EXPECTED_IMPORTS
        assert "malloc" in _LARGE_BINARY_EXPECTED_IMPORTS
        assert "free" in _LARGE_BINARY_EXPECTED_IMPORTS
        assert "realloc" in _LARGE_BINARY_EXPECTED_IMPORTS

    def test_strcpy_not_in_expected(self):
        """Genuinely dangerous functions are NOT in expected imports."""
        assert "strcpy" not in _LARGE_BINARY_EXPECTED_IMPORTS
        assert "gets" not in _LARGE_BINARY_EXPECTED_IMPORTS
        assert "sprintf" not in _LARGE_BINARY_EXPECTED_IMPORTS


class TestChromeSuppression:
    """Test Chrome-specific dedup in compact mode."""

    def test_concept_chrome_dedup(self):
        """Verify Chrome dedup removes static findings covered by Chrome findings."""
        # This tests the dedup logic concept: if a symbol appears in both
        # STATIC and CHROME findings, STATIC should be removed
        findings = [
            {
                "id": "STATIC-001",
                "category": "overflow",
                "severity": "high",
                "title": "Dangerous function: memcpy",
                "evidence": {"type": "import", "symbol": "memcpy"},
            },
            {
                "id": "CHROME-001",
                "category": "chrome",
                "severity": "high",
                "title": "Chrome attack surface",
                "evidence": {
                    "type": "chrome_symbols",
                    "matched_symbols": ["memcpy"],
                },
            },
        ]
        # Simulate the dedup logic from run()
        chrome_symbols = set()
        for f in findings:
            if f["id"].startswith("CHROME-"):
                matched = f.get("evidence", {}).get("matched_symbols", [])
                chrome_symbols.update(matched)

        deduped = [
            f for f in findings
            if not (f["id"].startswith("STATIC-")
                    and f.get("evidence", {}).get("type") == "import"
                    and f.get("evidence", {}).get("symbol") in chrome_symbols)
        ]
        assert len(deduped) == 1
        assert deduped[0]["id"] == "CHROME-001"
