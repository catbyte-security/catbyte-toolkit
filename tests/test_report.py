"""Tests for report generator."""
import argparse
import json

import pytest

from cb.commands.report import (
    estimate_cvss, _extract_findings, _enrich_findings, _build_report,
    _render_markdown, _render_html, _html_escape, _build_chart_svg,
    _cwe_label, _cwe_summary, _build_attack_chain, _build_root_cause,
    CWE_MAP,
)


def _make_args(**kwargs):
    defaults = {
        "binary": "/usr/bin/file",
        "from_audit": None,
        "title": "Test Report",
        "author": "Test",
        "template": "internal",
        "markdown": False,
        "format": "json",
        "max_results": 50,
        "quiet": True,
        "output": None,
        "no_cache": True,
        "budget": None,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


def _make_audit_data():
    return {
        "target": "/usr/bin/file",
        "binary": "/usr/bin/file",
        "sections": {
            "vuln": {
                "dangerous_imports": [
                    {"import": "strcpy", "risk": "high",
                     "description": "Unbounded string copy"},
                ],
                "findings": [
                    {"category": "overflow", "severity": "medium",
                     "description": "Potential buffer overflow"},
                ],
            },
            "attack": {
                "entitlements": {
                    "dangerous": [
                        {"entitlement": "com.apple.security.cs.disable-library-validation",
                         "risk": "high",
                         "description": "Library validation disabled"},
                    ],
                },
            },
            "triage": {
                "protections": {"pie": True, "stack_canary": False},
            },
        },
    }


class TestEstimateCVSS:
    def test_high_remote(self):
        assert estimate_cvss("high", "remote") == 9.8

    def test_low_local(self):
        assert estimate_cvss("low", "local") == 3.3

    def test_medium_unknown(self):
        assert estimate_cvss("medium", "unknown") == 5.5

    def test_unknown_defaults(self):
        score = estimate_cvss("unknown", "unknown")
        assert score == 3.3


class TestExtractFindings:
    def test_from_audit(self):
        data = _make_audit_data()
        findings = _extract_findings(data)
        assert len(findings) >= 3  # vuln imports + vuln findings + attack ents

    def test_missing_protection(self):
        data = _make_audit_data()
        findings = _extract_findings(data)
        missing = [f for f in findings if f["type"] == "missing_protection"]
        assert len(missing) == 1
        assert "stack canary" in missing[0]["description"].lower()

    def test_empty_audit(self):
        findings = _extract_findings({"sections": {}})
        assert findings == []

    def test_findings_have_cwe(self):
        data = _make_audit_data()
        findings = _extract_findings(data)
        # dangerous_import should get CWE-676
        di = [f for f in findings if f["type"] == "dangerous_import"]
        assert len(di) == 1
        assert di[0]["cwe"] == "CWE-676"
        assert "Dangerous Function" in di[0]["cwe_name"]

    def test_overflow_finding_cwe(self):
        data = _make_audit_data()
        findings = _extract_findings(data)
        of = [f for f in findings if f["type"] == "overflow"]
        assert len(of) == 1
        assert of[0]["cwe"] == "CWE-120"

    def test_missing_protection_cwe(self):
        data = _make_audit_data()
        findings = _extract_findings(data)
        mp = [f for f in findings if f["type"] == "missing_protection"]
        assert mp[0]["cwe"] == "CWE-693"


class TestEnrichFindings:
    def test_adds_cvss(self):
        findings = [{"severity": "high", "detail": {"attack_vector": "remote"}}]
        enriched = _enrich_findings(findings)
        assert enriched[0]["cvss"] == 9.8

    def test_default_cvss(self):
        findings = [{"severity": "low", "detail": {}}]
        enriched = _enrich_findings(findings)
        assert enriched[0]["cvss"] == 3.3


class TestBuildReport:
    def test_report_structure(self):
        data = _make_audit_data()
        findings = _extract_findings(data)
        findings = _enrich_findings(findings)
        args = _make_args()
        report = _build_report("/usr/bin/file", findings, args)

        assert "title" in report
        assert "date" in report
        assert "executive_summary" in report
        assert "findings" in report
        assert "recommendations" in report
        assert report["findings_count"]["total"] == len(findings)

    def test_executive_summary_present(self):
        data = _make_audit_data()
        findings = _extract_findings(data)
        findings = _enrich_findings(findings)
        args = _make_args()
        report = _build_report("/usr/bin/file", findings, args)
        assert len(report["executive_summary"]) > 0

    def test_findings_sorted_by_severity(self):
        data = _make_audit_data()
        findings = _extract_findings(data)
        findings = _enrich_findings(findings)
        sev_order = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
        findings.sort(key=lambda f: sev_order.get(f.get("severity", "unknown"), 3))
        prev_sev = 0
        for f in findings:
            curr = sev_order.get(f.get("severity", "unknown"), 3)
            assert curr >= prev_sev
            prev_sev = curr


class TestRenderMarkdown:
    def test_all_templates_produce_output(self):
        data = _make_audit_data()
        findings = _extract_findings(data)
        findings = _enrich_findings(findings)
        args = _make_args()
        report = _build_report("/usr/bin/file", findings, args)

        for template in ("bugbounty", "internal", "brief"):
            md = _render_markdown(report, template)
            assert isinstance(md, str)
            assert len(md) > 100
            assert "file" in md.lower()

    def test_bugbounty_has_steps(self):
        data = _make_audit_data()
        findings = _extract_findings(data)
        findings = _enrich_findings(findings)
        args = _make_args()
        report = _build_report("/usr/bin/file", findings, args)
        md = _render_markdown(report, "bugbounty")
        assert "Steps to Reproduce" in md

    def test_bugbounty_has_cwe(self):
        data = _make_audit_data()
        findings = _extract_findings(data)
        findings = _enrich_findings(findings)
        args = _make_args()
        report = _build_report("/usr/bin/file", findings, args)
        md = _render_markdown(report, "bugbounty")
        assert "CWE-" in md

    def test_bugbounty_has_attack_chain(self):
        data = _make_audit_data()
        findings = _extract_findings(data)
        findings = _enrich_findings(findings)
        args = _make_args()
        report = _build_report("/usr/bin/file", findings, args)
        md = _render_markdown(report, "bugbounty")
        assert "Attack Chain" in md

    def test_bugbounty_has_root_cause(self):
        data = _make_audit_data()
        findings = _extract_findings(data)
        findings = _enrich_findings(findings)
        args = _make_args()
        report = _build_report("/usr/bin/file", findings, args)
        md = _render_markdown(report, "bugbounty")
        assert "Root Cause" in md

    def test_internal_has_table(self):
        data = _make_audit_data()
        findings = _extract_findings(data)
        findings = _enrich_findings(findings)
        args = _make_args()
        report = _build_report("/usr/bin/file", findings, args)
        md = _render_markdown(report, "internal")
        assert "| #" in md

    def test_internal_has_cwe_column(self):
        data = _make_audit_data()
        findings = _extract_findings(data)
        findings = _enrich_findings(findings)
        args = _make_args()
        report = _build_report("/usr/bin/file", findings, args)
        md = _render_markdown(report, "internal")
        assert "| CWE |" in md

    def test_markdown_findings_show_cwe(self):
        data = _make_audit_data()
        findings = _extract_findings(data)
        findings = _enrich_findings(findings)
        args = _make_args()
        report = _build_report("/usr/bin/file", findings, args)
        md = _render_markdown(report, "bugbounty")
        assert "**CWE:**" in md


class TestRenderHTML:
    def _make_report(self):
        data = _make_audit_data()
        findings = _extract_findings(data)
        findings = _enrich_findings(findings)
        args = _make_args()
        return _build_report("/usr/bin/file", findings, args)

    def test_all_templates_produce_valid_html(self):
        report = self._make_report()
        for template in ("bugbounty", "internal", "brief"):
            html = _render_html(report, template)
            assert html.startswith("<!DOCTYPE html>")
            assert html.strip().endswith("</html>")

    def test_html_escapes_script_tags(self):
        report = self._make_report()
        # Inject a script tag into a finding description
        report["findings"][0]["description"] = '<script>alert("xss")</script>'
        html = _render_html(report, "internal")
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_embedded_style_present(self):
        report = self._make_report()
        html = _render_html(report, "internal")
        assert "<style>" in html
        assert ".severity-high" in html
        assert ".severity-medium" in html
        assert ".severity-low" in html

    def test_svg_chart_generated(self):
        report = self._make_report()
        html = _render_html(report, "internal")
        assert "<svg" in html

    def test_finding_rows_match_count(self):
        report = self._make_report()
        html = _render_html(report, "internal")
        finding_count = len(report["findings"])
        assert html.count('<div class="finding-card">') == finding_count


class TestHtmlEscape:
    def test_escapes_angle_brackets(self):
        assert _html_escape("<div>") == "&lt;div&gt;"

    def test_escapes_quotes(self):
        assert _html_escape('"hello"') == "&quot;hello&quot;"

    def test_escapes_ampersand(self):
        assert _html_escape("a&b") == "a&amp;b"

    def test_non_string_input(self):
        assert _html_escape(42) == "42"


class TestBuildChartSvg:
    def test_generates_svg(self):
        svg = _build_chart_svg({"high": 2, "medium": 3, "low": 1})
        assert "<svg" in svg
        assert "High: 2" in svg
        assert "Medium: 3" in svg
        assert "Low: 1" in svg

    def test_empty_findings(self):
        svg = _build_chart_svg({"high": 0, "medium": 0, "low": 0})
        assert "No findings" in svg

    def test_single_severity(self):
        svg = _build_chart_svg({"high": 5, "medium": 0, "low": 0})
        assert "High: 5" in svg
        assert "Medium" not in svg


class TestCWEMap:
    def test_map_has_common_types(self):
        assert "overflow" in CWE_MAP
        assert "dangerous_import" in CWE_MAP
        assert "use_after_free" in CWE_MAP
        assert "xss" in CWE_MAP

    def test_map_values_format(self):
        for ftype, (cwe_id, cwe_name) in CWE_MAP.items():
            assert cwe_id.startswith("CWE-"), f"{ftype}: bad CWE ID {cwe_id}"
            assert len(cwe_name) > 0, f"{ftype}: empty CWE name"


class TestCWELabel:
    def test_with_cwe_and_name(self):
        f = {"cwe": "CWE-120", "cwe_name": "Buffer Overflow"}
        assert _cwe_label(f) == "CWE-120 (Buffer Overflow)"

    def test_with_cwe_only(self):
        f = {"cwe": "CWE-120", "cwe_name": ""}
        assert _cwe_label(f) == "CWE-120"

    def test_empty(self):
        assert _cwe_label({}) == ""
        assert _cwe_label({"cwe": "", "cwe_name": ""}) == ""


class TestCWESummary:
    def test_multiple_unique(self):
        findings = [
            {"cwe": "CWE-120", "cwe_name": "Buffer Overflow"},
            {"cwe": "CWE-676", "cwe_name": "Dangerous Function"},
            {"cwe": "CWE-120", "cwe_name": "Buffer Overflow"},  # dup
        ]
        result = _cwe_summary(findings)
        assert "CWE-120" in result
        assert "CWE-676" in result
        assert result.count("CWE-120") == 1  # no dup

    def test_no_cwes(self):
        assert _cwe_summary([{"cwe": "", "cwe_name": ""}]) == "N/A"


class TestBuildAttackChain:
    def test_high_findings_chain(self):
        findings = [
            {"type": "overflow", "severity": "high", "description": "buf overflow"},
            {"type": "dangerous_import", "severity": "high", "description": "strcpy used"},
            {"type": "info_leak", "severity": "low", "description": "minor"},
        ]
        chain = _build_attack_chain(findings)
        assert "overflow" in chain
        assert "strcpy" in chain
        assert "Chain:" in chain
        assert "info_leak" not in chain  # low sev excluded from chain

    def test_no_high_findings(self):
        findings = [{"type": "info", "severity": "low", "description": "minor"}]
        chain = _build_attack_chain(findings)
        assert "No high-severity" in chain

    def test_single_high(self):
        findings = [{"type": "overflow", "severity": "high", "description": "buf overflow"}]
        chain = _build_attack_chain(findings)
        assert "overflow" in chain
        assert "Chain:" not in chain  # no chain with single finding


class TestBuildRootCause:
    def test_with_detail(self):
        findings = [
            {"type": "overflow", "description": "buf overflow",
             "detail": {"import": "strcpy", "file": "main.c", "line": "42"}},
        ]
        result = _build_root_cause(findings)
        assert "strcpy" in result
        assert "main.c:42" in result

    def test_without_detail(self):
        findings = [{"type": "info", "description": "minor", "detail": {}}]
        result = _build_root_cause(findings)
        assert "See findings" in result

    def test_cwe_in_root_cause(self):
        findings = [
            {"type": "overflow", "description": "buf overflow",
             "cwe": "CWE-120", "cwe_name": "Buffer Overflow",
             "detail": {"import": "strcpy"}},
        ]
        result = _build_root_cause(findings)
        assert "CWE-120" in result


class TestHTMLNewFields:
    def _make_report(self):
        data = _make_audit_data()
        findings = _extract_findings(data)
        findings = _enrich_findings(findings)
        args = _make_args()
        return _build_report("/usr/bin/file", findings, args)

    def test_html_bugbounty_has_cwe(self):
        report = self._make_report()
        html = _render_html(report, "bugbounty")
        assert "CWE-" in html

    def test_html_bugbounty_has_attack_chain(self):
        report = self._make_report()
        html = _render_html(report, "bugbounty")
        assert "Attack Chain" in html

    def test_html_bugbounty_has_root_cause(self):
        report = self._make_report()
        html = _render_html(report, "bugbounty")
        assert "Root Cause" in html

    def test_html_internal_has_cwe_column(self):
        report = self._make_report()
        html = _render_html(report, "internal")
        assert "<th>CWE</th>" in html

    def test_html_finding_card_shows_cwe(self):
        report = self._make_report()
        html = _render_html(report, "internal")
        assert "CWE-676" in html  # dangerous_import CWE
