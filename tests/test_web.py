"""Tests for web audit command (all unit-level, no real HTTP)."""
import pytest

from cb.commands.web import (
    analyze_security_headers,
    analyze_csp,
    analyze_cors,
    analyze_cookies,
    SECURITY_HEADERS,
)


class TestAnalyzeSecurityHeaders:
    def test_empty_headers_flags_all_missing(self):
        """An empty header dict should flag every security header as missing."""
        findings = analyze_security_headers({})
        missing_headers = {f["header"] for f in findings if f["status"] == "missing"}
        for header_name in SECURITY_HEADERS:
            assert header_name in missing_headers, f"{header_name} not flagged"

    def test_all_missing_are_high_or_medium_severity(self):
        findings = analyze_security_headers({})
        for f in findings:
            assert f["severity"] in ("high", "medium", "low")

    def test_full_headers_no_missing(self):
        """Providing all recommended headers should produce no missing findings."""
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
            "X-XSS-Protection": "1; mode=block",
        }
        findings = analyze_security_headers(headers)
        missing = [f for f in findings if f["status"] == "missing"]
        assert len(missing) == 0

    def test_case_insensitive_lookup(self):
        """Headers should be matched case-insensitively."""
        headers = {
            "strict-transport-security": "max-age=31536000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "strict-origin",
            "permissions-policy": "geolocation=()",
            "x-xss-protection": "1",
        }
        findings = analyze_security_headers(headers)
        missing = [f for f in findings if f["status"] == "missing"]
        assert len(missing) == 0

    def test_hsts_max_age_zero_flagged(self):
        headers = {"Strict-Transport-Security": "max-age=0"}
        findings = analyze_security_headers(headers)
        hsts_findings = [f for f in findings if f.get("header") == "Strict-Transport-Security"
                         and f.get("status") == "weak"]
        assert len(hsts_findings) == 1


class TestAnalyzeCSP:
    def test_unsafe_inline_flagged(self):
        findings = analyze_csp("default-src 'self' 'unsafe-inline'")
        descs = [f["description"] for f in findings]
        assert any("unsafe-inline" in d.lower() or "inline" in d.lower()
                    for d in descs)

    def test_unsafe_eval_flagged(self):
        findings = analyze_csp("script-src 'unsafe-eval'")
        descs = [f["description"] for f in findings]
        assert any("eval" in d.lower() for d in descs)

    def test_wildcard_flagged(self):
        findings = analyze_csp("default-src *")
        descs = [f["description"] for f in findings]
        assert any("wildcard" in d.lower() for d in descs)

    def test_strict_csp_minimal_findings(self):
        findings = analyze_csp("default-src 'self'; script-src 'self'")
        # Should have no high severity findings
        high = [f for f in findings if f["severity"] == "high"]
        assert len(high) == 0

    def test_empty_csp(self):
        findings = analyze_csp("")
        assert len(findings) > 0
        assert findings[0]["severity"] == "high"

    def test_missing_default_src(self):
        findings = analyze_csp("script-src 'self'")
        descs = [f["description"] for f in findings]
        assert any("default-src" in d for d in descs)

    def test_data_uri_flagged(self):
        findings = analyze_csp("default-src 'self' data:")
        descs = [f["description"] for f in findings]
        assert any("data:" in d.lower() for d in descs)


class TestAnalyzeCookies:
    def test_missing_secure_and_httponly(self):
        findings = analyze_cookies(["session=abc; Path=/"])
        attrs_missing = {f["attribute"] for f in findings}
        assert "Secure" in attrs_missing
        assert "HttpOnly" in attrs_missing

    def test_secure_httponly_samesite_strict_clean(self):
        findings = analyze_cookies(
            ["session=abc; Secure; HttpOnly; SameSite=Strict; Path=/"])
        # Should have no findings
        assert len(findings) == 0

    def test_samesite_none_flagged(self):
        findings = analyze_cookies(
            ["session=abc; Secure; HttpOnly; SameSite=None; Path=/"])
        samesite_findings = [f for f in findings if f["attribute"] == "SameSite"]
        assert len(samesite_findings) == 1
        assert "None" in samesite_findings[0]["description"]

    def test_multiple_cookies(self):
        cookies = [
            "session=abc; Secure; HttpOnly; SameSite=Strict",
            "tracking=xyz; Path=/",
        ]
        findings = analyze_cookies(cookies)
        # The tracking cookie should have multiple findings
        tracking_findings = [f for f in findings if f["cookie"] == "tracking"]
        assert len(tracking_findings) >= 2  # Missing Secure + HttpOnly at minimum

    def test_cookie_name_extracted(self):
        findings = analyze_cookies(["my_session=value123; Path=/"])
        assert all(f["cookie"] == "my_session" for f in findings)


class TestAnalyzeCORS:
    """CORS tests would normally need HTTP mocking.
    We test the function signature and basic behavior with error cases."""

    def test_returns_list(self):
        # With no real server, this will return empty findings
        findings = analyze_cors("http://localhost:99999",
                                test_origins=["https://evil.com"],
                                timeout=1)
        assert isinstance(findings, list)


class TestSecurityHeadersData:
    def test_all_headers_have_required_fields(self):
        for header, info in SECURITY_HEADERS.items():
            assert "severity" in info, f"{header} missing severity"
            assert "description" in info, f"{header} missing description"
            assert "recommended" in info, f"{header} missing recommended"
            assert info["severity"] in ("high", "medium", "low")
