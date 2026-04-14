"""Tests for cb sandbox extract_security_findings: enhanced profile analysis."""
import pytest

from cb.commands.sandbox import extract_security_findings, IOKIT_CVE_MAP


class TestFileIssueExtension:
    """Test file-issue-extension rule detection."""

    def test_critical_subpath_root(self):
        """file-issue-extension with subpath '/' is CRITICAL."""
        profile = '(allow file-issue-extension (subpath "/"))'
        findings = extract_security_findings(profile)
        fie = [f for f in findings if f["type"] == "file-issue-extension"]
        assert len(fie) == 1
        assert fie[0]["severity"] == "critical"
        assert fie[0]["scope_value"] == "/"

    def test_narrow_subpath_medium(self):
        """file-issue-extension with narrow subpath is medium."""
        profile = '(allow file-issue-extension (subpath "/tmp/myapp"))'
        findings = extract_security_findings(profile)
        fie = [f for f in findings if f["type"] == "file-issue-extension"]
        assert len(fie) == 1
        assert fie[0]["severity"] == "medium"
        assert fie[0]["scope_value"] == "/tmp/myapp"


class TestIOKitCVEMapping:
    """Test IOKit user client class CVE cross-referencing."""

    def test_known_iokit_class_matched(self):
        """Known IOKit class matched with CVEs and risk level."""
        profile = '(allow iokit-open (iokit-user-client-class "IOSurfaceRootUserClient"))'
        findings = extract_security_findings(profile)
        iokit = [f for f in findings if f["type"] == "iokit-user-client-class"]
        assert len(iokit) == 1
        assert iokit[0]["class_name"] == "IOSurfaceRootUserClient"
        assert iokit[0]["severity"] == "high"
        assert len(iokit[0]["known_cves"]) > 0

    def test_unknown_iokit_class_low(self):
        """Unknown IOKit class gets low severity."""
        profile = '(allow iokit-open (iokit-user-client-class "MyCustomDriver"))'
        findings = extract_security_findings(profile)
        iokit = [f for f in findings if f["type"] == "iokit-user-client-class"]
        assert len(iokit) == 1
        assert iokit[0]["severity"] == "low"


class TestBroadRules:
    """Test detection of overly broad sandbox rules."""

    def test_unrestricted_mach_lookup(self):
        """Unrestricted mach-lookup is flagged."""
        profile = '(allow mach-lookup)'
        findings = extract_security_findings(profile)
        broad = [f for f in findings if f["type"] == "broad-mach-lookup"]
        assert len(broad) == 1
        assert broad[0]["severity"] == "high"

    def test_broad_file_write(self):
        """file-write* with subpath '/' is flagged."""
        profile = '(allow file-write* (subpath "/"))'
        findings = extract_security_findings(profile)
        broad = [f for f in findings if f["type"] == "broad-file-write*"]
        assert len(broad) == 1
        assert broad[0]["severity"] == "high"

    def test_narrow_rules_clean(self):
        """Narrow, specific rules produce no broad-rule findings."""
        profile = '''
        (allow mach-lookup (global-name "com.apple.fonts"))
        (allow file-read-data (subpath "/Library/Fonts"))
        '''
        findings = extract_security_findings(profile)
        broad = [f for f in findings if f["type"].startswith("broad-")]
        assert len(broad) == 0


class TestCombinedProfile:
    """Test a realistic profile with multiple rule types."""

    def test_chrome_gpu_profile_findings(self):
        """Simulate Chrome GPU sandbox profile with known issues."""
        profile = '''
        (version 1)
        (allow file-issue-extension (subpath "/"))
        (allow iokit-open (iokit-user-client-class "AGXCommandQueue"))
        (allow iokit-open (iokit-user-client-class "IOSurfaceRootUserClient"))
        (allow mach-lookup (global-name "com.apple.windowserver.active"))
        (allow file-read-data (subpath "/System/Library"))
        '''
        findings = extract_security_findings(profile)

        # Should have critical file-issue-extension
        fie = [f for f in findings if f["type"] == "file-issue-extension"]
        assert any(f["severity"] == "critical" for f in fie)

        # Should have IOKit findings
        iokit = [f for f in findings if f["type"] == "iokit-user-client-class"]
        assert len(iokit) == 2
        class_names = {f["class_name"] for f in iokit}
        assert "AGXCommandQueue" in class_names
        assert "IOSurfaceRootUserClient" in class_names
