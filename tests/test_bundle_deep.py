"""Tests for cb bundle --deep: deep bundle analysis with sandbox and privilege detection."""
import os
from unittest import mock

import pytest

from cb.commands.bundle import (
    _scan_binary_deep, _detect_privilege_level, _check_launch_daemon,
    _build_security_comparison, register,
)


class TestScanBinaryDeep:
    """Test deep binary scanning."""

    @mock.patch("cb.commands.bundle._scan_binary_quick")
    @mock.patch("cb.commands.bundle._detect_privilege_level")
    @mock.patch("cb.macho.get_embedded_sandbox_profile", return_value=None)
    def test_deep_scan_includes_privilege(self, mock_profile, mock_priv, mock_quick):
        """Deep scan adds privilege info to quick scan results."""
        mock_quick.return_value = {
            "path": "/app/helper",
            "signed": True,
            "entitlements": {},
            "dangerous_entitlements": [],
        }
        mock_priv.return_value = {
            "level": "standard",
            "runs_as_root": False,
            "is_setuid": False,
            "is_launch_daemon": False,
            "has_sandbox": True,
        }
        result = _scan_binary_deep("/app/helper", "/app")
        assert "privilege" in result
        assert result["privilege"]["level"] == "standard"

    @mock.patch("cb.commands.bundle._scan_binary_quick")
    @mock.patch("cb.commands.bundle._detect_privilege_level")
    @mock.patch("cb.macho.get_embedded_sandbox_profile")
    def test_deep_scan_with_sandbox_profile(self, mock_profile, mock_priv, mock_quick):
        """Deep scan extracts sandbox profile findings."""
        mock_quick.return_value = {
            "path": "/app/helper",
            "signed": True,
            "entitlements": {},
            "dangerous_entitlements": [],
        }
        mock_priv.return_value = {"level": "standard", "runs_as_root": False,
                                  "is_setuid": False, "is_launch_daemon": False,
                                  "has_sandbox": True}
        mock_profile.return_value = '(allow file-issue-extension (subpath "/"))'
        result = _scan_binary_deep("/app/helper", "/app")
        assert result["has_sandbox_profile"] is True
        assert result["sandbox_findings_count"] >= 1


class TestDetectPrivilegeLevel:
    """Test privilege level detection."""

    @mock.patch("cb.commands.bundle.get_entitlements")
    def test_sandboxed_standard(self, mock_ents):
        """Sandboxed binary returns standard privilege."""
        mock_ents.return_value = {"com.apple.security.app-sandbox": True}
        result = _detect_privilege_level("/app/helper", "/app")
        assert result["level"] == "standard"
        assert result["has_sandbox"] is True

    @mock.patch("cb.commands.bundle.get_entitlements")
    def test_unsandboxed_binary(self, mock_ents):
        """Non-sandboxed binary returns unsandboxed level."""
        mock_ents.return_value = {}
        result = _detect_privilege_level("/app/helper", "/app")
        assert result["level"] == "unsandboxed"
        assert result["has_sandbox"] is False


class TestCheckLaunchDaemon:
    """Test LaunchDaemon reference detection."""

    def test_finds_daemon_reference(self, tmp_path):
        """Binary referenced in LaunchDaemon plist is detected."""
        import plistlib
        daemon_dir = tmp_path / "Contents" / "Library" / "LaunchDaemons"
        daemon_dir.mkdir(parents=True)

        plist_data = {
            "Label": "com.test.helper",
            "Program": "/usr/local/bin/TestHelper",
            "ProgramArguments": ["/usr/local/bin/TestHelper"],
        }
        with open(daemon_dir / "com.test.helper.plist", "wb") as f:
            plistlib.dump(plist_data, f)

        assert _check_launch_daemon("/usr/local/bin/TestHelper", str(tmp_path)) is True

    def test_no_daemon_reference(self, tmp_path):
        """Binary not referenced returns False."""
        import plistlib
        daemon_dir = tmp_path / "Contents" / "Library" / "LaunchDaemons"
        daemon_dir.mkdir(parents=True)

        plist_data = {
            "Label": "com.test.other",
            "Program": "/usr/local/bin/OtherHelper",
        }
        with open(daemon_dir / "com.test.other.plist", "wb") as f:
            plistlib.dump(plist_data, f)

        assert _check_launch_daemon("/usr/local/bin/TestHelper", str(tmp_path)) is False


class TestBuildSecurityComparison:
    """Test security comparison table generation."""

    def test_sorted_by_risk(self):
        """Comparison table sorted by risk score (highest first)."""
        binaries = [
            {
                "relative_path": "safe_helper",
                "type": "helper",
                "signed": True,
                "dangerous_entitlements": [],
                "privilege": {"level": "standard", "runs_as_root": False,
                              "has_sandbox": True},
            },
            {
                "relative_path": "root_daemon",
                "type": "helper",
                "signed": True,
                "dangerous_entitlements": ["com.apple.security.cs.allow-jit"],
                "privilege": {"level": "root", "runs_as_root": True,
                              "has_sandbox": False, "is_setuid": False},
            },
        ]
        result = _build_security_comparison(binaries)
        assert len(result) == 2
        assert result[0]["binary"] == "root_daemon"
        assert result[0]["risk_score"] > result[1]["risk_score"]

    def test_comparison_includes_all_fields(self):
        """Each entry has expected fields."""
        binaries = [{
            "relative_path": "helper",
            "type": "helper",
            "signed": True,
            "dangerous_entitlements": [],
            "privilege": {"level": "standard", "runs_as_root": False,
                          "has_sandbox": True},
        }]
        result = _build_security_comparison(binaries)
        entry = result[0]
        assert "binary" in entry
        assert "privilege_level" in entry
        assert "runs_as_root" in entry
        assert "sandboxed" in entry
        assert "risk_score" in entry


class TestDeepFlagRegistered:
    """Test that --deep flag is registered."""

    def test_deep_flag(self):
        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()
        register(sub)
        args = parser.parse_args(["bundle", "/fake/app", "--deep"])
        assert args.deep is True
