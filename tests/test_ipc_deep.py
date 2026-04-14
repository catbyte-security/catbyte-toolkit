"""Tests for cb ipc --xpc-deep: deep XPC security audit."""
import os
from unittest import mock

import pytest

from cb.commands.ipc import analyze_xpc_deep, _extract_sm_authorized_clients, register


class TestAnalyzeXpcDeep:
    """Test analyze_xpc_deep auth gap detection."""

    def _make_strings_data(self, extra_strings=None):
        strings = extra_strings or []
        return {"categories": {"misc": strings}}

    def test_no_auth_critical_when_root(self):
        """XPC handler + no auth + runs as root → CRITICAL."""
        import_set = {"xpc_connection_set_event_handler"}
        selectors = ["listener:shouldAcceptNewConnection:"]
        bundle_info = {
            "launchd_plists": [{
                "path": "/app/Contents/Library/LaunchDaemons/com.test.plist",
                "label": "com.test.helper",
                "program": "/usr/local/bin/TestHelper",
            }]
        }
        out = mock.MagicMock()
        result = analyze_xpc_deep(
            "/usr/local/bin/TestHelper",
            import_set, selectors,
            self._make_strings_data(), bundle_info, out,
        )
        assert result["has_xpc_listener"] is True
        assert result["runs_as_root"] is True
        assert any(f["severity"] == "critical" for f in result["findings"])

    def test_with_audit_auth_clean(self):
        """XPC handler + audit_token auth → no critical findings."""
        import_set = {
            "xpc_connection_set_event_handler",
            "xpc_connection_get_audit_token",
            "SecTaskCreateWithAuditToken",
        }
        selectors = ["listener:shouldAcceptNewConnection:"]
        out = mock.MagicMock()
        result = analyze_xpc_deep(
            "/usr/local/bin/TestHelper",
            import_set, selectors,
            self._make_strings_data(), None, out,
        )
        assert "audit_token" in result["auth_methods"]
        assert not any(f["severity"] == "critical" for f in result["findings"])

    def test_pid_only_weak_auth(self):
        """PID-only auth without audit_token is flagged as weak."""
        import_set = {
            "xpc_connection_set_event_handler",
            "xpc_connection_get_pid",
        }
        selectors = []
        out = mock.MagicMock()
        result = analyze_xpc_deep(
            "/usr/local/bin/TestHelper",
            import_set, selectors,
            self._make_strings_data(), None, out,
        )
        assert result["has_pid_only_auth"] is True
        pid_findings = [f for f in result["findings"]
                        if "PID" in f.get("issue", "")]
        assert len(pid_findings) >= 1

    def test_process_requirement_clean(self):
        """ProcessRequirement (macOS 13+) is recognized as auth method."""
        import_set = {"xpc_connection_set_event_handler"}
        selectors = ["listener:shouldAcceptNewConnection:"]
        out = mock.MagicMock()
        result = analyze_xpc_deep(
            "/usr/local/bin/TestHelper",
            import_set, selectors,
            self._make_strings_data(["ProcessRequirement"]),
            None, out,
        )
        assert "ProcessRequirement" in result["auth_methods"]
        # Should not flag as critical since ProcessRequirement is present
        assert not any(f["severity"] == "critical" for f in result["findings"])

    def test_sm_authorized_clients_note(self):
        """SMAuthorizedClients presence includes restriction note."""
        import_set = set()
        selectors = []
        out = mock.MagicMock()

        # Mock _extract_sm_authorized_clients to return data
        with mock.patch("cb.commands.ipc._extract_sm_authorized_clients",
                        return_value=["identifier com.test.app"]):
            result = analyze_xpc_deep(
                "/usr/local/bin/TestHelper",
                import_set, selectors,
                self._make_strings_data(), None, out,
            )
        assert "sm_authorized_clients" in result
        assert "INSTALL" in result["sm_note"]
        assert "CONNECT" in result["sm_note"]


class TestExtractSmAuthorizedClients:
    """Test SMAuthorizedClients extraction."""

    def test_extracts_from_info_plist(self, tmp_path):
        import plistlib
        binary = tmp_path / "MacOS" / "helper"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"\x00")

        plist_path = tmp_path / "Info.plist"
        plist_data = {
            "CFBundleIdentifier": "com.test.helper",
            "SMAuthorizedClients": [
                "identifier com.test.app and certificate leaf = H\"abc123\"",
            ],
        }
        with open(plist_path, "wb") as f:
            plistlib.dump(plist_data, f)

        result = _extract_sm_authorized_clients(str(binary))
        assert len(result) == 1
        assert "com.test.app" in result[0]

    def test_empty_when_no_plist(self, tmp_path):
        binary = tmp_path / "helper"
        binary.write_bytes(b"\x00")
        result = _extract_sm_authorized_clients(str(binary))
        assert result == []


class TestRegister:
    """Test that --xpc-deep flag is registered."""

    def test_xpc_deep_flag_registered(self):
        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()
        register(sub)
        args = parser.parse_args(["ipc", "/fake/bin", "--xpc-deep"])
        assert args.xpc_deep is True
