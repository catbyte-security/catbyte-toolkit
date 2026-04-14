"""Tests for cb ipc --mojo: Mojo interface extraction."""
from unittest import mock

import pytest

from cb.commands.ipc import analyze_mojo_interfaces, MOJO_NAMESPACE_PROCESS, register


class TestAnalyzeMojoInterfaces:
    """Test Mojo interface extraction and classification."""

    def _make_strings_data(self, strings):
        return {"categories": {"misc": strings}}

    def test_extracts_mojom_interfaces(self):
        """Mojo interface names are extracted from binary strings."""
        strings = [
            "blink.mojom.Authenticator",
            "network.mojom.URLLoaderFactory",
            "some random string",
            "blink.mojom.BlobRegistry",
        ]
        out = mock.MagicMock()
        result = analyze_mojo_interfaces("/fake", self._make_strings_data(strings), out)
        assert result["total"] == 3
        iface_names = {i["interface"] for i in result["interfaces"]}
        assert "blink.mojom.Authenticator" in iface_names
        assert "network.mojom.URLLoaderFactory" in iface_names
        assert "blink.mojom.BlobRegistry" in iface_names

    def test_namespace_mapping(self):
        """Interfaces are classified by namespace → process type."""
        strings = [
            "blink.mojom.Frame",
            "network.mojom.TCPSocket",
            "viz.mojom.Compositor",
        ]
        out = mock.MagicMock()
        result = analyze_mojo_interfaces("/fake", self._make_strings_data(strings), out)

        by_type = result["by_process_type"]
        assert by_type.get("renderer", 0) >= 1
        assert by_type.get("network", 0) >= 1
        assert by_type.get("gpu", 0) >= 1

    def test_no_mojom_clean(self):
        """Binary without Mojo interfaces returns empty result."""
        strings = ["hello world", "com.apple.test", "some/path/here"]
        out = mock.MagicMock()
        result = analyze_mojo_interfaces("/fake", self._make_strings_data(strings), out)
        assert result["total"] == 0
        assert result["interfaces"] == []
        assert result["by_process_type"] == {}

    def test_deduplication(self):
        """Duplicate interface names are deduplicated."""
        strings = [
            "blink.mojom.Widget",
            "blink.mojom.Widget",
            "blink.mojom.Widget",
        ]
        out = mock.MagicMock()
        result = analyze_mojo_interfaces("/fake", self._make_strings_data(strings), out)
        assert result["total"] == 1

    def test_renderer_accessible_count(self):
        """renderer_accessible count is reported."""
        strings = [
            "blink.mojom.A",
            "blink.mojom.B",
            "network.mojom.C",
        ]
        out = mock.MagicMock()
        result = analyze_mojo_interfaces("/fake", self._make_strings_data(strings), out)
        assert result["renderer_accessible"] == 2


class TestMojoRegister:
    """Test that --mojo flag is registered."""

    def test_mojo_flag_registered(self):
        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()
        register(sub)
        args = parser.parse_args(["ipc", "/fake/bin", "--mojo"])
        assert args.mojo is True
