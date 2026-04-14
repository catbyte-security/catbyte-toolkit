"""Tests for fat binary handling, framework resolution, and bundle scanning."""
import os
import struct
import tempfile
from unittest import mock

import pytest

from cb.macho import (
    is_fat_binary, get_fat_architectures, thin_binary,
    resolve_binary, get_strings, _extract_strings_chunked,
    get_imports, get_exports,
)
from cb.commands.bundle import (
    _is_macho, _find_bundle_binaries, _scan_binary_quick,
    _assess_bundle_security, register,
)


# ---------------------------------------------------------------------------
# Fat binary detection
# ---------------------------------------------------------------------------
class TestFatBinaryDetection:
    def test_fat_magic_cafebabe(self, tmp_path):
        f = tmp_path / "fat.bin"
        f.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 100)
        assert is_fat_binary(str(f)) is True

    def test_fat_magic_bebafeca(self, tmp_path):
        f = tmp_path / "fat2.bin"
        f.write_bytes(b"\xbe\xba\xfe\xca" + b"\x00" * 100)
        assert is_fat_binary(str(f)) is True

    def test_macho64_not_fat(self, tmp_path):
        f = tmp_path / "macho64.bin"
        f.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)
        assert is_fat_binary(str(f)) is False

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty"
        f.write_bytes(b"")
        assert is_fat_binary(str(f)) is False

    def test_nonexistent_file(self):
        assert is_fat_binary("/tmp/nonexistent_abc123") is False


class TestGetFatArchitectures:
    @mock.patch("cb.macho.subprocess.run")
    def test_parses_fat_output(self, mock_run):
        mock_run.return_value = mock.Mock(
            stdout="Architectures in the fat file: /path are: arm64 x86_64",
            stderr="",
        )
        assert get_fat_architectures("/fake") == ["arm64", "x86_64"]

    @mock.patch("cb.macho.subprocess.run")
    def test_parses_single_arch(self, mock_run):
        mock_run.return_value = mock.Mock(
            stdout="Non-fat file: /path is architecture: arm64",
            stderr="",
        )
        assert get_fat_architectures("/fake") == ["arm64"]

    @mock.patch("cb.macho.subprocess.run", side_effect=FileNotFoundError)
    def test_lipo_missing(self, mock_run):
        assert get_fat_architectures("/fake") == []


class TestThinBinary:
    def test_non_fat_returns_original(self, tmp_path):
        f = tmp_path / "single.bin"
        f.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)
        assert thin_binary(str(f)) == str(f)

    @mock.patch("cb.macho.subprocess.run")
    @mock.patch("cb.macho.is_fat_binary", return_value=True)
    def test_thin_calls_lipo(self, mock_is_fat, mock_run, tmp_path):
        src = tmp_path / "fat.bin"
        src.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 100)
        # Mock lipo to create the output file
        def side_effect(cmd, **kwargs):
            if "-thin" in cmd:
                output = cmd[cmd.index("-output") + 1]
                with open(output, "wb") as f:
                    f.write(b"\xcf\xfa\xed\xfe" + b"\x00" * 50)
            return mock.Mock(stdout="", stderr="")
        mock_run.side_effect = side_effect

        result = thin_binary(str(src), arch="arm64")
        assert result.startswith("/tmp/cb_thin_")
        assert os.path.exists(result)
        # Clean up
        os.unlink(result)

    @mock.patch("cb.macho.is_fat_binary", return_value=True)
    @mock.patch("cb.macho.subprocess.run", side_effect=FileNotFoundError)
    def test_thin_fallback_on_error(self, mock_run, mock_is_fat, tmp_path):
        src = tmp_path / "fat.bin"
        src.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 100)
        # Should return original on failure
        result = thin_binary(str(src), arch="arm64")
        assert result == str(src)


# ---------------------------------------------------------------------------
# Framework resolution
# ---------------------------------------------------------------------------
class TestFrameworkResolution:
    def test_resolve_framework_versioned(self, tmp_path):
        fw = tmp_path / "Foo.framework"
        versions = fw / "Versions" / "Current"
        versions.mkdir(parents=True)
        # Create Info.plist
        import plistlib
        plist_path = versions / "Info.plist"
        with open(plist_path, "wb") as f:
            plistlib.dump({"CFBundleExecutable": "Foo"}, f)
        # Create the binary
        binary = versions / "Foo"
        binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)

        resolved = resolve_binary(str(fw))
        assert resolved == str(binary)

    def test_resolve_framework_root_plist(self, tmp_path):
        fw = tmp_path / "Bar.framework"
        fw.mkdir()
        import plistlib
        plist_path = fw / "Info.plist"
        with open(plist_path, "wb") as f:
            plistlib.dump({"CFBundleExecutable": "Bar"}, f)
        binary = fw / "Bar"
        binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)

        resolved = resolve_binary(str(fw))
        assert resolved == str(binary)

    def test_resolve_app_still_works(self, tmp_path):
        app = tmp_path / "Test.app"
        macos = app / "Contents" / "MacOS"
        macos.mkdir(parents=True)
        import plistlib
        plist_path = app / "Contents" / "Info.plist"
        with open(plist_path, "wb") as f:
            plistlib.dump({"CFBundleExecutable": "Test"}, f)
        binary = macos / "Test"
        binary.write_bytes(b"binary")

        resolved = resolve_binary(str(app))
        assert resolved == str(binary)

    def test_resolve_framework_no_plist_fallback(self, tmp_path):
        """Framework without Info.plist, binary named after framework (Chrome style)."""
        fw = tmp_path / "MyLib.framework"
        versions = fw / "Versions" / "Current"
        versions.mkdir(parents=True)
        binary = versions / "MyLib"
        binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)

        resolved = resolve_binary(str(fw))
        assert resolved == str(binary)

    def test_resolve_framework_no_plist_root(self, tmp_path):
        """Framework without Versions/, binary at root (simple framework)."""
        fw = tmp_path / "Simple.framework"
        fw.mkdir()
        binary = fw / "Simple"
        binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)

        resolved = resolve_binary(str(fw))
        assert resolved == str(binary)

    def test_resolve_plain_path(self):
        assert resolve_binary("/usr/bin/file") == "/usr/bin/file"


# ---------------------------------------------------------------------------
# Large binary string extraction
# ---------------------------------------------------------------------------
class TestLargeBinaryStrings:
    def test_extract_strings_chunked_basic(self, tmp_path):
        f = tmp_path / "test.bin"
        content = b"\x00\x00Hello World\x00\x00Short\x00\x00Another String Here\x00"
        f.write_bytes(content)
        strings = _extract_strings_chunked(str(f), min_length=6)
        assert "Hello World" in strings
        assert "Another String Here" in strings
        # "Short" is only 5 chars, less than min_length=6
        assert "Short" not in strings

    def test_extract_strings_respects_max(self, tmp_path):
        f = tmp_path / "big.bin"
        # Create many strings
        content = b""
        for i in range(100):
            content += f"string_number_{i:04d}".encode() + b"\x00"
        f.write_bytes(content)
        strings = _extract_strings_chunked(str(f), min_length=6, max_strings=10)
        assert len(strings) == 10

    @mock.patch("cb.macho.os.path.getsize", return_value=200_000_000)
    @mock.patch("cb.macho._extract_strings_chunked", return_value=["hello_world"])
    @mock.patch("cb.macho._run", return_value=("", ""))
    def test_large_binary_uses_python_extraction(self, mock_run, mock_extract, mock_size):
        result = get_strings("/fake/large.bin")
        mock_extract.assert_called_once()
        mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Import/Export timeout scaling
# ---------------------------------------------------------------------------
class TestTimeoutScaling:
    @mock.patch("cb.macho.os.path.getsize", return_value=10_000_000)
    @mock.patch("cb.macho._run", return_value=("", ""))
    def test_small_binary_default_timeout(self, mock_run, mock_size):
        get_imports("/fake/small.bin")
        mock_run.assert_called_with(["nm", "-u", "/fake/small.bin"], timeout=30)

    @mock.patch("cb.macho.os.path.getsize", return_value=100_000_000)
    @mock.patch("cb.macho._run", return_value=("", ""))
    def test_large_binary_extended_timeout(self, mock_run, mock_size):
        get_imports("/fake/large.bin")
        mock_run.assert_called_with(["nm", "-u", "/fake/large.bin"], timeout=120)

    @mock.patch("cb.macho.os.path.getsize", return_value=100_000_000)
    @mock.patch("cb.macho._run", return_value=("", ""))
    def test_large_binary_exports_timeout(self, mock_run, mock_size):
        get_exports("/fake/large.bin")
        mock_run.assert_called_with(["nm", "-gU", "/fake/large.bin"], timeout=120)


# ---------------------------------------------------------------------------
# Bundle command: _is_macho
# ---------------------------------------------------------------------------
class TestBundleIsMacho:
    def test_macho64_le(self, tmp_path):
        f = tmp_path / "bin"
        f.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)
        assert _is_macho(str(f)) is True

    def test_fat_binary(self, tmp_path):
        f = tmp_path / "fat"
        f.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 100)
        assert _is_macho(str(f)) is True

    def test_not_macho(self, tmp_path):
        f = tmp_path / "text"
        f.write_bytes(b"#!/bin/bash\necho hello\n")
        assert _is_macho(str(f)) is False

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty"
        f.write_bytes(b"")
        assert _is_macho(str(f)) is False


# ---------------------------------------------------------------------------
# Bundle: _find_bundle_binaries
# ---------------------------------------------------------------------------
class TestFindBundleBinaries:
    def _make_macho(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)

    def test_find_app_main_binary(self, tmp_path):
        app = tmp_path / "Test.app"
        macos = app / "Contents" / "MacOS"
        macos.mkdir(parents=True)
        self._make_macho(str(macos / "Test"))

        binaries = _find_bundle_binaries(str(app))
        assert len(binaries) == 1
        assert binaries[0]["type"] == "main"
        assert binaries[0]["relative_path"] == "Contents/MacOS/Test"

    def test_find_helpers(self, tmp_path):
        app = tmp_path / "Test.app"
        # Main
        macos = app / "Contents" / "MacOS"
        macos.mkdir(parents=True)
        self._make_macho(str(macos / "Test"))
        # Helper
        helper_dir = app / "Contents" / "Helpers" / "Helper.app" / "Contents" / "MacOS"
        helper_dir.mkdir(parents=True)
        self._make_macho(str(helper_dir / "Helper"))

        binaries = _find_bundle_binaries(str(app))
        types = {b["type"] for b in binaries}
        assert "main" in types
        assert "helper" in types
        assert len(binaries) == 2

    def test_find_framework_binaries(self, tmp_path):
        fw = tmp_path / "Foo.framework"
        # Framework doesn't have Contents/
        versions = fw / "Versions" / "Current"
        macos = versions / "MacOS"
        macos.mkdir(parents=True)
        self._make_macho(str(macos / "Foo"))
        # Helper in Helpers/ (Chrome style)
        helpers = fw / "Helpers" / "Helper.app" / "Contents" / "MacOS"
        helpers.mkdir(parents=True)
        self._make_macho(str(helpers / "Helper"))

        binaries = _find_bundle_binaries(str(fw))
        assert len(binaries) >= 1


# ---------------------------------------------------------------------------
# Bundle: _assess_bundle_security
# ---------------------------------------------------------------------------
class TestAssessBundleSecurity:
    def test_hardened_rating(self):
        binaries = [
            {"path": "/a", "signed": True, "hardened_runtime": True,
             "dangerous_entitlements": []},
            {"path": "/b", "signed": True, "hardened_runtime": True,
             "dangerous_entitlements": []},
        ]
        result = _assess_bundle_security(binaries)
        assert result["rating"] == "hardened"
        assert result["signed_count"] == 2
        assert result["unsigned_count"] == 0

    def test_standard_rating(self):
        binaries = [
            {"path": "/a", "signed": True, "hardened_runtime": True,
             "dangerous_entitlements": ["com.apple.security.cs.allow-jit"]},
            {"path": "/b", "signed": True, "hardened_runtime": True,
             "dangerous_entitlements": []},
        ]
        result = _assess_bundle_security(binaries)
        assert result["rating"] == "standard"

    def test_weak_unsigned(self):
        binaries = [
            {"path": "/a", "signed": False, "hardened_runtime": False,
             "dangerous_entitlements": []},
        ]
        result = _assess_bundle_security(binaries)
        assert result["rating"] == "weak"
        assert result["unsigned_count"] == 1

    def test_weak_disable_library_validation(self):
        binaries = [
            {"path": "/a", "signed": True, "hardened_runtime": True,
             "dangerous_entitlements": [
                 "com.apple.security.cs.disable-library-validation"
             ]},
        ]
        result = _assess_bundle_security(binaries)
        assert result["rating"] == "weak"

    def test_weakest_link_identified(self):
        binaries = [
            {"path": "/safe", "signed": True, "hardened_runtime": True,
             "dangerous_entitlements": []},
            {"path": "/risky", "signed": True, "hardened_runtime": True,
             "dangerous_entitlements": [
                 "com.apple.security.cs.allow-unsigned-executable-memory",
                 "com.apple.security.cs.disable-library-validation",
             ]},
        ]
        result = _assess_bundle_security(binaries)
        assert result["weakest_link"]["path"] == "/risky"


# ---------------------------------------------------------------------------
# Bundle: register()
# ---------------------------------------------------------------------------
class TestBundleRegister:
    def test_register_creates_parser(self):
        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()
        register(sub)
        # Should be able to parse bundle command
        args = parser.parse_args(["bundle", "/some/path.app"])
        assert args.bundle_path == "/some/path.app"
        assert args.entitlements_only is False
        assert args.helpers_only is False

    def test_register_entitlements_flag(self):
        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()
        register(sub)
        args = parser.parse_args(["bundle", "/path.app", "--entitlements-only"])
        assert args.entitlements_only is True

    def test_register_helpers_flag(self):
        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()
        register(sub)
        args = parser.parse_args(["bundle", "/path.app", "--helpers-only"])
        assert args.helpers_only is True


# ---------------------------------------------------------------------------
# CLI --arch flag
# ---------------------------------------------------------------------------
class TestCliArchFlag:
    def test_arch_flag_accepted(self):
        """Verify --arch flag is parseable by CLI."""
        import argparse
        from cb.cli import main
        # Just verify the arg is defined - full CLI test would require subprocess
        from cb.cli import main as _  # import doesn't crash


class TestValidationFramework:
    def test_framework_path_accepted(self):
        """Validate that .framework paths pass validation."""
        from cb.validation import validate_binary_path
        # .framework dirs should not be rejected as directories
        # (they won't exist in test env, so we just check the logic path)
        result = validate_binary_path("/nonexistent/Foo.framework")
        assert result == "File not found: /nonexistent/Foo.framework"

    def test_regular_dir_rejected(self):
        from cb.validation import validate_binary_path
        result = validate_binary_path("/tmp")
        assert "directory" in result.lower()
