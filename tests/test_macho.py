"""Tests for Mach-O parser and format detection."""
import os
import pytest

from cb.macho import detect_format, get_file_info, resolve_binary, is_dyld_shared_cache


class TestDetectFormat:
    def test_macho_binary(self):
        # /usr/bin/file is always present on macOS
        fmt = detect_format("/usr/bin/file")
        assert fmt in ("macho64", "macho64_le", "fat", "macho32")

    def test_nonexistent(self):
        with pytest.raises(FileNotFoundError):
            detect_format("/nonexistent/binary")


class TestGetFileInfo:
    def test_basic_info(self):
        info = get_file_info("/usr/bin/file")
        assert info["path"] == "/usr/bin/file"
        assert info["size_bytes"] > 0
        assert info["format"] in ("macho64", "macho64_le", "fat")
        assert "size_human" in info


class TestResolve:
    def test_resolve_app_bundle(self):
        text_edit = "/System/Applications/TextEdit.app"
        if os.path.exists(text_edit):
            resolved = resolve_binary(text_edit)
            assert resolved.endswith("/TextEdit")
            assert "MacOS" in resolved

    def test_resolve_plain_binary(self):
        assert resolve_binary("/usr/bin/file") == "/usr/bin/file"


class TestDyldCache:
    def test_detect_cache(self):
        assert is_dyld_shared_cache("dyld_shared_cache_arm64e") is True
        assert is_dyld_shared_cache("dyld_shared_cache_x86_64h") is True
        assert is_dyld_shared_cache("/usr/bin/file") is False
