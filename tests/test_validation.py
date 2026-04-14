"""Tests for input validation module."""
import os
import pytest

from cb.validation import validate_binary_path, validate_regex, validate_piped_input


class TestValidateBinaryPath:
    def test_valid_file(self):
        assert validate_binary_path("/usr/bin/file") is None

    def test_nonexistent_file(self):
        err = validate_binary_path("/nonexistent/path/binary")
        assert err is not None
        assert "not found" in err.lower()

    def test_directory_rejected(self, tmp_path):
        err = validate_binary_path(str(tmp_path))
        assert err is not None
        assert "directory" in err.lower()

    def test_app_bundle_allowed(self, tmp_path):
        app_dir = tmp_path / "Test.app"
        app_dir.mkdir()
        # .app directories should not be rejected as bare directories
        err = validate_binary_path(str(app_dir))
        assert err is None

    def test_unreadable_file(self, tmp_path):
        f = tmp_path / "noperm"
        f.write_text("data")
        f.chmod(0o000)
        err = validate_binary_path(str(f))
        assert err is not None
        assert "not readable" in err.lower()
        # Restore permissions for cleanup
        f.chmod(0o644)


class TestValidateRegex:
    def test_valid_regex(self):
        assert validate_regex(r"foo.*bar") is None

    def test_invalid_regex(self):
        err = validate_regex("[bad")
        assert err is not None
        assert "invalid regex" in err.lower()

    def test_empty_regex(self):
        assert validate_regex("") is None

    def test_complex_valid_regex(self):
        assert validate_regex(r"^NS[A-Z]\w+Handler$") is None


class TestValidatePipedInput:
    def test_valid_dict(self):
        assert validate_piped_input({"key": "value"}) is None

    def test_list_rejected(self):
        err = validate_piped_input([1, 2, 3])
        assert err is not None
        assert "dict" in err.lower() or "object" in err.lower()

    def test_string_rejected(self):
        err = validate_piped_input("not a dict")
        assert err is not None

    def test_none_rejected(self):
        err = validate_piped_input(None)
        assert err is not None
