"""Tests for cb models: ML model file permission and integrity audit."""
import os
from unittest import mock

import pytest

from cb.commands.models import (
    _find_model_files, _analyze_model,
    MODEL_EXTENSIONS, SENSITIVE_MODEL_INDICATORS, register,
)


class TestFindModelFiles:
    """Test model file discovery."""

    def test_finds_tflite_files(self, tmp_path):
        """Discovers .tflite files recursively."""
        (tmp_path / "model.tflite").write_bytes(b"\x00" * 100)
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "deep.tflite").write_bytes(b"\x00" * 50)
        (tmp_path / "not_a_model.txt").write_text("hello")

        result = _find_model_files(str(tmp_path))
        assert len(result) == 2
        assert all(f.endswith(".tflite") for f in result)

    def test_finds_multiple_extensions(self, tmp_path):
        """Finds models with various extensions."""
        for ext in [".tflite", ".onnx", ".mlmodel", ".safetensors"]:
            (tmp_path / f"model{ext}").write_bytes(b"\x00" * 10)

        result = _find_model_files(str(tmp_path))
        assert len(result) == 4

    def test_empty_dir(self, tmp_path):
        """Empty directory returns no results."""
        result = _find_model_files(str(tmp_path))
        assert result == []


class TestAnalyzeModel:
    """Test individual model file analysis."""

    def test_writable_detection(self, tmp_path):
        """User-writable file is flagged."""
        model = tmp_path / "model.tflite"
        model.write_bytes(b"\x00" * 100)
        os.chmod(str(model), 0o666)

        result = _analyze_model(str(model))
        assert result["user_writable"] is True
        assert result["format"] == "TensorFlow Lite"

    def test_readonly_clean(self, tmp_path):
        """Read-only file is not flagged as writable."""
        model = tmp_path / "model.tflite"
        model.write_bytes(b"\x00" * 100)
        os.chmod(str(model), 0o444)

        result = _analyze_model(str(model))
        assert result["user_writable"] is False

    def test_sensitive_purpose_escalation(self, tmp_path):
        """Model in security-sensitive directory gets purpose info."""
        safe_browsing_dir = tmp_path / "safe_browsing"
        safe_browsing_dir.mkdir()
        model = safe_browsing_dir / "model.tflite"
        model.write_bytes(b"\x00" * 100)

        result = _analyze_model(str(model))
        assert result["purpose_info"] is not None
        assert result["purpose_info"]["risk"] == "high"

    def test_hash_computation(self, tmp_path):
        """SHA256 hash is computed when requested."""
        model = tmp_path / "model.tflite"
        model.write_bytes(b"\x00" * 100)

        result = _analyze_model(str(model), check_hash=True)
        assert "sha256" in result
        assert len(result["sha256"]) == 64  # SHA256 hex digest length


class TestRegisterCommand:
    """Test command registration."""

    def test_models_command_registered(self):
        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()
        register(sub)
        args = parser.parse_args(["models", "/fake/path"])
        assert hasattr(args, "func")

    def test_check_hashes_flag(self):
        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()
        register(sub)
        args = parser.parse_args(["models", "/fake/path", "--check-hashes"])
        assert args.check_hashes is True

    def test_writable_only_flag(self):
        import argparse
        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers()
        register(sub)
        args = parser.parse_args(["models", "/fake/path", "--writable-only"])
        assert args.writable_only is True
