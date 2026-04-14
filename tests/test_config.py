"""Tests for config loading."""
import os
import json
import tempfile
import pytest

from cb.config import load_config, get_ghidra_home


class TestConfig:
    def test_load_config_missing(self):
        # Should return defaults, not crash
        cfg = load_config()
        assert isinstance(cfg, dict)

    def test_ghidra_home_returns_string_or_none(self):
        result = get_ghidra_home()
        assert result is None or isinstance(result, str)
