"""Tests for result caching."""
import json
import os
import time

import pytest

from cb.result_cache import ResultCache


@pytest.fixture
def cache_dir(tmp_path):
    return str(tmp_path / "cache")


@pytest.fixture
def cache(cache_dir):
    return ResultCache(cache_dir=cache_dir)


@pytest.fixture
def sample_binary(tmp_path):
    """Create a temporary binary file for testing."""
    binary = tmp_path / "test_binary"
    binary.write_bytes(b"\xcf\xfa\xed\xfe" + b"\x00" * 100)
    return str(binary)


class TestResultCache:
    def test_put_and_get(self, cache, sample_binary):
        data = {"findings": ["vuln1"], "count": 1}
        cache.put(sample_binary, "triage", {"checksec": True}, data)
        result = cache.get(sample_binary, "triage", {"checksec": True})
        assert result is not None
        assert result["findings"] == ["vuln1"]
        assert result["count"] == 1

    def test_cache_miss(self, cache, sample_binary):
        result = cache.get(sample_binary, "triage", {"checksec": True})
        assert result is None

    def test_mtime_invalidation(self, cache, sample_binary):
        data = {"findings": []}
        cache.put(sample_binary, "triage", {}, data)

        # Modify file (changes mtime and content)
        time.sleep(0.05)
        with open(sample_binary, "ab") as f:
            f.write(b"\xff" * 10)

        result = cache.get(sample_binary, "triage", {})
        assert result is None

    def test_size_invalidation(self, cache, sample_binary, tmp_path):
        data = {"findings": []}
        cache.put(sample_binary, "triage", {}, data)

        # Rewrite with different size but try to preserve mtime
        original_stat = os.stat(sample_binary)
        with open(sample_binary, "wb") as f:
            f.write(b"\xcf\xfa\xed\xfe" + b"\x00" * 50)
        # Force mtime to match (size still differs)
        os.utime(sample_binary, (original_stat.st_atime, original_stat.st_mtime))

        result = cache.get(sample_binary, "triage", {})
        assert result is None

    def test_different_args(self, cache, sample_binary):
        data1 = {"mode": "checksec"}
        data2 = {"mode": "full"}
        cache.put(sample_binary, "triage", {"checksec": True}, data1)
        cache.put(sample_binary, "triage", {"checksec": False}, data2)

        r1 = cache.get(sample_binary, "triage", {"checksec": True})
        r2 = cache.get(sample_binary, "triage", {"checksec": False})
        assert r1["mode"] == "checksec"
        assert r2["mode"] == "full"

    def test_clear_specific(self, cache, sample_binary, tmp_path):
        other = tmp_path / "other_binary"
        other.write_bytes(b"\x7fELF" + b"\x00" * 100)
        other = str(other)

        cache.put(sample_binary, "triage", {}, {"a": 1})
        cache.put(other, "triage", {}, {"b": 2})

        count = cache.clear(binary_path=sample_binary)
        assert count >= 1
        assert cache.get(sample_binary, "triage", {}) is None
        assert cache.get(other, "triage", {}) is not None

    def test_clear_all(self, cache, sample_binary):
        cache.put(sample_binary, "triage", {}, {"a": 1})
        cache.put(sample_binary, "attack", {}, {"b": 2})

        count = cache.clear()
        assert count >= 2
        assert cache.get(sample_binary, "triage", {}) is None
        assert cache.get(sample_binary, "attack", {}) is None

    def test_stats(self, cache, sample_binary):
        cache.put(sample_binary, "triage", {}, {"a": 1})
        cache.put(sample_binary, "attack", {}, {"b": 2})

        stats = cache.stats()
        assert stats["total_entries"] == 2
        assert stats["total_bytes"] > 0
