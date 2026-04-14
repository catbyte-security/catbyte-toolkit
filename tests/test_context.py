"""Tests for context-window budget management."""
import json

import pytest

from cb.commands.context import estimate_tokens, recommend_max_results
from cb.output import OutputFormatter


class TestEstimateTokens:
    def test_basic_estimation(self):
        text = "a" * 400
        assert estimate_tokens(text) == 100

    def test_empty_string(self):
        assert estimate_tokens("") == 0

    def test_json_estimation(self):
        data = {"key": "value", "list": [1, 2, 3]}
        text = json.dumps(data)
        tokens = estimate_tokens(text)
        assert tokens > 0
        assert tokens == len(text) // 4


class TestRecommendMaxResults:
    def test_within_budget(self):
        assert recommend_max_results(100, 200) == 50

    def test_over_budget(self):
        result = recommend_max_results(200, 100)
        assert result < 50
        assert result >= 1

    def test_zero_budget(self):
        assert recommend_max_results(100, 0) == 50

    def test_zero_tokens(self):
        assert recommend_max_results(0, 100) == 50


class TestBudgetTruncation:
    def test_budget_zero_unlimited(self):
        fmt = OutputFormatter(max_results=50, budget=0)
        data = {"items": list(range(100)), "_meta": {}}
        result = fmt._truncate(data)
        assert len(result["items"]) == 50
        assert "budget_adjusted" not in result["_meta"]

    def test_budget_truncation(self):
        fmt = OutputFormatter(max_results=50, budget=10)
        data = {"items": list(range(100)), "_meta": {}}
        result = fmt._truncate(data)
        assert len(result["items"]) < 50
        assert result["_meta"].get("budget_adjusted") is True
