"""Tests for vulnerability pattern matching."""
import re
import pytest

from cb.commands.vuln import DECOMPILED_PATTERNS
from cb.patterns.dangerous_functions import DANGEROUS_IMPORTS


class TestDecompiledPatterns:
    """Test that regex patterns match known-good and reject known-bad."""

    def test_format_string_variable(self):
        pat = DECOMPILED_PATTERNS["format_string_variable"]["pattern"]
        assert re.search(pat, 'printf(user_input)')
        assert re.search(pat, 'fprintf(stderr, buf)')
        assert not re.search(pat, 'printf("hello %s", name)')

    def test_unbounded_copy(self):
        pat = DECOMPILED_PATTERNS["unbounded_copy"]["pattern"]
        assert re.search(pat, 'strcpy(dst, src)')
        assert re.search(pat, 'gets(buffer)')
        assert not re.search(pat, 'strncpy(dst, src, n)')

    def test_malloc_multiplication(self):
        pat = DECOMPILED_PATTERNS["malloc_multiplication"]["pattern"]
        assert re.search(pat, 'malloc(width * height)')
        assert re.search(pat, 'malloc(n * sizeof(int))')
        assert not re.search(pat, 'malloc(256)')

    def test_system_call_concat(self):
        pat = DECOMPILED_PATTERNS["system_call"]["pattern"]
        assert re.search(pat, 'system(cmd + " -flag")')
        assert not re.search(pat, 'system("/bin/ls")')

    def test_signed_comparison(self):
        pat = DECOMPILED_PATTERNS["signed_comparison"]["pattern"]
        assert re.search(pat, 'if ((int)len < 0)')
        assert re.search(pat, 'if ((int)size >= 0)')

    def test_unchecked_return(self):
        pat = DECOMPILED_PATTERNS["unchecked_return"]["pattern"]
        assert re.search(pat, 'malloc(256);')
        assert re.search(pat, 'open("/tmp/x", O_RDONLY);')
        # Assignment captures the return value
        assert not re.search(pat, 'ptr = malloc(256);')


class TestDangerousImports:
    def test_structure(self):
        assert "high" in DANGEROUS_IMPORTS
        assert "medium" in DANGEROUS_IMPORTS
        for severity, categories in DANGEROUS_IMPORTS.items():
            assert isinstance(categories, dict)
            for category, funcs in categories.items():
                assert isinstance(funcs, (list, set, tuple))

    def test_known_dangerous(self):
        all_funcs = set()
        for categories in DANGEROUS_IMPORTS.values():
            for funcs in categories.values():
                all_funcs.update(funcs)
        assert "strcpy" in all_funcs
        assert "system" in all_funcs
        assert "gets" in all_funcs
