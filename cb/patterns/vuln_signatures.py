"""Vulnerability pattern signatures for decompiled code scanning."""

# These patterns are applied to Ghidra's decompiled C output.
# Each pattern is a dict with: regex, severity, category, description.

DECOMPILED_VULN_PATTERNS = {
    # Buffer overflow patterns
    "strcpy_usage": {
        "pattern": r"\bstrcpy\s*\(",
        "severity": "high",
        "category": "overflow",
        "description": "Unbounded string copy (strcpy)",
    },
    "sprintf_usage": {
        "pattern": r"\bsprintf\s*\(",
        "severity": "high",
        "category": "overflow",
        "description": "Unbounded formatted string (sprintf)",
    },
    "gets_usage": {
        "pattern": r"\bgets\s*\(",
        "severity": "high",
        "category": "overflow",
        "description": "Unbounded input read (gets)",
    },
    "memcpy_variable_size": {
        "pattern": r"\bmemcpy\s*\([^,]+,\s*[^,]+,\s*[a-zA-Z_]\w*\s*\)",
        "severity": "medium",
        "category": "overflow",
        "description": "memcpy with variable size (check bounds)",
    },
    "stack_buffer_overflow": {
        "pattern": r"char\s+\w+\s*\[\s*\d+\s*\].*?(strcpy|strcat|sprintf|memcpy)",
        "severity": "high",
        "category": "overflow",
        "description": "Stack buffer with unsafe copy operation",
        "multiline": True,
    },

    # Format string patterns
    "printf_variable_fmt": {
        "pattern": r"\b(printf|fprintf|syslog)\s*\(\s*[a-zA-Z_]\w*\s*\)",
        "severity": "high",
        "category": "format",
        "description": "Format function with variable format string",
    },
    "nslog_variable_fmt": {
        "pattern": r"\bNSLog\s*\(\s*[a-zA-Z_]\w*\s*\)",
        "severity": "high",
        "category": "format",
        "description": "NSLog with variable format string",
    },
    "percent_n_in_format": {
        "pattern": r'"%[^"]*%n',
        "severity": "high",
        "category": "format",
        "description": "Format string with %n (arbitrary write)",
    },

    # Integer overflow patterns
    "malloc_multiply": {
        "pattern": r"\bmalloc\s*\([^)]*\*[^)]*\)",
        "severity": "medium",
        "category": "integer",
        "description": "Multiplication in malloc size (integer overflow risk)",
    },
    "calloc_overflow": {
        "pattern": r"\bcalloc\s*\([^,]*[a-zA-Z_]\w*\s*,\s*[a-zA-Z_]\w*\s*\)",
        "severity": "low",
        "category": "integer",
        "description": "calloc with variable arguments (check overflow)",
    },
    "int_to_size_cast": {
        "pattern": r"\(\s*size_t\s*\)\s*\(\s*int\s*\)",
        "severity": "medium",
        "category": "integer",
        "description": "Cast from int to size_t (sign extension issue)",
    },
    "signed_size_check": {
        "pattern": r"if\s*\(\s*\(int\)\s*\w+\s*[<>]",
        "severity": "medium",
        "category": "integer",
        "description": "Signed comparison for size check",
    },

    # Use-after-free patterns
    "use_after_free": {
        "pattern": r"\bfree\s*\(\s*(\w+)\s*\)(?:(?!\1\s*=)[\s\S]){1,200}\b\1\b",
        "severity": "high",
        "category": "uaf",
        "description": "Variable used after free without reassignment",
        "multiline": True,
    },
    "double_free": {
        "pattern": r"\bfree\s*\(\s*(\w+)\s*\)(?:(?!\1\s*=)[\s\S]){1,500}\bfree\s*\(\s*\1\s*\)",
        "severity": "high",
        "category": "uaf",
        "description": "Double free of same variable",
        "multiline": True,
    },

    # Race condition patterns
    "toctou_access_open": {
        "pattern": r"\b(access|stat|lstat)\s*\([^)]+\)[\s\S]{1,300}\b(open|fopen)\s*\(",
        "severity": "medium",
        "category": "race",
        "description": "TOCTOU: check-then-use file access pattern",
        "multiline": True,
    },
    "tmpnam_usage": {
        "pattern": r"\b(tmpnam|mktemp|tempnam)\s*\(",
        "severity": "medium",
        "category": "race",
        "description": "Unsafe temporary file creation (race condition)",
    },

    # Command injection
    "system_concatenation": {
        "pattern": r"\bsystem\s*\([^)]*\+",
        "severity": "high",
        "category": "injection",
        "description": "system() with string concatenation (command injection)",
    },
    "popen_variable": {
        "pattern": r"\bpopen\s*\(\s*[a-zA-Z_]\w*\s*,",
        "severity": "high",
        "category": "injection",
        "description": "popen() with variable command string",
    },

    # Dangerous deserialization
    "nskeyedunarchiver": {
        "pattern": r"\bNSKeyedUnarchiver\b.*\bunarchive",
        "severity": "medium",
        "category": "type",
        "description": "NSKeyedUnarchiver deserialization (type confusion risk)",
        "multiline": True,
    },

    # Chrome/Chromium/V8 patterns
    "mojo_unvalidated_size": {
        "pattern": r"\bmemcpy\s*\([^,]+,\s*[^,]+,\s*\w+\.size\(\)\s*\)",
        "severity": "high",
        "category": "overflow",
        "description": "memcpy using Mojo message size without validation",
    },
    "chrome_check_on_ipc": {
        "pattern": r"\b(CHECK|DCHECK)\s*\(\s*\w+\s*[<>=!]+\s*\w+\s*\)",
        "severity": "medium",
        "category": "logic",
        "description": "CHECK/DCHECK on potentially IPC-derived value (crashes browser, use ReportBadMessage)",
    },
    "unretained_cross_thread": {
        "pattern": r"base::Unretained\s*\(\s*(this|\w+)\s*\)[\s\S]{0,200}PostTask",
        "severity": "high",
        "category": "uaf",
        "description": "base::Unretained pointer captured across thread boundary (dangling pointer risk)",
        "multiline": True,
    },
    "bigbuffer_no_copy": {
        "pattern": r"BigBuffer\b[\s\S]{0,300}\b(if|switch|while)\b[\s\S]{0,200}BigBuffer",
        "severity": "high",
        "category": "race",
        "description": "BigBuffer data read multiple times without local copy (shared memory TOCTOU)",
        "multiline": True,
    },
    "v8_unchecked_cast": {
        "pattern": r"\bCast<\w+>\s*\(\s*\w+\s*\)(?!.*\bIs<)",
        "severity": "medium",
        "category": "type",
        "description": "V8 Cast<> without preceding Is<> type check (type confusion risk)",
    },
    "partition_alloc_raw": {
        "pattern": r"\bPartitionAlloc\w*\s*\([^)]*\)[\s\S]{0,300}\bfree\s*\(",
        "severity": "high",
        "category": "uaf",
        "description": "PartitionAlloc memory freed with wrong allocator (heap mismatch)",
        "multiline": True,
    },
}
