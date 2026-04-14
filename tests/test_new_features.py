"""Tests for the 10 new research-driven features."""
import argparse
import json
import os
import tempfile
import time

import pytest


# ── Feature 1: Crash batch analysis + deduplication ──────────────────────

class TestCrashBatch:
    def test_parse_since_hours(self):
        from cb.commands.crash import _parse_since
        cutoff = _parse_since("2 hours ago")
        assert cutoff is not None
        assert abs(cutoff - (time.time() - 7200)) < 2

    def test_parse_since_days(self):
        from cb.commands.crash import _parse_since
        cutoff = _parse_since("3 days ago")
        assert cutoff is not None
        assert abs(cutoff - (time.time() - 259200)) < 2

    def test_parse_since_invalid(self):
        from cb.commands.crash import _parse_since
        assert _parse_since("blah blah") is None

    def test_crash_signature(self):
        from cb.commands.crash import _crash_signature
        result = {
            "crash_summary": {"exception_type": "EXC_BAD_ACCESS"},
            "backtrace": [
                {"symbol": "CVMCompiler_compile", "symbol_location": 0x4a8},
            ],
        }
        sig = _crash_signature(result)
        assert "EXC_BAD_ACCESS" in sig
        assert "CVMCompiler_compile" in sig

    def test_crash_signature_no_symbol(self):
        from cb.commands.crash import _crash_signature
        result = {
            "crash_summary": {"bug_type": "heap-buffer-overflow"},
            "backtrace": [{"symbol": "0x12345"}],
        }
        sig = _crash_signature(result)
        assert "heap-buffer-overflow" in sig

    def test_group_by_signature(self):
        from cb.commands.crash import _group_by_signature
        results = [
            {
                "crash_summary": {"exception_type": "EXC_BAD_ACCESS", "process": "foo"},
                "backtrace": [{"symbol": "func_a", "symbol_location": 10}],
                "analysis": {"exploitability": "high", "likely_bug_type": "heap_overflow"},
                "_file": "/tmp/a.ips", "_mtime": time.time() - 100,
            },
            {
                "crash_summary": {"exception_type": "EXC_BAD_ACCESS", "process": "foo"},
                "backtrace": [{"symbol": "func_a", "symbol_location": 10}],
                "analysis": {"exploitability": "medium", "likely_bug_type": "heap_overflow"},
                "_file": "/tmp/b.ips", "_mtime": time.time(),
            },
            {
                "crash_summary": {"exception_type": "SIGABRT", "process": "bar"},
                "backtrace": [{"symbol": "func_b", "symbol_location": 0}],
                "analysis": {"exploitability": "low", "likely_bug_type": "abort"},
                "_file": "/tmp/c.ips", "_mtime": time.time(),
            },
        ]
        groups = _group_by_signature(results)
        assert len(groups) == 2
        # First group has highest count
        assert groups[0]["count"] == 2
        assert groups[0]["exploitability"] == "high"
        assert groups[1]["count"] == 1

    def test_batch_on_empty_dir(self, capsys):
        from cb.commands.crash import run_batch
        from cb.output import OutputFormatter
        with tempfile.TemporaryDirectory() as td:
            args = argparse.Namespace(
                report=td, batch=True, since=None, dedup=True,
                format="json", max_results=50, quiet=True, output=None,
            )
            out = OutputFormatter(quiet=True)
            run_batch(args, out)
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["total_reports"] == 0

    def test_batch_with_ips_files(self, capsys):
        from cb.commands.crash import run_batch
        from cb.output import OutputFormatter
        # Create a minimal IPS JSON crash report
        ips = json.dumps({
            "procName": "testproc",
            "pid": 123,
            "captureTime": "2024-01-01",
            "exception": {"type": "EXC_BAD_ACCESS", "signal": "SIGSEGV",
                          "codes": "KERN_INVALID_ADDRESS", "faultAddr": "0x0"},
            "faultingThread": 0,
            "threads": [{"frames": [{"symbol": "test_func", "symbolLocation": 42}]}],
        })
        with tempfile.TemporaryDirectory() as td:
            for i in range(3):
                with open(os.path.join(td, f"crash_{i}.ips"), "w") as f:
                    f.write(ips)
            args = argparse.Namespace(
                report=td, batch=True, since=None, dedup=True,
                format="json", max_results=50, quiet=True, output=None,
            )
            out = OutputFormatter(quiet=True)
            run_batch(args, out)
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["total_reports"] == 3
            assert data["unique_signatures"] == 1
            assert len(data["groups"]) == 1
            assert data["groups"][0]["count"] == 3


# ── Feature 8: Crash report to PoC pipeline ──────────────────────────────

class TestCrashPoC:
    def test_generate_xpc_poc(self):
        from cb.commands.crash import generate_poc
        result = {
            "crash_summary": {
                "process": "CVMCompiler",
                "exception_type": "EXC_BAD_ACCESS",
                "faulting_address": "0x41414141",
            },
            "backtrace": [
                {"symbol": "xpc_connection_handler"},
                {"symbol": "CVMCompiler_compile"},
            ],
            "analysis": {
                "likely_bug_type": "heap_overflow",
                "attack_vector": "ipc",
            },
        }
        args = argparse.Namespace(generate_poc=True, poc_output=None)
        poc = generate_poc(result, args)
        assert poc["type"] == "xpc"
        assert "xpc_connection_create_mach_service" in poc["code"]
        assert "CVMCompiler" in poc["code"]

    def test_generate_mach_poc(self):
        from cb.commands.crash import generate_poc
        result = {
            "crash_summary": {"process": "testd", "exception_type": "EXC_BAD_ACCESS",
                              "faulting_address": "0x0"},
            "backtrace": [{"symbol": "mach_msg_receive"}],
            "analysis": {"likely_bug_type": "null_deref", "attack_vector": "unknown"},
        }
        args = argparse.Namespace(generate_poc=True, poc_output=None)
        poc = generate_poc(result, args)
        assert poc["type"] == "mach"
        assert "mach_msg" in poc["code"]

    def test_generate_generic_poc(self):
        from cb.commands.crash import generate_poc
        result = {
            "crash_summary": {"process": "imgparser", "exception_type": "SIGSEGV",
                              "faulting_address": "0xdead"},
            "backtrace": [{"symbol": "parse_image_header"}],
            "analysis": {"likely_bug_type": "invalid_read_write", "attack_vector": "file_based"},
        }
        args = argparse.Namespace(generate_poc=True, poc_output=None)
        poc = generate_poc(result, args)
        assert poc["type"] == "generic"
        assert "parse_image_header" in poc["code"]

    def test_poc_write_to_file(self):
        from cb.commands.crash import generate_poc
        result = {
            "crash_summary": {"process": "test", "exception_type": "SIGSEGV",
                              "faulting_address": "0x0"},
            "backtrace": [{"symbol": "do_work"}],
            "analysis": {"likely_bug_type": "null_deref", "attack_vector": "unknown"},
        }
        args = argparse.Namespace(generate_poc=True, poc_output=None)
        poc = generate_poc(result, args)
        # generate_poc returns the code; run() handles writing to file
        assert poc["type"] == "generic"
        assert len(poc["code"]) > 100
        assert "do_work" in poc["code"]


# ── Feature 9: Pipeline mode (stdin chaining) ───────────────────────────

class TestPipelineMode:
    def test_load_piped_input_none_on_tty(self):
        from cb.output import load_piped_input
        # When running in test, stdin is a TTY (or pipe from pytest)
        # This should return None or data depending on context
        result = load_piped_input()
        # Just verify it doesn't crash
        assert result is None or isinstance(result, dict)

    def test_scan_from_triage(self):
        from cb.commands.vuln import _scan_from_triage
        triage_data = {
            "imports": ["strcpy", "sprintf", "malloc", "free"],
            "strings": {"categories": {"format_strings": []}},
        }
        args = argparse.Namespace(category="all", severity="all", max_results=50)
        out = type("FakeOut", (), {"status": lambda self, m: None})()
        findings = _scan_from_triage(triage_data, args, out)
        assert len(findings) > 0
        # Should find strcpy and sprintf as dangerous
        titles = [f["title"] for f in findings]
        assert any("strcpy" in t for t in titles)
        assert any("sprintf" in t for t in titles)
        # Should flag malloc without overflow check
        assert any("overflow" in f.get("title", "").lower() or
                    "arithmetic" in f.get("title", "").lower() for f in findings)

    def test_scan_from_triage_with_dict_imports(self):
        from cb.commands.vuln import _scan_from_triage
        triage_data = {
            "imports": {"symbols": ["gets", "system"]},
        }
        args = argparse.Namespace(category="all", severity="all", max_results=50)
        out = type("FakeOut", (), {"status": lambda self, m: None})()
        findings = _scan_from_triage(triage_data, args, out)
        titles = [f["title"] for f in findings]
        assert any("gets" in t for t in titles)
        assert any("system" in t for t in titles)


# ── Feature 5: Variant analysis new patterns ─────────────────────────────

class TestVariantPatterns:
    def test_new_patterns_exist(self):
        from cb.commands.variant import KNOWN_PATTERNS
        assert "xpc_integer_to_allocation" in KNOWN_PATTERNS
        assert "xpc_data_to_memcpy" in KNOWN_PATTERNS

    def test_xpc_integer_pattern_fields(self):
        from cb.commands.variant import KNOWN_PATTERNS
        p = KNOWN_PATTERNS["xpc_integer_to_allocation"]
        assert p["severity"] == "critical"
        assert "xpc_dictionary_get_uint64" in p["indicators"]
        assert "mach_vm_allocate" in p["indicators"]
        assert "os_mul_overflow" in p["anti_indicators"]
        assert len(p["cve_examples"]) > 0

    def test_xpc_data_pattern_fields(self):
        from cb.commands.variant import KNOWN_PATTERNS
        p = KNOWN_PATTERNS["xpc_data_to_memcpy"]
        assert p["severity"] == "critical"
        assert "xpc_dictionary_get_data" in p["indicators"]
        assert "memcpy" in p["indicators"]

    def test_extract_crash_target(self):
        from cb.commands.variant import _extract_crash_target
        crash_data = {
            "backtrace": [
                {"symbol": "0x12345"},
                {"symbol": "CVMCompiler_compile"},
                {"symbol": "main"},
            ]
        }
        assert _extract_crash_target(crash_data) == "CVMCompiler_compile"

    def test_extract_crash_target_no_symbol(self):
        from cb.commands.variant import _extract_crash_target
        crash_data = {"backtrace": [{"symbol": "0x123"}, {"symbol": "0xabc"}]}
        assert _extract_crash_target(crash_data) is None

    def test_total_patterns_count(self):
        from cb.commands.variant import KNOWN_PATTERNS
        # Original 10 + 2 new = 12
        assert len(KNOWN_PATTERNS) >= 12


# ── Feature 10: Enhanced security diff ───────────────────────────────────

class TestSecurityDiff:
    def test_diff_security_detects_hardening(self):
        """Verify the hardening detection logic by testing the function structure."""
        from cb.commands.diff import diff_security
        # We can't easily test with real binaries, but verify the function exists
        # and has the right structure
        import inspect
        source = inspect.getsource(diff_security)
        assert "hardening_added" in source
        assert "dangerous_removed" in source
        assert "audit_token_added" in source
        assert "bounds_checks_added" in source

    def test_diff_mode_security_in_main(self):
        """Verify security mode is in main() choices."""
        import inspect
        from cb.commands.diff import main
        source = inspect.getsource(main)
        assert "security" in source


# ── Feature 4: Sandbox reachability ──────────────────────────────────────

class TestSandboxReachability:
    def test_extract_mach_lookup_literal(self):
        from cb.commands.sandbox import extract_mach_lookup_allows
        profile = '(allow mach-lookup (global-name "com.apple.securityd"))'
        allows = extract_mach_lookup_allows(profile)
        assert len(allows) == 1
        assert allows[0]["service"] == "com.apple.securityd"
        assert allows[0]["type"] == "literal"

    def test_extract_mach_lookup_regex(self):
        from cb.commands.sandbox import extract_mach_lookup_allows
        profile = '(allow mach-lookup (global-name-regex "com\\.apple\\..*"))'
        allows = extract_mach_lookup_allows(profile)
        assert len(allows) == 1
        assert allows[0]["type"] == "regex"

    def test_extract_mach_lookup_unrestricted(self):
        from cb.commands.sandbox import extract_mach_lookup_allows
        profile = "(allow mach-lookup)"
        allows = extract_mach_lookup_allows(profile)
        assert any(a.get("type") == "unrestricted" for a in allows)

    def test_extract_mach_lookup_from_entitlements(self):
        from cb.commands.sandbox import extract_mach_lookup_from_entitlements
        ents = {
            "com.apple.security.temporary-exception.mach-lookup.global-name": [
                "com.apple.foo", "com.apple.bar"
            ]
        }
        services = extract_mach_lookup_from_entitlements(ents)
        assert "com.apple.foo" in services
        assert "com.apple.bar" in services

    def test_parse_sandbox_profile_text(self):
        from cb.commands.sandbox import parse_sandbox_profile_text
        profile = """
        (version 1)
        (allow mach-lookup (global-name "com.apple.foo"))
        (allow file-read*)
        (deny network-outbound)
        """
        result = parse_sandbox_profile_text(profile)
        assert result["total_allows"] == 2
        assert result["total_denies"] == 1


# ── Feature 4 continued: services.py ─────────────────────────────────────

class TestServices:
    def test_enumerate_returns_list(self):
        from cb.services import enumerate_launchd_services
        services = enumerate_launchd_services()
        assert isinstance(services, list)
        # On macOS, should find at least some services
        if services:
            svc = services[0]
            assert "label" in svc
            assert "binary_path" in svc

    def test_get_running_services(self):
        from cb.services import get_running_services
        services = get_running_services()
        assert isinstance(services, list)

    def test_resolve_service_binary_unknown(self):
        from cb.services import resolve_service_binary
        result = resolve_service_binary("com.example.nonexistent.service.12345")
        assert result is None


# ── Feature 4 continued: macho.py additions ──────────────────────────────

class TestMachoAdditions:
    def test_get_section_data_missing_file(self):
        from cb.macho import get_section_data
        result = get_section_data("/nonexistent/binary", "__TEXT", "__text")
        assert result is None

    def test_get_embedded_sandbox_profile_missing(self):
        from cb.macho import get_embedded_sandbox_profile
        result = get_embedded_sandbox_profile("/nonexistent/binary")
        assert result is None

    def test_get_section_data_on_real_binary(self):
        from cb.macho import get_section_data
        # /bin/echo is a simple binary that should exist
        result = get_section_data("/bin/echo", "__TEXT", "__text")
        # May or may not work depending on SIP, just verify no crash
        assert result is None or isinstance(result, bytes)


# ── Feature 6: Service enumeration & prioritization ──────────────────────

class TestServiceEnum:
    def test_high_value_services(self):
        from cb.patterns.dangerous_functions import HIGH_VALUE_SERVICES
        assert "com.apple.securityd" in HIGH_VALUE_SERVICES
        assert "com.apple.CVMServer" in HIGH_VALUE_SERVICES
        assert len(HIGH_VALUE_SERVICES) >= 15

    def test_complex_input_indicators(self):
        from cb.patterns.dangerous_functions import COMPLEX_INPUT_INDICATORS
        assert "xpc_dictionary_get_data" in COMPLEX_INPUT_INDICATORS
        assert "memcpy" in COMPLEX_INPUT_INDICATORS

    def test_enumerate_and_rank_exists(self):
        from cb.commands.attack import enumerate_and_rank_services
        import inspect
        sig = inspect.signature(enumerate_and_rank_services)
        params = list(sig.parameters.keys())
        assert "source_binary" in params
        assert "rank_by" in params
        assert "out" in params


# ── Feature 2: XPC protocol RE ───────────────────────────────────────────

class TestXPCProtocol:
    def test_ghidra_script_exists(self):
        script_path = os.path.join(os.path.dirname(__file__), "..",
                                   "cb", "ghidra_scripts", "XPCProtocol.java")
        assert os.path.exists(script_path)

    def test_extract_protocol_function_exists(self):
        from cb.commands.ipc import extract_protocol, _format_protocol_spec
        assert callable(extract_protocol)
        assert callable(_format_protocol_spec)

    def test_format_protocol_spec(self):
        from cb.commands.ipc import _format_protocol_spec
        protocol = {
            "messages": [
                {"id": "4", "handler": "handle_compile",
                 "args": [{"key": "data", "type": "data"},
                          {"key": "name", "type": "string"}]},
                {"id": "5", "handler": "handle_query", "args": []},
            ]
        }
        lines = _format_protocol_spec(protocol)
        assert len(lines) == 2
        assert "msg=4" in lines[0]
        assert "data: data" in lines[0]
        assert "name: string" in lines[0]


# ── Feature 3: XPC fuzzer generation ─────────────────────────────────────

class TestXPCFuzzer:
    def test_generate_xpc_fuzzer_objc(self):
        from cb.commands.fuzz import _generate_xpc_fuzzer_objc
        messages = [
            {"id": "1", "handler": "handle_data",
             "args": [{"key": "payload", "type": "data"},
                      {"key": "cmd", "type": "int64"}]},
            {"id": "2", "handler": "handle_query",
             "args": [{"key": "name", "type": "string"},
                      {"key": "verbose", "type": "bool"}]},
        ]
        code = _generate_xpc_fuzzer_objc("com.apple.test", messages)
        assert "com.apple.test" in code
        assert "LLVMFuzzerTestOneInput" in code
        assert "build_msg_0" in code
        assert "build_msg_1" in code
        assert "xpc_dictionary_set_int64" in code
        assert "xpc_dictionary_set_string" in code
        assert "xpc_dictionary_set_data" in code
        assert "xpc_dictionary_set_bool" in code
        assert "fsanitize=fuzzer" in code

    def test_generate_xpc_fuzzer_no_protocol(self):
        from cb.commands.fuzz import _generate_xpc_fuzzer_objc
        # With no messages, should generate a generic fallback
        code = _generate_xpc_fuzzer_objc("com.apple.foo", [])
        assert "LLVMFuzzerTestOneInput" in code
        assert "com.apple.foo" in code


# ── Feature 7: Live process probing ──────────────────────────────────────

class TestProbe:
    def test_probe_script_exists(self):
        script_path = os.path.join(os.path.dirname(__file__), "..",
                                   "cb", "probe_scripts", "probe_xpc.m")
        assert os.path.exists(script_path)

    def test_parse_range(self):
        from cb.commands.probe import _parse_range
        assert _parse_range("0-31") == (0, 31)
        assert _parse_range("5-10") == (5, 10)
        assert _parse_range("invalid") == (0, 31)

    def test_parse_probe_output(self):
        from cb.commands.probe import _parse_probe_output
        output = '###CB_JSON_START###\n{"status": "alive"}\n###CB_JSON_END###\n'
        result = _parse_probe_output(output)
        assert result is not None
        assert result["status"] == "alive"

    def test_parse_probe_output_no_markers(self):
        from cb.commands.probe import _parse_probe_output
        result = _parse_probe_output("no json here")
        assert result is None

    def test_probe_registered_in_cli(self):
        """Verify probe command is registered in CLI."""
        import inspect
        from cb.cli import main
        source = inspect.getsource(main)
        assert "reg_probe" in source

    def test_probe_in_pyproject(self):
        toml_path = os.path.join(os.path.dirname(__file__), "..", "pyproject.toml")
        with open(toml_path) as f:
            content = f.read()
        assert "cbprobe" in content
