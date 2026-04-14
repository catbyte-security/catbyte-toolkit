"""Tests for Chrome/Chromium security pattern additions."""
import re
import unittest
from unittest.mock import patch, MagicMock


class TestChromePatterns(unittest.TestCase):
    """Test chrome_patterns.py data structures and regex patterns."""

    def test_mojo_ipc_vuln_patterns_exist(self):
        from cb.patterns.chrome_patterns import MOJO_IPC_VULN_PATTERNS
        expected = [
            "mojo_self_owned_raw_ptr", "mojo_unretained_callback",
            "bigbuffer_double_read", "mojo_missing_report_bad_msg",
            "mojo_check_on_ipc_input", "handle_dup_no_restrict",
            "renderer_origin_trust",
        ]
        for name in expected:
            self.assertIn(name, MOJO_IPC_VULN_PATTERNS, f"Missing pattern: {name}")

    def test_mojo_patterns_have_required_keys(self):
        from cb.patterns.chrome_patterns import MOJO_IPC_VULN_PATTERNS
        for name, info in MOJO_IPC_VULN_PATTERNS.items():
            self.assertIn("pattern", info, f"{name} missing 'pattern'")
            self.assertIn("severity", info, f"{name} missing 'severity'")
            self.assertIn("category", info, f"{name} missing 'category'")
            self.assertIn("description", info, f"{name} missing 'description'")

    def test_mojo_patterns_compile(self):
        from cb.patterns.chrome_patterns import MOJO_IPC_VULN_PATTERNS
        for name, info in MOJO_IPC_VULN_PATTERNS.items():
            flags = re.DOTALL if info.get("multiline") else 0
            try:
                re.compile(info["pattern"], flags)
            except re.error as e:
                self.fail(f"Pattern '{name}' failed to compile: {e}")

    def test_self_owned_pattern_matches(self):
        from cb.patterns.chrome_patterns import MOJO_IPC_VULN_PATTERNS
        pat = re.compile(MOJO_IPC_VULN_PATTERNS["mojo_self_owned_raw_ptr"]["pattern"])
        self.assertIsNotNone(pat.search("MakeSelfOwnedReceiver(new FooImpl(raw_ptr))"))
        self.assertIsNone(pat.search("some_other_function(arg)"))

    def test_unretained_pattern_matches(self):
        from cb.patterns.chrome_patterns import MOJO_IPC_VULN_PATTERNS
        pat = re.compile(MOJO_IPC_VULN_PATTERNS["mojo_unretained_callback"]["pattern"])
        self.assertIsNotNone(pat.search(
            "base::BindOnce(&Foo::Bar, base::Unretained(this))"))
        self.assertIsNotNone(pat.search(
            "base::BindRepeating(&Foo::Baz, base::Unretained(ptr))"))
        self.assertIsNone(pat.search("base::BindOnce(&Foo::Bar, weak_ptr)"))

    def test_check_on_ipc_pattern_matches(self):
        from cb.patterns.chrome_patterns import MOJO_IPC_VULN_PATTERNS
        pat = re.compile(MOJO_IPC_VULN_PATTERNS["mojo_check_on_ipc_input"]["pattern"])
        self.assertIsNotNone(pat.search("CHECK(message > 0)"))
        self.assertIsNotNone(pat.search("DCHECK(params != nullptr)"))
        self.assertIsNotNone(pat.search("CHECK_LE(data, limit)"))

    def test_chrome_dangerous_symbols_exist(self):
        from cb.patterns.chrome_patterns import CHROME_DANGEROUS_SYMBOLS
        expected_components = [
            "mojo_ipc", "v8_engine", "partition_alloc",
            "browser_process", "blink_renderer", "gpu_process",
        ]
        for comp in expected_components:
            self.assertIn(comp, CHROME_DANGEROUS_SYMBOLS)

    def test_chrome_symbols_have_required_keys(self):
        from cb.patterns.chrome_patterns import CHROME_DANGEROUS_SYMBOLS
        for comp, info in CHROME_DANGEROUS_SYMBOLS.items():
            self.assertIn("risk", info, f"{comp} missing 'risk'")
            self.assertIn("symbols", info, f"{comp} missing 'symbols'")
            self.assertIn("description", info, f"{comp} missing 'description'")
            self.assertIsInstance(info["symbols"], list)
            self.assertGreater(len(info["symbols"]), 0, f"{comp} has empty symbols list")

    def test_mojo_symbols_include_key_names(self):
        from cb.patterns.chrome_patterns import CHROME_DANGEROUS_SYMBOLS
        mojo_syms = CHROME_DANGEROUS_SYMBOLS["mojo_ipc"]["symbols"]
        self.assertIn("MakeSelfOwnedReceiver", mojo_syms)
        self.assertIn("ReportBadMessage", mojo_syms)
        self.assertIn("BigBuffer", mojo_syms)

    def test_v8_exploit_patterns_exist(self):
        from cb.patterns.chrome_patterns import V8_EXPLOIT_PATTERNS
        expected = [
            "type_confusion_gadget", "trusted_pointer_table_access",
            "external_pointer_table_access", "arraybuffer_backing_store",
            "code_pointer_manipulation",
        ]
        for name in expected:
            self.assertIn(name, V8_EXPLOIT_PATTERNS)

    def test_v8_patterns_compile(self):
        from cb.patterns.chrome_patterns import V8_EXPLOIT_PATTERNS
        for name, info in V8_EXPLOIT_PATTERNS.items():
            flags = re.DOTALL if info.get("multiline") else 0
            try:
                re.compile(info["pattern"], flags)
            except re.error as e:
                self.fail(f"V8 pattern '{name}' failed to compile: {e}")

    def test_chrome_entitlements_exist(self):
        from cb.patterns.chrome_patterns import CHROME_ENTITLEMENTS
        self.assertIn("com.apple.security.cs.allow-jit", CHROME_ENTITLEMENTS)
        self.assertIn("com.apple.security.cs.allow-unsigned-executable-memory",
                       CHROME_ENTITLEMENTS)
        self.assertIn("com.apple.security.network.client", CHROME_ENTITLEMENTS)

    def test_chrome_fuzz_targets_exist(self):
        from cb.patterns.chrome_patterns import CHROME_FUZZ_TARGETS
        expected = [
            "mojo_interface_stubs", "struct_traits_read",
            "v8_builtin_functions", "image_decoder",
        ]
        for name in expected:
            self.assertIn(name, CHROME_FUZZ_TARGETS)

    def test_fuzz_targets_have_required_keys(self):
        from cb.patterns.chrome_patterns import CHROME_FUZZ_TARGETS
        for name, info in CHROME_FUZZ_TARGETS.items():
            self.assertIn("pattern", info, f"{name} missing 'pattern'")
            self.assertIn("description", info, f"{name} missing 'description'")
            self.assertIn("priority", info, f"{name} missing 'priority'")

    def test_sandbox_escape_indicators_exist(self):
        from cb.patterns.chrome_patterns import SANDBOX_ESCAPE_INDICATORS
        expected = [
            "mach_msg_renderer", "iosurface_from_sandbox",
            "file_broker_access", "gpu_process_ipc",
            "seatbelt_profile_ops", "task_port_access",
        ]
        for name in expected:
            self.assertIn(name, SANDBOX_ESCAPE_INDICATORS)

    def test_sandbox_indicators_have_symbols(self):
        from cb.patterns.chrome_patterns import SANDBOX_ESCAPE_INDICATORS
        for name, info in SANDBOX_ESCAPE_INDICATORS.items():
            self.assertIn("symbols", info, f"{name} missing 'symbols'")
            self.assertIsInstance(info["symbols"], list)
            self.assertGreater(len(info["symbols"]), 0)


class TestVulnChromeMode(unittest.TestCase):
    """Test cb vuln --chrome scanning mode."""

    def setUp(self):
        from cb.commands.vuln import scan_chrome_static
        self.scan_chrome_static = scan_chrome_static

    def _make_args(self, **overrides):
        args = MagicMock()
        args.binary = "/fake/binary"
        args.from_triage = None
        args.static = True
        args.decompiled = False
        args.chrome = True
        args.category = "all"
        args.severity = "all"
        args.context = 3
        args.max_results = 50
        args.format = "json"
        args.no_cache = True
        args.output = None
        for k, v in overrides.items():
            setattr(args, k, v)
        return args

    @patch("cb.commands.vuln.get_strings")
    @patch("cb.commands.vuln.get_imports")
    def test_chrome_scan_finds_mojo_symbols(self, mock_imports, mock_strings):
        from cb.commands.vuln import scan_chrome_static
        mock_imports.return_value = ["_MakeSelfOwnedReceiver", "_mojo_Remote"]
        mock_strings.return_value = {
            "categories": {"general": ["MakeSelfOwnedReceiver", "base::Unretained"]},
        }
        args = self._make_args()
        out = MagicMock()

        findings = self.scan_chrome_static("/fake/chrome", args, out)

        self.assertGreater(len(findings), 0)
        categories = {f["category"] for f in findings}
        # Should find mojo-related findings
        self.assertTrue(categories & {"chrome", "mojo"})

    @patch("cb.commands.vuln.get_strings")
    @patch("cb.commands.vuln.get_imports")
    def test_chrome_scan_detects_self_owned_without_frame_base(self, mock_imports, mock_strings):
        mock_imports.return_value = []
        mock_strings.return_value = {
            "categories": {"general": ["MakeSelfOwnedReceiver"]},
        }
        args = self._make_args()
        out = MagicMock()

        findings = self.scan_chrome_static("/fake/chrome", args, out)

        mojo_findings = [f for f in findings if f["category"] == "mojo"]
        self.assertGreater(len(mojo_findings), 0)
        titles = [f["title"] for f in mojo_findings]
        self.assertTrue(any("SelfOwnedReceiver" in t for t in titles))

    @patch("cb.commands.vuln.get_strings")
    @patch("cb.commands.vuln.get_imports")
    def test_chrome_scan_safe_with_frame_service_base(self, mock_imports, mock_strings):
        mock_imports.return_value = []
        mock_strings.return_value = {
            "categories": {"general": [
                "MakeSelfOwnedReceiver", "FrameServiceBase"
            ]},
        }
        args = self._make_args()
        out = MagicMock()

        findings = self.scan_chrome_static("/fake/chrome", args, out)

        # Should NOT flag SelfOwnedReceiver when FrameServiceBase is present
        self_owned_findings = [f for f in findings
                               if "SelfOwnedReceiver" in f.get("title", "")]
        self.assertEqual(len(self_owned_findings), 0)

    @patch("cb.commands.vuln.get_strings")
    @patch("cb.commands.vuln.get_imports")
    def test_chrome_scan_detects_unretained(self, mock_imports, mock_strings):
        mock_imports.return_value = []
        mock_strings.return_value = {
            "categories": {"general": ["Unretained"]},
        }
        args = self._make_args()
        out = MagicMock()

        findings = self.scan_chrome_static("/fake/chrome", args, out)

        unretained = [f for f in findings if "Unretained" in f.get("title", "")]
        self.assertGreater(len(unretained), 0)

    @patch("cb.commands.vuln.get_strings")
    @patch("cb.commands.vuln.get_imports")
    def test_chrome_scan_detects_missing_report_bad_message(self, mock_imports, mock_strings):
        mock_imports.return_value = []
        mock_strings.return_value = {
            "categories": {"general": ["Stub::Accept", "mojo::Receiver"]},
        }
        args = self._make_args()
        out = MagicMock()

        findings = self.scan_chrome_static("/fake/chrome", args, out)

        rbm_findings = [f for f in findings if "ReportBadMessage" in f.get("title", "")]
        self.assertGreater(len(rbm_findings), 0)

    @patch("cb.commands.vuln.get_strings")
    @patch("cb.commands.vuln.get_imports")
    def test_chrome_scan_detects_v8_jit(self, mock_imports, mock_strings):
        mock_imports.return_value = []
        mock_strings.return_value = {
            "categories": {"general": ["TurboFan", "v8::Isolate", "CompileLazy"]},
        }
        args = self._make_args()
        out = MagicMock()

        findings = self.scan_chrome_static("/fake/chrome", args, out)

        v8_findings = [f for f in findings if f["category"] == "v8"]
        self.assertGreater(len(v8_findings), 0)

    @patch("cb.commands.vuln.get_strings")
    @patch("cb.commands.vuln.get_imports")
    def test_chrome_scan_no_findings_for_normal_binary(self, mock_imports, mock_strings):
        mock_imports.return_value = ["_malloc", "_free", "_printf"]
        mock_strings.return_value = {
            "categories": {"general": ["hello world"]},
        }
        args = self._make_args()
        out = MagicMock()

        findings = self.scan_chrome_static("/fake/normal", args, out)

        # Normal binary should have no Chrome-specific findings
        chrome_findings = [f for f in findings
                           if f["category"] in ("chrome", "mojo", "v8")]
        self.assertEqual(len(chrome_findings), 0)

    @patch("cb.commands.vuln.get_strings")
    @patch("cb.commands.vuln.get_imports")
    def test_chrome_findings_have_correct_structure(self, mock_imports, mock_strings):
        mock_imports.return_value = ["_MakeSelfOwnedReceiver"]
        mock_strings.return_value = {
            "categories": {"general": ["MakeSelfOwnedReceiver"]},
        }
        args = self._make_args()
        out = MagicMock()

        findings = self.scan_chrome_static("/fake/chrome", args, out)

        for f in findings:
            self.assertIn("id", f)
            self.assertTrue(f["id"].startswith("CHROME-"))
            self.assertIn("category", f)
            self.assertIn("severity", f)
            self.assertIn("title", f)
            self.assertIn("description", f)
            self.assertIn("evidence", f)
            self.assertIn("recommendation", f)

    @patch("cb.commands.vuln.get_strings")
    @patch("cb.commands.vuln.get_imports")
    def test_chrome_sandbox_escape_indicators(self, mock_imports, mock_strings):
        mock_imports.return_value = ["_IOSurfaceCreate", "_IOSurfaceLookup"]
        mock_strings.return_value = {
            "categories": {"general": ["IOSurfaceCreate", "IOSurfaceLookup"]},
        }
        args = self._make_args()
        out = MagicMock()

        findings = self.scan_chrome_static("/fake/chrome", args, out)

        sandbox_findings = [f for f in findings
                            if "sandbox_escape" in str(f.get("evidence", {}).get("type", ""))]
        self.assertGreater(len(sandbox_findings), 0)


class TestFuzzChromeEnhancements(unittest.TestCase):
    """Test fuzz.py Chrome-specific enhancements."""

    def test_chrome_target_indicators_exist(self):
        from cb.commands.fuzz import CHROME_TARGET_INDICATORS
        self.assertIn("stub_accept", CHROME_TARGET_INDICATORS)
        self.assertIn("structtraits_read", CHROME_TARGET_INDICATORS)
        self.assertIn("fromwire", CHROME_TARGET_INDICATORS)

    def test_chrome_high_value_names_exist(self):
        from cb.commands.fuzz import CHROME_HIGH_VALUE_NAMES
        self.assertIn("mojo", CHROME_HIGH_VALUE_NAMES)
        self.assertIn("v8", CHROME_HIGH_VALUE_NAMES)
        self.assertIn("blink", CHROME_HIGH_VALUE_NAMES)
        self.assertIn("renderer", CHROME_HIGH_VALUE_NAMES)

    def test_mojo_handler_gets_high_score(self):
        from cb.commands.fuzz import score_target
        score = score_target("MyInterface_Stub_Accept", 300, set())
        # Should get points for stub_accept indicator + stub+accept combo
        self.assertGreater(score, 50)

    def test_structtraits_read_gets_high_score(self):
        from cb.commands.fuzz import score_target
        score = score_target("StructTraits_Read_MyType", 200, set())
        self.assertGreater(score, 40)

    def test_v8_function_gets_chrome_bonus(self):
        from cb.commands.fuzz import score_target
        score = score_target("v8_CompileLazy", 500, set())
        # Gets 15 (chrome high-value "v8") + size bonus
        self.assertGreater(score, 20)

    def test_normal_function_no_chrome_bonus(self):
        from cb.commands.fuzz import score_target
        score_chrome = score_target("mojo_DispatchMessage", 200, set())
        score_normal = score_target("print_message", 200, set())
        self.assertGreater(score_chrome, score_normal)

    def test_score_reasons_include_chrome(self):
        from cb.commands.fuzz import get_score_reasons
        reasons = get_score_reasons("MojoInterface_Stub_Accept", 300, set())
        chrome_reasons = [r for r in reasons if "Chrome" in r or "Mojo" in r]
        self.assertGreater(len(chrome_reasons), 0)

    def test_generate_mojo_fuzzer(self):
        from cb.commands.fuzz import generate_mojo_fuzzer
        args = MagicMock()
        args.target = "TestInterface"
        args.generate = False
        args.output_dir = "."
        out = MagicMock()

        result = generate_mojo_fuzzer(args, out)

        self.assertEqual(result["framework"], "mojolpm")
        self.assertEqual(result["target"], "TestInterface")
        self.assertIn("code", result)
        self.assertIn("DEFINE_PROTO_FUZZER", result["code"])
        self.assertIn("TestInterface", result["code"])

    def test_mojo_fuzzer_default_target(self):
        from cb.commands.fuzz import generate_mojo_fuzzer
        args = MagicMock()
        args.target = None
        args.generate = False
        args.output_dir = "."
        out = MagicMock()

        result = generate_mojo_fuzzer(args, out)

        self.assertEqual(result["target"], "TargetInterface")

    def test_structure_aware_harness(self):
        from cb.commands.fuzz import _fuzzed_data_provider_template
        code = _fuzzed_data_provider_template("MyParser", "/fake/binary")
        self.assertIn("FuzzedDataProvider", code)
        self.assertIn("ConsumeIntegralInRange", code)
        self.assertIn("ConsumeRandomLengthString", code)
        self.assertIn("ConsumeRemainingBytes", code)
        self.assertIn("MyParser", code)

    def test_suggest_corpus_chrome_patterns(self):
        from cb.commands.fuzz import suggest_corpus
        with patch("cb.commands.fuzz.get_imports") as mock:
            mock.return_value = ["_mojo_ipc", "_blink_html"]
            suggestions = suggest_corpus("/fake/chrome")
            mojo_sugg = [s for s in suggestions if "Mojo" in s or "mojo" in s]
            self.assertGreater(len(mojo_sugg), 0)

    def test_suggest_corpus_v8_patterns(self):
        from cb.commands.fuzz import suggest_corpus
        with patch("cb.commands.fuzz.get_imports") as mock:
            mock.return_value = ["_v8_compile"]
            suggestions = suggest_corpus("/fake/chrome")
            v8_sugg = [s for s in suggestions if "JavaScript" in s or "V8" in s]
            self.assertGreater(len(v8_sugg), 0)


class TestPatternExtensions(unittest.TestCase):
    """Test additions to existing pattern files."""

    def test_dangerous_imports_has_ipc_category(self):
        from cb.patterns.dangerous_functions import DANGEROUS_IMPORTS
        self.assertIn("ipc", DANGEROUS_IMPORTS["high"])
        self.assertIsInstance(DANGEROUS_IMPORTS["high"]["ipc"], list)

    def test_import_categories_has_chromium_ipc(self):
        from cb.patterns.dangerous_functions import IMPORT_CATEGORIES
        self.assertIn("chromium_ipc", IMPORT_CATEGORIES)
        self.assertIn("MakeSelfOwnedReceiver", IMPORT_CATEGORIES["chromium_ipc"])

    def test_import_categories_has_v8_engine(self):
        from cb.patterns.dangerous_functions import IMPORT_CATEGORIES
        self.assertIn("v8_engine", IMPORT_CATEGORIES)
        self.assertIn("v8_Isolate", IMPORT_CATEGORIES["v8_engine"])

    def test_dangerous_entitlements_has_jit(self):
        from cb.patterns.dangerous_functions import DANGEROUS_ENTITLEMENTS
        self.assertIn("com.apple.security.cs.allow-jit", DANGEROUS_ENTITLEMENTS)

    def test_parser_indicators_has_chromium(self):
        from cb.patterns.dangerous_functions import PARSER_INDICATORS
        self.assertIn("chromium", PARSER_INDICATORS)

    def test_high_value_services_has_chrome(self):
        from cb.patterns.dangerous_functions import HIGH_VALUE_SERVICES
        self.assertIn("com.google.Chrome.helper", HIGH_VALUE_SERVICES)

    def test_vuln_signatures_has_chrome_patterns(self):
        from cb.patterns.vuln_signatures import DECOMPILED_VULN_PATTERNS
        chrome_patterns = [
            "mojo_unvalidated_size", "chrome_check_on_ipc",
            "unretained_cross_thread", "bigbuffer_no_copy",
            "v8_unchecked_cast", "partition_alloc_raw",
        ]
        for name in chrome_patterns:
            self.assertIn(name, DECOMPILED_VULN_PATTERNS)

    def test_new_vuln_patterns_compile(self):
        from cb.patterns.vuln_signatures import DECOMPILED_VULN_PATTERNS
        chrome_names = [
            "mojo_unvalidated_size", "chrome_check_on_ipc",
            "unretained_cross_thread", "bigbuffer_no_copy",
            "v8_unchecked_cast", "partition_alloc_raw",
        ]
        for name in chrome_names:
            info = DECOMPILED_VULN_PATTERNS[name]
            flags = re.DOTALL if info.get("multiline") else 0
            try:
                re.compile(info["pattern"], flags)
            except re.error as e:
                self.fail(f"Pattern '{name}' failed to compile: {e}")

    def test_check_on_ipc_pattern_matches(self):
        from cb.patterns.vuln_signatures import DECOMPILED_VULN_PATTERNS
        pat = re.compile(DECOMPILED_VULN_PATTERNS["chrome_check_on_ipc"]["pattern"])
        self.assertIsNotNone(pat.search("CHECK(size < MAX_SIZE)"))
        self.assertIsNotNone(pat.search("DCHECK(count > 0)"))

    def test_v8_unchecked_cast_pattern(self):
        from cb.patterns.vuln_signatures import DECOMPILED_VULN_PATTERNS
        pat = re.compile(DECOMPILED_VULN_PATTERNS["v8_unchecked_cast"]["pattern"])
        self.assertIsNotNone(pat.search("Cast<JSArray>(obj)"))


if __name__ == "__main__":
    unittest.main()
