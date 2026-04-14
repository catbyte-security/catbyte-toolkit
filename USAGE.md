# Catbyte Toolkit (cb) -- AI Reference Guide

> Binary analysis toolkit for macOS/iOS security research.
> Python >= 3.10 | Version 1.2.0

---

## Architecture

```
cb/
  cli.py              # Unified dispatcher: cb <command>
  output.py            # OutputFormatter (JSON/text/summary), pipeline helpers
  config.py            # ~/.cbconfig.json loader, default paths
  macho.py             # Mach-O parser (otool/nm/codesign/LIEF)
  disasm.py            # Capstone disassembler + objdump fallback
  services.py          # launchd service enumeration
  ghidra_bridge.py     # Ghidra headless analysis
  lldb_bridge.py       # LLDB scripted debugging
  commands/             # One file per command (register + run pattern)
  patterns/             # Static pattern databases
  ghidra_scripts/       # Java scripts for Ghidra headless
  lldb_scripts/         # Python scripts for LLDB
  probe_scripts/        # ObjC probing tools (compiled on first use)
```

Every command module exports `register(subparsers)` and `run(args)`.
Output always goes through `OutputFormatter.emit(data, "tool_name")`.

---

## Global Flags (all commands)

| Flag | Default | Effect |
|---|---|---|
| `--format json\|text\|summary` | json | Output mode |
| `--summary` | -- | Shorthand for `--format summary` |
| `--max-results N` | 50 | Cap list lengths |
| `-q, --quiet` | off | Suppress `[*]` progress on stderr |
| `-o, --output FILE` | stdout | Write to file |

---

## Commands Reference

### Reconnaissance

#### `cb triage <binary>`
Quick security overview. First command to run on any target.

```
cb triage /usr/libexec/syspolicyd
cb triage /Applications/Safari.app --checksec
cb triage target --full --format text
```

Flags: `--checksec` (protections only), `--no-sections`, `--no-imports`, `--no-exports`, `--no-strings`, `--strings-min N` (default 6), `--strings-max N` (default 30), `--full`.

Output: file info, architectures, protections (PIE, code signing, hardened runtime), sections, categorized imports, exports, categorized strings (URLs, paths, format strings, errors, crypto).

#### `cb attack <binary>`
Map attack surface. Identifies IPC endpoints, parsers, network, entitlements.

```
cb attack /usr/libexec/syspolicyd
cb attack /Applications/Safari.app --app-bundle --depth deep
cb attack target --services-from /usr/libexec/sandboxd --rank-by risk
```

Flags: `--app-bundle`, `--ipc`, `--parsers`, `--network`, `--entitlements`, `--syscalls`, `--depth shallow|deep`, `--services-from <binary>` (enumerate reachable services), `--rank-by risk|attack_surface|privilege`.

#### `cb objc <binary>`
Objective-C runtime analysis.

```
cb objc target --classes --class-filter "NS.*Coder"
cb objc target --selectors --selector-filter "initWith"
cb objc target --dangerous
cb objc target --protocols
```

Flags: `--classes`, `--selectors`, `--dangerous` (default), `--protocols`, `--class-filter REGEX`, `--selector-filter REGEX`.

Dangerous categories: deserialization (NSCoding), dynamic dispatch, code execution, file ops, IPC, pasteboard, webview, keychain.

#### `cb grep <binary> <pattern>`
Search binary content by mode.

```
cb grep target "xpc_dictionary_get" --mode disasm
cb grep target "414141" --mode bytes
cb grep target "password" --mode strings
cb grep target "ret" --mode gadgets --gadget-type rop --gadget-depth 5
```

Flags: `--mode disasm|bytes|strings|gadgets` (default disasm), `--case-sensitive`, `--context N` (default 3), `--function NAME`, `--section NAME`, `--gadget-type rop|jop|all`, `--gadget-depth N`, `--no-duplicates`.

---

### Vulnerability Analysis

#### `cb vuln [binary]`
Pattern-based vulnerability scanner. Static analysis + optional Ghidra decompilation.

```
cb vuln target
cb vuln target --decompiled --category overflow --severity high
cb triage target | cb vuln --from-triage -
```

Flags: `--static` (default on), `--decompiled`, `--from-triage FILE|-`, `--category overflow|format|integer|uaf|race|type|heap|injection|logic|info_leak|all`, `--severity high|medium|low|all`, `--context N`.

Static checks: dangerous imports, format strings, hardcoded credentials, logic bugs.
Decompiled checks: 15+ regex patterns on Ghidra output (format string vars, unbounded copies, malloc overflow, signed comparison, etc.).

#### `cb variant [binary]`
Find variant bugs from known vulnerability patterns.

```
cb variant target --pattern xpc_type_confusion
cb variant --from-crash crash.ips --heuristic
cb variant target --list-patterns
cb variant target --custom-pattern "xpc_dictionary_get_int64.*malloc" --custom-description "Integer to allocation"
```

Flags: `--pattern NAME`, `--list-patterns`, `--custom-pattern REGEX`, `--custom-description TEXT`, `--from-crash FILE|-`, `--heuristic`, `--from-cve CVE-ID`, `--static`, `--timeout N` (default 600).

12 known patterns: `oob_read`, `integer_overflow`, `type_confusion`, `mach_msg_overflow`, `xpc_type_confusion`, `format_string`, `double_free`, `heap_overflow`, `sandbox_escape_mach`, `toctou`, `xpc_integer_to_allocation`, `xpc_data_to_memcpy`.

#### `cb taint <binary>`
Inter-procedural taint tracking via Ghidra. Traces data from sources to sinks.

```
cb taint target --source auto --depth 5
cb taint target --source recv --severity critical
```

Flags: `--source FUNC|auto` (default auto), `--depth N` (default 5), `--severity critical|high|medium|all`, `--timeout N` (default 600).

Sources: read, recv, xpc_dictionary_get_*, mach_msg. Sinks: memcpy, system, exec, sprintf.

#### `cb callgraph <binary>`
Call graph recovery and sink reachability.

```
cb callgraph target --mode sinks
cb callgraph target --mode from --function parseImage --depth 10
cb callgraph target --mode stats
```

Flags: `--mode sinks|from|stats` (default sinks), `--function NAME` (required for `from`), `--depth N` (default 8), `--timeout N` (default 600).

#### `cb audit <binary>`
Full security audit. Runs triage + attack + vuln + objc + ipc + sandbox + variant. Consolidates into risk assessment.

```
cb audit /usr/libexec/syspolicyd
cb audit target --deep --skip objc,sandbox
```

Flags: `--skip NAMES` (comma-sep), `--deep` (adds taint + callgraph via Ghidra), `--timeout N` (default 120, per-command).

---

### IPC & Sandbox

#### `cb ipc <binary>`
Deep IPC/XPC handler analysis.

```
cb ipc target --all
cb ipc target --xpc --protocol
cb ipc target --protocol --protocol-func handleXPCMessage --timeout 300
```

Flags: `--xpc`, `--mach`, `--mig`, `--handlers`, `--all` (default), `--protocol` (Ghidra-based XPC extraction), `--protocol-func NAME`, `--timeout N` (default 600).

#### `cb sandbox <binary>`
Sandbox profile and entitlement analysis.

```
cb sandbox target --profile /path/to/profile.sb
cb sandbox target --reachable-from /usr/libexec/sandboxd
cb sandbox target --chain com.apple.WindowServer
cb sandbox target --extract-profile --capability-map
```

Flags: `--profile PATH`, `--escape-vectors` (default on), `--capability-map`, `--compare-apis`, `--reachable-from BINARY`, `--chain SERVICE`, `--extract-profile`.

#### `cb probe <service>`
Live XPC service probing. Compiles and caches ObjC probe binary on first run.

```
cb probe com.apple.securityd
cb probe com.apple.WindowServer --enumerate-messages --range 0-63
cb probe com.apple.securityd --key command --timeout 5
```

Flags: `--enumerate-messages`, `--range START-END` (default 0-31), `--key NAME` (default "message"), `--timeout N` (default 2).

---

### Diffing

#### `cb diff <old> <new>`
Binary version diffing with fuzzy matching.

```
cb diff old_binary new_binary
cb diff old new --mode security
cb diff old new --mode functions --fuzzy --decompile-changed
```

Flags: `--mode functions|symbols|strings|imports|security` (default functions), `--show-added`, `--show-removed`, `--show-changed`, `--show-all` (default), `--fuzzy`, `--decompile-changed`.

Security mode detects: new dangerous imports, removed dangerous imports, hardening added, audit token added, bounds checks added, entitlement changes.

---

### Verification

#### `cb verify <binary> <input>`
Run a binary under macOS memory guards (MallocGuardEdges, MallocScribble) to detect heap corruption, use-after-free, and buffer overflows that might not crash under normal conditions.

```
cb verify /usr/libexec/syspolicyd payload.bin
cb verify target fuzzed_input.dat --mode stdin --timeout 30
cb verify target input.txt --mode args --repeat 10
cb verify target payload.bin --no-guards
cb verify target input.bin --args "--parse" "--verbose"
```

Flags: `--mode file|stdin|args` (default file), `--timeout N` (default 10), `--args ARGS` (additional CLI arguments), `--repeat N` (default 1, run N times for intermittent crashes), `--no-guards` (disable malloc guards for baseline comparison).

Input modes:
- `file`: pass input path as a positional argument to the binary
- `stdin`: feed input file contents via stdin
- `args`: read lines from file and pass as CLI arguments

Output: exit code, crash detection (signal name/number), ASAN detection (bug type, access type/size), elapsed time, exploitability assessment (reuses `cb crash` analysis). With `--repeat`, includes crash rate across runs.

Guards enabled by default: `MallocGuardEdges`, `MallocScribble`, `MallocStackLogging`, `MallocStackLoggingNoCompact`.

---

### Crash Analysis

#### `cb crash <report>`
Crash report parser with exploitability assessment.

```
cb crash report.ips
cb crash report.ips --symbolicate --binary target
cb crash --batch /path/to/crash/dir --since "2 days ago" --dedup
cb crash report.ips --generate-poc --poc-output poc.py
```

Flags: `--symbolicate`, `--binary PATH`, `--show-registers` (default on), `--backtrace-depth N` (default 20), `--all-threads`, `--batch`, `--since AGE`, `--dedup`, `--generate-poc`, `--poc-output FILE`.

Formats: IPS JSON (.ips), legacy (.crash), ASAN, TSAN, MSAN.

Exploitability: pc_corruption, controlled_registers, heap_corruption, stack_corruption, null_deref, divide_by_zero.

PoC generation: auto-detects XPC/Mach/generic from backtrace symbols.

---

### Ghidra Integration

#### `cb ghidra <subcommand>`
Ghidra headless analysis. Requires Ghidra installation.

```
cb ghidra setup --ghidra-home /Applications/ghidra_11.0
cb ghidra analyze target
cb ghidra decompile target functionName
cb ghidra functions target
cb ghidra xrefs target functionName
cb ghidra search target "memcpy.*size"
cb ghidra types target
```

Subcommands: `setup`, `analyze`, `decompile`, `functions`, `xrefs`, `search`, `types`.

---

### Dynamic Analysis

#### `cb lldb <subcommand>`
LLDB scripted debugging bridge.

```
cb lldb info target
cb lldb modules --pid 1234
cb lldb symbols target "xpc.*handler"
cb lldb disasm target functionName --count 50
cb lldb memory --pid 1234 0x100000 --size 256
cb lldb backtrace --pid 1234
cb lldb registers --pid 1234
cb lldb breakpoint target func1,func2 --args "--flag" --collect registers
cb lldb eval --pid 1234 "(int)[NSObject class]"
```

#### `cb hook <binary>`
Frida-based dynamic instrumentation harness generator.

```
cb hook target -f vulnerable_function --generate
cb hook target --objc-class NSXPCConnection
cb hook target --trace-ipc
cb hook target --trace-parsers
cb hook target --trace-alloc
cb hook target -f targetFunc --run --pid 1234
```

Flags: `-f, --function NAME`, `--objc-class NAME`, `--trace-ipc`, `--trace-parsers`, `--trace-alloc`, `--generate` (default), `--run`, `--pid PID`, `--output-dir DIR`.

---

### Fuzzing

#### `cb fuzz <binary>`
Fuzzer harness generation and target identification.

```
cb fuzz target --auto
cb fuzz target --target parseImage --generate --framework libfuzzer
cb fuzz target --dict --suggest-corpus
cb fuzz target --xpc --service com.apple.ImageIO --protocol-json protocol.json --xpc-style objc
```

Flags: `--target FUNC`, `--auto` (default), `--generate`, `--framework libfuzzer|afl|honggfuzz`, `--output-dir DIR`, `--dict`, `--suggest-corpus`, `--xpc`, `--service NAME`, `--protocol-json FILE`, `--xpc-style c|objc`.

---

### Web Security

#### `cb web <subcommand>`
Web application security auditing. Checks security headers, CSP, CORS, cookies, and enumerates endpoints.

```
cb web headers https://example.com
cb web endpoints https://example.com --wordlist custom_paths.txt --max-requests 100
cb web cors https://example.com --origins https://evil.com null
cb web csp https://example.com
cb web csp https://example.com --policy "default-src 'self'; script-src 'unsafe-inline'"
cb web cookies https://example.com
cb web scan https://example.com --timeout 15
```

Subcommands:
- `headers` -- check for missing/misconfigured security headers (HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection)
- `endpoints` -- enumerate common paths (robots.txt, .env, .git/HEAD, admin/, api/, graphql, swagger.json, etc.)
- `cors` -- test for CORS misconfigurations by sending crafted Origin headers
- `csp` -- parse and analyze Content Security Policy for unsafe directives ('unsafe-inline', 'unsafe-eval', wildcards, data: URIs)
- `cookies` -- check Set-Cookie attributes (Secure, HttpOnly, SameSite)
- `scan` -- run all checks in sequence (headers + CSP + cookies + CORS + endpoints)

Flags (shared): `--timeout N` (default 10).
Flags (`endpoints`/`scan`): `--wordlist FILE` (custom wordlist, one path per line), `--max-requests N` (default 50).
Flags (`cors`): `--origins ORIGIN [ORIGIN ...]` (default: evil.com, null, attacker.example.com).
Flags (`csp`): `--policy STRING` (analyze a CSP string directly instead of fetching from URL).

Output: findings with severity levels (high/medium/low), present/missing headers, endpoint discovery results.

---

### Exploit Development

#### `cb cache <subcommand>`
Extract binaries from dyld shared cache.

```
cb cache list                                      # List all images
cb cache list /path/to/dyld_shared_cache_arm64e   # Explicit cache path
cb cache extract libsystem_malloc.dylib            # Extract single library
cb cache extract-all --targets exploit             # Extract WindowServer, SkyLight, libsystem_malloc, ImageIO
cb cache symbols libsystem_malloc.dylib malloc     # Search symbols
```

Predefined target sets:
- `exploit`: WindowServer, SkyLight, libsystem_malloc, ImageIO, libRadiance

Auto-detects cache at `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/` or `/System/Library/dyld/`.

Extraction methods tried in order: `dyld_shared_cache_util` (Xcode), `ipsw` (brew), `dsc_extractor`.

Extracted binaries cached in `~/.cb/dsc_extract/`.

#### `cb struct <subcommand>`
Recover struct field layouts from ARM64 disassembly.

```
cb struct recover extracted_SkyLight --functions SLSSetWindowLevel,SLSSetWindowAlpha,SLSSetWindowTags,SLSMoveWindow
cb struct from-lldb --pid 1234 --address 0x7fff00001000 --size 512
cb struct format layout.json --struct-name CGSWindow
```

How it works:
1. Finds function addresses via `nm -defined-only`
2. Disassembles each function (first 200 instructions via Capstone)
3. Parses ARM64 ldr/str/ldp/stp for `[base_reg, #offset]` patterns
4. Auto-detects struct base register (most frequent, typically x19)
5. Merges field maps across functions, infers names from function semantics

Field naming heuristics: `SetWindowLevel` -> `level`, `SetWindowAlpha` -> `alpha`, `SetWindowTags` -> `tags`, `MoveWindow` -> `position`, `ReleaseWindow` -> `refcount`, `NewWindow` -> `window_id`.

Output includes C struct definition with padding, types, and offset comments.

#### `cb heap <subcommand>`
macOS heap zone classification and spray planning.

```
cb heap classify 288                                # Zone + size class
cb heap plan 288 --spray-count 5000 --language objc # Full spray plan with code
cb heap chart                                       # ASCII zone boundary chart
cb heap frida-hooks --zone tiny                     # Zone-aware allocation tracking
```

Zone boundaries (arm64):
| Zone | Size Range | Quantum |
|---|---|---|
| nano | 1 -- 256 | 16 B |
| tiny | 257 -- 1008 | 16 B |
| small | 1009 -- 130048 | 512 B |
| large | 130049+ | 16384 B (page) |

Spray plan output: zone classification, recommended count, fill-and-free strategy, generated ObjC/C spray code, magazine awareness notes.

#### `cb gadget <subcommand>`
ARM64 ROP/JOP gadget finder and chain builder.

```
cb gadget find extracted_WindowServer --type stack_pivot
cb gadget find target --type all --depth 8
cb gadget search target "ldp x29.*ret"
cb gadget chain target --template mprotect_shellcode --base-address 0x180000000
cb gadget multi binary1 binary2 binary3 --type register_control
cb gadget pac-check target
```

Gadget categories: `stack_pivot`, `register_control`, `memory_write`, `memory_read`, `syscall`, `function_call`.

Chain templates (macOS ARM64, x16 = syscall number):
- `execve`: x0=/bin/sh, x1=NULL, x2=NULL, x16=59
- `mprotect_shellcode`: x0=page_addr, x1=0x4000, x2=7(RWX), x16=74
- `posix_spawn`: posix_spawn() call chain
- `dlopen_dlsym`: dlopen + dlsym + blr call sequence

PAC awareness: detects `com.apple.private.pac.exception` entitlement (PAC disabled), hardened runtime, PAC key usage in gadgets. Filters gadgets ending in plain `ret` vs `retab`/`retaa`.

Output: Python (pwntools) or C exploit code.

---

## Workflow & Reporting

### `cb plan <binary>`
Generate a deterministic audit plan based on binary triage data. Inspects imports, protections, and format to decide which commands to run and in what order.

```
cb plan /usr/libexec/syspolicyd
cb plan target --deep
cb plan target --quick
cb plan target --from-triage triage.json
cb plan target --crash-dir ~/Library/Logs/DiagnosticReports
cb triage target --full | cb plan target --from-triage -
```

Flags: `--from-triage FILE|-` (use pre-parsed triage data instead of running triage), `--deep` (include Ghidra/LLDB steps if available), `--quick` (only priority-1 steps), `--crash-dir DIR` (include crash report processing).

Output: ordered list of steps with command, rationale, priority level (1-3), dependencies, estimated time. Includes a combined pipeline command for copy-paste execution. Reports whether Ghidra is required.

Plan logic: always includes triage + attack + vuln. Conditionally adds IPC/sandbox (if IPC imports detected), ObjC analysis (if ObjC runtime detected), fuzzing (if parser imports detected), Ghidra taint/decompilation (if `--deep`), crash processing (if `--crash-dir`), verify, and report.

### `cb report [binary]`
Generate structured vulnerability reports from audit data. Supports multiple templates and output formats (JSON, Markdown, HTML).

```
cb audit target -o audit.json && cb report target --from-audit audit.json
cb audit target | cb report --from-audit -
cb report target --from-audit audit.json --template bugbounty --markdown
cb report target --from-audit audit.json --template internal --html
cb report target --from-audit audit.json --template brief
cb report target --from-audit audit.json --title "WindowServer Audit" --author "Security Team"
```

Flags: `--from-audit FILE|-` (audit JSON input, file path or stdin), `--title TEXT` (default "Security Assessment Report"), `--author TEXT` (default "CatByte Toolkit"), `--template bugbounty|internal|brief` (default internal), `--markdown` (output raw Markdown), `--html` (output standalone HTML with styled charts).

Templates:
- `bugbounty`: summary, severity, findings, steps to reproduce, impact, recommendations
- `internal`: executive summary, target info table, findings overview table, detailed findings, recommendations
- `brief`: one-page summary with numbered findings list and risk/CVSS score

Output includes CVSS score estimates based on severity and attack vector, findings sorted by severity, and actionable recommendations.

### `cb context`
Context-window budget management for AI-assisted workflows. Estimates token counts and recommends `--max-results` values to fit output within LLM context limits.

```
cb context
cb context --estimate < large_output.json
cb triage target --full | cb context --estimate
cb context --set-default --budget 8000
```

Flags: `--estimate` (estimate token count of piped input), `--set-default` (save budget as default in ~/.cbconfig.json, use with `--budget`).

Output: current budget settings, estimated token count, whether output fits budget, recommended `--max-results` if over budget.

---

## Pipeline Chaining

Commands can pipe JSON to each other via stdin:

```bash
# Triage -> Vuln scan
cb triage target | cb vuln --from-triage -

# Crash -> Variant analysis
cb crash report.ips | cb variant --from-crash -

# Triage -> Plan -> Execute
cb triage target --full | cb plan target --from-triage -

# Audit -> Report
cb audit target | cb report --from-audit - --template bugbounty --markdown

# Estimate output size for AI context window
cb triage target --full | cb context --estimate

# Full exploit development workflow
cb cache extract-all --targets exploit
cb struct recover ~/.cb/dsc_extract/*/SkyLight \
  --functions SLSSetWindowLevel,SLSSetWindowAlpha,SLSSetWindowTags,SLSMoveWindow
cb heap plan 288 --spray-count 5000 --language objc
cb gadget chain ~/.cb/dsc_extract/*/WindowServer --template mprotect_shellcode
```

---

## Configuration

Config file: `~/.cbconfig.json`

```json
{
  "ghidra_home": "/Applications/ghidra_11.0",
  "ghidra_project_dir": "~/.cb/ghidra_projects",
  "lldb_python": "",
  "lldb_pythonpath": "",
  "default_arch": "auto",
  "default_format": "json",
  "default_max_results": 50,
  "dsc_extract_dir": "~/.cb/dsc_extract"
}
```

Ghidra auto-detection: checks `/Applications/ghidra`, `/Applications/Ghidra`, `~/ghidra`, Homebrew Caskroom.

---

## Standalone Entry Points

Every command is also available as a standalone binary:

`cb`, `cbtriage`, `cbghidra`, `cbvuln`, `cbgrep`, `cbcrash`, `cbattack`, `cbdiff`, `cbfuzz`, `cbtaint`, `cbcallgraph`, `cbobjc`, `cbsandbox`, `cbipc`, `cbvariant`, `cbaudit`, `cbhook`, `cblldb`, `cbprobe`, `cbcache`, `cbstruct`, `cbheap`, `cbgadget`, `cbweb`, `cbcontext`, `cbplan`, `cbreport`, `cbverify`

---

## Dependencies

**Required:** pwntools>=4.12, capstone>=5.0, pyelftools>=0.29, ROPGadget>=7.0

**Optional:** lief>=0.14 (better Mach-O parsing), Ghidra (decompilation/taint/callgraph), Frida (dynamic hooks), LLDB (debugging)

**System tools used:** otool, nm, codesign, strings, file, atos, objdump, clang, launchctl, dyld_shared_cache_util, ipsw

---

## Pattern Databases

### `cb/patterns/dangerous_functions.py`
- `DANGEROUS_IMPORTS`: dict keyed by function name, values have severity + vuln_type
- `IMPORT_CATEGORIES`: memory, string, file_io, network, process, ipc, crypto, objc_runtime
- `DANGEROUS_ENTITLEMENTS`: risk levels (critical/high/medium) with descriptions
- `HIGH_VALUE_SERVICES`: 19 root/privileged macOS services worth targeting
- `COMPLEX_INPUT_INDICATORS`: imports suggesting complex input handling
- `PARSER_INDICATORS`: file format parsing function hints

### `cb/patterns/gadget_patterns.py`
- `ARM64_CLASSIFIERS`: regex patterns per gadget category (used by `cb gadget`)
- `CHAIN_TEMPLATES`: macOS ARM64 chain recipes (used by `cb gadget chain`)
- `ARM64_GADGETS`: simple grep patterns (used by `cb grep --mode gadgets`)
- `X86_64_GADGETS`: x86_64 grep patterns
- `USEFUL_CHAINS`: chain descriptions with needed gadgets

### `cb/patterns/vuln_signatures.py`
Vulnerability pattern definitions for `cb variant`. Includes Chrome/V8/Mojo-specific patterns (v1.2.0).

### `cb/patterns/chrome_patterns.py`
Chrome/Chromium-specific vulnerability detection patterns (v1.2.0):
- `MOJO_IPC_VULN_PATTERNS`: Mojo IPC vulnerability regexes (self-owned UAF, Unretained, BigBuffer TOCTOU, missing ReportBadMessage)
- `CHROME_DANGEROUS_SYMBOLS`: categorized by component (mojo_ipc, v8_engine, partition_alloc, browser_process, blink_renderer, gpu_process)
- `V8_EXPLOIT_PATTERNS`: V8 sandbox escape indicators (type confusion, pointer table, ArrayBuffer)
- `CHROME_ENTITLEMENTS`: Chrome-specific macOS entitlement risk assessment
- `CHROME_FUZZ_TARGETS`: high-value fuzz target patterns (Mojo stubs, StructTraits, Blink parsers, image decoders)
- `SANDBOX_ESCAPE_INDICATORS`: sandbox boundary crossing patterns (IOSurface, Mach ports, file broker, GPU IPC)

---

## Typical Workflows

### Quick security assessment
```bash
cb triage target --checksec
cb audit target
```

### Deep vulnerability research
```bash
cb triage target --full -o triage.json
cb vuln target --decompiled --category all
cb taint target --source auto --depth 8
cb callgraph target --mode sinks
```

### XPC service analysis
```bash
cb ipc target --protocol
cb sandbox target --reachable-from /usr/libexec/sandboxd
cb probe com.apple.service --enumerate-messages
cb fuzz target --xpc --service com.apple.service
```

### Patch diffing
```bash
cb diff old_binary new_binary --mode security
cb diff old new --mode functions --fuzzy --decompile-changed
```

### Chrome/Chromium security audit (v1.2.0)
```bash
cb vuln /path/to/Chromium.app --chrome          # Mojo IPC, V8, sandbox patterns
cb vuln chrome_helper --chrome --category mojo   # Focus on Mojo IPC findings
cb fuzz chrome_helper --mojo --target MyInterface  # Mojo IPC fuzzer (MojoLPM)
cb fuzz chrome_helper --structure-aware --target ParseData  # FuzzedDataProvider harness
cb sandbox /path/to/Chrome.app --chrome          # Chrome sandbox profile analysis
```

### Crash-driven exploit development
```bash
cb crash --batch ~/Library/Logs/DiagnosticReports --since "7 days ago" --dedup
cb crash interesting.ips --generate-poc --poc-output poc.py
cb variant --from-crash interesting.ips --heuristic
```

### Planned audit with report
```bash
cb plan target --deep
cb audit target --deep -o audit.json
cb report target --from-audit audit.json --html > report.html
cb report target --from-audit audit.json --template bugbounty --markdown > report.md
```

### Verify crash with memory guards
```bash
cb verify target fuzzed_input.bin --timeout 30
cb verify target payload.dat --mode stdin --repeat 20
cb verify target payload.dat --no-guards  # baseline comparison
```

### Web application audit
```bash
cb web scan https://target.example.com
cb web headers https://target.example.com
cb web cors https://api.example.com --origins https://evil.com null
cb web endpoints https://target.example.com --wordlist custom.txt
```

### Full exploit chain development
```bash
# Extract targets from shared cache
cb cache extract-all --targets exploit

# Recover struct layout
cb struct recover ~/.cb/dsc_extract/*/SkyLight \
  --functions SLSSetWindowLevel,SLSSetWindowAlpha,SLSSetWindowTags

# Plan heap spray
cb heap plan 288 --spray-count 5000 --language objc

# Find gadgets and build ROP chain
cb gadget find ~/.cb/dsc_extract/*/WindowServer --type all
cb gadget chain ~/.cb/dsc_extract/*/WindowServer --template mprotect_shellcode

# Check PAC status
cb gadget pac-check ~/.cb/dsc_extract/*/ImageIO
```
