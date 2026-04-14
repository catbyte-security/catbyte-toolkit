# cb  - Binary Analysis Toolkit for macOS/iOS Security Research

A command-line toolkit for binary security analysis, vulnerability research, and exploit development on macOS and iOS targets. 30+ commands covering reconnaissance, vulnerability scanning, IPC analysis, crash triage, fuzzer generation, Ghidra/LLDB integration, and more.

Built for security researchers, bug bounty hunters, and red teamers working on Apple platforms.

## Features

**Reconnaissance**
- `cb triage`  - Quick security overview (protections, imports, strings, sections)
- `cb attack`  - Attack surface mapping (IPC endpoints, parsers, entitlements)
- `cb objc`  - Objective-C runtime analysis (classes, selectors, dangerous methods)
- `cb grep`  - Binary content search (disassembly, bytes, strings, ROP/JOP gadgets)

**Vulnerability Analysis**
- `cb vuln`  - Pattern-based vulnerability scanner with optional Ghidra decompilation
- `cb variant`  - Find variant bugs from 12 known vulnerability patterns
- `cb taint`  - Inter-procedural taint tracking (sources to sinks via Ghidra)
- `cb callgraph`  - Call graph recovery and dangerous sink reachability
- `cb audit`  - Full security audit (runs triage + attack + vuln + objc + ipc + sandbox + variant)

**IPC & Sandbox**
- `cb ipc`  - XPC/Mach/MIG handler analysis
- `cb sandbox`  - Sandbox profile and entitlement analysis
- `cb probe`  - Live XPC service probing (compiles ObjC probe binary on first use)

**Dynamic Analysis**
- `cb lldb`  - Scripted LLDB debugging (modules, symbols, memory, breakpoints)
- `cb hook`  - Frida instrumentation harness generation
- `cb verify`  - Run binaries under macOS memory guards (MallocGuardEdges, MallocScribble)

**Exploit Development**
- `cb cache`  - Extract binaries from dyld shared cache
- `cb struct`  - Recover struct field layouts from ARM64 disassembly
- `cb heap`  - macOS heap zone classification and spray planning
- `cb gadget`  - ARM64 ROP/JOP gadget finder and chain builder (PAC-aware)

**Crash Analysis**
- `cb crash`  - Crash report parser with exploitability assessment and PoC generation
- `cb diff`  - Binary version diffing with security-focused mode

**Web Security**
- `cb web`  - Security header, CSP, CORS, cookie, and endpoint auditing

**Workflow**
- `cb plan`  - Generate deterministic audit plans from triage data
- `cb report`  - Structured vulnerability reports (Markdown, HTML, bug bounty templates)
- `cb context`  - Token budget management for AI-assisted workflows

## Install

```bash
# Clone and install
git clone https://github.com/catbyte-security/catbyte-toolkit.git
cd catbyte-toolkit
pip install -e .

# With full Mach-O parsing support
pip install -e ".[full]"
```

**Requirements:** Python 3.10+, macOS (primary target)

**Required dependencies:** pwntools, capstone, pyelftools, ROPGadget

**Optional:** [LIEF](https://lief.re/) (better Mach-O parsing), [Ghidra](https://ghidra-sre.org/) (decompilation/taint/callgraph), [Frida](https://frida.re/) (dynamic hooks), LLDB (debugging)

## Quick Start

```bash
# Security overview of a binary
cb triage /usr/libexec/syspolicyd

# Full audit
cb audit /usr/libexec/syspolicyd

# Attack surface mapping
cb attack /usr/libexec/syspolicyd --depth deep

# Find vulnerabilities with Ghidra decompilation
cb vuln target --decompiled --severity high

# XPC service analysis pipeline
cb ipc target --protocol
cb sandbox target --reachable-from /usr/libexec/sandboxd
cb probe com.apple.securityd --enumerate-messages

# Crash-driven exploit development
cb crash report.ips --generate-poc --poc-output poc.py
cb variant --from-crash report.ips --heuristic

# Exploit chain development
cb cache extract-all --targets exploit
cb struct recover ~/.cb/dsc_extract/*/SkyLight --functions SLSSetWindowLevel,SLSSetWindowAlpha
cb heap plan 288 --spray-count 5000 --language objc
cb gadget chain ~/.cb/dsc_extract/*/WindowServer --template mprotect_shellcode
```

## Pipeline Chaining

All commands output JSON and can be piped together:

```bash
# Triage -> Vulnerability scan
cb triage target | cb vuln --from-triage -

# Crash -> Variant analysis
cb crash report.ips | cb variant --from-crash -

# Full audit -> Report
cb audit target | cb report --from-audit - --template bugbounty --markdown

# Triage -> Plan -> Execute
cb triage target --full | cb plan target --from-triage -
```

## Output Formats

Every command supports structured output:

```bash
cb triage target --format json      # JSON (default, for AI/pipeline)
cb triage target --format text      # Human-readable
cb triage target --summary          # One-line summary
cb triage target --max-results 20   # Cap list lengths
cb triage target -q                 # Suppress progress messages
```

## Configuration

Optional config at `~/.cbconfig.json`:

```json
{
  "ghidra_home": "/Applications/ghidra_11.0",
  "ghidra_project_dir": "~/.cb/ghidra_projects",
  "default_format": "json",
  "default_max_results": 50
}
```

Ghidra is auto-detected from common install locations if not configured.

## Chrome/Chromium Analysis

Includes specialized patterns for Chrome security research:

```bash
cb vuln /path/to/Chromium.app --chrome          # Mojo IPC, V8, sandbox patterns
cb fuzz chrome_helper --mojo --target MyInterface  # Mojo IPC fuzzer (MojoLPM)
cb sandbox /path/to/Chrome.app --chrome          # Chrome sandbox profile analysis
```

## Architecture

```
cb/
  cli.py              # Unified dispatcher: cb <command>
  output.py           # OutputFormatter (JSON/text/summary)
  config.py           # ~/.cbconfig.json loader
  macho.py            # Mach-O parser (otool/nm/codesign/LIEF)
  disasm.py           # Capstone disassembler + objdump fallback
  ghidra_bridge.py    # Ghidra headless analysis
  lldb_bridge.py      # LLDB scripted debugging
  commands/           # One file per command (30 modules)
  patterns/           # Vulnerability signatures, gadget patterns, Chrome patterns
  ghidra_scripts/     # Java scripts for Ghidra headless
  lldb_scripts/       # Python scripts for LLDB
  probe_scripts/      # ObjC probing tools
```

## Tests

```bash
pip install -e .
pytest tests/ -v
```

## License

MIT
