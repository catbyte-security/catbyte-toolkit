# cb  - Binary Analysis Toolkit for macOS/iOS Security Research

A command-line toolkit for binary security analysis, vulnerability research, and exploit development on macOS and iOS targets. 30+ commands covering reconnaissance, vulnerability scanning, IPC analysis, crash triage, fuzzer generation, cryptographic primitive detection, Ghidra/LLDB integration, and more.

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

**Cryptographic Analysis**
- `cb crypto`  - Identify crypto primitives in stripped binaries by byte fingerprint (AES S-box, SHA round constants, ECC curve parameters, etc.). Flags weak/broken algorithms (MD5, DES, RC4, SHA-1) and rolled crypto (modified S-boxes detected by Hamming distance).

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

# Cryptographic primitive detection
cb crypto /opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib --render text
cb crypto suspect.bin --algorithms aes,des,rc4 --render markdown -o report.md
cb crypto firmware.bin --no-heuristics       # constants only, fastest

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

## Cryptographic Analysis

`cb crypto` detects cryptographic primitives in compiled binaries by their immutable byte fingerprints. You can strip symbols, but you cannot strip an AES S-box.

**What it detects**

- Block ciphers: AES, DES, Blowfish, RC2, TEA/XTEA
- Stream ciphers: ChaCha20, Salsa20
- Hashes: SHA-1/256/512, MD5, MD2, SHA-3/Keccak, BLAKE2b, BLAKE2s, Whirlpool
- ECC curves: P-256, secp256k1, Curve25519, Ed25519
- Asymmetric (via ASN.1 OIDs): RSA, ECDSA
- CRC tables: CRC-32 IEEE, CRC-32C Castagnoli
- Library markers: OpenSSL, LibreSSL, BoringSSL, CommonCrypto

**Beyond constant matching**

- Modified S-box detection: a 256-byte permutation that differs from the standard AES S-box by a small Hamming distance is a strong signal for rolled or "obfuscated" crypto.
- High-entropy region detection: blocks of bytes with near-uniform distribution flag potential embedded keys, encrypted blobs, or packed code.
- AES cluster detection: co-located AES tables in a small range strengthen confidence beyond a single hit.
- Dual-use disambiguation: BLAKE2b IV bytes are identical to SHA-512 H init bytes; the scanner uses K-table presence to resolve ambiguity. Same for BLAKE2s vs SHA-256 and MD5 H vs SHA-1 H.

**Risk-scored output**

Every detected primitive is scored: `critical` for broken algorithms (MD5, DES, RC4, MD2), `warn` for deprecated ones (SHA-1, 3DES, Blowfish, RC2), `ok` for modern primitives (AES, SHA-256+, ChaCha20, Curve25519). Action items list specific replacement guidance.

```bash
# Colored TUI report with action items
cb crypto target --render text

# Markdown for audit docs / PR comments
cb crypto target --render markdown -o crypto-audit.md

# JSON for AI/pipeline consumption (default)
cb crypto target --max-results 100

# Restrict to a single family
cb crypto target --algorithms aes,sha256,sha512

# Tune the modified-S-box scan stride (lower = more thorough, higher = faster)
cb crypto target --sbox-step 16
```

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
  commands/           # One file per command (30+ modules)
  crypto/             # Cryptographic primitive fingerprints, scanner, heuristics, report
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
