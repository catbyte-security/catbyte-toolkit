"""cb crash - Crash report parser and exploitability analysis."""
import argparse
import glob
import json
import os
import re
import subprocess
import sys
import time

from cb.output import add_output_args, make_formatter


def register(subparsers):
    p = subparsers.add_parser("crash", help="Analyze crash reports")
    p.add_argument("report", help="Path to crash report (.ips, .crash, or ASAN log)")
    p.add_argument("--symbolicate", action="store_true",
                   help="Attempt to symbolicate addresses")
    p.add_argument("--binary", type=str, default=None,
                   help="Binary to symbolicate against")
    p.add_argument("--show-registers", action="store_true", default=True)
    p.add_argument("--backtrace-depth", type=int, default=20)
    p.add_argument("--all-threads", action="store_true",
                   help="Show all threads (default: crashed thread only)")
    p.add_argument("--batch", action="store_true",
                   help="Analyze all crash reports in directory")
    p.add_argument("--since", type=str, default=None,
                   help="Filter by age (e.g. '2 hours ago', '1 day ago')")
    p.add_argument("--dedup", action="store_true",
                   help="Group by crash signature (default in batch mode)")
    p.add_argument("--parallel", type=int, default=1,
                   help="Number of parallel workers for batch mode (default: 1)")
    p.add_argument("--generate-poc", action="store_true",
                   help="Generate proof-of-concept skeleton from crash")
    p.add_argument("--poc-output", type=str, default=None,
                   help="Write PoC to file")
    add_output_args(p)
    p.set_defaults(func=run)


def run(args):
    out = make_formatter(args)
    path = args.report

    # Batch mode: directory of crash reports
    if os.path.isdir(path) or getattr(args, 'batch', False):
        run_batch(args, out)
        return

    with open(path) as f:
        content = f.read()

    # Auto-detect format
    report_type = detect_format(content)
    out.status(f"Detected format: {report_type}")

    if report_type == "ips_json":
        result = parse_ips(content, args)
    elif report_type == "legacy_crash":
        result = parse_legacy_crash(content, args)
    elif report_type == "asan":
        result = parse_asan(content, args)
    elif report_type == "tsan":
        result = parse_tsan(content, args)
    elif report_type == "msan":
        result = parse_msan(content, args)
    else:
        result = parse_generic(content, args)

    # Symbolicate if requested
    if args.symbolicate and args.binary:
        out.status("Symbolicating addresses...")
        symbolicate_backtrace(result.get("backtrace", []), args.binary)

    # Exploitability analysis (enhanced)
    result["analysis"] = analyze_exploitability(
        result.get("crash_summary", {}),
        result.get("backtrace", []),
        result.get("registers", {}),
    )

    # Generate PoC if requested
    if getattr(args, 'generate_poc', False):
        poc = generate_poc(result, args)
        result["poc_code"] = poc["code"]
        result["poc_type"] = poc["type"]
        if args.poc_output:
            with open(args.poc_output, "w") as f:
                f.write(poc["code"])
            out.status(f"PoC written to {args.poc_output}")

    out.emit(result, "crash")


def detect_format(content):
    stripped = content.strip()
    if stripped.startswith("{"):
        try:
            json.loads(stripped)
            return "ips_json"
        except json.JSONDecodeError:
            pass
    if "ERROR: AddressSanitizer:" in content:
        return "asan"
    if "WARNING: ThreadSanitizer:" in content:
        return "tsan"
    if "WARNING: MemorySanitizer:" in content:
        return "msan"
    if "Process:" in content and "Thread" in content and "crashed" in content.lower():
        return "legacy_crash"
    return "unknown"


def parse_ips(content, args):
    """Parse macOS .ips JSON crash report."""
    data = json.loads(content)
    result = {"crash_summary": {}, "backtrace": [], "registers": {}}

    # Basic info
    cs = result["crash_summary"]
    cs["process"] = data.get("procName", data.get("name", "unknown"))
    cs["pid"] = data.get("pid", -1)
    cs["parent_process"] = data.get("parentProc", "unknown")
    cs["timestamp"] = data.get("captureTime", data.get("timestamp", ""))

    # Exception info
    exc = data.get("exception", {})
    cs["signal"] = exc.get("signal", "unknown")
    cs["exception_type"] = exc.get("type", "unknown")
    cs["exception_codes"] = exc.get("codes", "")
    cs["faulting_address"] = exc.get("faultAddr", "unknown")

    # Termination reason
    term = data.get("termination", {})
    if term:
        cs["termination_reason"] = term.get("reason", "")
        cs["termination_namespace"] = term.get("namespace", "")

    # ASI (Application Specific Information)
    asi = data.get("asi", {})
    if asi:
        cs["app_specific_info"] = asi

    # Threads and backtrace
    threads = data.get("threads", [])
    crashed_idx = data.get("faultingThread", 0)

    for idx, thread in enumerate(threads):
        if not args.all_threads and idx != crashed_idx:
            continue

        frames = thread.get("frames", [])
        is_crashed = (idx == crashed_idx)

        for fi, frame in enumerate(frames[:args.backtrace_depth]):
            result["backtrace"].append({
                "thread": idx,
                "frame": fi,
                "crashed_thread": is_crashed,
                "image_offset": frame.get("imageOffset", ""),
                "image_name": frame.get("imageIndex", ""),
                "symbol": frame.get("symbol", ""),
                "symbol_location": frame.get("symbolLocation", 0),
            })

    # Thread state (registers)
    if args.show_registers and threads:
        crashed_thread = threads[crashed_idx] if crashed_idx < len(threads) else None
        if crashed_thread:
            ts = crashed_thread.get("threadState", {})
            flavor = ts.get("flavor", "")
            regs = ts.get("x", [])
            if regs:
                for i, val in enumerate(regs):
                    result["registers"][f"x{i}"] = format_reg(val)
            # Special registers
            for name in ("fp", "lr", "sp", "pc", "cpsr"):
                v = ts.get(name, {})
                if v:
                    result["registers"][name] = format_reg(v)

    # Binary images for context
    images = data.get("usedImages", [])
    if images:
        result["binary_images"] = [
            {"name": img.get("name", ""), "base": img.get("base", ""),
             "uuid": img.get("uuid", "")}
            for img in images[:20]
        ]

    return result


def format_reg(val):
    if isinstance(val, dict):
        return hex(val.get("value", 0))
    if isinstance(val, int):
        return hex(val)
    return str(val)


def parse_legacy_crash(content, args):
    """Parse legacy macOS .crash text format."""
    result = {"crash_summary": {}, "backtrace": [], "registers": {}}
    cs = result["crash_summary"]

    # Process info
    m = re.search(r"Process:\s+(.+?)(?:\s+\[(\d+)\])?$", content, re.M)
    if m:
        cs["process"] = m.group(1).strip()
        cs["pid"] = int(m.group(2)) if m.group(2) else -1

    # Exception type
    m = re.search(r"Exception Type:\s+(.+)", content)
    if m:
        cs["exception_type"] = m.group(1).strip()

    m = re.search(r"Exception Codes:\s+(.+)", content)
    if m:
        cs["exception_codes"] = m.group(1).strip()

    # Signal
    m = re.search(r"Exception Type:.*\((\w+)\)", content)
    if m:
        cs["signal"] = m.group(1)

    # Termination reason
    m = re.search(r"Termination Reason:\s+(.+)", content)
    if m:
        cs["termination_reason"] = m.group(1).strip()

    # Faulting address from exception codes
    m = re.search(r"KERN_\w+\s+at\s+(0x[0-9a-fA-F]+)", content)
    if m:
        cs["faulting_address"] = m.group(1)

    # Crashed thread
    m = re.search(r"Crashed Thread:\s+(\d+)", content)
    crashed_thread = int(m.group(1)) if m else 0

    # Parse backtrace
    bt_pattern = re.compile(
        r"^(\d+)\s+(\S+)\s+(0x[0-9a-fA-F]+)\s+(.+)$", re.M
    )
    in_crashed = False
    for line in content.splitlines():
        if f"Thread {crashed_thread} Crashed:" in line or \
           (f"Thread {crashed_thread}" in line and "Crashed" in line):
            in_crashed = True
            continue
        if in_crashed:
            if line.strip() == "" or line.startswith("Thread "):
                if line.startswith(f"Thread {crashed_thread}"):
                    continue
                break
            m = bt_pattern.match(line.strip())
            if m:
                result["backtrace"].append({
                    "frame": int(m.group(1)),
                    "module": m.group(2),
                    "address": m.group(3),
                    "symbol": m.group(4).strip(),
                    "crashed_thread": True,
                })
                if len(result["backtrace"]) >= args.backtrace_depth:
                    break

    # Parse registers
    if args.show_registers:
        reg_section = False
        for line in content.splitlines():
            if "Thread State" in line:
                reg_section = True
                continue
            if reg_section:
                if line.strip() == "" or line.startswith("Thread"):
                    break
                # Parse "  x0: 0x... x1: 0x..." format
                for m in re.finditer(r"(\w+):\s+(0x[0-9a-fA-F]+)", line):
                    result["registers"][m.group(1)] = m.group(2)

    return result


def parse_asan(content, args):
    """Parse AddressSanitizer report."""
    result = {"crash_summary": {}, "backtrace": [], "registers": {}}
    cs = result["crash_summary"]
    cs["sanitizer"] = "AddressSanitizer"

    # Bug type
    m = re.search(r"ERROR: AddressSanitizer: (\S+)", content)
    if m:
        cs["bug_type"] = m.group(1)

    # Access info
    m = re.search(r"(READ|WRITE) of size (\d+)", content)
    if m:
        cs["access_type"] = m.group(1)
        cs["access_size"] = int(m.group(2))

    # Address
    m = re.search(r"on (?:address|unknown address) (0x[0-9a-fA-F]+)", content)
    if m:
        cs["faulting_address"] = m.group(1)

    # Address description
    m = re.search(r"(0x[0-9a-fA-F]+) is located (\d+) bytes (\w+) (?:of|inside) "
                  r"(\d+)-byte region \[(0x[0-9a-fA-F]+),(0x[0-9a-fA-F]+)\)", content)
    if m:
        cs["address_description"] = {
            "offset_bytes": int(m.group(2)),
            "direction": m.group(3),
            "region_size": int(m.group(4)),
            "region_start": m.group(5),
            "region_end": m.group(6),
        }

    # Stack traces
    sections = {
        "crash": r"(?:ERROR|READ|WRITE).*?\n((?:\s+#\d+.*\n)+)",
        "alloc": r"(?:previously allocated|allocated).*?\n((?:\s+#\d+.*\n)+)",
        "free": r"(?:previously freed|freed).*?\n((?:\s+#\d+.*\n)+)",
    }

    for label, pattern in sections.items():
        m = re.search(pattern, content)
        if m:
            frames = parse_asan_frames(m.group(1), args.backtrace_depth)
            if label == "crash":
                result["backtrace"] = frames
            else:
                result[f"{label}_trace"] = frames

    return result


def parse_asan_frames(text, max_depth=20):
    """Parse ASAN stack frames."""
    frames = []
    for m in re.finditer(
        r"#(\d+)\s+(0x[0-9a-fA-F]+)\s+(?:in\s+)?(\S+)?(?:\s+(\S+:\d+))?", text
    ):
        frames.append({
            "frame": int(m.group(1)),
            "address": m.group(2),
            "symbol": m.group(3) or "",
            "source": m.group(4) or "",
        })
        if len(frames) >= max_depth:
            break
    return frames


def parse_tsan(content, args):
    """Parse ThreadSanitizer report."""
    result = {"crash_summary": {}, "backtrace": [], "registers": {}}
    cs = result["crash_summary"]
    cs["sanitizer"] = "ThreadSanitizer"

    m = re.search(r"WARNING: ThreadSanitizer: (.+?)(?:\s*\()", content)
    if m:
        cs["bug_type"] = m.group(1).strip()

    # Extract racing accesses
    accesses = []
    for m in re.finditer(
        r"(Read|Write) of size (\d+) at (0x[0-9a-fA-F]+) by (?:main )?thread(?: T(\d+))?",
        content
    ):
        accesses.append({
            "type": m.group(1),
            "size": int(m.group(2)),
            "address": m.group(3),
            "thread": m.group(4) or "main",
        })
    cs["racing_accesses"] = accesses

    # First stack trace
    m = re.search(r"((?:\s+#\d+.*\n)+)", content)
    if m:
        result["backtrace"] = parse_asan_frames(m.group(1), args.backtrace_depth)

    return result


def parse_msan(content, args):
    """Parse MemorySanitizer report."""
    result = {"crash_summary": {}, "backtrace": [], "registers": {}}
    cs = result["crash_summary"]
    cs["sanitizer"] = "MemorySanitizer"

    m = re.search(r"WARNING: MemorySanitizer: (.+)", content)
    if m:
        cs["bug_type"] = m.group(1).strip()

    m = re.search(r"((?:\s+#\d+.*\n)+)", content)
    if m:
        result["backtrace"] = parse_asan_frames(m.group(1), args.backtrace_depth)

    return result


def parse_generic(content, args):
    """Best-effort parse of unknown crash format."""
    result = {
        "crash_summary": {"format": "unknown"},
        "backtrace": [],
        "registers": {},
        "raw_excerpt": content[:2000],
    }

    # Try to find any stack-trace-like patterns
    for m in re.finditer(r"(0x[0-9a-fA-F]{8,16})\s+(?:in\s+)?(\S+)", content):
        result["backtrace"].append({
            "address": m.group(1),
            "symbol": m.group(2),
        })
        if len(result["backtrace"]) >= args.backtrace_depth:
            break

    return result


def symbolicate_backtrace(backtrace, binary_path):
    """Symbolicate addresses using atos."""
    addresses = []
    for frame in backtrace:
        addr = frame.get("address", "")
        if addr and addr.startswith("0x"):
            addresses.append(addr)
    if not addresses:
        return

    try:
        cmd = ["atos", "-o", binary_path, "-fullPath"] + addresses
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        symbols = result.stdout.strip().splitlines()
        addr_idx = 0
        for frame in backtrace:
            addr = frame.get("address", "")
            if addr and addr.startswith("0x") and addr_idx < len(symbols):
                sym = symbols[addr_idx].strip()
                if sym and not sym.startswith("0x"):
                    frame["symbolicated"] = sym
                addr_idx += 1
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass


def analyze_exploitability(crash_summary, backtrace=None, registers=None):
    """Enhanced exploitability assessment with register and backtrace analysis."""
    if backtrace is None:
        backtrace = []
    if registers is None:
        registers = {}

    analysis = {
        "likely_bug_type": "unknown",
        "exploitability": "unknown",
        "notes": [],
        "attack_vector": "unknown",
        "pc_corrupted": False,
        "controllable_registers": [],
    }

    bug_type = crash_summary.get("bug_type", "")
    signal = crash_summary.get("signal", "")
    exc_type = crash_summary.get("exception_type", "")
    fault_addr = crash_summary.get("faulting_address", "")
    sanitizer = crash_summary.get("sanitizer", "")

    # Determine fault address value
    try:
        addr_val = int(fault_addr, 16) if fault_addr and fault_addr != "unknown" else -1
    except (ValueError, TypeError):
        addr_val = -1

    # ASAN-specific
    if sanitizer == "AddressSanitizer":
        asan_types = {
            "heap-buffer-overflow": ("heap_overflow", "high",
                                     "Heap buffer overflow - likely exploitable for code execution"),
            "stack-buffer-overflow": ("stack_overflow", "high",
                                      "Stack buffer overflow - potential RCE via return address overwrite"),
            "heap-use-after-free": ("use_after_free", "high",
                                    "Use-after-free - exploitable for arbitrary read/write"),
            "double-free": ("double_free", "high",
                            "Double free - heap metadata corruption, likely exploitable"),
            "heap-buffer-underflow": ("heap_underflow", "medium",
                                      "Heap underflow - may corrupt adjacent heap metadata"),
            "stack-use-after-return": ("stack_uar", "medium",
                                       "Stack use-after-return"),
            "global-buffer-overflow": ("global_overflow", "medium",
                                       "Global buffer overflow"),
            "use-after-poison": ("use_after_poison", "medium",
                                  "Access to poisoned memory"),
            "alloc-dealloc-mismatch": ("alloc_mismatch", "low",
                                       "Allocator mismatch - unlikely to be exploitable"),
            "SEGV": ("null_deref", "low",
                     "Null dereference via ASAN"),
        }
        for key, (btype, expl, note) in asan_types.items():
            if key in bug_type:
                analysis["likely_bug_type"] = btype
                analysis["exploitability"] = expl
                analysis["notes"].append(note)
                break
        if analysis["likely_bug_type"] == "unknown":
            analysis["likely_bug_type"] = bug_type
            analysis["exploitability"] = "medium"
            analysis["notes"].append(f"ASAN bug type: {bug_type}")

        # Access size matters
        access_size = crash_summary.get("access_size", 0)
        if access_size > 8:
            analysis["notes"].append(
                f"Large access ({access_size} bytes) - more useful for exploitation")

        return analysis

    # TSAN
    if sanitizer == "ThreadSanitizer":
        analysis["likely_bug_type"] = "data_race"
        analysis["exploitability"] = "medium"
        analysis["notes"].append("Data race - may be exploitable depending on racing operation")
        return analysis

    # Signal-based analysis
    if signal == "SIGSEGV" or "SIGSEGV" in exc_type:
        if 0 <= addr_val < 0x10000:
            analysis["likely_bug_type"] = "null_deref"
            analysis["exploitability"] = "low"
            analysis["notes"].append("NULL or near-NULL dereference")
        elif addr_val > 0:
            analysis["likely_bug_type"] = "invalid_read_write"
            analysis["exploitability"] = "medium"
            analysis["notes"].append(
                f"Access violation at {fault_addr} - investigate if address is controlled")
    elif signal == "SIGABRT" or "SIGABRT" in exc_type:
        analysis["likely_bug_type"] = "abort"
        analysis["exploitability"] = "medium"
        analysis["notes"].append(
            "Abort - check for heap corruption (malloc/free assert) or failed assertion")
    elif signal == "SIGBUS" or "SIGBUS" in exc_type:
        analysis["likely_bug_type"] = "bus_error"
        analysis["exploitability"] = "medium"
        analysis["notes"].append("Bus error - alignment issue or invalid mapping")
    elif signal == "SIGILL" or "SIGILL" in exc_type:
        analysis["likely_bug_type"] = "illegal_instruction"
        analysis["exploitability"] = "high"
        analysis["notes"].append(
            "Illegal instruction - may indicate control flow hijack (pc corruption)")
    elif signal == "SIGTRAP" or "SIGTRAP" in exc_type:
        analysis["likely_bug_type"] = "trap"
        analysis["exploitability"] = "low"
        analysis["notes"].append("Debug trap / __builtin_trap()")

    # Exception code hints
    exc_codes = crash_summary.get("exception_codes", "")
    if "KERN_PROTECTION_FAILURE" in exc_codes:
        analysis["notes"].append(
            "Protection failure - write to read-only memory, potential for exploitation")
        if analysis["exploitability"] == "low":
            analysis["exploitability"] = "medium"

    # === Enhanced P0-level analysis ===

    # PC corruption detection
    pc = registers.get("pc", registers.get("rip", ""))
    if pc:
        try:
            pc_val = int(pc, 16)
            # PC pointing to unmapped/unusual memory = control flow hijack
            if 0 < pc_val < 0x10000:
                analysis["pc_corrupted"] = True
                analysis["exploitability"] = "high"
                analysis["notes"].append(
                    f"PC/RIP points to low address ({pc}) - likely control flow hijack")
            elif pc_val > 0x7fff00000000 and pc_val < 0x800000000000:
                # Non-canonical address on x86_64
                analysis["pc_corrupted"] = True
                analysis["exploitability"] = "high"
                analysis["notes"].append("PC/RIP is non-canonical - corrupted return address")
            # Check if PC looks like ASCII/controlled data
            pc_bytes = pc_val.to_bytes(8, "little")
            if all(0x20 <= b <= 0x7e for b in pc_bytes[:4]):
                analysis["pc_corrupted"] = True
                analysis["exploitability"] = "high"
                analysis["notes"].append(
                    f"PC contains ASCII-like bytes ({pc_bytes[:4]}) - likely controlled value")
        except (ValueError, OverflowError):
            pass

    # Register analysis for controlled values
    interesting_patterns = []
    for reg_name, reg_val in registers.items():
        if reg_name in ("cpsr", "fpcr", "fpsr"):
            continue
        try:
            val = int(reg_val, 16) if isinstance(reg_val, str) else int(reg_val)
            # Check for controlled patterns
            if val == 0x4141414141414141 or val == 0x41414141:
                analysis["controllable_registers"].append(reg_name)
                interesting_patterns.append(f"{reg_name}=0x{'41'*8} (AAAA... pattern)")
            elif val != 0 and (val & 0xFFFF) == (val >> 16 & 0xFFFF) and val > 0xFFFF:
                # Repeating pattern suggests controlled data
                analysis["controllable_registers"].append(reg_name)
        except (ValueError, TypeError):
            pass

    if interesting_patterns:
        analysis["exploitability"] = "high"
        analysis["notes"].append(
            "Controlled data in registers: " + ", ".join(interesting_patterns))

    # Backtrace-based analysis
    if backtrace:
        bt_symbols = " ".join(
            f.get("symbol", f.get("symbolicated", "")) for f in backtrace[:5]
        ).lower()
        # Heap corruption indicators
        if any(x in bt_symbols for x in ["malloc", "free", "realloc", "szone",
                                           "nano_malloc", "tiny_malloc"]):
            if analysis["likely_bug_type"] in ("abort", "unknown"):
                analysis["likely_bug_type"] = "heap_corruption"
                analysis["exploitability"] = "high"
                analysis["notes"].append(
                    "Crash in allocator functions suggests heap metadata corruption")
        # ObjC autorelease pool corruption
        if "autorelease" in bt_symbols or "objc_release" in bt_symbols:
            analysis["notes"].append(
                "ObjC reference counting crash - possible use-after-free of ObjC object")
            if analysis["exploitability"] != "high":
                analysis["exploitability"] = "medium"

    # Determine attack vector
    if backtrace:
        bt_all = " ".join(
            f.get("symbol", f.get("symbolicated", "")) for f in backtrace
        ).lower()
        if any(x in bt_all for x in ["recv", "socket", "http", "url", "network"]):
            analysis["attack_vector"] = "remote"
        elif any(x in bt_all for x in ["parse", "read", "decode", "image",
                                         "font", "pdf", "xml"]):
            analysis["attack_vector"] = "file_based"
        elif any(x in bt_all for x in ["xpc", "mach_msg", "mig", "ipc"]):
            analysis["attack_vector"] = "ipc"
        elif any(x in bt_all for x in ["iokit", "driver", "kext"]):
            analysis["attack_vector"] = "kernel"

    return analysis


def _process_single_crash(filepath):
    """Process one crash file. Module-level for multiprocessing pickling."""
    try:
        with open(filepath) as f:
            content = f.read()
        report_type = detect_format(content)
        parse_args = argparse.Namespace(
            backtrace_depth=20, all_threads=False, show_registers=False,
            symbolicate=False, binary=None,
        )
        if report_type == "ips_json":
            result = parse_ips(content, parse_args)
        elif report_type == "legacy_crash":
            result = parse_legacy_crash(content, parse_args)
        elif report_type == "asan":
            result = parse_asan(content, parse_args)
        elif report_type == "tsan":
            result = parse_tsan(content, parse_args)
        elif report_type == "msan":
            result = parse_msan(content, parse_args)
        else:
            result = parse_generic(content, parse_args)

        result["analysis"] = analyze_exploitability(
            result.get("crash_summary", {}),
            result.get("backtrace", []),
            result.get("registers", {}),
        )
        result["_file"] = filepath
        result["_mtime"] = os.path.getmtime(filepath)
        return result
    except Exception as e:
        return {"_file": filepath, "error": str(e)}


def run_batch(args, out):
    """Batch analysis of crash reports in a directory."""
    report_dir = args.report
    if not os.path.isdir(report_dir):
        out.emit({"error": f"Not a directory: {report_dir}"}, "crash")
        return

    # Collect crash files
    patterns = ["*.ips", "*.crash"]
    files = []
    for pat in patterns:
        files.extend(glob.glob(os.path.join(report_dir, pat)))
        files.extend(glob.glob(os.path.join(report_dir, "**", pat), recursive=True))
    files = sorted(set(files))

    # Filter by --since
    if args.since:
        cutoff = _parse_since(args.since)
        if cutoff:
            files = [f for f in files if os.path.getmtime(f) >= cutoff]

    if not files:
        out.emit({"total_reports": 0, "unique_signatures": 0, "groups": []}, "crash")
        return

    out.status(f"Processing {len(files)} crash reports...")

    # Parse each report (parallel or sequential)
    parallel = getattr(args, "parallel", 1)
    if parallel > 1 and len(files) > 1:
        from multiprocessing import Pool
        with Pool(processes=parallel) as pool:
            raw_results = pool.map(_process_single_crash, files)
    else:
        raw_results = [_process_single_crash(f) for f in files]

    # Filter out errors and report them
    results = []
    for r in raw_results:
        if "error" in r and "crash_summary" not in r:
            out.status(f"Warning: Failed to parse {r['_file']}: {r['error']}")
        else:
            results.append(r)

    # Generate signatures and group
    dedup = getattr(args, 'dedup', False) or getattr(args, 'batch', False)
    groups = _group_by_signature(results) if dedup else None

    batch_result = {
        "total_reports": len(results),
        "unique_signatures": len(groups) if groups else len(results),
    }
    if groups:
        batch_result["groups"] = groups
    else:
        batch_result["reports"] = [
            {
                "file": r["_file"],
                "process": r.get("crash_summary", {}).get("process", "unknown"),
                "exploitability": r.get("analysis", {}).get("exploitability", "unknown"),
                "bug_type": r.get("analysis", {}).get("likely_bug_type", "unknown"),
            }
            for r in results
        ]

    out.emit(batch_result, "crash")


def _parse_since(since_str):
    """Parse 'N hour/day ago' style time filters."""
    m = re.match(r"(\d+)\s*(hour|day|minute|week|month)s?\s*(?:ago)?", since_str.strip(), re.I)
    if not m:
        return None
    n = int(m.group(1))
    unit = m.group(2).lower()
    multipliers = {"minute": 60, "hour": 3600, "day": 86400, "week": 604800, "month": 2592000}
    seconds = n * multipliers.get(unit, 3600)
    return time.time() - seconds


def _crash_signature(result):
    """Generate a dedup signature from a crash result."""
    cs = result.get("crash_summary", {})
    bt = result.get("backtrace", [])
    exc_type = cs.get("exception_type", cs.get("bug_type", "unknown"))

    # Find faulting function from top of backtrace
    faulting_func = "unknown"
    offset = "0x0"
    for frame in bt[:3]:
        sym = frame.get("symbol", frame.get("symbolicated", ""))
        if sym and sym != "???" and not sym.startswith("0x"):
            faulting_func = sym.split("(")[0].split(" ")[-1].strip()
            sl = frame.get("symbol_location", frame.get("image_offset", "0"))
            offset = f"0x{sl:x}" if isinstance(sl, int) else str(sl)
            break

    return f"{exc_type}:{faulting_func}+{offset}"


def _group_by_signature(results):
    """Group crash results by signature for deduplication."""
    from collections import defaultdict
    groups = defaultdict(list)
    for r in results:
        sig = _crash_signature(r)
        groups[sig].append(r)

    output = []
    for sig, crashes in sorted(groups.items(), key=lambda x: -len(x[1])):
        exploitabilities = [c.get("analysis", {}).get("exploitability", "unknown") for c in crashes]
        sev_order = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
        max_expl = min(exploitabilities, key=lambda e: sev_order.get(e, 4))
        mtimes = [c.get("_mtime", 0) for c in crashes]
        processes = list(set(c.get("crash_summary", {}).get("process", "unknown") for c in crashes))
        bug_types = list(set(c.get("analysis", {}).get("likely_bug_type", "unknown") for c in crashes))

        output.append({
            "signature": sig,
            "count": len(crashes),
            "exploitability": max_expl,
            "first_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(min(mtimes))) if mtimes else "",
            "last_seen": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(max(mtimes))) if mtimes else "",
            "sample_report": crashes[0].get("_file", ""),
            "processes": processes,
            "bug_type": bug_types[0] if len(bug_types) == 1 else bug_types,
        })

    return output


def generate_poc(result, args):
    """Generate PoC skeleton from crash analysis."""
    cs = result.get("crash_summary", {})
    bt = result.get("backtrace", [])
    analysis = result.get("analysis", {})

    # Detect crash context from backtrace
    bt_text = " ".join(
        f.get("symbol", f.get("symbolicated", "")) for f in bt
    ).lower()

    process = cs.get("process", "unknown")
    attack_vector = analysis.get("attack_vector", "unknown")

    if "xpc" in bt_text or "_xpc_" in bt_text or attack_vector == "ipc":
        return _generate_xpc_poc(process, cs, bt, analysis)
    elif "mach_msg" in bt_text or "mig" in bt_text:
        return _generate_mach_poc(process, cs, bt, analysis)
    else:
        return _generate_generic_poc(process, cs, bt, analysis)


def _generate_xpc_poc(process, cs, bt, analysis):
    """Generate XPC-based PoC."""
    service_name = f"com.apple.{process}" if process != "unknown" else "com.apple.TARGET_SERVICE"
    bug_type = analysis.get("likely_bug_type", "unknown")

    code = f"""// XPC PoC skeleton for {process} crash
// Bug type: {bug_type}
// Auto-generated from crash report - MODIFY BEFORE USE
//
// Build: clang -framework Foundation -o poc poc.m
// Run:   ./poc

#import <Foundation/Foundation.h>
#include <xpc/xpc.h>

int main(int argc, char *argv[]) {{
    @autoreleasepool {{
        xpc_connection_t conn = xpc_connection_create_mach_service(
            "{service_name}",
            NULL,
            0  // or XPC_CONNECTION_MACH_SERVICE_PRIVILEGED
        );

        xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {{
            if (xpc_get_type(event) == XPC_TYPE_ERROR) {{
                NSLog(@"XPC Error: %s", xpc_dictionary_get_string(event, XPC_ERROR_KEY_DESCRIPTION));
            }} else {{
                NSLog(@"Response: %s", xpc_copy_description(event));
            }}
        }});
        xpc_connection_resume(conn);

        // TODO: Construct crash-triggering message
        // Based on crash analysis:
        //   Bug type: {bug_type}
        //   Exception: {cs.get('exception_type', 'unknown')}
        //   Faulting address: {cs.get('faulting_address', 'unknown')}
        xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);

        // TODO: Set message type / dispatch key
        // xpc_dictionary_set_int64(msg, "message", MESSAGE_ID);

        // TODO: Add crash-triggering payload
        // xpc_dictionary_set_data(msg, "key", payload, payload_size);

        xpc_object_t reply = xpc_connection_send_message_with_reply_sync(conn, msg);
        if (reply) {{
            NSLog(@"Reply: %s", xpc_copy_description(reply));
        }}

        NSLog(@"Done.");
    }}
    return 0;
}}
"""
    return {"type": "xpc", "code": code}


def _generate_mach_poc(process, cs, bt, analysis):
    """Generate Mach message PoC."""
    bug_type = analysis.get("likely_bug_type", "unknown")

    code = f"""// Mach message PoC skeleton for {process} crash
// Bug type: {bug_type}
// Auto-generated from crash report - MODIFY BEFORE USE
//
// Build: clang -o poc poc.c
// Run:   ./poc

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdio.h>
#include <string.h>

typedef struct {{
    mach_msg_header_t header;
    mach_msg_body_t body;
    // TODO: Add descriptors / inline data based on crash analysis
    char data[1024];
}} msg_t;

int main(int argc, char *argv[]) {{
    mach_port_t service_port;
    kern_return_t kr;

    // Look up target service
    kr = bootstrap_look_up(bootstrap_port, "com.apple.{process}", &service_port);
    if (kr != KERN_SUCCESS) {{
        fprintf(stderr, "bootstrap_look_up failed: %s\\n", mach_error_string(kr));
        return 1;
    }}

    msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    msg.header.msgh_size = sizeof(msg);
    msg.header.msgh_remote_port = service_port;
    msg.header.msgh_local_port = MACH_PORT_NULL;
    msg.header.msgh_id = 0; // TODO: Set message ID from crash context

    // TODO: Fill in crash-triggering payload
    // Bug type: {bug_type}
    // Exception: {cs.get('exception_type', 'unknown')}

    kr = mach_msg(&msg.header, MACH_SEND_MSG, msg.header.msgh_size,
                  0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {{
        fprintf(stderr, "mach_msg failed: %s\\n", mach_error_string(kr));
        return 1;
    }}

    printf("Message sent.\\n");
    return 0;
}}
"""
    return {"type": "mach", "code": code}


def _generate_generic_poc(process, cs, bt, analysis):
    """Generate generic C PoC."""
    bug_type = analysis.get("likely_bug_type", "unknown")
    faulting_func = "unknown"
    for frame in bt[:3]:
        sym = frame.get("symbol", frame.get("symbolicated", ""))
        if sym and not sym.startswith("0x"):
            faulting_func = sym
            break

    code = f"""// PoC skeleton for {process} crash
// Bug type: {bug_type}
// Crashing function: {faulting_func}
// Auto-generated from crash report - MODIFY BEFORE USE
//
// Build: clang -o poc poc.c
// Run:   ./poc <input_file>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {{
    if (argc < 2) {{
        fprintf(stderr, "Usage: %s <input_file>\\n", argv[0]);
        return 1;
    }}

    // Read input file
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {{ perror("open"); return 1; }}

    struct stat st;
    fstat(fd, &st);
    size_t size = st.st_size;

    void *data = malloc(size);
    if (!data) {{ perror("malloc"); close(fd); return 1; }}
    read(fd, data, size);
    close(fd);

    // TODO: Process data to trigger crash
    // Target function: {faulting_func}
    // Bug type: {bug_type}
    // Exception: {cs.get('exception_type', 'unknown')}
    // Faulting address: {cs.get('faulting_address', 'unknown')}

    printf("Input loaded: %zu bytes\\n", size);
    // TODO: Call target function or pass to service

    free(data);
    return 0;
}}
"""
    return {"type": "generic", "code": code}


def main():
    parser = argparse.ArgumentParser(prog="cbcrash", description="Crash analysis")
    parser.add_argument("report", help="Crash report path")
    parser.add_argument("--symbolicate", action="store_true")
    parser.add_argument("--binary", type=str, default=None)
    parser.add_argument("--show-registers", action="store_true", default=True)
    parser.add_argument("--backtrace-depth", type=int, default=20)
    parser.add_argument("--all-threads", action="store_true")
    parser.add_argument("--generate-poc", action="store_true")
    parser.add_argument("--poc-output", type=str, default=None)
    parser.add_argument("--batch", action="store_true")
    parser.add_argument("--since", type=str, default=None)
    parser.add_argument("--dedup", action="store_true")
    add_output_args(parser)
    args = parser.parse_args()
    run(args)
