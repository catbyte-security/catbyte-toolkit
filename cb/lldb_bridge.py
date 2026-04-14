"""LLDB dynamic analysis bridge - orchestrates LLDB via subprocess + system Python."""
import json
import os
import subprocess
import sys

from cb.config import load_config

SCRIPT_DIR = os.path.join(os.path.dirname(__file__), "lldb_scripts")
JSON_START = "###CB_JSON_START###"
JSON_END = "###CB_JSON_END###"


class LLDBError(Exception):
    pass


def _detect_lldb_python():
    """Detect the LLDB Python framework path.

    Strategy:
    1. Check config for explicit lldb_pythonpath
    2. Run `lldb -P` to get the framework path
    3. Fall back to known Xcode locations
    """
    cfg = load_config()

    # 1. Explicit config
    explicit = cfg.get("lldb_pythonpath", "")
    if explicit and os.path.isdir(explicit):
        return explicit

    # 2. `lldb -P` auto-detection
    try:
        result = subprocess.run(
            ["lldb", "-P"], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            path = result.stdout.strip()
            if path and os.path.isdir(path):
                return path
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # 3. Known Xcode locations
    candidates = [
        "/Applications/Xcode.app/Contents/SharedFrameworks/LLDB.framework/Resources/Python",
        "/Library/Developer/CommandLineTools/Library/PrivateFrameworks/LLDB.framework/Resources/Python",
    ]
    for c in candidates:
        if os.path.isdir(c):
            return c

    return None


def _get_lldb_python():
    """Get the system Python path for running LLDB scripts."""
    cfg = load_config()
    explicit = cfg.get("lldb_python", "")
    if explicit and os.path.exists(explicit):
        return explicit

    # Prefer /usr/bin/python3 on macOS (has lldb module access)
    if os.path.exists("/usr/bin/python3"):
        return "/usr/bin/python3"

    return "python3"


def is_available():
    """Check if LLDB Python bindings are available."""
    python = _get_lldb_python()
    pythonpath = _detect_lldb_python()
    if not pythonpath:
        return False

    try:
        env = os.environ.copy()
        env["PYTHONPATH"] = pythonpath
        result = subprocess.run(
            [python, "-c", "import lldb; print('ok')"],
            capture_output=True, text=True, timeout=10, env=env,
        )
        return result.returncode == 0 and "ok" in result.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _run_lldb_script(script_name, args=None, timeout=60):
    """Run an LLDB helper script under system Python with LLDB PYTHONPATH.

    Returns parsed JSON output from the script.
    """
    python = _get_lldb_python()
    pythonpath = _detect_lldb_python()
    if not pythonpath:
        raise LLDBError(
            "LLDB Python framework not found. Ensure Xcode or Command Line Tools "
            "are installed, or set lldb_pythonpath in ~/.cbconfig.json"
        )

    script_path = os.path.join(SCRIPT_DIR, script_name)
    if not os.path.exists(script_path):
        raise LLDBError(f"LLDB script not found: {script_path}")

    cmd = [python, script_path] + (args or [])

    env = os.environ.copy()
    env["PYTHONPATH"] = pythonpath

    print(f"[*] Running LLDB script: {script_name}", file=sys.stderr)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, env=env,
        )
    except subprocess.TimeoutExpired:
        raise LLDBError(f"LLDB script timed out after {timeout}s")

    # Parse JSON from markers
    output = result.stdout
    start = output.find(JSON_START)
    end = output.find(JSON_END)

    if start != -1 and end != -1:
        json_str = output[start + len(JSON_START):end].strip()
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise LLDBError(f"Invalid JSON from script: {e}\nRaw: {json_str[:300]}")
        # Check for error response from script
        if isinstance(data, dict) and "error" in data:
            raise LLDBError(data["error"])
        return data

    # No JSON markers found
    stderr_tail = result.stderr[-500:] if result.stderr else ""
    stdout_tail = result.stdout[-500:] if result.stdout else ""
    if result.returncode != 0:
        raise LLDBError(
            f"Script failed (rc={result.returncode}).\n"
            f"Stderr: {stderr_tail}\nStdout: {stdout_tail}"
        )
    raise LLDBError(
        f"Script {script_name} produced no JSON output.\n"
        f"Stderr: {stderr_tail}\nStdout: {stdout_tail}"
    )


# --- Public API ---

def get_info(binary, timeout=30):
    """Get static target info: arch, UUID, sections, entry point, symbol counts."""
    return _run_lldb_script("lldb_info.py", [binary], timeout=timeout)


def get_modules(binary=None, pid=None, timeout=30):
    """List loaded dylibs/modules."""
    args = []
    if binary:
        args.extend(["--binary", binary])
    if pid is not None:
        args.extend(["--pid", str(pid)])
    return _run_lldb_script("lldb_modules.py", args, timeout=timeout)


def find_symbols(binary, pattern, max_results=50, timeout=30):
    """Find symbols matching a name/regex pattern."""
    return _run_lldb_script(
        "lldb_symbols.py",
        [binary, pattern, "--max-results", str(max_results)],
        timeout=timeout,
    )


def disassemble(binary, target_func, pid=None, count=50, timeout=30):
    """Disassemble a function or address range."""
    args = [binary, target_func, "--count", str(count)]
    if pid is not None:
        args.extend(["--pid", str(pid)])
    return _run_lldb_script("lldb_disasm.py", args, timeout=timeout)


def read_memory(pid, address, size=256, timeout=30):
    """Read process memory at an address."""
    return _run_lldb_script(
        "lldb_memory.py",
        [str(pid), address, str(size)],
        timeout=timeout,
    )


def get_backtrace(pid, timeout=30):
    """Get backtraces for all threads."""
    return _run_lldb_script("lldb_threads.py", [str(pid), "backtrace"], timeout=timeout)


def get_registers(pid, timeout=30):
    """Get registers for all threads."""
    return _run_lldb_script("lldb_threads.py", [str(pid), "registers"], timeout=timeout)


def run_with_breakpoints(binary, functions, args=None, collect=None,
                          count=10, timeout=60):
    """Launch binary, set breakpoints, collect data at each hit."""
    script_args = [binary] + functions
    script_args.extend(["--count", str(count)])
    script_args.extend(["--timeout", str(timeout)])
    if args:
        script_args.extend(["--args"] + args)
    if collect:
        script_args.extend(["--collect", ",".join(collect)])
    # Give subprocess extra time beyond the script's internal timeout
    return _run_lldb_script("lldb_breakpoint.py", script_args, timeout=timeout + 30)


def evaluate(pid, expression, timeout=30):
    """Evaluate an expression in a stopped process context."""
    return _run_lldb_script(
        "lldb_eval.py", [str(pid), expression], timeout=timeout
    )
