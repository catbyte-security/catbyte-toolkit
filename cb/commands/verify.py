"""cb verify - Crash-first verification under memory guards."""
import argparse
import os
import signal
import subprocess
import sys
import time

from cb.output import add_output_args, make_formatter


GUARD_ENV = {
    "MallocGuardEdges": "1",
    "MallocScribble": "1",
    "MallocStackLogging": "1",
    "MallocStackLoggingNoCompact": "1",
}


def register(subparsers):
    p = subparsers.add_parser("verify", help="Run binary under memory guards")
    p.add_argument("binary", help="Path to executable")
    p.add_argument("input", help="Input file, data, or '-' for stdin")
    p.add_argument("--mode", choices=["file", "stdin", "args"], default="file",
                   help="Input delivery mode (default: file)")
    p.add_argument("--timeout", type=int, default=10,
                   help="Execution timeout in seconds (default: 10)")
    p.add_argument("--args", nargs="*", default=[], dest="extra_args",
                   help="Additional CLI arguments")
    p.add_argument("--repeat", type=int, default=1,
                   help="Run N times for intermittent crashes")
    p.add_argument("--no-guards", action="store_true",
                   help="Disable MallocGuardEdges/Scribble (baseline comparison)")
    add_output_args(p)
    p.set_defaults(func=run)


def _signal_name(signum):
    """Get signal name from number."""
    try:
        return signal.Signals(signum).name
    except (ValueError, AttributeError):
        return f"SIG{signum}"


def _execute_once(binary, input_path, mode, extra_args, timeout, env):
    """Execute binary once and capture result."""
    cmd = [binary] + list(extra_args)
    stdin_data = None

    if mode == "file":
        if input_path and input_path != "/dev/null":
            cmd.append(input_path)
    elif mode == "stdin":
        if input_path and input_path != "-":
            try:
                with open(input_path, "rb") as f:
                    stdin_data = f.read()
            except OSError:
                stdin_data = b""
    elif mode == "args":
        if input_path and os.path.isfile(input_path):
            try:
                with open(input_path) as f:
                    lines = [l.strip() for l in f if l.strip()]
                cmd.extend(lines)
            except OSError:
                pass

    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            timeout=timeout,
            env=env,
        )
        elapsed = round(time.time() - t0, 3)
        result = {
            "exit_code": proc.returncode,
            "elapsed_seconds": elapsed,
            "timed_out": False,
            "stdout_size": len(proc.stdout),
            "stderr_size": len(proc.stderr),
        }

        # Check for crash (negative return code = signal)
        if proc.returncode < 0:
            signum = -proc.returncode
            result["crashed"] = True
            result["crash_summary"] = {
                "signal": _signal_name(signum),
                "signal_number": signum,
            }
        else:
            result["crashed"] = False

        # Check for ASAN output
        stderr_text = proc.stderr.decode("utf-8", errors="replace")
        if "ERROR: AddressSanitizer:" in stderr_text:
            result["crashed"] = True
            result["asan_detected"] = True
            import re
            m = re.search(r"ERROR: AddressSanitizer: (\S+)", stderr_text)
            if m:
                result.setdefault("crash_summary", {})["bug_type"] = m.group(1)
            m = re.search(r"(READ|WRITE) of size (\d+)", stderr_text)
            if m:
                result.setdefault("crash_summary", {})["access_type"] = m.group(1)
                result.setdefault("crash_summary", {})["access_size"] = int(m.group(2))

        return result

    except subprocess.TimeoutExpired:
        elapsed = round(time.time() - t0, 3)
        return {
            "exit_code": None,
            "elapsed_seconds": elapsed,
            "crashed": False,
            "timed_out": True,
        }
    except OSError as e:
        return {
            "exit_code": None,
            "elapsed_seconds": 0,
            "crashed": False,
            "error": str(e),
        }


def run(args):
    out = make_formatter(args)
    binary = args.binary

    # Validate
    if not os.path.isfile(binary):
        out.emit({"error": f"Not a file: {binary}"}, "verify")
        return
    if not os.access(binary, os.X_OK):
        out.emit({"error": f"Not executable: {binary}"}, "verify")
        return

    # Build environment
    env = dict(os.environ)
    if not args.no_guards:
        env.update(GUARD_ENV)

    out.status(f"Verifying {binary} with input {args.input}")
    if not args.no_guards:
        out.status("Memory guards enabled: MallocGuardEdges, MallocScribble")

    # Run
    all_results = []
    total_crashes = 0

    for i in range(args.repeat):
        if args.repeat > 1:
            out.status(f"Run {i + 1}/{args.repeat}...")
        result = _execute_once(binary, args.input, args.mode,
                               args.extra_args, args.timeout, env)
        all_results.append(result)
        if result.get("crashed"):
            total_crashes += 1

    # Aggregate
    if args.repeat == 1:
        output = {
            "binary": binary,
            "input": args.input,
            "mode": args.mode,
            "guards_enabled": not args.no_guards,
            "total_runs": 1,
            "crashes": total_crashes,
            "results": all_results[0],
        }
    else:
        output = {
            "binary": binary,
            "input": args.input,
            "mode": args.mode,
            "guards_enabled": not args.no_guards,
            "total_runs": args.repeat,
            "crashes": total_crashes,
            "crash_rate": round(total_crashes / args.repeat, 2),
            "results": all_results,
        }

    # Exploitability assessment if crashed
    if total_crashes > 0:
        crash_result = next(r for r in all_results if r.get("crashed"))
        try:
            from cb.commands.crash import analyze_exploitability
            cs = crash_result.get("crash_summary", {})
            output["exploitability"] = analyze_exploitability(cs)
        except Exception:
            pass

    out.emit(output, "verify")


def main():
    parser = argparse.ArgumentParser(prog="cbverify",
                                     description="Crash-first verifier")
    parser.add_argument("binary", help="Path to executable")
    parser.add_argument("input", help="Input file or '-' for stdin")
    parser.add_argument("--mode", choices=["file", "stdin", "args"], default="file")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--args", nargs="*", default=[], dest="extra_args")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--no-guards", action="store_true")
    add_output_args(parser)
    args = parser.parse_args()
    run(args)
