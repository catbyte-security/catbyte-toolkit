"""cb probe - Live XPC service probing."""
import argparse
import json
import os
import subprocess
import sys
import tempfile

from cb.output import add_output_args, make_formatter


PROBE_CACHE_DIR = os.path.expanduser("~/.cb/probe_cache")
PROBE_SCRIPT = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                            "probe_scripts", "probe_xpc.m")


def register(subparsers):
    p = subparsers.add_parser("probe", help="Probe live XPC services")
    p.add_argument("service", help="Mach service name to probe")
    p.add_argument("--enumerate-messages", action="store_true",
                   help="Enumerate valid message IDs")
    p.add_argument("--range", type=str, default="0-31",
                   help="Message ID range for enumeration (default: 0-31)")
    p.add_argument("--key", type=str, default="message",
                   help="Dispatch key name (default: message)")
    p.add_argument("--timeout", type=int, default=2,
                   help="Response timeout in seconds (default: 2)")
    add_output_args(p)
    p.set_defaults(func=run)


def run(args):
    out = make_formatter(args)

    # Ensure probe binary is built
    probe_bin = _ensure_probe_binary(out)
    if not probe_bin:
        out.emit({"error": "Failed to build probe binary. "
                  "Ensure Xcode command line tools are installed."}, "probe")
        return

    # Build command
    cmd = [probe_bin, args.service]
    if args.enumerate_messages:
        start, end = _parse_range(args.range)
        cmd.extend(["--enumerate", str(start), str(end)])
    cmd.extend(["--key", args.key])
    cmd.extend(["--timeout", str(args.timeout)])

    out.status(f"Probing {args.service}...")

    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                          timeout=args.timeout * 40 + 10)
        result = _parse_probe_output(r.stdout)
        if not result:
            result = {"status": "error", "detail": "no output",
                      "stderr": r.stderr[:500] if r.stderr else ""}
    except subprocess.TimeoutExpired:
        result = {"status": "timeout", "detail": "probe process timed out"}
    except FileNotFoundError:
        result = {"status": "error", "detail": "probe binary not found"}

    out.emit(result, "probe")


def _ensure_probe_binary(out):
    """Build the probe binary if not cached."""
    os.makedirs(PROBE_CACHE_DIR, exist_ok=True)
    probe_bin = os.path.join(PROBE_CACHE_DIR, "probe_xpc")

    # Check if already built and up to date
    if os.path.exists(probe_bin):
        if not os.path.exists(PROBE_SCRIPT):
            return probe_bin
        if os.path.getmtime(probe_bin) > os.path.getmtime(PROBE_SCRIPT):
            return probe_bin

    if not os.path.exists(PROBE_SCRIPT):
        out.status("Warning: probe_xpc.m source not found")
        return None

    out.status("Building probe binary...")
    try:
        r = subprocess.run(
            ["clang", "-framework", "Foundation",
             "-o", probe_bin, PROBE_SCRIPT,
             "-O2", "-fobjc-arc"],
            capture_output=True, text=True, timeout=30
        )
        if r.returncode != 0:
            out.status(f"Build failed: {r.stderr[:200]}")
            return None
        os.chmod(probe_bin, 0o755)
        return probe_bin
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        out.status(f"Build failed: {e}")
        return None


def _parse_range(range_str):
    """Parse 'start-end' range string."""
    parts = range_str.split("-")
    if len(parts) == 2:
        try:
            return int(parts[0]), int(parts[1])
        except ValueError:
            pass
    return 0, 31


def _parse_probe_output(stdout):
    """Extract JSON from probe output markers."""
    start_marker = "###CB_JSON_START###"
    end_marker = "###CB_JSON_END###"
    start = stdout.find(start_marker)
    end = stdout.find(end_marker)
    if start >= 0 and end > start:
        json_str = stdout[start + len(start_marker):end].strip()
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass
    return None


def main():
    parser = argparse.ArgumentParser(prog="cbprobe", description="XPC service prober")
    parser.add_argument("service", help="Mach service name")
    parser.add_argument("--enumerate-messages", action="store_true")
    parser.add_argument("--range", type=str, default="0-31")
    parser.add_argument("--key", type=str, default="message")
    parser.add_argument("--timeout", type=int, default=2)
    add_output_args(parser)
    args = parser.parse_args()
    run(args)
