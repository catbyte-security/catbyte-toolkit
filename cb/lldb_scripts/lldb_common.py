"""Shared utilities for LLDB helper scripts (runs under system Python with lldb module)."""
import json
import os
import signal
import sys

JSON_START = "###CB_JSON_START###"
JSON_END = "###CB_JSON_END###"


def emit_json(data):
    """Print JSON between markers for the bridge to parse."""
    print(JSON_START, flush=True)
    print(json.dumps(data, default=str), flush=True)
    print(JSON_END, flush=True)


def emit_error(msg):
    """Emit an error response."""
    emit_json({"error": str(msg)})


def create_debugger(async_mode=False):
    """Create and configure an SBDebugger instance."""
    import lldb
    dbg = lldb.SBDebugger.Create()
    dbg.SetAsync(async_mode)
    return dbg


def create_target(dbg, path):
    """Create a target from a binary path with validation."""
    import lldb
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Binary not found: {path}")
    error = lldb.SBError()
    target = dbg.CreateTarget(path, None, None, True, error)
    if not target or not target.IsValid():
        raise RuntimeError(f"Failed to create target for {path}: {error}")
    return target


def attach_to_pid(target, pid):
    """Attach to a running process. Returns (process, error_msg).
    The process should be detached (not killed) on cleanup."""
    import lldb
    error = lldb.SBError()
    listener = target.GetDebugger().GetListener()
    process = target.AttachToProcessWithID(listener, pid, error)
    if not process or not process.IsValid() or error.Fail():
        raise RuntimeError(f"Failed to attach to PID {pid}: {error}")
    return process


def launch_process(target, args=None, stop_at_entry=True, env=None):
    """Launch a process under the debugger. Returns process.
    The process should be killed on cleanup."""
    import lldb
    error = lldb.SBError()
    launch_info = lldb.SBLaunchInfo(args or [])
    launch_info.SetLaunchFlags(
        lldb.eLaunchFlagStopAtEntry if stop_at_entry else 0
    )
    if env:
        for k, v in env.items():
            launch_info.SetEnvironmentEntries([f"{k}={v}"], True)
    process = target.Launch(launch_info, error)
    if not process or not process.IsValid() or error.Fail():
        raise RuntimeError(f"Failed to launch process: {error}")
    return process


def cleanup_process(process, detach=False):
    """Clean up a process - detach for attached, kill for launched."""
    if process is None or not process.IsValid():
        return
    import lldb
    state = process.GetState()
    if state == lldb.eStateExited:
        return
    try:
        if detach:
            process.Detach()
        else:
            process.Kill()
    except Exception:
        pass


def cleanup_debugger(dbg):
    """Destroy a debugger instance."""
    import lldb
    if dbg and dbg.IsValid():
        lldb.SBDebugger.Destroy(dbg)


def setup_timeout(seconds, cleanup_fn=None):
    """Set a SIGALRM-based timeout. cleanup_fn is called before exit."""
    def handler(signum, frame):
        if cleanup_fn:
            try:
                cleanup_fn()
            except Exception:
                pass
        emit_error(f"Operation timed out after {seconds}s")
        sys.exit(1)

    signal.signal(signal.SIGALRM, handler)
    signal.alarm(seconds)


def cancel_timeout():
    """Cancel any pending SIGALRM timeout."""
    signal.alarm(0)
