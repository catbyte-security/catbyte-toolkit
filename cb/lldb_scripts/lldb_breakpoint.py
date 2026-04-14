#!/usr/bin/env python3
"""Launch binary with breakpoints and collect data at each hit.

The killer feature: agents can observe dynamic behavior without interactive REPL.

Runs under system Python with LLDB module.
Usage: lldb_breakpoint.py <binary> <func1> [func2...] [--args ...] [--collect ...] [--count N] [--timeout T]
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from lldb_common import (
    emit_json, emit_error, create_debugger, create_target,
    cleanup_process, cleanup_debugger,
    setup_timeout, cancel_timeout,
)

# Argument registers by architecture
ARG_REGS = {
    "arm64": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
    "aarch64": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
    "x86_64": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
}


def collect_hit_data(thread, target, collect_types, arch_key):
    """Collect data at a breakpoint hit."""
    import lldb
    frame = thread.GetFrameAtIndex(0)
    if not frame.IsValid():
        return {"error": "invalid frame"}

    data = {
        "function": frame.GetFunctionName() or frame.GetSymbol().GetName() if frame.GetSymbol().IsValid() else "unknown",
        "address": hex(frame.GetPC()),
    }

    if "args" in collect_types:
        # Read argument registers
        arg_regs = ARG_REGS.get(arch_key, ARG_REGS.get("arm64", []))
        args = {}
        for reg_name in arg_regs:
            reg = frame.FindRegister(reg_name)
            if reg.IsValid():
                val = reg.GetValueAsUnsigned(0)
                args[reg_name] = hex(val)
        data["args"] = args

    if "registers" in collect_types:
        regs = {}
        for rs_idx in range(frame.GetRegisters().GetSize()):
            reg_set = frame.GetRegisters().GetValueAtIndex(rs_idx)
            if not reg_set.IsValid():
                continue
            # Only GPR for brevity
            if "general" not in reg_set.GetName().lower():
                continue
            for r_idx in range(reg_set.GetNumChildren()):
                reg = reg_set.GetChildAtIndex(r_idx)
                if reg.IsValid():
                    regs[reg.GetName()] = reg.GetValue() or hex(reg.GetValueAsUnsigned(0))
        data["registers"] = regs

    if "backtrace" in collect_types:
        frames = []
        for j in range(min(thread.GetNumFrames(), 20)):
            f = thread.GetFrameAtIndex(j)
            if not f.IsValid():
                continue
            func = f.GetFunction()
            sym = f.GetSymbol()
            name = None
            if func.IsValid():
                name = func.GetDisplayName() or func.GetName()
            elif sym.IsValid():
                name = sym.GetName()
            mod = f.GetModule()
            mod_name = mod.GetFileSpec().GetFilename() if mod.IsValid() else None
            frames.append({
                "index": j,
                "pc": hex(f.GetPC()),
                "function": name,
                "module": mod_name,
            })
        data["backtrace"] = frames

    return data


def main():
    if len(sys.argv) < 3:
        emit_error("Usage: lldb_breakpoint.py <binary> <func1> [func2...] [--args ...] [--collect ...] [--count N] [--timeout T]")
        sys.exit(1)

    binary = sys.argv[1]

    # Parse arguments
    functions = []
    proc_args = []
    collect_str = "args,backtrace"
    max_count = 10
    timeout = 60
    parsing_args = False

    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--args":
            parsing_args = True
            i += 1
            continue
        elif arg == "--collect" and i + 1 < len(sys.argv):
            parsing_args = False
            collect_str = sys.argv[i + 1]
            i += 2
            continue
        elif arg == "--count" and i + 1 < len(sys.argv):
            parsing_args = False
            max_count = int(sys.argv[i + 1])
            i += 2
            continue
        elif arg == "--timeout" and i + 1 < len(sys.argv):
            parsing_args = False
            timeout = int(sys.argv[i + 1])
            i += 2
            continue
        elif arg.startswith("--"):
            parsing_args = False
            i += 1
            continue

        if parsing_args:
            proc_args.append(arg)
        else:
            functions.append(arg)
        i += 1

    if not functions:
        emit_error("No functions specified for breakpoints")
        sys.exit(1)

    collect_types = [c.strip() for c in collect_str.split(",")]

    dbg = None
    process = None

    setup_timeout(timeout + 5, lambda: cleanup_process(process) if process else None)

    try:
        import lldb
        dbg = create_debugger(async_mode=False)
        target = create_target(dbg, binary)

        # Determine architecture for argument registers
        triple = target.GetTriple()
        if "arm64" in triple or "aarch64" in triple:
            arch_key = "arm64"
        elif "x86_64" in triple:
            arch_key = "x86_64"
        else:
            arch_key = "arm64"  # default

        # Set breakpoints
        bp_info = []
        for func_name in functions:
            bp = target.BreakpointCreateByName(func_name)
            if not bp.IsValid() or bp.GetNumLocations() == 0:
                bp_info.append({
                    "function": func_name,
                    "status": "not_found",
                    "locations": 0,
                })
            else:
                bp_info.append({
                    "function": func_name,
                    "status": "set",
                    "locations": bp.GetNumLocations(),
                    "id": bp.GetID(),
                })

        # Launch process
        error = lldb.SBError()
        launch_info = lldb.SBLaunchInfo(proc_args)
        process = target.Launch(launch_info, error)
        if not process or not process.IsValid() or error.Fail():
            emit_error(f"Failed to launch process: {error}")
            sys.exit(1)

        # Collect breakpoint hits
        hits = []
        start_time = time.time()

        while len(hits) < max_count:
            # Check timeout
            if time.time() - start_time > timeout:
                break

            state = process.GetState()
            if state == lldb.eStateExited:
                break

            if state == lldb.eStateStopped:
                # Check all threads for breakpoint stops
                found_bp = False
                for ti in range(process.GetNumThreads()):
                    thread = process.GetThreadAtIndex(ti)
                    if thread.GetStopReason() == lldb.eStopReasonBreakpoint:
                        hit_data = collect_hit_data(thread, target, collect_types, arch_key)
                        hit_data["hit_number"] = len(hits) + 1
                        hit_data["thread_index"] = ti
                        hit_data["tid"] = thread.GetThreadID()
                        hits.append(hit_data)
                        found_bp = True
                        break

                if not found_bp:
                    # Stopped for another reason (signal, etc.)
                    break

                # Continue execution
                error = process.Continue()
                if error is not None and hasattr(error, 'Fail') and error.Fail():
                    break
            else:
                break

        # Process exit info
        exit_status = None
        if process.GetState() == lldb.eStateExited:
            exit_status = process.GetExitStatus()

        cancel_timeout()
        emit_json({
            "binary": os.path.abspath(binary),
            "functions": functions,
            "process_args": proc_args,
            "collect": collect_types,
            "architecture": arch_key,
            "breakpoints": bp_info,
            "hit_count": len(hits),
            "max_count": max_count,
            "exit_status": exit_status,
            "elapsed_seconds": round(time.time() - start_time, 2),
            "hits": hits,
        })

    except Exception as e:
        cancel_timeout()
        emit_error(str(e))
        sys.exit(1)
    finally:
        if process:
            cleanup_process(process, detach=False)  # Kill launched process
        if dbg:
            cleanup_debugger(dbg)


if __name__ == "__main__":
    main()
