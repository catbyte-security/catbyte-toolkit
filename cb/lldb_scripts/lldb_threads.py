#!/usr/bin/env python3
"""Get thread backtraces and registers for a running process.

Runs under system Python with LLDB module.
Usage: lldb_threads.py <pid> <backtrace|registers>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from lldb_common import (
    emit_json, emit_error, create_debugger,
    attach_to_pid, cleanup_process, cleanup_debugger,
    setup_timeout, cancel_timeout,
)


def get_backtraces(process, target):
    """Collect backtraces for all threads."""
    threads = []
    for i in range(process.GetNumThreads()):
        thread = process.GetThreadAtIndex(i)
        if not thread.IsValid():
            continue

        frames = []
        for j in range(thread.GetNumFrames()):
            frame = thread.GetFrameAtIndex(j)
            if not frame.IsValid():
                continue

            pc = frame.GetPC()
            func = frame.GetFunction()
            sym = frame.GetSymbol()
            module = frame.GetModule()

            func_name = None
            if func.IsValid():
                func_name = func.GetDisplayName() or func.GetName()
            elif sym.IsValid():
                func_name = sym.GetName()

            mod_name = None
            if module.IsValid():
                mod_name = module.GetFileSpec().GetFilename()

            frames.append({
                "index": j,
                "pc": hex(pc),
                "function": func_name,
                "module": mod_name,
                "line_entry": str(frame.GetLineEntry()) if frame.GetLineEntry().IsValid() else None,
            })

        threads.append({
            "index": i,
            "tid": thread.GetThreadID(),
            "name": thread.GetName() or f"thread-{i}",
            "stop_reason": str(thread.GetStopReason()),
            "frame_count": thread.GetNumFrames(),
            "frames": frames,
        })

    return threads


def get_registers_data(process, target):
    """Collect registers for all threads."""
    threads = []
    for i in range(process.GetNumThreads()):
        thread = process.GetThreadAtIndex(i)
        if not thread.IsValid():
            continue

        frame = thread.GetFrameAtIndex(0)
        if not frame.IsValid():
            continue

        register_sets = []
        for rs_idx in range(frame.GetRegisters().GetSize()):
            reg_set = frame.GetRegisters().GetValueAtIndex(rs_idx)
            if not reg_set.IsValid():
                continue

            regs = {}
            for r_idx in range(reg_set.GetNumChildren()):
                reg = reg_set.GetChildAtIndex(r_idx)
                if reg.IsValid():
                    regs[reg.GetName()] = reg.GetValue() or hex(reg.GetValueAsUnsigned(0))

            register_sets.append({
                "name": reg_set.GetName(),
                "registers": regs,
            })

        threads.append({
            "index": i,
            "tid": thread.GetThreadID(),
            "name": thread.GetName() or f"thread-{i}",
            "register_sets": register_sets,
        })

    return threads


def main():
    if len(sys.argv) < 3:
        emit_error("Usage: lldb_threads.py <pid> <backtrace|registers>")
        sys.exit(1)

    pid = int(sys.argv[1])
    mode = sys.argv[2]

    if mode not in ("backtrace", "registers"):
        emit_error(f"Unknown mode: {mode}. Use 'backtrace' or 'registers'")
        sys.exit(1)

    dbg = None
    process = None

    setup_timeout(25)

    try:
        import lldb
        dbg = create_debugger()
        target = dbg.CreateTarget("")
        process = attach_to_pid(target, pid)

        if mode == "backtrace":
            threads = get_backtraces(process, target)
            cancel_timeout()
            emit_json({
                "pid": pid,
                "thread_count": len(threads),
                "threads": threads,
            })
        else:
            threads = get_registers_data(process, target)
            cancel_timeout()
            emit_json({
                "pid": pid,
                "thread_count": len(threads),
                "threads": threads,
            })

    except Exception as e:
        cancel_timeout()
        emit_error(str(e))
        sys.exit(1)
    finally:
        if process:
            cleanup_process(process, detach=True)
        if dbg:
            cleanup_debugger(dbg)


if __name__ == "__main__":
    main()
