#!/usr/bin/env python3
"""List loaded dylibs/modules for a binary or running process.

Runs under system Python with LLDB module.
Usage: lldb_modules.py [--binary <path>] [--pid <pid>]
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from lldb_common import (
    emit_json, emit_error, create_debugger, create_target,
    attach_to_pid, cleanup_process, cleanup_debugger,
    setup_timeout, cancel_timeout,
)


def main():
    binary = None
    pid = None

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--binary" and i + 1 < len(args):
            binary = args[i + 1]
            i += 2
        elif args[i] == "--pid" and i + 1 < len(args):
            pid = int(args[i + 1])
            i += 2
        else:
            # Positional fallback for binary
            binary = args[i]
            i += 1

    if not binary and pid is None:
        emit_error("Usage: lldb_modules.py [--binary <path>] [--pid <pid>]")
        sys.exit(1)

    dbg = None
    process = None
    detach = False

    setup_timeout(25)

    try:
        import lldb
        dbg = create_debugger()

        if pid is not None:
            # Attach to running process
            if binary:
                target = create_target(dbg, binary)
            else:
                target = dbg.CreateTarget("")
            process = attach_to_pid(target, pid)
            detach = True
        else:
            target = create_target(dbg, binary)

        modules = []
        for i in range(target.GetNumModules()):
            mod = target.GetModuleAtIndex(i)
            if not mod.IsValid():
                continue

            file_spec = mod.GetFileSpec()
            path = os.path.join(file_spec.GetDirectory() or "",
                                file_spec.GetFilename() or "")
            uuid = mod.GetUUIDString()
            triple = mod.GetTriple()

            # Get base address
            num_sections = mod.GetNumSections()
            base_addr = None
            if num_sections > 0:
                sec = mod.GetSectionAtIndex(0)
                if sec.IsValid():
                    addr = sec.GetLoadAddress(target)
                    if addr != 0xFFFFFFFFFFFFFFFF:
                        base_addr = hex(addr)
                    else:
                        base_addr = hex(sec.GetFileAddress())

            modules.append({
                "path": path,
                "uuid": uuid,
                "triple": triple,
                "base_address": base_addr,
                "num_symbols": mod.GetNumSymbols(),
                "num_sections": num_sections,
            })

        cancel_timeout()
        emit_json({
            "binary": os.path.abspath(binary) if binary else None,
            "pid": pid,
            "module_count": len(modules),
            "modules": modules,
        })

    except Exception as e:
        cancel_timeout()
        emit_error(str(e))
        sys.exit(1)
    finally:
        if process:
            cleanup_process(process, detach=detach)
        if dbg:
            cleanup_debugger(dbg)


if __name__ == "__main__":
    main()
