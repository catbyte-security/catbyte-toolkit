#!/usr/bin/env python3
"""Disassemble a function or address range.

Runs under system Python with LLDB module.
Usage: lldb_disasm.py <binary> <func|0xaddr> [--pid N] [--count N]
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
    if len(sys.argv) < 3:
        emit_error("Usage: lldb_disasm.py <binary> <func|0xaddr> [--pid N] [--count N]")
        sys.exit(1)

    binary = sys.argv[1]
    func_or_addr = sys.argv[2]
    pid = None
    count = 50

    args = sys.argv[3:]
    i = 0
    while i < len(args):
        if args[i] == "--pid" and i + 1 < len(args):
            pid = int(args[i + 1])
            i += 2
        elif args[i] == "--count" and i + 1 < len(args):
            count = int(args[i + 1])
            i += 2
        else:
            i += 1

    dbg = None
    process = None
    detach = False

    setup_timeout(25)

    try:
        import lldb
        dbg = create_debugger()
        target = create_target(dbg, binary)

        if pid is not None:
            process = attach_to_pid(target, pid)
            detach = True

        instructions = []
        func_name = None
        start_addr = None

        if func_or_addr.startswith("0x") or func_or_addr.startswith("0X"):
            # Disassemble from address
            addr_val = int(func_or_addr, 16)
            addr = lldb.SBAddress(addr_val, target)
            if not addr.IsValid():
                emit_error(f"Invalid address: {func_or_addr}")
                sys.exit(1)

            insts = target.ReadInstructions(addr, count)
            start_addr = func_or_addr

            for j in range(insts.GetSize()):
                inst = insts.GetInstructionAtIndex(j)
                if not inst.IsValid():
                    continue
                inst_addr = inst.GetAddress()
                load_addr = inst_addr.GetLoadAddress(target)
                if load_addr == 0xFFFFFFFFFFFFFFFF:
                    load_addr = inst_addr.GetFileAddress()
                instructions.append({
                    "address": hex(load_addr),
                    "mnemonic": inst.GetMnemonic(target),
                    "operands": inst.GetOperands(target),
                    "comment": inst.GetComment(target) or None,
                    "bytes": " ".join(f"{b:02x}" for b in inst.GetData(target).uint8s) if inst.GetData(target).IsValid() else None,
                })
        else:
            # Find function by name
            func_name = func_or_addr
            found = False
            for mi in range(target.GetNumModules()):
                mod = target.GetModuleAtIndex(mi)
                if not mod.IsValid():
                    continue
                for si in range(mod.GetNumSymbols()):
                    sym = mod.GetSymbolAtIndex(si)
                    if not sym.IsValid():
                        continue
                    name = sym.GetName() or ""
                    if name == func_name or name.endswith(f"::{func_name}"):
                        # Found the function
                        start = sym.GetStartAddress()
                        end = sym.GetEndAddress()
                        if not start.IsValid():
                            continue

                        file_start = start.GetFileAddress()
                        file_end = end.GetFileAddress() if end.IsValid() else file_start + 256

                        # Calculate instruction count from size
                        size = file_end - file_start
                        est_count = min(max(size // 4, 10), count)

                        insts = target.ReadInstructions(start, est_count)
                        start_addr = hex(file_start)

                        for j in range(insts.GetSize()):
                            inst = insts.GetInstructionAtIndex(j)
                            if not inst.IsValid():
                                continue
                            inst_addr = inst.GetAddress()
                            load_addr = inst_addr.GetLoadAddress(target)
                            if load_addr == 0xFFFFFFFFFFFFFFFF:
                                load_addr = inst_addr.GetFileAddress()
                            # Stop if we've gone past the function
                            if load_addr >= file_end:
                                break
                            instructions.append({
                                "address": hex(load_addr),
                                "mnemonic": inst.GetMnemonic(target),
                                "operands": inst.GetOperands(target),
                                "comment": inst.GetComment(target) or None,
                                "bytes": " ".join(f"{b:02x}" for b in inst.GetData(target).uint8s) if inst.GetData(target).IsValid() else None,
                            })

                        found = True
                        func_name = name
                        break
                if found:
                    break

            if not found:
                emit_error(f"Function not found: {func_or_addr}")
                sys.exit(1)

        cancel_timeout()
        emit_json({
            "binary": os.path.abspath(binary),
            "function": func_name,
            "start_address": start_addr,
            "pid": pid,
            "instruction_count": len(instructions),
            "instructions": instructions,
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
