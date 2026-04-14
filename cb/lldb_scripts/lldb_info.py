#!/usr/bin/env python3
"""Get static target info: arch, UUID, sections, entry point, symbol counts.

Runs under system Python with LLDB module.
Usage: lldb_info.py <binary_path>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from lldb_common import (
    emit_json, emit_error, create_debugger, create_target,
    cleanup_debugger, setup_timeout, cancel_timeout,
)


def main():
    if len(sys.argv) < 2:
        emit_error("Usage: lldb_info.py <binary>")
        sys.exit(1)

    binary = sys.argv[1]
    dbg = None

    setup_timeout(25)

    try:
        import lldb
        dbg = create_debugger()
        target = create_target(dbg, binary)

        # Architecture
        triple = target.GetTriple()

        # UUID
        exe_module = target.GetModuleAtIndex(0)
        uuid_str = exe_module.GetUUIDString() if exe_module.IsValid() else ""

        # Entry point
        entry = target.GetModuleAtIndex(0).GetObjectFileEntryPointAddress()
        entry_addr = entry.GetLoadAddress(target) if entry.IsValid() else None
        if entry_addr is not None and entry_addr == 0xFFFFFFFFFFFFFFFF:
            # Use file address if load address unavailable
            entry_addr = entry.GetFileAddress()

        # Sections
        sections = []
        for i in range(exe_module.GetNumSections()):
            sec = exe_module.GetSectionAtIndex(i)
            if sec.IsValid():
                sections.append({
                    "name": sec.GetName(),
                    "address": hex(sec.GetFileAddress()),
                    "size": sec.GetByteSize(),
                    "type": str(sec.GetSectionType()),
                })

        # Symbol counts
        sym_total = exe_module.GetNumSymbols()
        sym_types = {}
        for i in range(sym_total):
            sym = exe_module.GetSymbolAtIndex(i)
            stype = str(sym.GetType())
            sym_types[stype] = sym_types.get(stype, 0) + 1

        # Platform info
        platform = target.GetPlatform()
        platform_name = platform.GetName() if platform.IsValid() else ""

        result = {
            "binary": os.path.abspath(binary),
            "triple": triple,
            "uuid": uuid_str,
            "entry_point": hex(entry_addr) if entry_addr is not None else None,
            "platform": platform_name,
            "sections": sections,
            "symbol_count": sym_total,
            "symbol_types": sym_types,
        }

        cancel_timeout()
        emit_json(result)

    except Exception as e:
        cancel_timeout()
        emit_error(str(e))
        sys.exit(1)
    finally:
        if dbg:
            cleanup_debugger(dbg)


if __name__ == "__main__":
    main()
