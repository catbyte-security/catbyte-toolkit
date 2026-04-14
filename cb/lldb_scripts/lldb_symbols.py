#!/usr/bin/env python3
"""Find symbols by name/regex pattern with demangling.

Runs under system Python with LLDB module.
Usage: lldb_symbols.py <binary> <pattern> [--max-results N]
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
from lldb_common import (
    emit_json, emit_error, create_debugger, create_target,
    cleanup_debugger, setup_timeout, cancel_timeout,
)


def main():
    if len(sys.argv) < 3:
        emit_error("Usage: lldb_symbols.py <binary> <pattern> [--max-results N]")
        sys.exit(1)

    binary = sys.argv[1]
    pattern = sys.argv[2]
    max_results = 50

    args = sys.argv[3:]
    i = 0
    while i < len(args):
        if args[i] == "--max-results" and i + 1 < len(args):
            max_results = int(args[i + 1])
            i += 2
        else:
            i += 1

    dbg = None

    setup_timeout(25)

    try:
        import lldb
        dbg = create_debugger()
        target = create_target(dbg, binary)

        # Compile regex pattern
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            # Fall back to literal match
            regex = re.compile(re.escape(pattern), re.IGNORECASE)

        symbols = []
        total_checked = 0

        for mi in range(target.GetNumModules()):
            mod = target.GetModuleAtIndex(mi)
            if not mod.IsValid():
                continue

            mod_name = mod.GetFileSpec().GetFilename() or ""

            for si in range(mod.GetNumSymbols()):
                sym = mod.GetSymbolAtIndex(si)
                if not sym.IsValid():
                    continue

                total_checked += 1
                name = sym.GetName() or ""
                mangled = sym.GetMangledName() or ""

                # Check if name or mangled name matches
                if regex.search(name) or (mangled and regex.search(mangled)):
                    addr = sym.GetStartAddress()
                    file_addr = addr.GetFileAddress() if addr.IsValid() else None

                    symbols.append({
                        "name": name,
                        "mangled": mangled if mangled and mangled != name else None,
                        "address": hex(file_addr) if file_addr is not None else None,
                        "size": sym.GetEndAddress().GetFileAddress() - file_addr
                               if file_addr is not None and sym.GetEndAddress().IsValid()
                               else None,
                        "type": str(sym.GetType()),
                        "module": mod_name,
                        "external": sym.IsExternal(),
                    })

                    if len(symbols) >= max_results:
                        break

            if len(symbols) >= max_results:
                break

        cancel_timeout()
        emit_json({
            "binary": os.path.abspath(binary),
            "pattern": pattern,
            "match_count": len(symbols),
            "symbols_checked": total_checked,
            "symbols": symbols,
        })

    except Exception as e:
        cancel_timeout()
        emit_error(str(e))
        sys.exit(1)
    finally:
        if dbg:
            cleanup_debugger(dbg)


if __name__ == "__main__":
    main()
