#!/usr/bin/env python3
"""Read process memory at an address.

Runs under system Python with LLDB module.
Usage: lldb_memory.py <pid> <address> [size]
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from lldb_common import (
    emit_json, emit_error, create_debugger,
    attach_to_pid, cleanup_process, cleanup_debugger,
    setup_timeout, cancel_timeout,
)


def format_hex_dump(data, base_addr):
    """Format bytes as hex dump with ASCII."""
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Pad hex part to fixed width
        hex_part = hex_part.ljust(47)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append({
            "address": hex(base_addr + offset),
            "hex": hex_part.strip(),
            "ascii": ascii_part,
        })
    return lines


def main():
    if len(sys.argv) < 3:
        emit_error("Usage: lldb_memory.py <pid> <address> [size]")
        sys.exit(1)

    pid = int(sys.argv[1])
    address = sys.argv[2]
    size = int(sys.argv[3]) if len(sys.argv) > 3 else 256

    # Clamp size
    size = min(size, 4096)

    addr_val = int(address, 16) if address.startswith("0x") else int(address)

    dbg = None
    process = None

    setup_timeout(25)

    try:
        import lldb
        dbg = create_debugger()
        target = dbg.CreateTarget("")
        process = attach_to_pid(target, pid)

        error = lldb.SBError()
        data = process.ReadMemory(addr_val, size, error)

        if error.Fail():
            emit_error(f"Failed to read memory at {address}: {error}")
            sys.exit(1)

        raw_bytes = list(data)
        hex_dump = format_hex_dump(raw_bytes, addr_val)

        cancel_timeout()
        emit_json({
            "pid": pid,
            "address": hex(addr_val),
            "size_requested": size,
            "size_read": len(data),
            "hex_dump": hex_dump,
            "raw_hex": data.hex(),
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
