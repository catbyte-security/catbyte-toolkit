"""Unified CLI dispatcher for cb toolkit."""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cb",
        description="CatByte Security Toolkit - Binary analysis for security research",
    )
    parser.add_argument("--version", action="version", version="cb 1.4.0")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output with debug info and stack traces")
    parser.add_argument("--arch", choices=["arm64", "x86_64", "auto"],
                        default="auto",
                        help="Architecture to analyze for universal binaries")

    sub = parser.add_subparsers(dest="command", help="Available commands")

    # Register all subcommands
    from cb.commands.triage import register as reg_triage
    from cb.commands.grep import register as reg_grep
    from cb.commands.crash import register as reg_crash
    from cb.commands.attack import register as reg_attack
    from cb.commands.vuln import register as reg_vuln
    from cb.commands.ghidra import register as reg_ghidra
    from cb.commands.diff import register as reg_diff
    from cb.commands.fuzz import register as reg_fuzz
    from cb.commands.taint import register as reg_taint
    from cb.commands.callgraph import register as reg_callgraph
    from cb.commands.objc import register as reg_objc
    from cb.commands.sandbox import register as reg_sandbox
    from cb.commands.ipc import register as reg_ipc
    from cb.commands.variant import register as reg_variant
    from cb.commands.audit import register as reg_audit
    from cb.commands.hook import register as reg_hook
    from cb.commands.lldb import register as reg_lldb
    from cb.commands.probe import register as reg_probe
    from cb.commands.cache import register as reg_cache
    from cb.commands.struct import register as reg_struct
    from cb.commands.heap import register as reg_heap
    from cb.commands.gadget import register as reg_gadget
    from cb.commands.plan import register as reg_plan
    from cb.commands.verify import register as reg_verify
    from cb.commands.context import register as reg_context
    from cb.commands.report import register as reg_report
    from cb.commands.web import register as reg_web
    from cb.commands.session import register as reg_session
    from cb.commands.bundle import register as reg_bundle
    from cb.commands.db import register as reg_db
    from cb.commands.models import register as reg_models
    from cb.commands.kernel_vuln import register as reg_kernel_vuln
    from cb.commands.kernel_diff import register as reg_kernel_diff

    reg_triage(sub)
    reg_grep(sub)
    reg_crash(sub)
    reg_attack(sub)
    reg_vuln(sub)
    reg_ghidra(sub)
    reg_diff(sub)
    reg_fuzz(sub)
    reg_taint(sub)
    reg_callgraph(sub)
    reg_objc(sub)
    reg_sandbox(sub)
    reg_ipc(sub)
    reg_variant(sub)
    reg_audit(sub)
    reg_hook(sub)
    reg_lldb(sub)
    reg_probe(sub)
    reg_cache(sub)
    reg_struct(sub)
    reg_heap(sub)
    reg_gadget(sub)
    reg_plan(sub)
    reg_verify(sub)
    reg_context(sub)
    reg_report(sub)
    reg_web(sub)
    reg_session(sub)
    reg_bundle(sub)
    reg_db(sub)
    reg_models(sub)
    reg_kernel_vuln(sub)
    reg_kernel_diff(sub)

    # Load user plugins
    _register_plugins(sub)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Validate binary path if present
    binary_path = getattr(args, "binary", None)
    if binary_path and binary_path != "-":
        from cb.validation import validate_binary_path
        err = validate_binary_path(binary_path)
        if err:
            print(f"[!] {err}", file=sys.stderr)
            sys.exit(1)

        # Auto-resolve .app/.framework bundles to actual binary
        from cb.macho import resolve_binary, is_fat_binary, thin_binary
        resolved = resolve_binary(binary_path)
        if resolved != binary_path:
            print(f"[*] Resolved bundle to: {resolved}", file=sys.stderr)
            args.original_binary = binary_path
            args.binary = resolved

        # Auto-thin fat/universal binaries when they're large (>50MB) or
        # when the user explicitly chose an architecture
        arch = getattr(args, "arch", "auto")
        if is_fat_binary(args.binary):
            file_size = os.path.getsize(args.binary)
            should_thin = arch != "auto" or file_size > 50_000_000
            if should_thin:
                thin_arch = None if arch == "auto" else arch
                thinned = thin_binary(args.binary, arch=thin_arch)
                if thinned != args.binary:
                    print(f"[*] Extracted {arch if arch != 'auto' else 'native'} "
                          f"slice: {thinned}", file=sys.stderr)
                    if not hasattr(args, "original_binary"):
                        args.original_binary = args.binary
                    args.binary = thinned

    # Also validate diff command's binary_old / binary_new
    for attr in ("binary_old", "binary_new"):
        path = getattr(args, attr, None)
        if path and path != "-":
            from cb.validation import validate_binary_path
            err = validate_binary_path(path)
            if err:
                print(f"[!] {attr}: {err}", file=sys.stderr)
                sys.exit(1)

    # Dispatch with error handling
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        if getattr(args, "verbose", False):
            import traceback
            traceback.print_exc(file=sys.stderr)
        else:
            print(f"[!] Error: {e}", file=sys.stderr)
            print("[!] Run with --verbose for full traceback", file=sys.stderr)
        sys.exit(1)


def _get_plugin_dir() -> str:
    """Return the plugin directory path from config."""
    from cb.config import load_config
    cfg = load_config()
    return cfg.get("plugin_dir", os.path.expanduser("~/.cb/plugins"))


def _register_plugins(subparsers) -> None:
    """Discover and load plugins from the plugin directory.

    Each .py file (not starting with _) in the plugin dir must export
    a ``register(subparsers)`` function that adds a subcommand.
    Load errors are printed to stderr but never crash the CLI.
    """
    plugin_dir = _get_plugin_dir()
    if not os.path.isdir(plugin_dir):
        return

    for filename in sorted(os.listdir(plugin_dir)):
        if not filename.endswith(".py") or filename.startswith("_"):
            continue

        filepath = os.path.join(plugin_dir, filename)
        module_name = f"cb_plugin_{filename[:-3]}"

        try:
            spec = importlib.util.spec_from_file_location(module_name, filepath)
            if spec is None or spec.loader is None:
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

            register_fn = getattr(mod, "register", None)
            if register_fn is None:
                print(f"[!] Plugin {filename}: no register() function, skipping",
                      file=sys.stderr)
                continue

            register_fn(subparsers)
        except Exception as e:
            print(f"[!] Plugin {filename}: {e}", file=sys.stderr)
