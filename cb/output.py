"""Shared output formatting with context-window-friendly truncation."""
from __future__ import annotations

import json
import sys
import time
from typing import Any


class OutputFormatter:
    def __init__(self, fmt: str = "json", max_results: int = 50,
                 quiet: bool = False, verbose: bool = False,
                 budget: int = 0, binary_path: str | None = None,
                 store_enabled: bool = True) -> None:
        self.fmt = fmt
        self.max_results = max_results
        self.quiet = quiet
        self.verbose = verbose
        self.budget = budget
        self._binary_path = binary_path
        self._store_enabled = store_enabled
        self._start = time.time()

    def status(self, msg: str) -> None:
        if not self.quiet:
            print(f"[*] {msg}", file=sys.stderr)

    def debug(self, msg: str, exc: BaseException | None = None) -> None:
        if not self.verbose:
            return
        elapsed = round(time.time() - self._start, 2)
        print(f"[DEBUG +{elapsed}s] {msg}", file=sys.stderr)
        if exc is not None:
            import traceback
            traceback.print_exception(type(exc), exc, exc.__traceback__,
                                      file=sys.stderr)

    def emit(self, data: dict[str, Any], tool_name: str) -> None:
        elapsed = round(time.time() - self._start, 2)
        meta = data.setdefault("_meta", {})
        meta["tool"] = tool_name
        meta["time_seconds"] = elapsed

        # Store to analysis DB before truncation (capture full data)
        if self._store_enabled:
            try:
                from cb.store import get_store
                run_id = get_store().record_run(
                    data, tool_name, binary_path=self._binary_path)
                meta["run_id"] = run_id
            except Exception:
                pass  # never block output

        data = self._truncate(data)

        if self.fmt == "json":
            json.dump(data, sys.stdout, indent=2, default=str)
            print()
        elif self.fmt == "summary":
            self._emit_summary(data, tool_name)
        else:
            self._emit_text(data)

    def _truncate(self, data: dict[str, Any]) -> dict[str, Any]:
        data.setdefault("_meta", {})
        for key, value in list(data.items()):
            if key == "_meta":
                continue
            if isinstance(value, list) and len(value) > self.max_results:
                data["_meta"][f"{key}_total"] = len(value)
                data["_meta"][f"{key}_shown"] = self.max_results
                data["_meta"]["truncated"] = True
                data[key] = value[: self.max_results]
            elif isinstance(value, dict) and key != "_meta":
                data[key] = self._truncate(value)

        # Budget-aware truncation
        if self.budget > 0:
            estimated = len(json.dumps(data, default=str)) // 4
            if estimated > self.budget:
                ratio = self.budget / estimated
                new_max = max(1, int(self.max_results * ratio))
                for key, value in list(data.items()):
                    if key == "_meta":
                        continue
                    if isinstance(value, list) and len(value) > new_max:
                        data["_meta"][f"{key}_total"] = data["_meta"].get(
                            f"{key}_total", len(value))
                        data["_meta"][f"{key}_shown"] = new_max
                        data["_meta"]["truncated"] = True
                        data[key] = value[:new_max]
                data["_meta"]["budget_adjusted"] = True

        return data

    def _emit_summary(self, data: dict[str, Any], tool_name: str) -> None:
        summary: dict[str, Any] = {"_meta": data.get("_meta", {})}
        for key in ("summary", "crash_summary", "file_info", "protections",
                     "imports_summary", "strings_interesting"):
            if key in data:
                summary[key] = data[key]
        # If no summary keys found, show top-level keys with counts
        if len(summary) <= 1:
            for k, v in data.items():
                if k == "_meta":
                    continue
                if isinstance(v, list):
                    summary[k] = f"[{len(v)} items]"
                elif isinstance(v, dict):
                    summary[k] = {sk: (f"[{len(sv)} items]" if isinstance(sv, list) else sv)
                                  for sk, sv in v.items()}
                else:
                    summary[k] = v
        json.dump(summary, sys.stdout, indent=2, default=str)
        print()

    def _emit_text(self, data: dict[str, Any]) -> None:
        _print_dict(data, indent=0)


def _print_dict(d: dict[str, Any], indent: int = 0) -> None:
    prefix = "  " * indent
    for k, v in d.items():
        if k == "_meta":
            continue
        if isinstance(v, dict):
            print(f"{prefix}{k}:")
            _print_dict(v, indent + 1)
        elif isinstance(v, list):
            print(f"{prefix}{k}: ({len(v)} items)")
            for item in v[:10]:
                if isinstance(item, dict):
                    _print_dict(item, indent + 1)
                    print(f"{prefix}  ---")
                else:
                    print(f"{prefix}  {item}")
            if len(v) > 10:
                print(f"{prefix}  ... and {len(v) - 10} more")
        else:
            print(f"{prefix}{k}: {v}")


def add_output_args(parser: Any) -> None:
    """Add standard output arguments to an argparse parser."""
    parser.add_argument("--format", choices=["json", "text", "summary"],
                        default="json", help="Output format")
    parser.add_argument("--summary", action="store_const", const="summary",
                        dest="format", help="Compact summary output")
    parser.add_argument("--max-results", type=int, default=50,
                        help="Max items per list (default: 50)")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress progress messages")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Write output to file")
    parser.add_argument("--no-cache", action="store_true",
                        help="Bypass result cache")
    parser.add_argument("--budget", type=int, default=None,
                        help="Token budget for output (0=unlimited)")
    parser.add_argument("--no-store", action="store_true",
                        help="Don't record results to analysis database")


def make_formatter(args: Any) -> OutputFormatter:
    """Create OutputFormatter from parsed args."""
    verbose = getattr(args, "verbose", False)
    if args.output:
        import atexit
        _original_stdout = sys.stdout
        output_file = open(args.output, "w")
        sys.stdout = output_file

        def _cleanup() -> None:
            sys.stdout = _original_stdout
            output_file.close()
        atexit.register(_cleanup)

    # Resolve budget: CLI arg > config > 0
    budget = getattr(args, "budget", None)
    if budget is None:
        from cb.config import load_config
        budget = load_config().get("context_budget", 0)

    # Resolve store_enabled: --no-store > config > True
    no_store = getattr(args, "no_store", False)
    if no_store:
        store_enabled = False
    else:
        from cb.config import load_config
        store_enabled = load_config().get("db_enabled", True)

    binary_path = getattr(args, "binary", None)

    return OutputFormatter(fmt=args.format, max_results=args.max_results,
                           quiet=args.quiet, verbose=verbose, budget=budget,
                           binary_path=binary_path,
                           store_enabled=store_enabled)


def load_piped_input() -> dict[str, Any] | None:
    """Load JSON from stdin when '-' is passed as input.

    Enables pipeline chaining: cb triage binary | cb vuln --from-triage -
    """
    if not sys.stdin.isatty():
        try:
            data = sys.stdin.read()
            if data.strip():
                return json.loads(data)
        except json.JSONDecodeError as e:
            print(f"[!] Invalid JSON in pipeline input: {e}", file=sys.stderr)
            return None
        except Exception:
            return None
    return None
