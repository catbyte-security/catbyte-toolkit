"""cb db - Query the analysis database for findings, runs, and properties."""
from __future__ import annotations

import argparse
import sys

from cb.output import add_output_args, make_formatter


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "db", help="Query the analysis database",
        description="Query stored analysis results. Subcommands: "
                    "findings, runs, get, stats, query, props",
    )
    add_output_args(p)

    sub = p.add_subparsers(dest="db_command", help="Database subcommands")

    # cb db findings
    f = sub.add_parser("findings", help="Query findings")
    f.add_argument("--severity", "-s", help="Filter by severity (high/medium/low)")
    f.add_argument("--category", "-c", help="Filter by category")
    f.add_argument("--binary", "-b", help="Filter by binary path (resolved to sha256)")
    f.add_argument("--tool", "-t", help="Filter by tool name")
    f.add_argument("--limit", type=int, default=50, help="Max results (default: 50)")
    f.add_argument("--fields", help="Comma-separated fields to return (e.g. title,severity,category)")

    # cb db runs
    r = sub.add_parser("runs", help="List analysis runs")
    r.add_argument("--tool", "-t", help="Filter by tool name")
    r.add_argument("--binary", "-b", help="Filter by binary path")
    r.add_argument("--limit", type=int, default=50, help="Max results (default: 50)")

    # cb db get <run_id>
    g = sub.add_parser("get", help="Get full result for a run")
    g.add_argument("run_id", help="Run ID to retrieve")

    # cb db stats
    sub.add_parser("stats", help="Show database statistics")

    # cb db query "SELECT ..."
    q = sub.add_parser("query", help="Execute raw SELECT query")
    q.add_argument("sql", help="SQL SELECT query")

    # cb db props
    pr = sub.add_parser("props", help="Query properties")
    pr.add_argument("--binary", "-b", help="Filter by binary path")
    pr.add_argument("--key", "-k", help="Key pattern (supports SQL LIKE wildcards)")
    pr.add_argument("--limit", type=int, default=200, help="Max results (default: 200)")

    p.set_defaults(func=run)


def _resolve_sha256(binary_path: str) -> str | None:
    """Resolve a binary path to its sha256 for DB lookups."""
    import hashlib
    import os
    if not binary_path or not os.path.isfile(binary_path):
        return None
    try:
        sha = hashlib.sha256()
        with open(binary_path, "rb") as f:
            while chunk := f.read(65536):
                sha.update(chunk)
        return sha.hexdigest()
    except (OSError, IOError):
        return None


def run(args) -> None:
    # db command should never store its own output
    args.no_store = True
    fmt = make_formatter(args)

    from cb.store import get_store
    store = get_store()

    subcmd = getattr(args, "db_command", None)
    if not subcmd:
        print("Usage: cb db {findings|runs|get|stats|query|props}", file=sys.stderr)
        print("Run 'cb db -h' for help.", file=sys.stderr)
        sys.exit(1)

    if subcmd == "findings":
        binary_sha = None
        if getattr(args, "binary", None):
            binary_sha = _resolve_sha256(args.binary)
        fields = None
        if getattr(args, "fields", None):
            fields = [f.strip() for f in args.fields.split(",")]
        results = store.query_findings(
            severity=getattr(args, "severity", None),
            category=getattr(args, "category", None),
            binary_sha256=binary_sha,
            tool_name=getattr(args, "tool", None),
            limit=args.limit,
            fields=fields,
        )
        fmt.emit({"findings": results, "count": len(results)}, "db_findings")

    elif subcmd == "runs":
        binary_sha = None
        if getattr(args, "binary", None):
            binary_sha = _resolve_sha256(args.binary)
        results = store.query_runs(
            tool_name=getattr(args, "tool", None),
            binary_sha256=binary_sha,
            limit=args.limit,
        )
        fmt.emit({"runs": results, "count": len(results)}, "db_runs")

    elif subcmd == "get":
        result = store.get_run(args.run_id)
        if result is None:
            print(f"[!] Run {args.run_id} not found", file=sys.stderr)
            sys.exit(1)
        # Emit the stored result data if available, otherwise the run metadata
        data = result.get("result_data", result)
        fmt.emit(data, "db_get")

    elif subcmd == "stats":
        stats = store.get_stats()
        fmt.emit(stats, "db_stats")

    elif subcmd == "query":
        try:
            results = store.execute_raw(args.sql)
        except ValueError as e:
            print(f"[!] {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"[!] Query error: {e}", file=sys.stderr)
            sys.exit(1)
        fmt.emit({"results": results, "count": len(results)}, "db_query")

    elif subcmd == "props":
        binary_sha = None
        if getattr(args, "binary", None):
            binary_sha = _resolve_sha256(args.binary)
        results = store.query_properties(
            binary_sha256=binary_sha,
            key_pattern=getattr(args, "key", None),
            limit=args.limit,
        )
        fmt.emit({"properties": results, "count": len(results)}, "db_props")


def main() -> None:
    """Standalone entry point for cbdb."""
    parser = argparse.ArgumentParser(prog="cbdb", description="Query cb analysis database")
    add_output_args(parser)

    sub = parser.add_subparsers(dest="db_command")

    f = sub.add_parser("findings", help="Query findings")
    f.add_argument("--severity", "-s")
    f.add_argument("--category", "-c")
    f.add_argument("--binary", "-b")
    f.add_argument("--tool", "-t")
    f.add_argument("--limit", type=int, default=50)
    f.add_argument("--fields")

    r = sub.add_parser("runs", help="List runs")
    r.add_argument("--tool", "-t")
    r.add_argument("--binary", "-b")
    r.add_argument("--limit", type=int, default=50)

    g = sub.add_parser("get", help="Get run by ID")
    g.add_argument("run_id")

    sub.add_parser("stats", help="Show stats")

    q = sub.add_parser("query", help="Raw SELECT query")
    q.add_argument("sql")

    pr = sub.add_parser("props", help="Query properties")
    pr.add_argument("--binary", "-b")
    pr.add_argument("--key", "-k")
    pr.add_argument("--limit", type=int, default=200)

    args = parser.parse_args()
    args.no_store = True
    args.verbose = getattr(args, "verbose", False)

    if not args.db_command:
        parser.print_help()
        sys.exit(1)

    run(args)
