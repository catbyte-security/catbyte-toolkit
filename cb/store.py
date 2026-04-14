"""SQLite analysis database for queryable security findings."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid
from typing import Any


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    tool_name TEXT NOT NULL,
    binary_path TEXT,
    binary_sha256 TEXT,
    binary_name TEXT,
    args_hash TEXT,
    created_at TEXT,
    elapsed_sec REAL,
    session_name TEXT,
    result_json TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    run_id TEXT REFERENCES runs(run_id),
    finding_id TEXT,
    tool_name TEXT,
    binary_sha256 TEXT,
    category TEXT,
    severity TEXT,
    title TEXT,
    description TEXT,
    evidence_json TEXT,
    recommendation TEXT,
    created_at TEXT
);

CREATE TABLE IF NOT EXISTS properties (
    id INTEGER PRIMARY KEY,
    run_id TEXT REFERENCES runs(run_id),
    binary_sha256 TEXT,
    tool_name TEXT,
    key TEXT,
    value TEXT,
    value_type TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_binary ON findings(binary_sha256);
CREATE INDEX IF NOT EXISTS idx_runs_tool ON runs(tool_name);
CREATE INDEX IF NOT EXISTS idx_runs_binary ON runs(binary_sha256);
CREATE INDEX IF NOT EXISTS idx_properties_binary_key ON properties(binary_sha256, key);
"""


class AnalysisStore:
    """SQLite-backed store for analysis results and findings."""

    def __init__(self, db_path: str | None = None) -> None:
        if db_path is None:
            from cb.config import load_config
            cfg = load_config()
            db_path = cfg.get("db_path", os.path.expanduser("~/.cb/analysis.db"))
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._local = threading.local()
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        """Get a thread-local connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self.db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return self._local.conn

    def _init_schema(self) -> None:
        conn = self._get_conn()
        conn.executescript(_SCHEMA_SQL)
        conn.commit()

    def record_run(self, data: dict[str, Any], tool_name: str,
                   binary_path: str | None = None,
                   session_name: str | None = None) -> str:
        """Record an emit() call and extract findings/properties. Returns run_id."""
        conn = self._get_conn()
        run_id = uuid.uuid4().hex[:16]
        now = time.strftime("%Y-%m-%dT%H:%M:%S")

        meta = data.get("_meta", {})
        elapsed = meta.get("time_seconds")

        binary_sha256 = None
        binary_name = None
        if binary_path:
            binary_name = os.path.basename(binary_path)
            binary_sha256 = self._hash_path(binary_path)

        # Also check if data contains sha256 (from triage results, etc.)
        if not binary_sha256:
            for key in ("sha256", "binary_sha256"):
                if key in data:
                    binary_sha256 = data[key]
                    break
            fi = data.get("file_info", {})
            if not binary_sha256 and isinstance(fi, dict):
                binary_sha256 = fi.get("sha256")

        args_hash = meta.get("args_hash")
        result_json = json.dumps(data, default=str)

        conn.execute(
            "INSERT INTO runs (run_id, tool_name, binary_path, binary_sha256, "
            "binary_name, args_hash, created_at, elapsed_sec, session_name, result_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, tool_name, binary_path, binary_sha256,
             binary_name, args_hash, now, elapsed, session_name, result_json),
        )

        self._extract_findings(conn, run_id, data, tool_name, binary_sha256, now)
        self._extract_properties(conn, run_id, data, tool_name, binary_sha256)
        conn.commit()
        return run_id

    def _extract_findings(self, conn: sqlite3.Connection, run_id: str,
                          data: dict, tool_name: str,
                          binary_sha256: str | None, created_at: str) -> None:
        """Extract individual findings from result data."""
        findings = data.get("findings", [])
        if not isinstance(findings, list):
            return
        for f in findings:
            if not isinstance(f, dict):
                continue
            evidence = f.get("evidence")
            evidence_json = json.dumps(evidence, default=str) if evidence else None
            conn.execute(
                "INSERT INTO findings (run_id, finding_id, tool_name, binary_sha256, "
                "category, severity, title, description, evidence_json, "
                "recommendation, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id,
                 f.get("id") or f.get("finding_id"),
                 tool_name,
                 binary_sha256,
                 f.get("category"),
                 f.get("severity"),
                 f.get("title") or f.get("name"),
                 f.get("description") or f.get("detail"),
                 evidence_json,
                 f.get("recommendation") or f.get("fix"),
                 created_at),
            )

    def _extract_properties(self, conn: sqlite3.Connection, run_id: str,
                            data: dict, tool_name: str,
                            binary_sha256: str | None) -> None:
        """Extract scalar properties from triage/attack/sandbox results."""
        extractable = {
            "protections": data.get("protections", {}),
            "file_info": data.get("file_info", {}),
            "sandbox": data.get("sandbox", {}),
            "summary": data.get("summary", {}),
        }
        for section_name, section in extractable.items():
            if not isinstance(section, dict):
                continue
            self._flatten_props(conn, run_id, tool_name, binary_sha256,
                                section_name, section)

    def _flatten_props(self, conn: sqlite3.Connection, run_id: str,
                       tool_name: str, binary_sha256: str | None,
                       prefix: str, d: dict) -> None:
        """Flatten nested dict into dot-separated key/value property rows."""
        for k, v in d.items():
            key = f"{prefix}.{k}"
            if isinstance(v, dict):
                self._flatten_props(conn, run_id, tool_name, binary_sha256, key, v)
            elif isinstance(v, list):
                # Store list length as a property, skip large lists
                conn.execute(
                    "INSERT INTO properties (run_id, binary_sha256, tool_name, "
                    "key, value, value_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (run_id, binary_sha256, tool_name, key, str(len(v)), "list_len"),
                )
            else:
                vtype = type(v).__name__
                conn.execute(
                    "INSERT INTO properties (run_id, binary_sha256, tool_name, "
                    "key, value, value_type) VALUES (?, ?, ?, ?, ?, ?)",
                    (run_id, binary_sha256, tool_name, key, str(v), vtype),
                )

    @staticmethod
    def _hash_path(path: str) -> str | None:
        """SHA256 hash of file at path, or None if unreadable."""
        try:
            sha = hashlib.sha256()
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    sha.update(chunk)
            return sha.hexdigest()
        except (OSError, IOError):
            return None

    def query_findings(self, severity: str | None = None,
                       category: str | None = None,
                       binary_sha256: str | None = None,
                       tool_name: str | None = None,
                       limit: int = 50,
                       fields: list[str] | None = None) -> list[dict]:
        """Query findings with optional filters."""
        conn = self._get_conn()
        conditions = []
        params: list[Any] = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if category:
            conditions.append("category = ?")
            params.append(category)
        if binary_sha256:
            conditions.append("binary_sha256 = ?")
            params.append(binary_sha256)
        if tool_name:
            conditions.append("tool_name = ?")
            params.append(tool_name)

        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        sql = f"SELECT * FROM findings{where} ORDER BY id DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(sql, params).fetchall()
        results = [dict(row) for row in rows]

        if fields:
            results = [{k: r.get(k) for k in fields if k in r} for r in results]

        return results

    def query_runs(self, tool_name: str | None = None,
                   binary_sha256: str | None = None,
                   limit: int = 50) -> list[dict]:
        """Query runs with optional filters."""
        conn = self._get_conn()
        conditions = []
        params: list[Any] = []

        if tool_name:
            conditions.append("tool_name = ?")
            params.append(tool_name)
        if binary_sha256:
            conditions.append("binary_sha256 = ?")
            params.append(binary_sha256)

        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        # Exclude result_json from listing queries for brevity
        sql = (f"SELECT run_id, tool_name, binary_path, binary_sha256, "
               f"binary_name, created_at, elapsed_sec, session_name "
               f"FROM runs{where} ORDER BY created_at DESC LIMIT ?")
        params.append(limit)

        rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def get_run(self, run_id: str) -> dict | None:
        """Get full result JSON for a specific run."""
        conn = self._get_conn()
        row = conn.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        # Parse result_json back to dict
        if result.get("result_json"):
            try:
                result["result_data"] = json.loads(result["result_json"])
            except json.JSONDecodeError:
                pass
        return result

    def get_stats(self) -> dict:
        """Get database statistics."""
        conn = self._get_conn()
        stats: dict[str, Any] = {}

        stats["total_runs"] = conn.execute(
            "SELECT COUNT(*) FROM runs"
        ).fetchone()[0]
        stats["total_findings"] = conn.execute(
            "SELECT COUNT(*) FROM findings"
        ).fetchone()[0]
        stats["total_properties"] = conn.execute(
            "SELECT COUNT(*) FROM properties"
        ).fetchone()[0]

        # Severity breakdown
        rows = conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM findings "
            "WHERE severity IS NOT NULL GROUP BY severity ORDER BY cnt DESC"
        ).fetchall()
        stats["findings_by_severity"] = {r["severity"]: r["cnt"] for r in rows}

        # Tool breakdown
        rows = conn.execute(
            "SELECT tool_name, COUNT(*) as cnt FROM runs "
            "GROUP BY tool_name ORDER BY cnt DESC"
        ).fetchall()
        stats["runs_by_tool"] = {r["tool_name"]: r["cnt"] for r in rows}

        # Category breakdown
        rows = conn.execute(
            "SELECT category, COUNT(*) as cnt FROM findings "
            "WHERE category IS NOT NULL GROUP BY category ORDER BY cnt DESC"
        ).fetchall()
        stats["findings_by_category"] = {r["category"]: r["cnt"] for r in rows}

        # DB file size
        try:
            stats["db_size_bytes"] = os.path.getsize(self.db_path)
        except OSError:
            stats["db_size_bytes"] = 0

        stats["db_path"] = self.db_path
        return stats

    def execute_raw(self, sql: str) -> list[dict]:
        """Execute a raw SELECT query. Only SELECT is allowed."""
        stripped = sql.strip().upper()
        if not stripped.startswith("SELECT"):
            raise ValueError("Only SELECT queries are allowed")
        conn = self._get_conn()
        rows = conn.execute(sql).fetchall()
        return [dict(row) for row in rows]

    def query_properties(self, binary_sha256: str | None = None,
                         key_pattern: str | None = None,
                         limit: int = 200) -> list[dict]:
        """Query properties with optional binary/key filters."""
        conn = self._get_conn()
        conditions = []
        params: list[Any] = []

        if binary_sha256:
            conditions.append("binary_sha256 = ?")
            params.append(binary_sha256)
        if key_pattern:
            conditions.append("key LIKE ?")
            params.append(key_pattern)

        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        sql = f"SELECT * FROM properties{where} ORDER BY key LIMIT ?"
        params.append(limit)

        rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def close(self) -> None:
        """Close the thread-local connection."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None


# Thread-safe singleton
_store_lock = threading.Lock()
_store_instance: AnalysisStore | None = None


def get_store() -> AnalysisStore:
    """Get or create the global AnalysisStore singleton."""
    global _store_instance
    if _store_instance is None:
        with _store_lock:
            if _store_instance is None:
                _store_instance = AnalysisStore()
    return _store_instance
