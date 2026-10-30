"""SQLite schema and migrations for AUREON historical data.

Migrations are append-only: each entry upgrades schema ``from_version`` to
``from_version + 1`` and is applied inside a transaction. The user_version
pragma records the current level, so upgrades are safe and idempotent.
"""

from __future__ import annotations

import sqlite3
from typing import List, Tuple

SCHEMA_VERSION = 2

MIGRATION_0_1 = (
    """
    CREATE TABLE IF NOT EXISTS security_events (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        occurred_at   TEXT NOT NULL,          -- ISO-8601, timezone aware
        occurred_ts   INTEGER NOT NULL,       -- epoch seconds for fast range queries
        kind          TEXT NOT NULL,          -- ban | unban | auth_failure | ...
        jail          TEXT NOT NULL DEFAULT '',
        ip            TEXT NOT NULL DEFAULT '',
        username      TEXT NOT NULL DEFAULT '',
        source        TEXT NOT NULL,          -- origin channel
        source_id     TEXT NOT NULL DEFAULT '',
        dedup_key     TEXT NOT NULL UNIQUE,
        host_id       TEXT NOT NULL DEFAULT '',
        ingested_at   TEXT NOT NULL,
        collection_state TEXT NOT NULL DEFAULT 'ok',
        meta          TEXT NOT NULL DEFAULT '{}'
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_events_ts ON security_events(occurred_ts)",
    "CREATE INDEX IF NOT EXISTS idx_events_ip ON security_events(ip)",
    "CREATE INDEX IF NOT EXISTS idx_events_jail ON security_events(jail)",
    "CREATE INDEX IF NOT EXISTS idx_events_kind_ts ON security_events(kind, occurred_ts)",
    "CREATE INDEX IF NOT EXISTS idx_events_ip_kind_ts ON security_events(ip, kind, occurred_ts)",
    """
    CREATE TABLE IF NOT EXISTS ingest_sources (
        source_key    TEXT PRIMARY KEY,
        path          TEXT NOT NULL DEFAULT '',
        inode         INTEGER,
        device        INTEGER,
        size          INTEGER NOT NULL DEFAULT 0,
        offset        INTEGER NOT NULL DEFAULT 0,
        line          INTEGER NOT NULL DEFAULT 0,
        last_event_ts TEXT,
        last_scan     TEXT,
        state         TEXT NOT NULL DEFAULT 'ok',
        note          TEXT NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS collection_runs (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at   TEXT NOT NULL,
        finished_at  TEXT,
        source       TEXT NOT NULL,
        events_seen  INTEGER NOT NULL DEFAULT 0,
        events_added INTEGER NOT NULL DEFAULT 0,
        duplicates   INTEGER NOT NULL DEFAULT 0,
        state        TEXT NOT NULL DEFAULT 'ok',
        note         TEXT NOT NULL DEFAULT ''
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
)

MIGRATION_1_2 = (
    """
    CREATE TABLE IF NOT EXISTS assessments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        assessed_at TEXT NOT NULL,
        tool_version TEXT NOT NULL,
        definition_version TEXT NOT NULL,
        score INTEGER,
        payload TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_assessments_assessed_at ON assessments(assessed_at)",
)

MIGRATIONS: List[Tuple[int, Tuple[str, ...]]] = [(1, MIGRATION_0_1), (2, MIGRATION_1_2)]


def connect(path, read_only: bool = False) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=15.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if not read_only:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def migrate(conn: sqlite3.Connection) -> int:
    """Apply pending migrations. Safe to call on every start."""
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    for version, statements in MIGRATIONS:
        if version > current:
            conn.execute("BEGIN")
            try:
                for statement in statements:
                    conn.execute(statement)
                conn.execute(f"PRAGMA user_version = {version}")
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            current = version
    return current
