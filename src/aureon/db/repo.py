"""Repository layer: the only component that talks to SQLite.

All statistics queries are bounded by explicit ``[start_ts, end_ts)`` epoch
ranges, and the repository reports data coverage so callers can distinguish
"zero events observed" from "no data collected".
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from ..models import PeriodStats, SecurityEvent
from ..util import Result
from .schema import connect, migrate


def _iso(moment: datetime) -> str:
    return moment.isoformat()


def _parse_iso(text: str) -> Optional[datetime]:
    try:
        parsed = datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class Repository:
    def __init__(self, path, read_only: bool = False) -> None:
        self.path = Path(path)
        self.read_only = read_only
        self.conn: Optional[sqlite3.Connection] = None

    # -- lifecycle ------------------------------------------------------
    def open(self) -> None:
        """Open (and migrate) the database. Raises sqlite3.DatabaseError when
        the file is not a usable SQLite database - callers that must degrade
        gracefully use :meth:`try_open`."""
        if self.conn is not None:
            return
        if not self.read_only:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = connect(self.path, read_only=self.read_only)
        if not self.read_only:
            migrate(self.conn)

    def close(self) -> None:
        if self.conn is not None:
            try:
                self.conn.close()
            finally:
                self.conn = None

    def __enter__(self) -> "Repository":
        self.open()
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def try_open(self) -> Optional[sqlite3.Error]:
        """Open without raising. Returns the error when the store is unusable."""
        try:
            self.open()
            return None
        except sqlite3.Error as exc:
            return exc

    def available(self) -> Result:
        try:
            self.open()
            with self.conn:  # type: ignore[union-attr]
                self.conn.execute("SELECT 1 FROM meta LIMIT 1").fetchall()
            return Result.ok_result(True, str(self.path))
        except sqlite3.Error as exc:
            return Result(str(exc), str(self.path), "error", str(exc))

    # -- writes ---------------------------------------------------------
    def insert_events(self, events: Sequence[SecurityEvent], host_id: str = "") -> Tuple[int, int]:
        """Insert events idempotently. Returns ``(inserted, duplicates)``."""
        if not self.conn:
            self.open()
        assert self.conn is not None
        inserted = 0
        duplicates = 0
        now = datetime.now(timezone.utc).isoformat()
        rows = []
        for event in events:
            epoch = int(event.occurred_at.timestamp())
            dedup = event.dedup_key
            exists = self.conn.execute(
                "SELECT 1 FROM security_events WHERE dedup_key = ?", (dedup,)
            ).fetchone()
            if exists:
                duplicates += 1
                continue
            rows.append(
                (
                    _iso(event.occurred_at),
                    epoch,
                    event.kind,
                    event.jail,
                    event.ip,
                    event.username,
                    event.source,
                    event.source_id,
                    dedup,
                    event.host_id or host_id,
                    event.ingested_at.isoformat() if event.ingested_at else now,
                    event.collection_state,
                    json.dumps(event.meta, sort_keys=True),
                )
            )
        if not rows:
            return 0, duplicates
        cur = self.conn.executemany(
            """
            INSERT OR IGNORE INTO security_events
                (occurred_at, occurred_ts, kind, jail, ip, username, source, source_id,
                 dedup_key, host_id, ingested_at, collection_state, meta)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            rows,
        )
        inserted = cur.rowcount if cur.rowcount and cur.rowcount > 0 else len(rows)
        return inserted, duplicates

    def record_run(
        self,
        source: str,
        started_at: datetime,
        finished_at: datetime,
        events_seen: int,
        events_added: int,
        duplicates: int,
        state: str,
        note: str = "",
    ) -> None:
        if not self.conn:
            self.open()
        assert self.conn is not None
        self.conn.execute(
            """
            INSERT INTO collection_runs
                (started_at, finished_at, source, events_seen, events_added, duplicates, state, note)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (_iso(started_at), _iso(finished_at), source, events_seen, events_added, duplicates, state, note),
        )

    def last_run(self) -> Optional[Dict[str, str]]:
        if not self.conn:
            self.open()
        assert self.conn is not None
        row = self.conn.execute(
            "SELECT * FROM collection_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None

    def runs(self, limit: int = 20) -> List[Dict[str, str]]:
        if not self.conn:
            self.open()
        assert self.conn is not None
        rows = self.conn.execute(
            "SELECT * FROM collection_runs ORDER BY id DESC LIMIT ?", (int(limit),)
        ).fetchall()
        return [dict(row) for row in rows]

    # -- ingest cursors -------------------------------------------------
    def get_cursor(self, source_key: str) -> Optional[Dict]:
        if not self.conn:
            self.open()
        assert self.conn is not None
        row = self.conn.execute(
            "SELECT * FROM ingest_sources WHERE source_key = ?", (source_key,)
        ).fetchone()
        return dict(row) if row else None

    def set_cursor(self, source_key: str, values: Dict[str, object]) -> None:
        if not self.conn:
            self.open()
        assert self.conn is not None
        columns = {
            "path": str(values.get("path", "")),
            "inode": values.get("inode"),
            "device": values.get("device"),
            "size": int(values.get("size", 0) or 0),
            "offset": int(values.get("offset", 0) or 0),
            "line": int(values.get("line", 0) or 0),
            "last_event_ts": values.get("last_event_ts"),
            "last_scan": values.get("last_scan") or datetime.now(timezone.utc).isoformat(),
            "state": str(values.get("state", "ok")),
            "note": str(values.get("note", "")),
        }
        self.conn.execute(
            """
            INSERT INTO ingest_sources
                (source_key, path, inode, device, size, offset, line, last_event_ts, last_scan, state, note)
            VALUES (:source_key, :path, :inode, :device, :size, :offset, :line, :last_event_ts, :last_scan, :state, :note)
            ON CONFLICT(source_key) DO UPDATE SET
                path=excluded.path, inode=excluded.inode, device=excluded.device,
                size=excluded.size, offset=excluded.offset, line=excluded.line,
                last_event_ts=excluded.last_event_ts, last_scan=excluded.last_scan,
                state=excluded.state, note=excluded.note
            """,
            {"source_key": source_key, **columns},
        )

    def all_cursors(self) -> List[Dict]:
        if not self.conn:
            self.open()
        assert self.conn is not None
        return [dict(row) for row in self.conn.execute("SELECT * FROM ingest_sources").fetchall()]

    # -- reads ----------------------------------------------------------
    def coverage(self) -> Tuple[Optional[datetime], Optional[datetime], int]:
        if not self.conn:
            self.open()
        assert self.conn is not None
        row = self.conn.execute(
            "SELECT MIN(occurred_ts) AS lo, MAX(occurred_ts) AS hi, COUNT(*) AS n FROM security_events"
        ).fetchone()
        if not row or not row["n"]:
            return None, None, 0
        lo = datetime.fromtimestamp(row["lo"], tz=timezone.utc)
        hi = datetime.fromtimestamp(row["hi"], tz=timezone.utc)
        return lo, hi, int(row["n"])

    def count_events(self, kind: Optional[str] = None) -> int:
        if not self.conn:
            self.open()
        assert self.conn is not None
        if kind:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM security_events WHERE kind = ?", (kind,)
            ).fetchone()
        else:
            row = self.conn.execute("SELECT COUNT(*) AS n FROM security_events").fetchone()
        return int(row["n"]) if row else 0

    def stats_for_period(
        self,
        period_name: str,
        start: datetime,
        end: datetime,
        tzinfo,
        tz_label: str = "",
        current_banned: Optional[int] = None,
        recurrent_threshold: int = 2,
    ) -> PeriodStats:
        if not self.conn:
            self.open()
        assert self.conn is not None
        lo, hi = int(start.timestamp()), int(end.timestamp())
        stats = PeriodStats(
            period=period_name,
            start=start,
            end=end,
            timezone=tz_label or str(tzinfo),
            currently_banned=current_banned,
        )

        row = self.conn.execute(
            """
            SELECT
              SUM(CASE WHEN kind='ban' THEN 1 ELSE 0 END) AS ban_events,
              SUM(CASE WHEN kind='unban' THEN 1 ELSE 0 END) AS unban_events,
              COUNT(DISTINCT CASE WHEN kind='ban' AND ip<>'' THEN ip END) AS unique_banned,
              COUNT(DISTINCT CASE WHEN kind='unban' AND ip<>'' THEN ip END) AS unbanned_ips,
              COUNT(CASE WHEN kind='auth_failure' THEN 1 ELSE 0 END) AS failed_auth,
              MAX(occurred_ts) AS last_event
            FROM security_events WHERE occurred_ts >= ? AND occurred_ts < ?
            """,
            (lo, hi),
        ).fetchone()
        stats.ban_events = int(row["ban_events"] or 0)
        stats.unban_events = int(row["unban_events"] or 0)
        stats.unique_banned_ips = int(row["unique_banned"] or 0)
        stats.unbanned_ips = int(row["unbanned_ips"] or 0)
        stats.failed_auth_attempts = int(row["failed_auth"] or 0)
        if row["last_event"]:
            stats.last_event_at = datetime.fromtimestamp(int(row["last_event"]), tz=timezone.utc).astimezone(tzinfo)

        rows = self.conn.execute(
            """
            SELECT ip, COUNT(*) AS events,
                   SUM(CASE WHEN kind='ban' THEN 1 ELSE 0 END) AS bans
            FROM security_events
            WHERE occurred_ts >= ? AND occurred_ts < ? AND ip <> ''
            GROUP BY ip HAVING events >= ? ORDER BY events DESC, ip ASC LIMIT 50
            """,
            (lo, hi, recurrent_threshold),
        ).fetchall()
        stats.top_ips = [
            {
                "ip": row["ip"],
                "events": int(row["events"]),
                "bans": int(row["bans"] or 0),
                "recurrent": int(row["events"]) >= recurrent_threshold,
            }
            for row in rows
        ]
        stats.recurrent_ips = sum(1 for item in stats.top_ips if item["recurrent"])

        jail_rows = self.conn.execute(
            """
            SELECT jail, SUM(CASE WHEN kind='ban' THEN 1 ELSE 0 END) AS bans
            FROM security_events WHERE occurred_ts >= ? AND occurred_ts < ? AND jail <> ''
            GROUP BY jail ORDER BY bans DESC
            """,
            (lo, hi),
        ).fetchall()
        stats.jails = {row["jail"]: int(row["bans"] or 0) for row in jail_rows}

        cov_lo, cov_hi, total = self.coverage()
        stats.coverage_start = cov_lo
        stats.coverage_end = cov_hi
        stats.data_available = total > 0
        if total == 0:
            stats.warnings.append("no events have ever been collected: statistics are unavailable, not zero")
        elif cov_lo and cov_lo > start:
            stats.warnings.append(
                f"stored data starts {cov_lo.astimezone(tzinfo):%Y-%m-%d %H:%M}; "
                "the beginning of the requested period has no coverage"
            )
        return stats

    def banned_ips_in_period(self, start: datetime, end: datetime, limit: int = 500) -> List[Dict]:
        if not self.conn:
            self.open()
        assert self.conn is not None
        rows = self.conn.execute(
            """
            SELECT ip, jail, MAX(occurred_ts) AS last_ts, COUNT(*) AS events
            FROM security_events
            WHERE occurred_ts >= ? AND occurred_ts < ? AND kind='ban' AND ip <> ''
            GROUP BY ip, jail ORDER BY last_ts DESC LIMIT ?
            """,
            (int(start.timestamp()), int(end.timestamp()), int(limit)),
        ).fetchall()
        return [
            {
                "ip": row["ip"],
                "jail": row["jail"],
                "last": datetime.fromtimestamp(int(row["last_ts"]), tz=timezone.utc),
                "events": int(row["events"]),
            }
            for row in rows
        ]

    def events_for_ip(self, ip: str, limit: int = 100) -> List[Dict]:
        if not self.conn:
            self.open()
        assert self.conn is not None
        rows = self.conn.execute(
            "SELECT * FROM security_events WHERE ip = ? ORDER BY occurred_ts DESC LIMIT ?",
            (ip, int(limit)),
        ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["occurred_dt"] = _parse_iso(row["occurred_at"])
            out.append(item)
        return out

    def purge_older_than(self, cutoff: datetime) -> int:
        if not self.conn:
            self.open()
        assert self.conn is not None
        cur = self.conn.execute("DELETE FROM security_events WHERE occurred_ts < ?", (int(cutoff.timestamp()),))
        return cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0

    def vacuum(self) -> None:
        if self.conn and not self.read_only:
            self.conn.execute("VACUUM")

    def db_size(self) -> int:
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def backup(self, destination: Path) -> Path:
        """Consistent online backup using SQLite's backup API."""
        self.open()
        assert self.conn is not None
        destination.parent.mkdir(parents=True, exist_ok=True)
        target = connect(destination)
        try:
            with target:
                self.conn.backup(target)
        finally:
            target.close()
        try:
            os.chmod(destination, 0o600)
        except OSError:  # pragma: no cover
            pass
        return destination

    def integrity_check(self) -> Result:
        error = self.try_open()
        if error is not None:
            return Result(str(error), str(self.path), "error", f"corrupt or unreadable database: {error}")
        assert self.conn is not None
        try:
            rows = self.conn.execute("PRAGMA integrity_check").fetchall()
        except sqlite3.DatabaseError as exc:
            return Result(str(exc), str(self.path), "error", f"corrupt database: {exc}")
        messages = [row[0] for row in rows]
        if messages == ["ok"]:
            return Result.ok_result("ok", str(self.path))
        return Result(messages, str(self.path), "error", "; ".join(messages)[:200])
