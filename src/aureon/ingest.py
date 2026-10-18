"""Event ingestion: file cursors, rotation detection and idempotent writes.

Guarantees
----------
* Re-processing the same byte range never duplicates an event (UNIQUE
  ``dedup_key`` + explicit pre-check).
* Rotation is detected through ``(st_dev, st_ino)`` changes and through a
  truncated size, which also covers logrotate ``copytruncate``.
* A crash mid-ingest is safe: events are inserted in one transaction and the
  cursor is only advanced after a successful insert, so the next run re-reads
  the same region and deduplicates it.
* No auxiliary service is installed. AUREON ingests while the console runs; if
  the server is never rebooted into AUREON again, history simply stops growing
  - which the UI reports honestly (see docs/FAIL2BAN.md).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from .db.repo import Repository
from .models import SecurityEvent
from .util import which
from .fail2ban.parser import (
    parse_auth_log,
    parse_fail2ban_journal,
    parse_fail2ban_log,
    parse_journal_sshd,
)

F2B_LOG_CANDIDATES = ("/var/log/fail2ban.log", "/usr/local/var/log/fail2ban.log")
AUTH_LOG_CANDIDATES = ("/var/log/auth.log", "/var/log/secure")


@dataclass
class IngestReport:
    source: str
    seen: int = 0
    added: int = 0
    duplicates: int = 0
    bytes_read: int = 0
    state: str = "ok"
    notes: List[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None

    def merge(self, other: "IngestReport") -> "IngestReport":
        return IngestReport(
            source=f"{self.source}+{other.source}",
            seen=self.seen + other.seen,
            added=self.added + other.added,
            duplicates=self.duplicates + other.duplicates,
            bytes_read=self.bytes_read + other.bytes_read,
            state="ok" if self.state == other.state == "ok" else "partial",
            notes=self.notes + other.notes,
            started_at=min(self.started_at, other.started_at),
            finished_at=self.finished_at or other.finished_at,
        )


class Ingestor:
    def __init__(self, repo: Repository, tzinfo, host_id: str = "") -> None:
        self.repo = repo
        self.tz = tzinfo
        self.host_id = host_id or _default_host_id()

    # -- public API ------------------------------------------------------
    def ingest_files(self, paths: Optional[Sequence[str]] = None, max_bytes: int = 32 * 1024 * 1024) -> IngestReport:
        report = IngestReport(source="files")
        targets: List[str] = list(paths) if paths else list(F2B_LOG_CANDIDATES) + list(AUTH_LOG_CANDIDATES)
        for path in targets:
            if not Path(path).exists():
                continue
            kind = "auth" if "auth" in path or "secure" in path else "fail2ban"
            sub = self._ingest_file(path, kind, max_bytes)
            report = report.merge(sub)
        if report.seen == 0 and not targets:
            report.state = "unavailable"
            report.notes.append("no log file candidates exist on this system")
        self.repo.record_run(
            source=report.source,
            started_at=report.started_at,
            finished_at=report.finished_at or datetime.now(timezone.utc),
            events_seen=report.seen,
            events_added=report.added,
            duplicates=report.duplicates,
            state=report.state,
            note="; ".join(report.notes)[:400],
        )
        return report

    def ingest_journal(self, since: Optional[datetime] = None) -> IngestReport:
        """Ingest from journald when log files are unavailable or rotated."""
        from .util import run

        report = IngestReport(source="journal")
        journalctl = which("journalctl")
        if not journalctl:
            report.state = "unavailable"
            report.notes.append("journalctl not installed")
            return report

        since_text = f"--since={since.astimezone(self.tz).strftime('%Y-%m-%d %H:%M:%S')}" if since else "--since=-7days"
        for unit, parser, label in (
            ("fail2ban", parse_fail2ban_journal, "journal-fail2ban"),
            ("fail2ban", parse_auth_log, "journal-fail2ban-auth"),
            ("sshd", parse_journal_sshd, "journal-sshd"),
        ):
            argv = [journalctl, "--no-pager", "-o", "short-iso", since_text, "--unit", unit, "--lines", "20000"]
            res = run(argv, timeout=25.0)
            if res.returncode == 0 and res.stdout.strip():
                events = parser(res.stdout.splitlines(), self.tz, source=label)
                sub = self._store(events, label)
                report = report.merge(sub)
            elif res.returncode not in (0,):
                report.state = "partial"
                report.notes.append(f"{label}: journalctl exit {res.returncode}")
        report.finished_at = datetime.now(timezone.utc)
        return report

    def ingest_all(self, max_bytes: int = 32 * 1024 * 1024) -> IngestReport:
        report = self.ingest_files(max_bytes=max_bytes)
        if report.seen == 0:
            report = report.merge(self.ingest_journal())
        return report

    def import_history(self, max_lines: int = 200000) -> IngestReport:
        """Import everything still present in the Fail2ban log file.

        This is the "AUREON installed on an already-protected server" path. The
        report states exactly how much history was available.
        """
        report = IngestReport(source="history-import")
        imported_any = False
        for path in F2B_LOG_CANDIDATES:
            p = Path(path)
            if not p.exists():
                continue
            imported_any = True
            text = self._read_tail(p, max_lines)
            events = parse_fail2ban_log(text.splitlines(), self.tz, source="history-import")
            report = report.merge(self._store(events, f"history-import:{path}"))
            if events:
                first = min(event.occurred_at for event in events)
                last = max(event.occurred_at for event in events)
                report.notes.append(
                    f"{path}: {len(events)} events covering {first:%Y-%m-%d} .. {last:%Y-%m-%d}"
                )
            else:
                report.notes.append(f"{path}: present but no recognisable ban/unban lines")
        if not imported_any:
            report.state = "unavailable"
            report.notes.append("no Fail2ban log file found: nothing to import")
        report.finished_at = datetime.now(timezone.utc)
        self.repo.record_run(
            source="history-import",
            started_at=report.started_at,
            finished_at=report.finished_at,
            events_seen=report.seen,
            events_added=report.added,
            duplicates=report.duplicates,
            state=report.state,
            note="; ".join(report.notes)[:400],
        )
        return report

    # -- internals -------------------------------------------------------
    def _ingest_file(self, path: str, kind: str, max_bytes: int) -> IngestReport:
        report = IngestReport(source=path)
        p = Path(path)
        try:
            stat = p.stat()
        except OSError as exc:
            report.state = "error"
            report.notes.append(f"{path}: {exc}")
            return report
        if not os.access(path, os.R_OK):
            report.state = "denied"
            report.notes.append(f"{path}: not readable by the current user")
            return report

        key = f"file:{path}"
        cursor = self.repo.get_cursor(key) or {}
        stored_inode = cursor.get("inode")
        stored_offset = int(cursor.get("offset") or 0)
        stored_device = cursor.get("device")

        rotated = False
        if stored_inode is not None and stored_inode != stat.st_ino:
            rotated = True
            report.notes.append(f"{path}: file replaced (inode changed) - rescanning from the beginning")
        if stored_offset > stat.st_size:
            rotated = True
            report.notes.append(f"{path}: file truncated - rescanning from the beginning")

        offset = 0 if rotated else stored_offset
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                handle.seek(offset)
                chunk = handle.read(max_bytes)
                consumed = len(chunk.encode("utf-8", "replace"))
                lines = chunk.splitlines()
                # A trailing partial line is left for the next run.
                if chunk and not chunk.endswith("\n"):
                    keep = len(lines) - 1 if len(lines) > 1 else 0
                    lines = lines[:keep]
                    consumed = sum(len(line) + 1 for line in lines)
        except OSError as exc:
            report.state = "error"
            report.notes.append(f"{path}: {exc}")
            return report

        report.bytes_read = consumed
        report.seen = len(lines)
        if kind == "auth":
            events = parse_auth_log(lines, self.tz, source=f"auth:{os.path.basename(path)}")
        else:
            events = parse_fail2ban_log(lines, self.tz, source=f"log:{os.path.basename(path)}")

        sub = self._store(events, key)
        report.added = sub.added
        report.duplicates = sub.duplicates
        report.notes.extend(sub.notes)
        if report.state == "ok" and sub.state != "ok":
            report.state = sub.state

        new_offset = offset + consumed
        self.repo.set_cursor(
            key,
            {
                "path": path,
                "inode": stat.st_ino,
                "device": stat.st_dev,
                "size": stat.st_size,
                "offset": new_offset,
                "line": int(cursor.get("line") or 0) + report.seen,
                "last_scan": datetime.now(timezone.utc).isoformat(),
                "state": report.state,
                "note": "; ".join(report.notes)[:300],
            },
        )
        report.finished_at = datetime.now(timezone.utc)
        return report

    def _store(self, events: Sequence[SecurityEvent], source_label: str) -> IngestReport:
        report = IngestReport(source=source_label)
        report.seen = len(events)
        if not events:
            return report
        now = datetime.now(timezone.utc)
        prepared = []
        for event in events:
            event.host_id = self.host_id
            event.ingested_at = now
            prepared.append(event)
        try:
            added, duplicates = self.repo.insert_events(prepared, self.host_id)
            report.added = added
            report.duplicates = duplicates
        except Exception as exc:  # noqa: BLE001 - never break the console
            report.state = "error"
            report.notes.append(f"storage error: {exc}")
        report.finished_at = datetime.now(timezone.utc)
        return report

    @staticmethod
    def _read_tail(path: Path, max_lines: int) -> str:
        try:
            size = path.stat().st_size
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                if size > 64 * 1024 * 1024:
                    handle.seek(size - 64 * 1024 * 1024)
                    handle.readline()
                lines = handle.read().splitlines()
            return "\n".join(lines[-max_lines:])
        except OSError:
            return ""


def _default_host_id() -> str:
    try:
        import socket

        return socket.gethostname()
    except OSError:  # pragma: no cover
        return "unknown-host"
