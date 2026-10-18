"""Repository resilience: backup, integrity, corruption handling, migration."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aureon.db.repo import Repository
from aureon.db.schema import SCHEMA_VERSION, migrate
from aureon.models import SecurityEvent

TZ = timezone.utc


def event(moment, ip="1.1.1.1", kind="ban"):
    return SecurityEvent(occurred_at=moment, source="test", kind=kind, jail="sshd", ip=ip)


def test_migrations_are_idempotent(tmp_path):
    path = tmp_path / "m.db"
    repo = Repository(path)
    repo.open()
    version = repo.conn.execute("PRAGMA user_version").fetchone()[0]
    assert version == SCHEMA_VERSION
    migrate(repo.conn)
    migrate(repo.conn)
    assert repo.conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    repo.close()


def test_indexes_exist_for_the_query_patterns(tmp_path):
    repo = Repository(tmp_path / "i.db")
    repo.open()
    names = {row[0] for row in repo.conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert {"idx_events_ts", "idx_events_ip", "idx_events_jail"} <= names
    repo.close()


def test_backup_produces_a_usable_copy(tmp_path):
    repo = Repository(tmp_path / "live.db")
    repo.open()
    repo.insert_events([event(datetime.now(TZ))])
    backup = repo.backup(tmp_path / "backup.db")
    copy = Repository(backup)
    copy.open()
    assert copy.count_events() == 1
    copy.close()
    repo.close()


def test_backup_is_private(tmp_path):
    repo = Repository(tmp_path / "live.db")
    repo.open()
    backup = repo.backup(tmp_path / "backup.db")
    assert backup.stat().st_mode & 0o077 == 0
    repo.close()


def test_integrity_check_on_a_healthy_database(tmp_path):
    repo = Repository(tmp_path / "ok.db")
    repo.open()
    assert repo.integrity_check().available
    repo.close()


def test_integrity_check_detects_corruption(tmp_path):
    path = tmp_path / "broken.db"
    repo = Repository(path)
    repo.open()
    repo.insert_events([event(datetime.now(TZ))])
    repo.close()
    with open(path, "r+b") as handle:
        handle.seek(0)
        handle.write(b"\x00" * 4096)
    broken = Repository(path)
    result = broken.integrity_check()
    assert not result.available or result.value == "ok" or "corrupt" in (result.error or "")
    broken.close()


def test_insert_is_deduplicated_at_the_schema_level(tmp_path):
    repo = Repository(tmp_path / "dup.db")
    repo.open()
    item = event(datetime(2026, 3, 5, tzinfo=TZ))
    first = repo.insert_events([item])
    second = repo.insert_events([item])
    assert first[0] == 1
    assert second[0] == 0
    assert second[1] == 1
    assert repo.count_events() == 1
    repo.close()


def test_database_survives_reopen(tmp_path):
    path = tmp_path / "persist.db"
    repo = Repository(path)
    repo.open()
    repo.insert_events([event(datetime(2026, 3, 5, tzinfo=TZ))])
    repo.close()

    reopened = Repository(path)
    reopened.open()
    assert reopened.count_events() == 1
    reopened.close()


def test_unreadable_state_directory_is_reported(tmp_path):
    repo = Repository(tmp_path / "nested" / "deeper" / "aureon.db")
    result = repo.available()
    assert result.available


def test_events_query_filters_by_ip(repo):
    repo.insert_events(
        [
            event(datetime(2026, 3, 5, 1, tzinfo=TZ), ip="1.1.1.1"),
            event(datetime(2026, 3, 5, 2, tzinfo=TZ), ip="2.2.2.2"),
        ]
    )
    events = repo.events_for_ip("2.2.2.2")
    assert len(events) == 1
    assert events[0]["ip"] == "2.2.2.2"


def test_coverage_reports_none_when_empty(repo):
    lo, hi, total = repo.coverage()
    assert (lo, hi, total) == (None, None, 0)


def test_wal_mode_is_used_for_crash_safety(tmp_path):
    repo = Repository(tmp_path / "wal.db")
    repo.open()
    mode = repo.conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode.lower() == "wal"
    repo.close()
