"""Ingestion tests: idempotency, rotation, truncation, duplicates, history import."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from aureon.db.repo import Repository
from aureon.ingest import Ingestor

TZ = timezone(timedelta(hours=1), name="TEST+1")


def make_repo(tmp_path: Path) -> Repository:
    repo = Repository(tmp_path / "test.db")
    repo.open()
    return repo


def write_log(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


F2B_LOG = (
    "2026-03-05 14:22:31,123 fail2ban.actions [1201]: NOTICE [sshd] Ban 203.0.113.10\n"
    "2026-03-05 14:22:31,200 fail2ban.actions [1201]: NOTICE [sshd] Ban 203.0.113.11\n"
)


def test_first_ingest_inserts_events(tmp_path):
    log = tmp_path / "fail2ban.log"
    write_log(log, F2B_LOG)
    repo = make_repo(tmp_path)
    report = Ingestor(repo, TZ).ingest_files(paths=[str(log)])
    assert report.added == 2
    assert repo.count_events("ban") == 2


def test_reingesting_the_same_file_is_idempotent(tmp_path):
    log = tmp_path / "fail2ban.log"
    write_log(log, F2B_LOG)
    repo = make_repo(tmp_path)
    ingestor = Ingestor(repo, TZ)
    ingestor.ingest_files(paths=[str(log)])
    ingestor.ingest_files(paths=[str(log)])
    ingestor.ingest_files(paths=[str(log)])
    assert repo.count_events() == 2, "re-processing must not duplicate events"


def test_duplicate_lines_in_the_file_are_deduplicated(tmp_path):
    log = tmp_path / "fail2ban.log"
    write_log(log, F2B_LOG + F2B_LOG)
    repo = make_repo(tmp_path)
    report = Ingestor(repo, TZ).ingest_files(paths=[str(log)])
    assert report.added == 2
    assert repo.count_events() == 2


def test_appended_lines_are_ingested_incrementally(tmp_path):
    log = tmp_path / "fail2ban.log"
    write_log(log, F2B_LOG)
    repo = make_repo(tmp_path)
    ingestor = Ingestor(repo, TZ)
    ingestor.ingest_files(paths=[str(log)])
    with open(log, "a", encoding="utf-8") as handle:
        handle.write("2026-03-06 09:00:00,000 fail2ban.actions [1201]: NOTICE [sshd] Ban 198.51.100.7\n")
    report = ingestor.ingest_files(paths=[str(log)])
    assert report.added == 1
    assert report.duplicates == 0
    assert repo.count_events() == 3


def test_partial_trailing_line_is_not_ingested_until_complete(tmp_path):
    log = tmp_path / "fail2ban.log"
    write_log(log, F2B_LOG + "2026-03-06 09:00:00,000 fail2ban.actions [1201]: NOTICE [sshd] Ban 198.51.100.7")
    repo = make_repo(tmp_path)
    ingestor = Ingestor(repo, TZ)
    ingestor.ingest_files(paths=[str(log)])
    assert repo.count_events() == 2, "the incomplete trailing line must be left for the next run"

    write_log(log, F2B_LOG + "2026-03-06 09:00:00,000 fail2ban.actions [1201]: NOTICE [sshd] Ban 198.51.100.7\n")
    report = ingestor.ingest_files(paths=[str(log)])
    assert report.added == 1
    assert repo.count_events() == 3


def test_rotation_is_detected_and_rescanned(tmp_path):
    log = tmp_path / "fail2ban.log"
    write_log(log, F2B_LOG)
    repo = make_repo(tmp_path)
    ingestor = Ingestor(repo, TZ)
    ingestor.ingest_files(paths=[str(log)])

    # Simulate logrotate: brand new inode with different content.
    rotated = tmp_path / "fail2ban.log.1"
    rotated.write_text(F2B_LOG, encoding="utf-8")
    write_log(log, "2026-03-07 08:00:00,000 fail2ban.actions [1201]: NOTICE [sshd] Ban 203.0.113.99\n")
    report = ingestor.ingest_files(paths=[str(log)])
    assert repo.count_events() == 3
    assert any("rescanning" in note for note in report.notes)


def test_truncation_is_detected(tmp_path):
    log = tmp_path / "fail2ban.log"
    write_log(log, F2B_LOG * 20)
    repo = make_repo(tmp_path)
    ingestor = Ingestor(repo, TZ)
    ingestor.ingest_files(paths=[str(log)])

    write_log(log, "2026-03-07 08:00:00,000 fail2ban.actions [1201]: NOTICE [sshd] Ban 203.0.113.99\n")
    report = ingestor.ingest_files(paths=[str(log)])
    assert any("truncated" in note for note in report.notes)
    assert repo.count_events() == 3


def test_unreadable_file_is_reported_not_ignored(tmp_path):
    log = tmp_path / "fail2ban.log"
    write_log(log, F2B_LOG)
    log.chmod(0o000)
    repo = make_repo(tmp_path)
    try:
        report = Ingestor(repo, TZ).ingest_files(paths=[str(log)])
        assert report.state in ("denied", "error", "partial")
        assert report.notes
    finally:
        log.chmod(0o600)


def test_missing_files_are_reported(tmp_path):
    repo = make_repo(tmp_path)
    report = Ingestor(repo, TZ).ingest_files(paths=[str(tmp_path / "nope.log")])
    assert report.state in ("ok", "unavailable")
    assert repo.count_events() == 0


def test_history_import_reads_everything_available(tmp_path, monkeypatch):
    log = tmp_path / "fail2ban.log"
    write_log(log, F2B_LOG)
    monkeypatch.setattr("aureon.ingest.F2B_LOG_CANDIDATES", (str(log),))
    repo = make_repo(tmp_path)
    report = Ingestor(repo, TZ).import_history()
    assert report.added == 2
    assert any("covering" in note for note in report.notes)


def test_history_import_without_any_log(tmp_path, monkeypatch):
    monkeypatch.setattr("aureon.ingest.F2B_LOG_CANDIDATES", (str(tmp_path / "missing.log"),))
    repo = make_repo(tmp_path)
    report = Ingestor(repo, TZ).import_history()
    assert report.state == "unavailable"
    assert repo.count_events() == 0


def test_collection_runs_are_recorded(tmp_path):
    log = tmp_path / "fail2ban.log"
    write_log(log, F2B_LOG)
    repo = make_repo(tmp_path)
    Ingestor(repo, TZ).ingest_files(paths=[str(log)])
    last = repo.last_run()
    assert last is not None
    assert int(last["events_added"]) == 2


def test_cursor_state_survives_a_new_repository_instance(tmp_path):
    log = tmp_path / "fail2ban.log"
    write_log(log, F2B_LOG)
    first = make_repo(tmp_path)
    Ingestor(first, TZ).ingest_files(paths=[str(log)])
    first.close()

    second = make_repo(tmp_path)
    report = Ingestor(second, TZ).ingest_files(paths=[str(log)])
    assert report.added == 0
    assert second.count_events() == 2
    second.close()


def test_max_bytes_limits_a_single_read(tmp_path):
    log = tmp_path / "fail2ban.log"
    body = "".join(
        f"2026-03-05 14:22:{index % 60:02d},000 fail2ban.actions [1201]: NOTICE [sshd] Ban 203.0.113.{index % 250}\n"
        for index in range(50)
    )
    write_log(log, body)
    repo = make_repo(tmp_path)
    report = Ingestor(repo, TZ).ingest_files(paths=[str(log)], max_bytes=200)
    assert report.bytes_read <= 200
    assert 0 < report.seen < 50
