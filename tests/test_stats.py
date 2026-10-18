"""Statistics tests: unique IPs vs events, periods, coverage, recurrence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from aureon.fail2ban.stats import SecurityStatsService, coverage_note
from aureon.models import PeriodStats, SecurityEvent
from aureon.periods import PERIOD_MONTH, PERIOD_TODAY, PERIOD_WEEK, PERIOD_YEAR

TZ = timezone(timedelta(hours=1), name="TEST+1")
NOW = datetime(2026, 3, 7, 12, 0, 0, tzinfo=TZ)


def event(moment, ip, kind="ban", jail="sshd", source="test"):
    return SecurityEvent(occurred_at=moment, source=source, kind=kind, jail=jail, ip=ip)


def seed(repo, events):
    added, duplicates = repo.insert_events(events)
    assert duplicates == 0
    return added


def test_unique_ips_and_events_are_distinct(repo):
    seed(
        repo,
        [
            event(datetime(2026, 3, 7, 1, 0, tzinfo=TZ), "1.1.1.1"),
            event(datetime(2026, 3, 7, 2, 0, tzinfo=TZ), "1.1.1.1"),
            event(datetime(2026, 3, 7, 3, 0, tzinfo=TZ), "2.2.2.2"),
        ],
    )
    stats = repo.stats_for_period("today", NOW - timedelta(days=1), NOW, TZ, "TEST+1")
    assert stats.ban_events == 3
    assert stats.unique_banned_ips == 2


def test_recurrent_ips_are_counted(repo):
    seed(
        repo,
        [
            event(datetime(2026, 3, 7, 1, 0, tzinfo=TZ), "1.1.1.1"),
            event(datetime(2026, 3, 7, 2, 0, tzinfo=TZ), "1.1.1.1"),
            event(datetime(2026, 3, 7, 3, 0, tzinfo=TZ), "3.3.3.3"),
        ],
    )
    stats = repo.stats_for_period("today", NOW - timedelta(days=1), NOW, TZ, "TEST+1")
    assert stats.recurrent_ips == 1
    top = stats.top_ips[0]
    assert top["ip"] == "1.1.1.1" and top["recurrent"] is True


def test_unban_events_are_tracked_separately(repo):
    seed(
        repo,
        [
            event(datetime(2026, 3, 7, 1, 0, tzinfo=TZ), "1.1.1.1", kind="ban"),
            event(datetime(2026, 3, 7, 5, 0, tzinfo=TZ), "1.1.1.1", kind="unban"),
        ],
    )
    stats = repo.stats_for_period("today", NOW - timedelta(days=1), NOW, TZ, "TEST+1")
    assert stats.ban_events == 1
    assert stats.unban_events == 1
    assert stats.unbanned_ips == 1


def test_empty_store_reports_unavailable_not_zero(repo):
    stats = repo.stats_for_period("today", NOW - timedelta(days=1), NOW, TZ, "TEST+1")
    assert stats.ban_events == 0
    assert stats.data_available is False
    assert any("unavailable" in warning for warning in stats.warnings)


def test_partial_coverage_is_flagged(repo):
    seed(repo, [event(datetime(2026, 3, 5, 12, 0, tzinfo=TZ), "1.1.1.1")])
    span_start = datetime(2026, 3, 1, 0, 0, tzinfo=TZ)
    stats = repo.stats_for_period("month", span_start, datetime(2026, 4, 1, tzinfo=TZ), TZ, "TEST+1")
    assert stats.data_available is True
    assert stats.complete is False
    assert any("no coverage" in warning for warning in stats.warnings)


def test_failed_auth_events_are_counted_separately(repo):
    seed(
        repo,
        [
            event(datetime(2026, 3, 7, 1, 0, tzinfo=TZ), "1.1.1.1", kind="auth_failure", jail=""),
            event(datetime(2026, 3, 7, 1, 5, tzinfo=TZ), "1.1.1.1", kind="auth_failure", jail=""),
        ],
    )
    stats = repo.stats_for_period("today", NOW - timedelta(days=1), NOW, TZ, "TEST+1")
    assert stats.failed_auth_attempts == 2
    assert stats.ban_events == 0


def test_period_windows_do_not_leak_into_each_other(repo):
    seed(repo, [event(datetime(2025, 12, 31, 23, 59, tzinfo=TZ), "9.9.9.9")])
    service = SecurityStatsService(repo, TZ)
    stats = service.period(PERIOD_YEAR, now=datetime(2026, 3, 7, tzinfo=TZ))
    assert stats.ban_events == 0


def test_currently_banned_is_passed_through_not_derived(repo):
    seed(repo, [event(datetime(2026, 3, 7, 1, 0, tzinfo=TZ), "1.1.1.1")])
    service = SecurityStatsService(repo, TZ)
    stats = service.period(PERIOD_TODAY, now=NOW)
    assert stats.currently_banned is None, "without live state the value must stay unverified"


def test_all_periods_service(repo):
    seed(
        repo,
        [
            event(datetime(2026, 3, 7, 1, 0, tzinfo=TZ), "1.1.1.1"),
            event(datetime(2026, 3, 1, 1, 0, tzinfo=TZ), "2.2.2.2"),
        ],
    )
    service = SecurityStatsService(repo, TZ)
    periods = service.all_periods(now=NOW)
    assert set(periods) == {"24h", "today", "week", "month", "year"}
    assert periods["today"].ban_events == 1
    assert periods["24h"].ban_events == 1
    # 2026-03-01 is a Sunday, so it belongs to the previous ISO week.
    assert periods["week"].ban_events == 1
    assert periods["month"].ban_events == 2
    assert periods["year"].ban_events == 2


def test_coverage_note_without_data(repo):
    assert "unavailable" in coverage_note(repo, TZ)


def test_coverage_note_with_data(repo):
    seed(repo, [event(datetime(2026, 3, 5, 12, 0, tzinfo=TZ), "1.1.1.1")])
    note = coverage_note(repo, TZ)
    assert "1 events" in note
    assert "2026-03-05" in note


def test_banned_ips_in_period(repo):
    seed(
        repo,
        [
            event(datetime(2026, 3, 7, 1, 0, tzinfo=TZ), "1.1.1.1"),
            event(datetime(2026, 3, 7, 2, 0, tzinfo=TZ), "1.1.1.1"),
            event(datetime(2026, 3, 7, 3, 0, tzinfo=TZ), "2.2.2.2", jail="apache-auth"),
        ],
    )
    rows = repo.banned_ips_in_period(NOW - timedelta(days=1), NOW)
    assert len(rows) == 2
    assert {row["ip"] for row in rows} == {"1.1.1.1", "2.2.2.2"}


def test_retention_prunes_old_events(repo):
    seed(
        repo,
        [
            event(datetime(2020, 1, 1, tzinfo=TZ), "1.1.1.1"),
            event(datetime(2026, 3, 7, tzinfo=TZ), "2.2.2.2"),
        ],
    )
    removed = repo.purge_older_than(datetime(2026, 1, 1, tzinfo=TZ))
    assert removed == 1
    assert repo.count_events() == 1


def test_stats_never_mix_jails(repo):
    seed(
        repo,
        [
            event(datetime(2026, 3, 7, 1, 0, tzinfo=TZ), "1.1.1.1", jail="sshd"),
            event(datetime(2026, 3, 7, 2, 0, tzinfo=TZ), "1.1.1.1", jail="apache-auth"),
        ],
    )
    stats = repo.stats_for_period("today", NOW - timedelta(days=1), NOW, TZ, "TEST+1")
    assert stats.unique_banned_ips == 1
    assert stats.jails == {"sshd": 1, "apache-auth": 1}
