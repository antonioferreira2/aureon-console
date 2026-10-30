"""Parser tests for fail2ban.log, journal output and auth logs."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from aureon.fail2ban.parser import (
    parse_auth_log,
    parse_fail2ban_journal,
    parse_fail2ban_log,
    parse_journal_sshd,
)

TZ = timezone(timedelta(hours=1), name="TEST+1")


def test_parses_ban_and_unban(sample_fail2ban_log):
    events = parse_fail2ban_log(sample_fail2ban_log.splitlines(), TZ)
    kinds = [event.kind for event in events]
    assert kinds.count("ban") == 5
    assert kinds.count("unban") == 1
    bans = [event for event in events if event.kind == "ban"]
    assert all(event.jail == "sshd" for event in bans)
    assert events[0].ip == "203.0.113.10"
    assert events[0].occurred_at == datetime(2026, 3, 5, 14, 22, 31, tzinfo=TZ)


def test_filter_match_lines_are_not_bans(sample_fail2ban_log):
    events = parse_fail2ban_log(sample_fail2ban_log.splitlines(), TZ)
    assert any(event.kind == "found" for event in events)
    found = [event for event in events if event.kind == "found"]
    assert found[0].ip == "203.0.113.55"


def test_repeated_bans_from_same_ip_produce_distinct_events(sample_fail2ban_log):
    events = [e for e in parse_fail2ban_log(sample_fail2ban_log.splitlines(), TZ) if e.ip == "198.51.100.7"]
    assert len(events) == 2
    assert events[0].source_id != events[1].source_id
    assert events[0].dedup_key != events[1].dedup_key


def test_parsing_is_deterministic(sample_fail2ban_log):
    first = parse_fail2ban_log(sample_fail2ban_log.splitlines(), TZ)
    second = parse_fail2ban_log(sample_fail2ban_log.splitlines(), TZ)
    assert [e.dedup_key for e in first] == [e.dedup_key for e in second]


def test_unparsable_lines_are_ignored():
    events = parse_fail2ban_log(["not a log line", "", "\x00binary"], TZ)
    assert events == []


def test_journal_events_use_journald_timestamp():
    lines = ["2026-03-06T09:00:00+0100 afia01 fail2ban.actions[1201]: NOTICE [sshd] Ban 198.51.100.7"]
    events = parse_fail2ban_journal(lines, TZ)
    assert len(events) == 1
    assert events[0].kind == "ban"
    assert events[0].occurred_at.astimezone(TZ).hour == 9


def test_iso_parser_accepts_compact_offsets_and_fractions_across_python_versions():
    from aureon.fail2ban.parser import _iso_to_datetime

    parsed = _iso_to_datetime("2026-03-06T09:00:00.123456+0100", TZ)
    assert parsed == datetime(2026, 3, 6, 9, 0, 0, 123456, tzinfo=TZ)
    assert _iso_to_datetime("2026-03-06T09:00:00+25:00", TZ) is None


def test_invalid_journal_timestamp_is_skipped_not_replaced_with_current_time():
    fail2ban = ["2026-03-06T09:00:00+2500 afia01 fail2ban.actions[1201]: NOTICE [sshd] Ban 198.51.100.7"]
    sshd = ["2026-03-06T09:00:00+2500 afia01 sshd[904]: Failed password for test from 192.0.2.5 port 22 ssh2"]
    assert parse_fail2ban_journal(fail2ban, TZ) == []
    assert parse_journal_sshd(sshd, TZ) == []
    assert parse_auth_log(["2026-03-06T09:00:00+25:00 afia01 sshd[904]: Failed password for test from 192.0.2.5 port 22 ssh2"], TZ) == []


def test_journal_ignores_unrelated_units():
    lines = ["2026-03-06T09:00:00+0100 afia01 CRON[5]: something NOTICE [sshd] Ban 1.2.3.4"]
    assert parse_fail2ban_journal(lines, TZ) == []


def test_classic_syslog_auth_log(sample_auth_log_classic):
    events = parse_auth_log(sample_auth_log_classic.splitlines(), TZ, year_hint=2026)
    assert len(events) == 2
    assert events[0].username == "admin"
    assert events[0].occurred_at.month == 3


def test_auth_failures_are_not_bans(sample_auth_log):
    events = parse_auth_log(sample_auth_log.splitlines(), TZ)
    assert events
    assert all(event.kind == "auth_failure" for event in events)
    assert all(event.jail == "" for event in events)


def test_auth_usernames_are_captured(sample_auth_log):
    events = parse_auth_log(sample_auth_log.splitlines(), TZ)
    users = {event.username for event in events}
    assert "admin" in users
    assert "root" in users
    assert "oracle" in users


def test_successful_logins_and_irrelevant_lines_are_not_events(sample_auth_log):
    events = parse_auth_log(sample_auth_log.splitlines(), TZ)
    assert all("Accepted publickey" not in event.meta.get("raw", "") for event in events)
    assert all("CRON" not in event.meta.get("unit", "") for event in events)


def test_auth_dedup_keys_are_unique(sample_auth_log):
    events = parse_auth_log(sample_auth_log.splitlines(), TZ)
    keys = [event.dedup_key for event in events]
    # two failures from the same IP in the same second share a key by design:
    # identical second + IP is one observed event from this source.
    assert len(keys) == len(set(keys))


def test_iso_timestamp_auth_log():
    lines = [
        "2026-03-05T14:20:00.123456+01:00 afia01 sshd[900]: Failed password for root from 203.0.113.9 port 22 ssh2"
    ]
    events = parse_auth_log(lines, TZ)
    assert len(events) == 1
    assert events[0].ip == "203.0.113.9"
    assert events[0].occurred_at.year == 2026


def test_journal_sshd_failures():
    lines = [
        "2026-03-06T09:00:02+0100 afia01 sshd[904]: Failed password for invalid user test from 192.0.2.5 port 4001 ssh2"
    ]
    events = parse_journal_sshd(lines, TZ)
    assert len(events) == 1
    assert events[0].ip == "192.0.2.5"
    assert events[0].kind == "auth_failure"
