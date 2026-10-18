"""Period boundary tests: timezone, ISO week, year rollover, custom ranges."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aureon.periods import (
    PERIOD_24H,
    PERIOD_CUSTOM,
    PERIOD_MONTH,
    PERIOD_TODAY,
    PERIOD_WEEK,
    PERIOD_YEAR,
    period_range,
    resolve_timezone,
    timezone_name,
)

TZ = timezone(timedelta(hours=1), name="TEST+1")


def test_today_starts_at_local_midnight():
    now = datetime(2026, 3, 7, 14, 30, 0, tzinfo=TZ)
    period = period_range(PERIOD_TODAY, now=now, tz=TZ)
    assert period.start == datetime(2026, 3, 7, 0, 0, 0, tzinfo=TZ)
    assert period.end == datetime(2026, 3, 8, 0, 0, 0, tzinfo=TZ)
    assert period.contains(now)


def test_today_excludes_midnight_of_next_day():
    now = datetime(2026, 3, 7, 23, 59, 59, tzinfo=TZ)
    period = period_range(PERIOD_TODAY, now=now, tz=TZ)
    assert not period.contains(datetime(2026, 3, 8, 0, 0, 0, tzinfo=TZ))


def test_week_starts_on_monday_iso8601():
    # 2026-03-07 is a Saturday; the ISO week starts on Monday 2026-03-02.
    now = datetime(2026, 3, 7, 12, 0, 0, tzinfo=TZ)
    period = period_range(PERIOD_WEEK, now=now, tz=TZ)
    assert period.start.weekday() == 0
    assert period.start == datetime(2026, 3, 2, 0, 0, 0, tzinfo=TZ)
    assert period.end == datetime(2026, 3, 9, 0, 0, 0, tzinfo=TZ)


def test_week_on_monday_starts_same_day():
    now = datetime(2026, 3, 2, 0, 0, 0, tzinfo=TZ)
    period = period_range(PERIOD_WEEK, now=now, tz=TZ)
    assert period.start == now
    assert period.duration_seconds == 7 * 86400


def test_month_boundaries():
    now = datetime(2026, 3, 31, 23, 0, 0, tzinfo=TZ)
    period = period_range(PERIOD_MONTH, now=now, tz=TZ)
    assert period.start == datetime(2026, 3, 1, 0, 0, 0, tzinfo=TZ)
    assert period.end == datetime(2026, 4, 1, 0, 0, 0, tzinfo=TZ)


def test_december_rolls_into_next_year():
    now = datetime(2026, 12, 15, 8, 0, 0, tzinfo=TZ)
    month = period_range(PERIOD_MONTH, now=now, tz=TZ)
    assert month.end == datetime(2027, 1, 1, 0, 0, 0, tzinfo=TZ)
    year = period_range(PERIOD_YEAR, now=now, tz=TZ)
    assert year.start == datetime(2026, 1, 1, 0, 0, 0, tzinfo=TZ)
    assert year.end == datetime(2027, 1, 1, 0, 0, 0, tzinfo=TZ)


def test_year_starting_period_in_january():
    now = datetime(2027, 1, 1, 0, 0, 1, tzinfo=TZ)
    year = period_range(PERIOD_YEAR, now=now, tz=TZ)
    assert year.start == datetime(2027, 1, 1, 0, 0, 0, tzinfo=TZ)
    assert year.end == datetime(2028, 1, 1, 0, 0, 0, tzinfo=TZ)


def test_iso_week_crossing_year_boundary():
    # 2027-01-01 is a Friday; its ISO week starts on Monday 2026-12-28.
    now = datetime(2027, 1, 1, 10, 0, 0, tzinfo=TZ)
    week = period_range(PERIOD_WEEK, now=now, tz=TZ)
    assert week.start == datetime(2026, 12, 28, 0, 0, 0, tzinfo=TZ)
    assert week.end == datetime(2027, 1, 4, 0, 0, 0, tzinfo=TZ)
    assert week.start.year == 2026 and week.end.year == 2027


def test_24h_is_a_rolling_window():
    now = datetime(2026, 3, 7, 14, 0, 0, tzinfo=TZ)
    period = period_range(PERIOD_24H, now=now, tz=TZ)
    assert period.duration_seconds == 86400
    assert period.end == now
    assert not period.contains(datetime(2026, 3, 6, 13, 59, 59, tzinfo=TZ))


def test_timezone_shift_changes_boundaries():
    plus_two = timezone(timedelta(hours=2), name="TEST+2")
    utc_now = datetime(2026, 3, 7, 23, 30, 0, tzinfo=timezone.utc)
    period = period_range(PERIOD_TODAY, now=utc_now, tz=plus_two)
    assert period.start == datetime(2026, 3, 8, 0, 0, 0, tzinfo=plus_two)
    assert period.contains(utc_now)


def test_naive_now_is_interpreted_in_the_given_timezone():
    naive = datetime(2026, 3, 7, 9, 0, 0)
    period = period_range(PERIOD_TODAY, now=naive, tz=TZ)
    assert period.start == datetime(2026, 3, 7, 0, 0, 0, tzinfo=TZ)


def test_custom_range_normalises_naive_inputs():
    period = period_range(
        PERIOD_CUSTOM,
        now=datetime(2026, 3, 7, 12, 0, 0, tzinfo=TZ),
        tz=TZ,
        custom_start=datetime(2026, 2, 1, 0, 0, 0),
        custom_end=datetime(2026, 2, 2, 0, 0, 0),
    )
    assert period.start == datetime(2026, 2, 1, 0, 0, 0, tzinfo=TZ)
    assert period.duration_seconds == 86400


def test_unknown_period_raises():
    with pytest.raises(ValueError):
        period_range("decade", now=datetime(2026, 3, 7, tzinfo=TZ), tz=TZ)


def test_resolve_timezone_falls_back_for_invalid_names():
    resolved = resolve_timezone("Not/AZone")
    assert resolved is not None
    assert timezone_name(resolved)
