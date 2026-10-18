"""Timezone-aware period boundaries.

Every statistic exposed by AUREON is computed over an explicit
``[start, end)`` interval expressed in the *server's configured local timezone*
(documented in docs/DATA-ACCURACY.md):

  * "today"  -> local midnight until the next local midnight
  * "week"   -> ISO 8601 week, Monday 00:00 local as the first instant
  * "month"  -> first day of the local month at 00:00
  * "year"   -> 1 January local at 00:00
  * 24h      -> rolling window ending now

All boundaries are computed on *naive local* wall-clock values and then
converted with the configured tzinfo. That keeps the results identical to what
an administrator reading ``date`` expects, and avoids mixing UTC and local
midnights. Year transitions are handled naturally by ISO week arithmetic.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Optional

try:  # Python 3.9+
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover - Python < 3.9 unsupported by pyproject
    ZoneInfo = None  # type: ignore[assignment]

PERIOD_TODAY = "today"
PERIOD_24H = "24h"
PERIOD_WEEK = "week"
PERIOD_MONTH = "month"
PERIOD_YEAR = "year"
PERIOD_CUSTOM = "custom"

BUILTIN_PERIODS = (PERIOD_24H, PERIOD_TODAY, PERIOD_WEEK, PERIOD_MONTH, PERIOD_YEAR)


@dataclass(frozen=True)
class Period:
    """A half-open interval ``[start, end)`` with tzinfo attached."""

    name: str
    start: datetime
    end: datetime

    def contains(self, moment: datetime) -> bool:
        return self.start <= moment < self.end

    @property
    def duration_seconds(self) -> int:
        return int((self.end - self.start).total_seconds())

    def label(self) -> str:
        return f"{self.start:%Y-%m-%d %H:%M} -> {self.end:%Y-%m-%d %H:%M}"


def _read_system_timezone_name() -> Optional[str]:
    tz_path = Path("/etc/timezone")
    if tz_path.exists():
        name = tz_path.read_text(encoding="utf-8", errors="replace").strip()
        if name:
            return name
    localtime = Path("/etc/localtime")
    if localtime.is_symlink():
        target = str(localtime.resolve())
        marker = "/zoneinfo/"
        if marker in target:
            return target.split(marker, 1)[1]
    return None


def resolve_timezone(name: Optional[str] = None) -> tzinfo:
    """Resolve a timezone name to a tzinfo, falling back to the local clock."""
    candidates = []
    if name:
        candidates.append(name)
    system_name = _read_system_timezone_name()
    if system_name:
        candidates.append(system_name)
    for candidate in candidates:
        if ZoneInfo is None:  # pragma: no cover
            break
        try:
            return ZoneInfo(candidate)
        except Exception:  # noqa: BLE001 - invalid tz database entry
            continue
    return datetime.now().astimezone().tzinfo or timezone.utc


def timezone_name(tz: tzinfo) -> str:
    return getattr(tz, "key", None) or str(tz)


def local_now(tz: tzinfo) -> datetime:
    return datetime.now(tz)


def period_range(
    name: str,
    now: Optional[datetime] = None,
    tz: Optional[tzinfo] = None,
    custom_start: Optional[datetime] = None,
    custom_end: Optional[datetime] = None,
) -> Period:
    """Return the concrete interval for a named period."""
    tz = tz or resolve_timezone()
    now = now or local_now(tz)
    if now.tzinfo is None:
        now = now.replace(tzinfo=tz)
    now = now.astimezone(tz)

    if name == PERIOD_24H:
        return Period(PERIOD_24H, now - timedelta(hours=24), now)

    start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if name == PERIOD_TODAY:
        return Period(PERIOD_TODAY, start_of_day, start_of_day + timedelta(days=1))

    if name == PERIOD_WEEK:
        iso_year, iso_week, iso_weekday = now.isocalendar()
        monday = (now - timedelta(days=iso_weekday - 1)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        return Period(PERIOD_WEEK, monday, monday + timedelta(days=7))

    if name == PERIOD_MONTH:
        first = start_of_day.replace(day=1)
        end_year = first.year + (1 if first.month == 12 else 0)
        end_month = 1 if first.month == 12 else first.month + 1
        return Period(PERIOD_MONTH, first, first.replace(year=end_year, month=end_month))

    if name == PERIOD_YEAR:
        first = start_of_day.replace(month=1, day=1)
        return Period(PERIOD_YEAR, first, first.replace(year=first.year + 1))

    if name == PERIOD_CUSTOM:
        start = custom_start or now - timedelta(days=1)
        end = custom_end or now
        start = start if start.tzinfo else start.replace(tzinfo=tz)
        end = end if end.tzinfo else end.replace(tzinfo=tz)
        return Period(PERIOD_CUSTOM, start.astimezone(tz), end.astimezone(tz))

    raise ValueError(f"unknown period: {name!r}")


def to_naive_local(moment: datetime, tz: tzinfo) -> datetime:
    """Normalise any datetime (aware or naive) into aware local time."""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=tz)
    return moment.astimezone(tz)


def naive_to_aware(moment: datetime, tz: tzinfo) -> datetime:
    if moment.tzinfo is None:
        return moment.replace(tzinfo=tz)
    return moment.astimezone(tz)
