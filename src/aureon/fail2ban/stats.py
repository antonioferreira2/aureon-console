"""Security statistics over explicit periods, with honest data coverage."""

from __future__ import annotations

from datetime import datetime, timedelta, tzinfo
from typing import Dict, List, Optional

from ..db.repo import Repository
from ..models import PeriodStats
from ..periods import BUILTIN_PERIODS, PERIOD_CUSTOM, Period, period_range, timezone_name
from .detect import Fail2banStatus


class SecurityStatsService:
    """Builds period statistics for the security dashboard.

    Two very different quantities are kept strictly apart:

    ``currently_banned``
        a *live* fact read from the running daemon (or from AUREON's last
        observation). It says nothing about when the ban started.

    ``unique_banned_ips`` / ``ban_events``
        *historical* facts read from AUREON's own store. They say nothing about
        the current state.
    """

    def __init__(self, repo: Repository, tz: tzinfo, status: Optional[Fail2banStatus] = None) -> None:
        self.repo = repo
        self.tz = tz
        self.status = status

    # ------------------------------------------------------------------
    def current_banned(self) -> Optional[int]:
        """Live count, preferring the daemon's own per-jail numbers.

        ``fail2ban-client status <jail>`` reports "Currently banned" per jail and
        is the authoritative figure; the IP list is used as a fallback. When
        neither is available the value stays ``None`` and the UI shows
        "unverified" instead of guessing.
        """
        if self.status is None:
            return None
        if any(jail.runtime for jail in self.status.jails):
            return sum(jail.currently_banned for jail in self.status.jails if jail.runtime)
        if self.status.banned_total:
            return self.status.banned_total
        if self.status.jails:
            return None  # configured but not verified live
        return None

    def period(self, name: str, now: Optional[datetime] = None, **kwargs) -> PeriodStats:
        span = period_range(name, now=now, tz=self.tz, **kwargs)
        stats = self.repo.stats_for_period(
            period_name=name,
            start=span.start,
            end=span.end,
            tzinfo=self.tz,
            tz_label=timezone_name(self.tz),
            current_banned=self.current_banned(),
        )
        self._attach_live_context(stats)
        return stats

    def all_periods(self, now: Optional[datetime] = None) -> Dict[str, PeriodStats]:
        return {name: self.period(name, now=now) for name in BUILTIN_PERIODS}

    def summary_table(self, now: Optional[datetime] = None) -> List[Dict[str, object]]:
        rows: List[Dict[str, object]] = []
        for name in BUILTIN_PERIODS:
            stats = self.period(name, now=now)
            rows.append(
                {
                    "period": name,
                    "range": stats,
                    "stats": stats,
                }
            )
        return rows

    # ------------------------------------------------------------------
    def _attach_live_context(self, stats: PeriodStats) -> None:
        if self.status is None:
            stats.warnings.append("live Fail2ban state unavailable: 'currently banned' cannot be confirmed")
            return
        if not self.status.installed:
            stats.warnings.append("Fail2ban is not installed: no live ban state exists")
            return
        if self.status.root_required:
            stats.warnings.append(
                "run AUREON as root to confirm the live ban list; the value shown is the last stored observation"
            )
        for jail in self.status.jails:
            if jail.runtime and jail.total_banned is not None:
                stats.warnings.append(
                    f"jail {jail.name}: daemon reports {jail.total_banned} total bans since start, "
                    f"{jail.currently_banned} currently banned"
                )


def coverage_note(repo: Repository, tz: tzinfo) -> str:
    lo, hi, total = repo.coverage()
    if total == 0 or lo is None or hi is None:
        return "No events collected yet. Statistics are unavailable (not zero)."
    return (
        f"AUREON holds {total} events covering {lo.astimezone(tz):%Y-%m-%d %H:%M} .. "
        f"{hi.astimezone(tz):%Y-%m-%d %H:%M} ({timezone_name(tz)})."
    )
