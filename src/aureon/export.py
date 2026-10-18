"""Report export.

Exports never include hostnames of clients, usernames or raw log lines unless
the administrator explicitly asks for them (``--include-users``), because log
content may contain personal data.
"""

from __future__ import annotations

import csv
import json
import os
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from .models import PeriodStats
from .periods import BUILTIN_PERIODS, period_range, resolve_timezone, timezone_name


def _iso(value):
    return value.isoformat() if isinstance(value, datetime) else value


def export_json(stats: PeriodStats, path: Path) -> Path:
    payload = {}
    for key, value in asdict(stats).items():
        payload[key] = _iso(value)
    payload["top_ips"] = list(stats.top_ips)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")
    _restrict(path)
    return path


def export_csv(rows: Sequence[Dict[str, object]], path: Path, fieldnames: Optional[Sequence[str]] = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    names = list(fieldnames or (rows[0].keys() if rows else ["value"]))
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=names)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in names})
    _restrict(path)
    return path


def export_period_summary(
    repo,
    tz=None,
    periods: Sequence[str] = BUILTIN_PERIODS,
    path: Optional[Path] = None,
) -> Path:
    tz = tz or resolve_timezone()
    now = datetime.now(tz)
    rows: List[Dict[str, object]] = []
    for name in periods:
        span = period_range(name, now=now, tz=tz)
        stats = repo.stats_for_period(
            period_name=name,
            start=span.start,
            end=span.end,
            tzinfo=tz,
            tz_label=timezone_name(tz),
        )
        rows.append(
            {
                "period": name,
                "start": span.start.isoformat(),
                "end": span.end.isoformat(),
                "timezone": timezone_name(tz),
                "unique_banned_ips": stats.unique_banned_ips,
                "ban_events": stats.ban_events,
                "unban_events": stats.unban_events,
                "unbanned_ips": stats.unbanned_ips,
                "failed_auth_attempts": stats.failed_auth_attempts,
                "recurrent_ips": stats.recurrent_ips,
                "data_available": stats.data_available,
                "coverage_start": stats.coverage_start.isoformat() if stats.coverage_start else "",
                "coverage_end": stats.coverage_end.isoformat() if stats.coverage_end else "",
            }
        )
    target = path or Path("aureon-security-summary.csv")
    return export_csv(rows, target)


def export_ip_report(rows: Sequence[Dict[str, object]], path: Path, include_users: bool = False) -> Path:
    fields = ["ip", "jail", "last", "events"]
    target = path or Path("aureon-banned-ips.csv")
    return export_csv(rows, target, fieldnames=fields)


def _restrict(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - platform dependent
        pass
