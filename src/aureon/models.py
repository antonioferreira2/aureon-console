"""Domain models shared across collectors, the persistence layer and the TUI."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional


class Health(Enum):
    """Health of a module or indicator.

    ``UNVERIFIED`` is deliberately distinct from ``ERROR``: AUREON must not
    claim a failure it did not actually confirm, nor a success it could not
    measure.
    """

    OK = "ok"
    WARN = "warn"
    ERROR = "error"
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"

    @property
    def symbol(self) -> str:
        return {
            Health.OK: "\u25cf",       # filled circle
            Health.WARN: "\u25b2",     # triangle
            Health.ERROR: "\u2716",    # cross
            Health.UNKNOWN: "\u25cb",  # hollow circle
            Health.UNAVAILABLE: "\u2013",  # en dash
        }[self]

    @property
    def label(self) -> str:
        return {
            Health.OK: "OK",
            Health.WARN: "WARN",
            Health.ERROR: "ERROR",
            Health.UNKNOWN: "UNVERIFIED",
            Health.UNAVAILABLE: "N/A",
        }[self]


@dataclass
class Indicator:
    """A single health indicator shown in a dashboard header."""

    key: str
    label: str
    health: Health
    value: str = ""
    source: str = ""
    detail: str = ""

    def to_row(self) -> List[str]:
        return [f"{self.health.symbol} {self.label}", self.value, self.source]


@dataclass
class SecurityEvent:
    """A normalised ban/unban/failure event stored by AUREON."""

    occurred_at: datetime          # timezone-aware, event time
    source: str                    # 'fail2ban.log', 'journal', 'import', ...
    source_id: str = ""            # deterministic identity used for dedup
    kind: str = "ban"              # ban | unban | auth_failure | ...
    jail: str = ""
    ip: str = ""
    username: str = ""
    host_id: str = ""
    ingested_at: Optional[datetime] = None
    collection_state: str = "ok"   # ok | partial | failed
    meta: Dict[str, str] = field(default_factory=dict)

    @property
    def dedup_key(self) -> str:
        if self.source_id:
            return f"{self.source}:{self.source_id}"
        return "|".join(
            [
                self.source,
                self.kind,
                self.jail,
                self.ip,
                self.occurred_at.astimezone(self.occurred_at.tzinfo).isoformat(),
            ]
        )


@dataclass
class PeriodStats:
    """Statistics for one period, with explicit data-coverage information."""

    period: str
    start: datetime
    end: datetime
    timezone: str
    unique_banned_ips: int = 0
    ban_events: int = 0
    unban_events: int = 0
    unbanned_ips: int = 0
    currently_banned: Optional[int] = None
    failed_auth_attempts: Optional[int] = None
    recurrent_ips: int = 0
    top_ips: List[tuple] = field(default_factory=list)
    jails: Dict[str, int] = field(default_factory=dict)
    data_available: bool = True
    coverage_start: Optional[datetime] = None
    coverage_end: Optional[datetime] = None
    warnings: List[str] = field(default_factory=list)
    last_event_at: Optional[datetime] = None

    @property
    def complete(self) -> bool:
        """True when the whole requested window is covered by stored data."""
        if not self.data_available or self.coverage_start is None:
            return False
        return self.coverage_start <= self.start and (self.coverage_end or self.start) >= self.start
