"""Security service: the single entry point used by the TUI and the CLI.

It combines three independent facts and never merges them:

  live state   - what the running Fail2ban daemon reports right now
  stored state - what AUREON has recorded historically (SQLite)
  config state - what the configuration files declare
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from .config import Config
from .db.repo import Repository
from .ingest import IngestReport, Ingestor
from .models import Health, Indicator, PeriodStats
from .periods import BUILTIN_PERIODS, Period, resolve_timezone, timezone_name
from .util import Result
from .fail2ban.detect import Fail2banClient, Fail2banStatus, detect_status
from .fail2ban.stats import SecurityStatsService, coverage_note
from .fail2ban.wizard import WizardPlan, apply_plan, build_plan, diff_plan


@dataclass
class SecurityOverview:
    status: Fail2banStatus
    periods: Dict[str, PeriodStats]
    coverage_text: str
    indicators: List[Indicator] = field(default_factory=list)
    ingestion: Optional[IngestReport] = None
    db_note: str = ""


class SecurityService:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.tz = resolve_timezone(config.timezone or None)
        self.repo = Repository(config.db_path)
        self._status: Optional[Fail2banStatus] = None

    # -- lifecycle -------------------------------------------------------
    def refresh_status(self) -> Fail2banStatus:
        client = Fail2banClient()
        ctx = _SimpleCtx(self.config)
        self._status = detect_status(client, ctx)
        return self._status

    @property
    def status(self) -> Fail2banStatus:
        if self._status is None:
            self.refresh_status()
        assert self._status is not None
        return self._status

    # -- collection ------------------------------------------------------
    def ingest(self, import_history: bool = False) -> IngestReport:
        self.repo.open()
        ingestor = Ingestor(self.repo, self.tz)
        report = ingestor.import_history() if import_history else ingestor.ingest_all(
            max_bytes=int(self.config.ingest_max_bytes_per_file)
        )
        return report

    def stats(self) -> SecurityStatsService:
        self.repo.open()
        return SecurityStatsService(self.repo, self.tz, self.status)

    # -- overview --------------------------------------------------------
    def overview(self, now: Optional[datetime] = None) -> SecurityOverview:
        status = self.status
        service = self.stats()
        periods = {name: service.period(name, now=now) for name in BUILTIN_PERIODS}
        try:
            coverage = coverage_note(self.repo, self.tz)
            db_note = f"store: {self.config.db_path}"
        except Exception as exc:  # noqa: BLE001
            coverage = f"history store unavailable: {exc}"
            db_note = ""
        overview = SecurityOverview(
            status=status,
            periods=periods,
            coverage_text=coverage,
            indicators=self.indicators(status, periods),
            db_note=db_note,
        )
        return overview

    # -- indicators ------------------------------------------------------
    @staticmethod
    def indicators(status: Fail2banStatus, periods: Dict[str, PeriodStats]) -> List[Indicator]:
        out: List[Indicator] = []

        if not status.installed:
            return [Indicator("f2b", "Fail2ban", Health.UNAVAILABLE, "not installed", "package")]

        if status.service_state == "active":
            service_health = Health.OK
        elif status.service_state == "failed":
            service_health = Health.ERROR
        elif status.service_state == "inactive":
            service_health = Health.WARN
        else:
            service_health = Health.UNKNOWN
        out.append(Indicator("f2b-service", "Service", service_health, status.service_state, "systemctl"))

        jail = status.ssh_jail
        if jail is None:
            out.append(Indicator("f2b-ssh", "SSH jail", Health.ERROR, "missing", status.config_dir or "config"))
        elif jail.runtime and jail.enabled:
            out.append(Indicator("f2b-ssh", "SSH jail", Health.OK, f"{jail.name} (running)", "fail2ban-client"))
        elif jail.enabled is False:
            out.append(Indicator("f2b-ssh", "SSH jail", Health.ERROR, f"{jail.name} disabled", jail.file_origin))
        else:
            out.append(Indicator("f2b-ssh", "SSH jail", Health.UNVERIFIED, f"{jail.name} configured", jail.file_origin))

        banned_today = periods.get("today")
        if banned_today and banned_today.data_available:
            out.append(
                Indicator(
                    "f2b-today",
                    "Bans today",
                    Health.OK if banned_today.ban_events else Health.OK,
                    f"{banned_today.ban_events} events / {banned_today.unique_banned_ips} IPs",
                    "AUREON store",
                )
            )
        else:
            out.append(Indicator("f2b-today", "Bans today", Health.UNVERIFIED, "no data", "AUREON store"))

        if status.root_required:
            out.append(Indicator("f2b-live", "Live ban list", Health.UNKNOWN, "root required", "fail2ban-client"))
        else:
            value = str(status.banned_total) if status.banned_total else "0"
            out.append(Indicator("f2b-live", "Live ban list", Health.OK, value, "fail2ban-client"))
        return out

    # -- wizard ----------------------------------------------------------
    def plan(self, policy: str = "balanced", ignoreip: Optional[List[str]] = None) -> WizardPlan:
        return build_plan(self.status, policy=policy, ignoreip=ignoreip)

    def apply(self, plan: WizardPlan, confirmed: bool = False) -> Result:
        outcome = apply_plan(plan, confirmed=confirmed, allow_writes=self.config.allow_fail2ban_writes)
        self.refresh_status()
        if outcome.applied:
            return Result.ok_result(outcome, "fail2ban configuration")
        return Result(outcome, "fail2ban configuration", "error", "; ".join(outcome.errors) or "not applied")

    def plan_diff(self, plan: WizardPlan) -> str:
        return diff_plan(plan)

    # -- housekeeping ----------------------------------------------------
    def retention(self) -> int:
        from datetime import timedelta

        cutoff = datetime.now(self.tz) - timedelta(days=int(self.config.retention_days))
        return self.repo.purge_older_than(cutoff)

    def timezone_label(self) -> str:
        return timezone_name(self.tz)


class _SimpleCtx:
    """Minimal stand-in for CollectionContext used outside the TUI."""

    def __init__(self, config: Config) -> None:
        self.config = config

    def run(self, argv, timeout=None):
        from .util import run

        return run(argv, timeout=timeout or self.config.command_timeout)
