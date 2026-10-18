"""systemd services (with a sysvinit fallback) - strictly read-only.

Service control (start/stop/restart) is *not* implemented in this release; see
docs/SECURITY.md. The wizard surfaces recommendations but never executes them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..util import Result, which
from .base import Collector

PROPERTY_FIELDS = (
    "Id",
    "Description",
    "LoadState",
    "ActiveState",
    "SubState",
    "UnitFileState",
    "ActiveEnterTimestamp",
    "NRestarts",
    "MainPID",
)


@dataclass
class ServiceInfo:
    unit: str
    load_state: str = "unknown"
    active_state: str = "unknown"
    sub_state: str = ""
    enabled: str = "unknown"
    description: str = ""
    since: str = ""
    restarts: Optional[int] = None

    @property
    def is_failed(self) -> bool:
        return self.active_state == "failed" or self.load_state == "not-found"

    @property
    def is_running(self) -> bool:
        return self.active_state == "active"


@dataclass
class ServicesInfo:
    backend: str = "none"
    total: int = 0
    running: int = 0
    failed: List[ServiceInfo] = field(default_factory=list)
    services: List[ServiceInfo] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def _parse_properties(text: str) -> Dict[str, str]:
    props: Dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        props[key.strip()] = value.strip()
    return props


class ServiceCollector(Collector):
    key = "services"
    title = "Services"
    source = "systemctl show"

    def available(self) -> bool:
        return bool(which("systemctl")) or bool(which("service"))

    def collect(self) -> Result:
        info = ServicesInfo()
        if which("systemctl"):
            info.backend = "systemd"
            self._collect_systemd(info)
        elif which("service"):
            info.backend = "sysvinit"
            info.warnings.append("systemd not available: limited information via SysV")
            self._collect_sysv(info)
        else:
            return self.unavailable("neither systemctl nor service found")
        result = Result.ok_result(info, info.backend)
        result.warnings = info.warnings
        return result

    # ------------------------------------------------------------------
    def _collect_systemd(self, info: ServicesInfo) -> None:
        res = self.ctx.run(
            [
                "systemctl",
                "list-units",
                "--type=service",
                "--all",
                "--no-legend",
                "--no-pager",
                "--plain",
                "--no-legend",
                f"--output={' '.join(PROPERTY_FIELDS)}",
            ],
            timeout=max(self.timeout(), 10.0),
        )
        if not res.ok:
            # Older systemd lacks --output for list-units: fall back to the
            # classic single-line format and enrich lazily.
            res = self.ctx.run(
                ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager", "--plain"],
                timeout=max(self.timeout(), 10.0),
            )
            if not res.ok:
                info.warnings.append(f"systemctl failed: {(res.stderr or '').strip()[:100]}")
                return
            for line in res.lines:
                parts = line.split(None, 4)
                if len(parts) < 4:
                    continue
                unit, load, active, sub = parts[0], parts[1], parts[2], parts[3]
                description = parts[4] if len(parts) > 4 else ""
                info.services.append(
                    ServiceInfo(unit=unit, load_state=load, active_state=active, sub_state=sub, description=description)
                )
        else:
            for block in res.stdout.split("\n\n"):
                props = _parse_properties(block)
                if not props.get("Id"):
                    continue
                info.services.append(
                    ServiceInfo(
                        unit=props.get("Id", ""),
                        load_state=props.get("LoadState", "unknown"),
                        active_state=props.get("ActiveState", "unknown"),
                        sub_state=props.get("SubState", ""),
                        enabled=props.get("UnitFileState", "unknown"),
                        description=props.get("Description", ""),
                        since=props.get("ActiveEnterTimestamp", ""),
                        restarts=_int(props.get("NRestarts")),
                    )
                )

        info.total = len(info.services)
        info.running = sum(1 for s in info.services if s.is_running)
        info.failed = sorted(
            (s for s in info.services if s.is_failed),
            key=lambda s: s.unit,
        )
        info.services.sort(key=lambda s: (s.active_state != "failed", s.unit))

    def _collect_sysv(self, info: ServicesInfo) -> None:
        res = self.ctx.run(["service", "--status-all"], timeout=max(self.timeout(), 10.0))
        for line in res.lines:
            stripped = line.strip()
            if not stripped:
                continue
            parts = stripped.split(None, 1)
            name = parts[0]
            status = parts[1] if len(parts) > 1 else "unknown"
            active = "active" if status.startswith("running") or status.startswith("start") else "inactive"
            info.services.append(ServiceInfo(unit=name, active_state=active, sub_state=status))


def _int(value: Optional[str]) -> Optional[int]:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
