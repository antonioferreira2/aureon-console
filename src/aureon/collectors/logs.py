"""System logs through journalctl (or plain log files when journald is absent).

Volume and time limits are always applied: AUREON never reads an unbounded log
and never blocks the UI for more than the configured command timeout.
"""

from __future__ import annotations

import re
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from ..util import Result, which
from .base import Collector

PRIORITIES = (
    "emerg",
    "alert",
    "crit",
    "err",
    "warning",
    "notice",
    "info",
    "debug",
)

PRIORITY_RANK = {name: index for index, name in enumerate(PRIORITIES)}

_TIME_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[\w.\-/+]+(?:\[\d+\])?)"
)


@dataclass
class LogLine:
    timestamp: Optional[datetime]
    unit: str = ""
    priority: str = ""
    message: str = ""
    hostname: str = ""
    raw: str = ""

    def render(self) -> str:
        stamp = self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else "----------- --:--:--"
        unit = self.unit or "-"
        return f"{stamp} {unit:<24} {self.priority:<7} {self.message}"


@dataclass
class LogsInfo:
    backend: str = "none"
    lines: List[LogLine] = field(default_factory=list)
    errors: int = 0
    truncated: bool = False
    query: str = ""
    source: str = ""
    warnings: List[str] = field(default_factory=list)


def parse_journal_output(text: str) -> List[LogLine]:
    out: List[LogLine] = []
    for raw in text.splitlines():
        if not raw.strip():
            continue
        parts = raw.split(None, 4)
        if len(parts) < 5:
            out.append(LogLine(timestamp=None, message=raw, raw=raw))
            continue
        stamp, host, unit, priority, message = parts
        unit = unit.rstrip(":").split("[")[0]
        parsed_ts: Optional[datetime] = None
        for fmt in ("%b %d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                parsed_ts = datetime.strptime(stamp, fmt)
                break
            except ValueError:
                continue
        out.append(
            LogLine(
                timestamp=parsed_ts,
                hostname=host,
                unit=unit,
                priority=priority,
                message=message,
                raw=raw,
            )
        )
    return out


def parse_file_output(text: str) -> List[LogLine]:
    """Parse classic syslog lines (used when journalctl is unavailable)."""
    out: List[LogLine] = []
    for raw in text.splitlines():
        match = _TIME_RE.match(raw)
        if not match:
            out.append(LogLine(timestamp=None, message=raw, raw=raw))
            continue
        month = match.group("month")
        day = int(match.group("day"))
        year = datetime.now().year
        try:
            parsed = datetime.strptime(f"{month} {day} {year} {match.group('time')}", "%b %d %Y %H:%M:%S")
        except ValueError:
            parsed = None
        out.append(
            LogLine(
                timestamp=parsed,
                hostname=match.group("host"),
                unit=match.group("proc").split("[")[0].strip(),
                message=raw,
                raw=raw,
            )
        )
    return out


class LogCollector(Collector):
    key = "logs"
    title = "Logs"
    source = "journalctl"

    def available(self) -> bool:
        return True

    def collect(
        self,
        unit: Optional[str] = None,
        priority: Optional[str] = None,
        since_minutes: Optional[int] = None,
        search: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> Result:
        limit = limit or int(self.ctx.config.max_log_lines)
        journalctl = which("journalctl")
        if journalctl:
            info = self._from_journal(journalctl, unit, priority, since_minutes, search, limit)
        else:
            info = self._from_files(unit, priority, since_minutes, search, limit)
        result = Result.ok_result(info, info.source)
        result.warnings = info.warnings
        return result

    # ------------------------------------------------------------------
    def _build_journal_argv(self, unit, priority, since_minutes, search, limit):
        argv = [which("journalctl") or "journalctl", "--no-pager", "-o", "short-iso", "-n", str(limit)]
        if unit:
            argv += ["--unit", unit]
        if priority:
            argv += ["--priority", priority]
        if since_minutes:
            argv += ["--since", f"-{int(since_minutes)}min"]
        if search:
            # Passed as a single argv element: no shell, no injection surface.
            argv += ["--grep", search]
        return argv

    def _from_journal(self, journalctl, unit, priority, since_minutes, search, limit) -> LogsInfo:
        argv = self._build_journal_argv(unit, priority, since_minutes, search, limit)
        res = self.ctx.run(argv, timeout=self.timeout())
        info = LogsInfo(backend="journald", source=f"journalctl ({' '.join(argv[1:]) or 'no filter'})")
        info.query = " ".join(argv[1:])
        if res.timed_out:
            info.warnings.append("journalctl timed out - results may be incomplete")
            info.truncated = True
        elif res.returncode != 0:
            info.warnings.append((res.stderr or "journalctl failed").strip()[:160])
            return info
        lines = parse_journal_output(res.stdout)
        info.lines = lines
        info.truncated = res.truncated or len(lines) >= limit
        info.errors = sum(1 for line in lines if line.priority in ("emerg", "alert", "crit", "err"))
        return info

    def _from_files(self, unit, priority, since_minutes, search, limit) -> LogsInfo:
        info = LogsInfo(backend="files", source="/var/log (rsyslog-style files)")
        candidates = []
        if unit:
            base = Path("/var/log") / unit
            candidates = [base, base.with_suffix(".log")]
        else:
            candidates = [Path("/var/log/syslog"), Path("/var/log/messages"), Path("/var/log/auth.log")]
        collected: List[str] = []
        from ..util import read_text

        for path in candidates:
            text = read_text(path, limit=1024 * 1024)
            if text is None:
                info.warnings.append(f"{path} unreadable or absent")
                continue
            collected.extend(text.splitlines()[-limit:])
        if search:
            collected = [line for line in collected if search in line]
        lines = parse_file_output("\n".join(collected))
        if priority:
            wanted = PRIORITY_RANK.get(priority, 99)
            lines = [line for line in lines if _file_priority(line) is not None and _file_priority(line) <= wanted]
        info.lines = lines[-limit:]
        info.errors = sum(1 for line in lines if (line.priority or "") in ("emerg", "alert", "crit", "err"))
        if not lines:
            info.warnings.append("no readable log files matched the filter")
        return info


def _file_priority(line: LogLine) -> Optional[int]:
    return PRIORITY_RANK.get(line.priority or "")
