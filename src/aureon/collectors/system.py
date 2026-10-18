"""General system information: uptime, CPU, load, memory, swap, top processes."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from ..models import Health, Indicator
from ..util import Result, human_bytes, human_duration, read_text
from .base import Collector

PROC_STAT = Path("/proc/stat")
PROC_MEMINFO = Path("/proc/meminfo")
PROC_UPTIME = Path("/proc/uptime")
PROC_LOADAVG = Path("/proc/loadavg")


@dataclass
class ProcessInfo:
    pid: int
    user: str
    command: str
    cpu_percent: Optional[float]
    mem_percent: Optional[float]
    mem_rss: Optional[int]
    state: str = ""


@dataclass
class SystemInfo:
    hostname: str = ""
    os_name: str = ""
    os_version: str = ""
    kernel: str = ""
    arch: str = ""
    uptime_seconds: Optional[float] = None
    boot_time: Optional[datetime] = None
    cpu_count: int = 0
    cpu_model: str = ""
    cpu_percent: Optional[float] = None
    load1: Optional[float] = None
    load5: Optional[float] = None
    load15: Optional[float] = None
    mem_total: Optional[int] = None
    mem_available: Optional[int] = None
    swap_total: Optional[int] = None
    swap_free: Optional[int] = None
    processes: List[ProcessInfo] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def mem_used(self) -> Optional[int]:
        if self.mem_total is None or self.mem_available is None:
            return None
        return max(0, self.mem_total - self.mem_available)

    @property
    def mem_percent(self) -> Optional[float]:
        if not self.mem_total or self.mem_available is None:
            return None
        return (self.mem_used or 0) / self.mem_total * 100.0

    @property
    def swap_used(self) -> Optional[int]:
        if self.swap_total is None or self.swap_free is None:
            return None
        return max(0, self.swap_total - self.swap_free)


def read_os_release() -> Dict[str, str]:
    data: Dict[str, str] = {}
    text = read_text("/etc/os-release") or ""
    for line in text.splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            data[key.strip()] = value.strip().strip('"')
    return data


class SystemCollector(Collector):
    key = "system"
    title = "System"
    source = "/proc, /etc/os-release"

    def available(self) -> bool:
        return PROC_STAT.exists()

    def collect(self) -> Result:
        info = SystemInfo()
        info.hostname = self.ctx.cached("hostname", 30.0, lambda: os.uname().nodename)
        release = self.ctx.cached("osrelease", 300.0, read_os_release)
        info.os_name = release.get("PRETTY_NAME") or release.get("NAME") or "unknown"
        info.os_version = release.get("VERSION_ID", "")
        try:
            uname = os.uname()
            info.kernel = uname.release
            info.arch = uname.machine
        except OSError:  # pragma: no cover - extremely unusual
            info.warnings.append("uname unavailable")
        info.cpu_count = os.cpu_count() or 0

        self._cpu(info)
        self._uptime(info)
        self._memory(info)
        self._processes(info)

        availability = Result.ok_result(info, self.source)
        availability.warnings = info.warnings
        return availability

    # ------------------------------------------------------------------
    def _cpu(self, info: SystemInfo) -> None:
        text = read_text(PROC_STAT)
        if not text:
            info.warnings.append("/proc/stat unavailable")
            return
        total = 0.0
        idle_all = 0.0
        for line in text.splitlines():
            if not line.startswith("cpu"):
                continue
            parts = line.split()
            values = [float(v) for v in parts[1:] if _is_number(v)]
            if not values:
                continue
            if parts[0] == "cpu":
                total = sum(values)
                idle_all = values[3] + (values[4] if len(values) > 4 else 0.0)
            elif not info.cpu_model:
                info.cpu_model = parts[0]
        loadavg = read_text(PROC_LOADAVG)
        if loadavg:
            bits = loadavg.split()
            try:
                info.load1 = float(bits[0])
                info.load5 = float(bits[1])
                info.load15 = float(bits[2])
            except (IndexError, ValueError):
                pass

        cpuinfo = read_text("/proc/cpuinfo")
        if cpuinfo and not info.cpu_model:
            match = re.search(r"^model name\s*:\s*(.+)$", cpuinfo, re.MULTILINE)
            if match:
                info.cpu_model = match.group(1).strip()

        prev = self.ctx.cache.get("cpu-ticks")
        if prev and total > prev[1] > 0:
            delta_total = total - prev[1]
            delta_idle = idle_all - prev[2]
            ratio = (delta_total - delta_idle) / delta_total * 100.0 if delta_total else 0.0
            info.cpu_percent = max(0.0, min(100.0, ratio))
        self.ctx.cache["cpu-ticks"] = (0.0, total, idle_all)

    def _uptime(self, info: SystemInfo) -> None:
        text = read_text(PROC_UPTIME)
        if not text:
            return
        try:
            uptime = float(text.split()[0])
        except (IndexError, ValueError):
            return
        info.uptime_seconds = uptime
        info.boot_time = datetime.now(timezone.utc) - timedelta(seconds=uptime)

    def _memory(self, info: SystemInfo) -> None:
        text = read_text(PROC_MEMINFO)
        if not text:
            info.warnings.append("/proc/meminfo unavailable")
            return
        values: Dict[str, int] = {}
        for line in text.splitlines():
            key, _, rest = line.partition(":")
            bits = rest.split()
            if bits and bits[0].isdigit():
                values[key.strip()] = int(bits[0]) * 1024
        info.mem_total = values.get("MemTotal")
        info.mem_available = values.get("MemAvailable", values.get("MemFree"))
        # /proc/meminfo exposes SwapFree and SwapCached separately. Cached
        # swap pages are still only allocated on demand, so they are counted
        # as used; this is the same accounting used by `free`.
        info.swap_total = values.get("SwapTotal")
        info.swap_free = values.get("SwapFree")

    def _processes(self, info: SystemInfo) -> None:
        proc_root = Path("/proc")
        try:
            entries = [e for e in proc_root.iterdir() if e.name.isdigit()]
        except OSError:
            info.warnings.append("/proc not readable")
            return
        page = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
        total_mem = info.mem_total or 0
        rows: List[ProcessInfo] = []
        for entry in entries:
            stat = read_text(entry / "stat", 8192)
            if not stat or ")" not in stat:
                continue
            name_part, _, rest = stat.rpartition(")")
            comm = name_part.partition("(")[2]
            fields = rest.split()
            try:
                utime = int(fields[11])
                stime = int(fields[12])
                rss_pages = int(fields[21])
                state = fields[0]
            except (IndexError, ValueError):
                continue
            uptime = info.uptime_seconds or 0.0
            hz = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
            cpu = ((utime + stime) / hz / uptime * 100.0) if uptime else None
            rss = rss_pages * page
            mem_pct = (rss / total_mem * 100.0) if total_mem else None
            try:
                uid = entry.stat().st_uid
            except OSError:
                uid = -1
            rows.append(
                ProcessInfo(
                    pid=int(entry.name),
                    user=self.ctx.cached(f"uid:{uid}", 120.0, lambda u=uid: _uid_to_name(u)),
                    command=comm,
                    cpu_percent=cpu,
                    mem_percent=mem_pct,
                    mem_rss=rss,
                    state=state,
                )
            )
        rows.sort(key=lambda p: (p.mem_percent or 0.0), reverse=True)
        info.processes = rows[:25]


def _uid_to_name(uid: int) -> str:
    import pwd

    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, OSError):
        return str(uid)


def _is_number(value: str) -> bool:
    try:
        float(value)
        return True
    except ValueError:
        return False


def system_indicators(info: SystemInfo) -> List[Indicator]:
    """Health indicators derived purely from measured values."""
    out: List[Indicator] = []
    if info.cpu_percent is not None:
        health = Health.WARN if info.cpu_percent >= 85 else Health.OK
        out.append(Indicator("cpu", "CPU", health, f"{info.cpu_percent:.1f}%", "/proc/stat"))
    else:
        out.append(Indicator("cpu", "CPU", Health.UNVERIFIED, "n/a", "/proc/stat"))

    if info.mem_percent is not None:
        health = Health.WARN if info.mem_percent >= 90 else Health.OK
        out.append(
            Indicator("mem", "Memory", health, f"{info.mem_percent:.1f}% ({human_bytes(info.mem_used)})", "/proc/meminfo")
        )
    else:
        out.append(Indicator("mem", "Memory", Health.UNVERIFIED, "n/a", "/proc/meminfo"))

    if info.load1 is not None and info.cpu_count:
        ratio = info.load1 / info.cpu_count * 100.0
        health = Health.WARN if ratio >= 90 else Health.OK
        out.append(Indicator("load", "Load", health, f"{info.load1:.2f} / {info.cpu_count} cpu", "/proc/loadavg"))
    elif info.load1 is not None:
        out.append(Indicator("load", "Load", Health.UNVERIFIED, f"{info.load1:.2f}", "/proc/loadavg"))

    if info.uptime_seconds is not None:
        out.append(Indicator("uptime", "Uptime", Health.OK, human_duration(info.uptime_seconds), "/proc/uptime"))
    return out
