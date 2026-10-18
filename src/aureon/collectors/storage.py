"""Storage: physical disks, partitions, filesystems, I/O and optional SMART.

Read-only by construction: no partition, filesystem or device is ever modified.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ..models import Health, Indicator
from ..util import Result, human_bytes, pct, read_text, which
from .base import Collector

MOUNT_GUESSES = (
    "/etc/mtab",
    "/proc/self/mounts",
    "/etc/fstab",
)


@dataclass
class MountEntry:
    device: str
    mountpoint: str
    fstype: str
    size: Optional[int] = None
    used: Optional[int] = None
    available: Optional[int] = None
    use_percent: Optional[float] = None
    source: str = ""

    @property
    def health(self) -> Health:
        if self.use_percent is None:
            return Health.UNKNOWN
        if self.use_percent >= 95:
            return Health.ERROR
        if self.use_percent >= 85:
            return Health.WARN
        return Health.OK


@dataclass
class DiskInfo:
    device: str
    size_bytes: Optional[int] = None
    model: str = ""
    rota: Optional[bool] = None
    transport: str = ""
    source: str = "/sys/block"
    smart_summary: Optional[str] = None
    smart_passed: Optional[bool] = None


@dataclass
class StorageInfo:
    mounts: List[MountEntry] = field(default_factory=list)
    disks: List[DiskInfo] = field(default_factory=list)
    io: List[Dict[str, str]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    lvms: List[Dict[str, str]] = field(default_factory=list)


def _read_mounts() -> List[MountEntry]:
    for path in MOUNT_GUESSES:
        text = read_text(path)
        if not text:
            continue
        entries: List[MountEntry] = []
        for line in text.splitlines():
            parts = line.split()
            if path.endswith("fstab"):
                if len(parts) < 3 or parts[1] == "none" or parts[2] in ("auto",):
                    continue
                device, mountpoint, fstype = parts[0], parts[1], parts[2]
                options = parts[3] if len(parts) > 3 else ""
            else:
                if len(parts) < 3:
                    continue
                device, mountpoint, fstype = parts[0], parts[1], parts[2]
                options = parts[3] if len(parts) > 3 else ""
            if any(mountpoint.startswith(skipped) for skipped in ("/proc", "/sys", "/dev", "/run", "/snap")):
                if mountpoint not in ("/dev",):
                    continue
            entries.append(
                MountEntry(
                    device=device,
                    mountpoint=mountpoint,
                    fstype=fstype,
                    source=f"{path} + statvfs",
                )
            )
        if entries:
            return entries
    return []


def _fill_usage(entries: List[MountEntry]) -> None:
    for entry in entries:
        try:
            stats = os.statvfs(entry.mountpoint)
        except OSError:
            continue
        if stats.f_blocks == 0:
            continue
        entry.size = stats.f_blocks * stats.f_frsize
        entry.available = stats.f_bavail * stats.f_frsize
        entry.used = (stats.f_blocks - stats.f_bfree) * stats.f_frsize
        entry.use_percent = pct(entry.used, entry.used + entry.available) if (entry.used + entry.available) else 0.0


def read_disks(sys_block: Path = Path("/sys/block")) -> List[DiskInfo]:
    disks: List[DiskInfo] = []
    if not sys_block.is_dir():
        return disks
    try:
        entries = sorted(sys_block.iterdir())
    except OSError:
        return disks
    for entry in entries:
        if entry.name.startswith(("loop", "ram", "zram", "dm-", "sr")):
            continue
        size_text = read_text(entry / "size", 64)
        size = None
        if size_text:
            try:
                size = int(size_text.strip()) * 512
            except ValueError:
                size = None
        rota_text = read_text(entry / "queue/rotational", 16)
        disks.append(
            DiskInfo(
                device=entry.name,
                size_bytes=size,
                model=_device_model(entry),
                rota=(rota_text.strip() == "1") if rota_text else None,
                transport="nvme" if entry.name.startswith("nvme") else "virtio" if entry.name.startswith("vd") else "scsi/sata",
                source=str(entry),
            )
        )
    return disks


def _device_model(entry: Path) -> str:
    vendor = (read_text(entry / "device/vendor", 128) or "").strip()
    model = (read_text(entry / "device/model", 128) or "").strip()
    if vendor or model:
        return f"{vendor} {model}".strip()
    return (read_text(entry / "device/name", 128) or "").strip()


class StorageCollector(Collector):
    key = "storage"
    title = "Storage"
    source = "/proc/self/mounts + statvfs + /sys/block"

    def collect(self) -> Result:
        info = StorageInfo()
        info.mounts = _read_mounts()
        if not info.mounts:
            info.warnings.append("no mount table readable")
        _fill_usage(info.mounts)
        info.disks = self.ctx.cached("disks", 60.0, read_disks)

        diskstats = read_text("/proc/diskstats")
        if diskstats:
            for line in diskstats.splitlines():
                parts = line.split()
                if len(parts) < 14:
                    continue
                name = parts[2]
                if name.startswith(("loop", "ram")):
                    continue
                try:
                    info.io.append(
                        {
                            "device": name,
                            "reads": parts[3],
                            "writes": parts[5],
                            "read_sectors": parts[6],
                            "write_sectors": parts[8],
                        }
                    )
                except IndexError:  # pragma: no cover - defensive
                    continue

        lvs = which("lvs")
        if lvs:
            res = self.ctx.run([lvs, "--noheadings", "--units=b", "-o", "lv_name,vg_name,lv_size,devices"])
            if res.ok:
                for line in res.lines:
                    fields = line.split()
                    if len(fields) >= 3:
                        info.lvms.append(
                            {
                                "lv": fields[0],
                                "vg": fields[1],
                                "size": human_bytes(_safe_int(fields[2])),
                                "devices": fields[3] if len(fields) > 3 else "",
                            }
                        )
            else:
                info.warnings.append(f"lvs failed: {(res.stderr or '').strip()[:80]}")

        result = Result.ok_result(info, self.source)
        result.warnings = info.warnings
        return result

    def smart(self, device: str) -> Result:
        """SMART health for one device. Requires smartmontools and root.

        The device name is validated *before* the tool is looked up so that a
        malformed argument can never reach a shell or a subprocess.
        """
        if not re.fullmatch(r"[A-Za-z0-9_./:-]{1,64}", device or ""):
            return Result(None, "smartctl", "error", "invalid device name")
        binary = which("smartctl")
        if not binary:
            return self.unavailable("smartmontools not installed")
        res = self.ctx.run([binary, "-H", device], timeout=12.0)
        if res.returncode not in (0, 2, 4, 8):
            return Result.from_command(res, "smartctl", lambda _out: None)
        text = res.stdout
        passed = "PASSED" in text or "OK" in text
        return Result.ok_result({"passed": passed, "raw": text.strip()[:400]}, "smartctl")


def _safe_int(value: str) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def storage_indicators(info: StorageInfo) -> List[Indicator]:
    out: List[Indicator] = []
    worst: Optional[MountEntry] = None
    for mount in info.mounts:
        if mount.use_percent is None:
            continue
        if worst is None or (mount.use_percent or 0) > (worst.use_percent or 0):
            worst = mount
    if worst is None:
        out.append(Indicator("disk", "Disks", Health.UNVERIFIED, "n/a", "/proc/self/mounts"))
    else:
        out.append(
            Indicator(
                "disk",
                "Disks",
                worst.health,
                f"{worst.use_percent:.0f}% {worst.mountpoint}",
                worst.source,
                detail=human_bytes(worst.available),
            )
        )
    return out
