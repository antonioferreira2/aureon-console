"""Sensors and GPUs.

Values are only ever reported when a real source provides them. No synthetic or
estimated temperatures are ever displayed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..util import Result, which
from .base import Collector



@dataclass
class SensorReading:
    label: str
    value: str
    kind: str  # temperature | fan | voltage | other

    @property
    def numeric(self) -> Optional[float]:
        match = re.search(r"-?\d+(?:\.\d+)?", self.value)
        return float(match.group(0)) if match else None


@dataclass
class SensorInfo:
    backend: str = "none"
    readings: List[SensorReading] = field(default_factory=list)
    gpus: List[Dict[str, str]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def parse_sensors(text: str) -> List[SensorReading]:
    readings: List[SensorReading] = []
    for line in text.splitlines():
        line = line.rstrip()
        if not line or line.strip().endswith(":"):
            continue
        if ":" not in line:
            continue
        label, _, value = line.partition(":")
        value = value.strip()
        if not value:
            continue
        if re.search(r"\d", value) is None:
            continue
        lowered = label.lower()
        if any(token in lowered for token in ("temp", "core", "tdie", "tctl", "package")):
            kind = "temperature"
        elif "fan" in lowered:
            kind = "fan"
        elif "volt" in lowered or re.search(r"\bin\s*$", lowered):
            kind = "voltage"
        else:
            kind = "other"
        readings.append(SensorReading(label=label.strip(), value=value.split("(")[0].strip(), kind=kind))
    return readings


class SensorCollector(Collector):
    key = "sensors"
    title = "Sensors"
    source = "lm-sensors"

    def available(self) -> bool:
        return bool(which("sensors")) or bool(which("nvidia-smi")) or bool(which("nvtop"))

    def collect(self) -> Result:
        info = SensorInfo()
        sensors = which("sensors")
        if sensors:
            info.backend = "lm-sensors"
            res = self.ctx.run([sensors, "-A"], timeout=6.0)
            if res.ok:
                info.readings = parse_sensors(res.stdout)
                if not info.readings:
                    info.warnings.append("no sensor values exposed by the kernel/driver")
            else:
                info.warnings.append((res.stderr or "sensors failed").strip()[:140])
        else:
            info.warnings.append("lm-sensors not installed (package: lm-sensors)")

        nvidia = which("nvidia-smi")
        if nvidia:
            info.backend = (info.backend + "+nvidia").strip("+")
            res = self.ctx.run(
                [nvidia, "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu",
                 "--format=csv,noheader,nounits"],
                timeout=6.0,
            )
            if res.ok:
                for line in res.lines:
                    fields = [f.strip() for f in line.split(",")]
                    if len(fields) >= 5:
                        info.gpus.append(
                            {
                                "name": fields[0],
                                "util": fields[1],
                                "mem": f"{fields[2]} / {fields[3]} MiB",
                                "temp": f"{fields[4]} C",
                            }
                        )
            else:
                info.warnings.append((res.stderr or "nvidia-smi failed").strip()[:140])
        elif info.backend == "lm-sensors":
            info.warnings.append("no NVIDIA GPU tooling detected (nvidia-smi absent)")

        result = Result.ok_result(info, info.backend or self.key)
        result.warnings = info.warnings
        return result
