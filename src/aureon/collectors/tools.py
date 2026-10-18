"""Optional external tools: detection, purpose and license classification.

AUREON does not install any of these. The module only reports what is present
and why it might be useful, so an administrator can decide.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from ..util import Result, which
from .base import Collector


@dataclass(frozen=True)
class ToolSpec:
    name: str
    binary: str
    purpose: str
    license: str
    package_hint: str
    integration: str  # how AUREON uses it, if at all
    category: str


TOOLS: tuple = (
    ToolSpec("btop", "btop", "Resource monitor TUI", "GPL-3.0", "btop", "informational only", "monitor"),
    ToolSpec("htop", "htop", "Process viewer", "GPL-2.0", "htop", "informational only", "monitor"),
    ToolSpec("glances", "glances", "All-in-one monitoring", "GPL-3.0", "glances", "informational only", "monitor"),
    ToolSpec("fastfetch", "fastfetch", "System summary", "MIT", "fastfetch", "informational only", "info"),
    ToolSpec("lm-sensors", "sensors", "Hardware temperatures/fans", "GPL-2.0", "lm-sensors", "native integration", "hardware"),
    ToolSpec("smartmontools", "smartctl", "SMART disk health", "GPL-2.0", "smartmontools", "native integration", "hardware"),
    ToolSpec("sysstat", "sar", "Historical resource stats", "GPL-2.0", "sysstat", "informational only", "history"),
    ToolSpec("iftop", "iftop", "Per-host bandwidth", "GPL-2.0", "iftop", "informational only", "network"),
    ToolSpec("nload", "nload", "Interface throughput", "GPL-2.0", "nload", "informational only", "network"),
    ToolSpec("nvtop", "nvtop", "NVIDIA GPU monitor", "GPL-3.0", "nvtop", "informational only", "hardware"),
    ToolSpec("nvidia-smi", "nvidia-smi", "NVIDIA GPU telemetry", "NVIDIA proprietary terms", "driver bundle", "native integration", "hardware"),
    ToolSpec("docker", "docker", "Container runtime", "Apache-2.0", "docker.io", "native integration", "containers"),
    ToolSpec("podman", "podman", "Rootless container runtime", "Apache-2.0", "podman", "native integration", "containers"),
    ToolSpec("fail2ban-client", "fail2ban-client", "Fail2ban control socket", "GPL-2.0", "fail2ban", "native integration", "security"),
    ToolSpec("lvm", "lvs", "LVM logical volumes", "GPL-2.0", "lvm2", "native integration", "storage"),
    ToolSpec("curl", "curl", "HTTP client", "curl (MIT-like)", "curl", "not used by AUREON", "network"),
    ToolSpec("jq", "jq", "JSON processor", "MIT", "jq", "not used by AUREON", "utility"),
    ToolSpec("ncdu", "ncdu", "Disk usage explorer", "GPL-2.0", "ncdu", "informational only", "storage"),
    ToolSpec("tree", "tree", "Directory tree", "GPL-2.0", "tree", "informational only", "utility"),
)


@dataclass
class ToolStatus:
    spec: ToolSpec
    path: Optional[str]
    version: str = ""

    @property
    def installed(self) -> bool:
        return bool(self.path)


class ToolCollector(Collector):
    key = "tools"
    title = "Optional tools"
    source = "PATH"

    def collect(self) -> Result:
        statuses: List[ToolStatus] = []
        for spec in TOOLS:
            path = which(spec.binary)
            status = ToolStatus(spec=spec, path=path)
            if path:
                status.version = self.ctx.cached(f"ver:{spec.binary}", 600.0, lambda p=path: self._version(p))
            statuses.append(status)
        result = Result.ok_result(statuses, "PATH")
        result.warnings = [f"{s.spec.name} not installed" for s in statuses if not s.installed]
        return result

    def _version(self, path: str) -> str:
        res = self.ctx.run([path, "--version"], timeout=4.0)
        if res.timed_out:
            return "installed"
        text = (res.stdout or res.stderr or "").strip().splitlines()
        return text[0][:80] if text else "installed"
