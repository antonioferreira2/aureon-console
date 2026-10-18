"""Docker / container runtime detection.

AUREON never installs Docker. If the socket is absent or unreadable the module
reports "unavailable" instead of pretending there are no containers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..util import Result, human_bytes, human_duration, which
from .base import Collector

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


@dataclass
class ContainerInfo:
    container_id: str
    name: str
    image: str
    state: str
    status: str = ""
    restarts: Optional[int] = None

    @property
    def short_id(self) -> str:
        return self.container_id[:12]


@dataclass
class DockerInfo:
    backend: str = "none"
    version: str = ""
    containers: List[ContainerInfo] = field(default_factory=list)
    images: List[Dict[str, str]] = field(default_factory=list)
    restart_loops: List[ContainerInfo] = field(default_factory=list)
    permissions_ok: bool = True
    warnings: List[str] = field(default_factory=list)


class DockerCollector(Collector):
    key = "docker"
    title = "Containers"
    source = "docker CLI"

    def available(self) -> bool:
        return bool(which("docker")) or bool(which("podman"))

    def collect(self) -> Result:
        info = DockerInfo()
        binary = which("docker") or which("podman")
        if not binary:
            return self.unavailable("docker/podman not installed")
        info.backend = "podman" if binary.endswith("podman") else "docker"

        version = self.ctx.run([binary, "version", "--format", "{{.Server.Version}}"], timeout=6.0)
        if version.returncode != 0:
            message = (version.stderr or version.stdout or "").strip()
            if "permission denied" in message.lower() or "connection refused" in message.lower():
                info.permissions_ok = False
                info.warnings.append("daemon reachable but access denied (socket permissions?)")
                result = Result.ok_result(info, info.backend)
                result.warnings = info.warnings
                return result
            info.warnings.append(f"version query failed: {message[:120]}")
        else:
            info.version = version.stdout.strip()

        listing = self.ctx.run(
            [binary, "ps", "-a", "--no-trunc", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}"],
            timeout=10.0,
        )
        if not listing.ok:
            info.warnings.append((listing.stderr or "ps failed").strip()[:140])
            result = Result.ok_result(info, info.backend)
            result.warnings = info.warnings
            return result

        for line in listing.lines:
            parts = line.split("\t")
            if len(parts) < 4:
                continue
            container = ContainerInfo(
                container_id=parts[0],
                name=parts[1],
                image=parts[2],
                state=parts[3],
                status=parts[4] if len(parts) > 4 else "",
            )
            match = re.search(r"\((\d+)\s+restart", container.status or "")
            if match:
                container.restarts = int(match.group(1))
            if container.restarts and container.restarts >= 3:
                info.restart_loops.append(container)
            info.containers.append(container)

        images = self.ctx.run(
            [binary, "images", "--format", "{{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}"], timeout=10.0
        )
        if images.ok:
            for line in images.lines:
                fields = line.split("\t")
                if len(fields) >= 2:
                    info.images.append({"image": fields[0], "id": fields[1][:19], "size": fields[2] if len(fields) > 2 else ""})

        result = Result.ok_result(info, info.backend)
        result.warnings = info.warnings
        return result

    def logs(self, container: str, tail: int = 200) -> Result:
        if not _NAME_RE.match(container or ""):
            return Result(None, self.key, "error", "invalid container name")
        binary = which("docker") or which("podman")
        if not binary:
            return self.unavailable("docker/podman not installed")
        res = self.ctx.run([binary, "logs", "--tail", str(int(tail)), container], timeout=self.timeout())
        return Result.from_command(res, f"{binary} logs", lambda text: text.splitlines())

    def stats(self) -> Result:
        binary = which("docker") or which("podman")
        if not binary:
            return self.unavailable("docker/podman not installed")
        res = self.ctx.run(
            [binary, "stats", "--no-stream", "--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"],
            timeout=10.0,
        )
        return Result.from_command(res, f"{binary} stats", lambda text: [ln.split("\t") for ln in text.splitlines() if ln])


def container_size_label(text: str) -> str:
    return text or human_bytes(0)


def container_age(status: str) -> str:
    return human_duration(0) if not status else status
