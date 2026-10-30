#!/usr/bin/env python
"""Capture reproducible AUREON TUI panels with synthetic demonstration data.

Usage:
    python scripts/capture_screenshots.py [output-dir]

Writes Textual SVG captures for dashboard, firewall, hardening assessment,
Banned IPs and Tools. No live host collectors or system commands are queried.
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aureon import __version__  # noqa: E402
from aureon.collectors.firewall import FirewallEvidence, FirewallInfo  # noqa: E402
from aureon.collectors.system import SystemInfo  # noqa: E402
from aureon.collectors.tools import TOOLS, ToolStatus  # noqa: E402
from aureon.config import Config  # noqa: E402
from aureon.hardening import Assessment, CHECK_DEFINITION_VERSION, CHECKS, CheckResult, Outcome, calculate_score  # noqa: E402
from aureon.i18n import navigation  # noqa: E402
from aureon.models import Health, Indicator  # noqa: E402
from aureon.tui import panels  # noqa: E402
from aureon.tui.app import AureonApp  # noqa: E402
from aureon.util import Availability, Result  # noqa: E402
from rich.console import Group  # noqa: E402
from rich.text import Text  # noqa: E402
from textual.widgets import ListView  # noqa: E402

PANELS = ("dashboard", "firewall", "assessment", "banned", "tools")
DEMO_NOW = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)


def _system_info() -> SystemInfo:
    return SystemInfo(
        hostname="audit-node-01.example.test",
        os_name="Ubuntu",
        os_version="24.04 LTS",
        kernel="6.8.0-55-generic",
        arch="x86_64",
        uptime_seconds=12 * 86400 + 12 * 3600 + 57 * 60,
        boot_time=DEMO_NOW - timedelta(days=12, hours=12, minutes=57),
        cpu_count=8,
        cpu_model="Example Virtual CPU",
        cpu_percent=32.7,
        load1=1.24,
        load5=0.98,
        load15=0.76,
        mem_total=8 * 1024**3,
        mem_available=5 * 1024**3,
        swap_total=2 * 1024**3,
        swap_free=2 * 1024**3,
    )


def _firewall_info() -> FirewallInfo:
    return FirewallInfo(
        detected=["ufw"],
        evidence=[
            FirewallEvidence("ufw", "version", Availability.OK, "ufw 0.36.2"),
            FirewallEvidence(
                "ufw", "status", Availability.OK,
                "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n",
            ),
            FirewallEvidence(
                "ufw", "numbered rules", Availability.OK,
                "Status: active\n     To                         Action      From\n[ 1] 22/tcp                     LIMIT IN    198.51.100.0/24\n[ 2] 443/tcp                    ALLOW IN    Anywhere\n[ 3] 443/tcp (v6)               ALLOW IN    Anywhere (v6)\n",
            ),
            FirewallEvidence("ufw", "application profiles", Availability.EMPTY),
        ],
        warnings=[
            "Synthetic demo output only; review live policy and upstream controls separately.",
            "Local rules do not prove external Internet reachability.",
        ],
    )


def _assessment() -> Assessment:
    outcomes = {
        "ACCOUNT-UID0": (Outcome.PASS, ["Synthetic passwd inventory: only root has UID 0."], "No additional UID 0 accounts were found in this sample."),
        "SUDOERS-PERMISSIONS": (Outcome.PASS, ["Synthetic metadata: /etc/sudoers mode 0440."], "Sample sudo policy is not group/world writable."),
        "HOST-SELINUX": (Outcome.FAIL, ["Synthetic state: SELinux is not enforcing."], "Review the host's applicable mandatory access-control policy."),
        "OS-REBOOT-REQUIRED": (Outcome.PASS, ["Synthetic distro marker: no reboot required."], "No reboot-required marker is present in this sample."),
        "TIME-SYNCHRONIZATION": (Outcome.PASS, ["Synthetic timedatectl result: synchronized."], "The sample reports system time synchronized."),
    }
    results = [
        CheckResult(next(check for check in CHECKS if check.id == check_id), outcome, evidence, reason)
        for check_id, (outcome, evidence, reason) in outcomes.items()
    ]
    score, domain_scores = calculate_score(results)
    return Assessment(
        assessed_at=DEMO_NOW.isoformat(),
        tool_version=__version__,
        definition_version=CHECK_DEFINITION_VERSION,
        score=score,
        domain_scores=domain_scores,
        checks=results,
    )


def _banned_rows():
    return [
        {"ip": "203.0.113.24", "jail": "sshd", "last": DEMO_NOW - timedelta(minutes=18), "events": 4},
        {"ip": "198.51.100.37", "jail": "sshd", "last": DEMO_NOW - timedelta(hours=2), "events": 2},
        {"ip": "203.0.113.81", "jail": "nginx-auth", "last": DEMO_NOW - timedelta(hours=5), "events": 1},
    ]


def _tools():
    versions = {
        "btop": "1.4.2",
        "htop": "3.3.0",
        "sensors": "3.6.0",
        "smartctl": "7.4",
        "docker": "27.5.1",
        "fail2ban-client": "1.1.0",
        "lvs": "2.03.16",
    }
    showcase = {"btop", "htop", "sensors", "smartctl", "docker", "podman", "fail2ban-client", "lvs"}
    return [
        ToolStatus(spec, f"/usr/bin/{spec.binary}" if spec.name in versions else None,
                   f"demo {versions[spec.name]}" if spec.name in versions else "")
        for spec in TOOLS if spec.name in showcase
    ]


class ScreenshotApp(AureonApp):
    """Use real application renderers but never contact the current host."""

    def _probe_modules(self):
        return {panel: "ok" for panel in PANELS}

    def _indicators(self, _states=None):
        return [
            Indicator("cpu", "CPU", Health.OK, "32.7%", "synthetic demo"),
            Indicator("mem", "Memory", Health.OK, "3.0 GiB / 8.0 GiB", "synthetic demo"),
            Indicator("load", "Load", Health.OK, "1.24 / 8 cpu", "synthetic demo"),
            Indicator("uptime", "Uptime", Health.OK, "12d 12h 57m", "synthetic demo"),
        ]

    def _build_panel(self, key: str):
        language = self.config.language
        if key == "dashboard":
            content = panels.panel(Result.ok_result(_system_info(), "synthetic demo fixture"), panels.render_system, language=language)
        elif key == "firewall":
            content = panels.panel(Result.ok_result(_firewall_info(), "synthetic demo fixture"), panels.render_firewall, language=language)
        elif key == "assessment":
            content = panels.render_assessment(_assessment(), language)
        elif key == "banned":
            live = {
                "sshd": [{"ip": "203.0.113.24", "when": "18 minutes ago"}],
                "nginx-auth": [{"ip": "198.51.100.37", "when": "2 hours ago"}],
            }
            content = panels.render_banned_ips(_banned_rows(), live, language=language)
        elif key == "tools":
            content = panels.panel(Result.ok_result(_tools(), "synthetic demo fixture"), panels.render_tools, language=language)
        else:
            return super()._build_panel(key)
        return panels.widget(Group(
            Text("DEMO DATA — synthetic example; not a live host", style="bold #e5c07b"),
            content,
        ))


async def capture(output: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="aureon-screenshot-") as temporary:
        config = Config()
        config.state_dir = str(Path(temporary) / "state")
        config.config_dir = str(Path(temporary) / "config")
        config.ensure_dirs()
        app = ScreenshotApp(config)
        # Avoid exposing even this runner's hostname or kernel in the chrome.
        with patch("aureon.tui.app.socket.gethostname", return_value="audit-node-01.example.test"), \
             patch("aureon.tui.app.platform.system", return_value="Linux"), \
             patch("aureon.tui.app.platform.release", return_value="6.8.0-demo"):
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                nav = app.query_one("#aureon-nav", ListView)
                for panel in PANELS:
                    app.current = panel
                    nav.index = next(i for i, (key, _label) in enumerate(navigation(config.language)) if key == panel)
                    await pilot.pause()
                    await app._render_current()
                    await pilot.pause()
                    target = output / f"{panel}.svg"
                    app.save_screenshot(str(target))
                    print(f"wrote {target}")


def main() -> int:
    output = Path(sys.argv[1] if len(sys.argv) > 1 else "assets/screenshots")
    output.mkdir(parents=True, exist_ok=True)
    asyncio.run(capture(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())