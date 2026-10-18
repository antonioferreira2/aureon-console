"""AUREON Console - the interactive TUI.

Navigation and interaction model
--------------------------------
* Left sidebar lists every module; ``Up``/``Down`` and mouse select them.
* ``1``-``9`` jump straight to a module, ``?`` opens the help screen.
* Data refresh runs in a Textual worker so the UI never blocks on a slow
  ``journalctl`` or ``systemctl`` call.
* Everything is read-only: quitting leaves the server exactly as it was.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime
from typing import Dict, List, Optional

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.widget import Widget
from textual.widgets import Footer, Header, Input, Label, ListItem, ListView, Static

from .. import APP_NAME, __version__
from ..collectors import COLLECTORS
from ..collectors.base import CollectionContext
from ..collectors.logs import PRIORITIES
from ..config import Config
from ..models import Health, Indicator
from ..periods import BUILTIN_PERIODS, PERIOD_TODAY, resolve_timezone, timezone_name
from ..security import SecurityService
from ..util import Result
from . import panels
from .widgets import AUREON_CSS, HEALTH_STYLE, THEME

NAV = [
    ("dashboard", "Dashboard"),
    ("processes", "Processes"),
    ("storage", "Storage"),
    ("network", "Network"),
    ("services", "Services"),
    ("logs", "Logs"),
    ("security", "Security (F2B)"),
    ("banned", "Banned IPs"),
    ("wizard", "F2B config"),
    ("containers", "Containers"),
    ("sensors", "Sensors"),
    ("tools", "Tools"),
    ("help", "Help"),
]


class Header3(Static):
    """Custom header: identity + host + health indicators."""

    def __init__(self, config: Config, **kwargs):
        super().__init__(**kwargs)
        self.config = config
        self.indicators: List[Indicator] = []
        self.module_states: Dict[str, str] = {}

    def set_data(self, indicators: List[Indicator], states: Dict[str, str]) -> None:
        self.indicators = indicators
        self.module_states = states
        self.update(self.render())

    def render(self):
        from rich.console import Group

        title = Text()
        title.append(f"{APP_NAME}", style="bold #58a6ff")
        title.append(f"  v{__version__}", style="#6e7681")
        title.append("   Author: António Lourenço Ferreira", style="#6e7681")
        host = Text()
        host.append(os.uname().nodename, style="bold")
        host.append(f"  {os.uname().sysname} {os.uname().release}", style="#6e7681")
        health = Text()
        for indicator in indicators_line(self.indicators):
            health.append_text(indicator)
            health.append("   ")
        if not self.indicators:
            health.append("collecting...", style="#6e7681")
        modules = Text()
        for key, label in NAV:
            state = self.module_states.get(key, "")
            symbol = {
                "ok": "\u25cf",
                "warn": "\u25b2",
                "error": "\u2716",
                "unavailable": "\u2013",
                "denied": "\u25b2",
                "timeout": "\u25b2",
                "error:": "\u2716",
            }.get(state, "\u25cb")
            style = {
                "ok": "#4ec9a8",
                "warn": "#e5c07b",
                "error": "#e06c75",
                "unavailable": "#6e7681",
                "denied": "#e5c07b",
                "timeout": "#e5c07b",
            }.get(state, "#6e7681")
            modules.append(f"{symbol} ", style=style)
            modules.append(f"{label} ")
        return Group(title, host, health, modules)


def indicators_line(items: List[Indicator]):
    from rich.text import Text as RText

    out = []
    for indicator in items:
        text = RText()
        text.append(f"{indicator.health.symbol} ", style=HEALTH_STYLE[indicator.health])
        text.append(indicator.label, style="bold")
        text.append(f": {indicator.value}", style="#6e7681")
        out.append(text)
    return out


class AureonApp(App):
    """The console application."""

    CSS = AUREON_CSS
    TITLE = APP_NAME
    SUB_TITLE = "read-only monitoring & security console"

    BINDINGS = [
        Binding("question_mark", "help", "Help"),
        Binding("f5", "refresh", "Refresh"),
        Binding("q", "quit", "Quit"),
        Binding("escape", "back", "Back"),
    ]

    def __init__(self, config: Config, **kwargs) -> None:
        super().__init__(**kwargs)
        self.config = config
        self.ctx = CollectionContext(config)
        self.security = SecurityService(config)
        self.tz = resolve_timezone(config.timezone or None)
        self.current = "dashboard"
        self._states: Dict[str, str] = {}
        self._log_unit = ""
        self._log_priority = ""
        self._log_search = ""
        self._log_since = 60
        self._collect_task: Optional[asyncio.Task] = None
        self._render_lock = asyncio.Lock()
        self._indicator_cache: List[Indicator] = []
        self._panels_rendered = False

    # -- layout ---------------------------------------------------------
    def compose(self) -> ComposeResult:
        self.header = Header3(self.config, id="aureon-header")
        yield self.header
        nav_items = [ListItem(Label(label), id=f"nav-{key}") for key, label in NAV]
        yield ListView(*nav_items, id="aureon-nav")
        with Vertical(id="aureon-main"):
            yield Static("", id="aureon-title")
            yield VerticalScroll(Static("", id="aureon-content"), id="aureon-body")
        yield Static("starting...", id="aureon-status")
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(max(1.0, self.config.refresh_seconds), self._tick)
        self.run_worker(self._collect_and_render(), exclusive=True, name="aureon-collect")

    # -- data collection -------------------------------------------------
    async def _tick(self) -> None:
        if self._collect_task and not self._collect_task.done():
            return
        self._collect_task = asyncio.create_task(self._collect_and_render())

    async def _collect_and_render(self) -> None:
        loop = asyncio.get_running_loop()

        def work():
            states = self._probe_modules()
            return states, self._indicators(states)

        try:
            self._states, self._indicator_cache = await loop.run_in_executor(None, work)
            await self._render_current()
        except Exception as exc:  # noqa: BLE001 - never kill the UI
            self._set_status(f"collection error: {exc}")

    def _probe_modules(self) -> Dict[str, str]:
        states: Dict[str, str] = {}
        from ..collectors.system import system_indicators

        try:
            from ..collectors.system import SystemCollector

            result = SystemCollector(self.ctx).collect()
            states["system"] = result.availability
            if result.available:
                self.header.set_data(system_indicators(result.value), {**states, "dashboard": result.availability})
        except Exception:  # noqa: BLE001
            states["system"] = "error"
        for key in ("storage", "network", "services", "docker", "sensors"):
            try:
                result = COLLECTORS[key](self.ctx).collect()
                states[key] = result.availability
            except Exception:  # noqa: BLE001
                states[key] = "error"
        states["dashboard"] = states.get("system", "unknown")
        states["processes"] = states.get("system", "unknown")
        states["logs"] = "ok"
        try:
            status = self.security.refresh_status()
            states["security"] = "error" if status.problems else "ok"
            states["banned"] = "ok" if not status.root_required else "denied"
            states["wizard"] = states["security"]
            states["containers"] = states.get("docker", "unknown")
            states["sensors"] = states.get("sensors", "unknown")
        except Exception:  # noqa: BLE001
            states["security"] = "error"
        return states

    # -- rendering -------------------------------------------------------
    async def _render_current(self) -> None:
        try:
            content = self._build_panel(self.current)
        except Exception as exc:  # noqa: BLE001
            content = panels.widget(panels.empty_state("This panel failed to render.", str(exc)))
        widget = content if isinstance(content, Widget) else panels.widget(content)
        async with self._render_lock:
            _key, label = self._nav_label(self.current)
            self.query_one("#aureon-title", Static).update(Text(label, style="bold #e6edf3"))
            container = self.query_one("#aureon-body")
            await container.remove_children()
            await container.mount(widget)
            self.header.set_data(self._indicator_cache, self._states)
        self._set_status(
            f"updated {datetime.now(self.tz):%H:%M:%S}  |  refresh {self.config.refresh_seconds:g}s  |  "
            f"timezone {timezone_name(self.tz)}  |  read-only"
        )

    def _indicators(self, states: Optional[Dict[str, str]] = None) -> List[Indicator]:
        from ..collectors.system import SystemCollector, system_indicators
        from ..collectors.storage import StorageCollector, storage_indicators

        items: List[Indicator] = []
        try:
            result = SystemCollector(self.ctx).collect()
            if result.available:
                items.extend(system_indicators(result.value))
        except Exception:  # noqa: BLE001
            pass
        try:
            result = StorageCollector(self.ctx).collect()
            if result.available:
                items.extend(storage_indicators(result.value))
        except Exception:  # noqa: BLE001
            pass
        try:
            overview = self.security.overview()
            items.extend(SecurityService.indicators(overview.status, overview.periods))
        except Exception:  # noqa: BLE001
            pass
        return items

    def _nav_label(self, key: str):
        for nav_key, label in NAV:
            if nav_key == key:
                return nav_key, label
        return key, key

    def _set_status(self, message: str) -> None:
        try:
            self.query_one("#aureon-status", Static).update(Text(message, style="#6e7681"))
        except Exception:  # noqa: BLE001 - during teardown
            pass

    def _build_panel(self, key: str) -> Static:
        ctx = self.ctx
        if key in ("dashboard", "processes"):
            result = COLLECTORS["system"](ctx).collect()
            if key == "dashboard":
                return panels.panel(result, panels.render_system)
            return panels.panel(result, panels.render_processes, redact=self.config.redact_usernames)
        if key == "storage":
            return panels.panel(COLLECTORS["storage"](ctx).collect(), panels.render_storage)
        if key == "network":
            return panels.panel(COLLECTORS["network"](ctx).collect(), panels.render_network)
        if key == "services":
            return panels.panel(COLLECTORS["services"](ctx).collect(), panels.render_services)
        if key == "logs":
            collector = COLLECTORS["logs"](ctx)
            return panels.panel(
                collector.collect(unit=self._log_unit or None, priority=self._log_priority or None,
                                  since_minutes=self._log_since, search=self._log_search or None),
                panels.render_logs,
            )
        if key == "security":
            overview = self.security.overview()
            return panels.render_security_periods(overview.periods, overview.coverage_text)
        if key == "banned":
            overview = self.security.overview()
            rows = self.security.repo.banned_ips_in_period(overview.periods["week"].start, overview.periods["week"].end)
            return panels.render_banned_ips(rows, overview.status.banned_ips)
        if key == "wizard":
            return self._wizard_panel()
        if key == "containers":
            return panels.panel(COLLECTORS["docker"](ctx).collect(), panels.render_docker)
        if key == "sensors":
            return panels.panel(COLLECTORS["sensors"](ctx).collect(), panels.render_sensors)
        if key == "tools":
            return panels.panel(COLLECTORS["tools"](ctx).collect(), panels.render_tools)
        return self._help_panel()

    def _wizard_panel(self) -> Static:
        from rich.console import Group

        from ..fail2ban.wizard import POLICY_NOTES

        status = self.security.status
        plan = self.security.plan()
        text = Text()
        text.append("AUREON Fail2ban configuration wizard\n\n", style="bold #e6edf3")
        text.append("Current state\n", style="bold")
        text.append(f"  installed     : {status.installed} {status.version}\n")
        text.append(f"  service       : {status.service_state}\n")
        text.append(f"  ssh jail      : {status.ssh_jail.name if status.ssh_jail else 'none'}\n\n")
        text.append("Proposal (nothing is written from the console)\n", style="bold")
        text.append(f"  distribution  : {plan.distro}\n")
        text.append(f"  package mgr   : {plan.package_manager}\n")
        text.append(f"  ssh port      : {plan.ssh_port} ({plan.ssh_port_source})\n")
        text.append(f"  log backend   : {plan.log_backend}\n")
        text.append(f"  policy        : {plan.policy} - {POLICY_NOTES.get(plan.policy, '')}\n")
        text.append(f"  values        : {plan.values}\n")
        text.append(f"  drop-in file  : {plan.dropin_path}\n\n")
        text.append("Proposed file content\n", style="bold")
        text.append(plan.content)
        text.append("\nSteps (execute manually or via `aureon f2b plan --apply --yes`)\n", style="bold")
        for index, step in enumerate(plan.steps, start=1):
            text.append(f"  {index}. {step.description} [{step.risk} risk]\n")
            if step.command:
                text.append(f"     $ {step.command}\n", style="#6e7681")
        for warning in plan.warnings:
            text.append(f"  ! {warning}\n", style="#e5c07b")
        for blocker in plan.blockers:
            text.append(f"  x {blocker}\n", style="#e06c75")
        return Static(Group(text))

    def _help_panel(self) -> Static:
        text = Text()
        text.append(f"{APP_NAME} {__version__}\n", style="bold #e6edf3")
        text.append("Read-only console for Linux servers over SSH.\n\n")
        text.append("Keys\n", style="bold")
        text.append("  Up/Down        navigate modules\n")
        text.append("  1-9            jump to a module\n")
        text.append("  F5             force a refresh\n")
        text.append("  ?              this help\n")
        text.append("  q              quit (nothing on the server is modified)\n\n")
        text.append("What is read\n", style="bold")
        text.append("  /proc (cpu, memory, network, disks, uptime)\n")
        text.append("  /sys/block (device inventory)\n")
        text.append("  systemctl (read-only queries)\n")
        text.append("  journalctl (bounded queries)\n")
        text.append("  fail2ban-client (read-only queries; root for the live list)\n")
        text.append("  sensors / smartctl / docker, only if already installed\n\n")
        text.append("What is never done\n", style="bold")
        text.append("  No service restarts, no firewall changes, no SSH changes,\n")
        text.append("  no process kills, no silent writes, no telemetry.\n\n")
        text.append("Documentation: docs/SECURITY.md, docs/FAIL2BAN.md, docs/DATA-ACCURACY.md\n",
                    style="#6e7681")
        return Static(text)

    # -- events ----------------------------------------------------------
    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.item is None:
            return
        item_id = getattr(event.item, "id", "") or ""
        if item_id.startswith("nav-"):
            key = item_id[4:]
            if key != self.current:
                self.current = key
                self.run_worker(self._collect_and_render(), exclusive=True)

    def on_key(self, event) -> None:
        if event.key and event.key.isdigit() and event.key != "0":
            index = int(event.key) - 1
            if index < len(NAV):
                self.current = NAV[index][0]
                self.run_worker(self._collect_and_render(), exclusive=True)

    def action_refresh(self) -> None:
        self.run_worker(self._collect_and_render(), exclusive=True)

    def action_help(self) -> None:
        self.current = "help"
        self.run_worker(self._collect_and_render(), exclusive=True)

    def action_back(self) -> None:
        self.current = "dashboard"
        self.run_worker(self._collect_and_render(), exclusive=True)


def run(config: Config) -> None:  # pragma: no cover - interactive
    AureonApp(config).run()
