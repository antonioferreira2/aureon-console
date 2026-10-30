"""TUI smoke tests (Textual headless driver)."""

from __future__ import annotations

import pytest

from aureon.security import SecurityService
from aureon.tui.app import NAV, AureonApp

pytest.importorskip("textual")


def build_app(config):
    return AureonApp(config)


@pytest.mark.tui
async def test_app_starts_and_renders_the_dashboard(config):
    app = build_app(config)
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.pause()
        assert app.current == "dashboard"
        assert app.query_one("#aureon-header")
        assert app.query_one("#aureon-nav")


@pytest.mark.tui
async def test_every_navigation_panel_renders(config):
    app = build_app(config)
    async with app.run_test() as pilot:
        await pilot.pause()
        for key, _label in NAV:
            app.current = key
            app.run_worker(app._collect_and_render(), exclusive=True)
            await pilot.pause()
            assert app.query_one("#aureon-body").children, f"panel {key} produced no content"


@pytest.mark.tui
async def test_help_binding_switches_panel(config):
    app = build_app(config)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.action_help()
        await pilot.pause()
        assert app.current == "help"


@pytest.mark.tui
async def test_refresh_only_ever_issues_read_only_commands(config, monkeypatch):
    """Every external command the UI triggers must be a read-only query."""
    issued = []

    def recording(argv, timeout=None, **kwargs):
        issued.append(list(argv))
        from aureon.util import run

        return run(argv, timeout=timeout or 3.0)

    monkeypatch.setattr("aureon.util.run", recording)
    app = build_app(config)
    async with app.run_test() as pilot:
        await pilot.pause()
        for panel in ("dashboard", "storage", "network", "services", "logs", "security", "banned", "firewall", "assessment", "assessment-history", "wizard", "containers", "sensors", "tools"):
            app.current = panel
            app.run_worker(app._collect_and_render(), exclusive=True)
            await pilot.pause()

    forbidden = {"start", "stop", "restart", "reload", "set", "unban", "ban", "kill", "pkill", "rm", "mv", "install"}
    for argv in issued:
        for token in argv:
            assert token.lower() not in forbidden, f"mutating token {token!r} in {argv}"
            assert not token.startswith("/etc/fail2ban"), "the console must not write fail2ban config"


@pytest.mark.tui
async def test_dashboard_survives_fail2ban_absence(config):
    app = build_app(config)
    async with app.run_test() as pilot:
        await pilot.pause()
        app.current = "security"
        app.run_worker(app._collect_and_render(), exclusive=True)
        await pilot.pause()
        status = app.security.status
        assert status.installed in (True, False)


# --- renderer regression tests -------------------------------------------------
# CI (not the developer's machine) caught widgets being composed into rich
# renderables. These tests render every panel with *degraded* data so that the
# empty-state paths are exercised too.
def test_empty_state_returns_a_renderable_not_a_widget():
    from rich.text import Text

    from aureon.tui.widgets import empty_state

    assert isinstance(empty_state("nothing here", "install the tool"), Text)


def test_panel_renders_when_the_source_is_unavailable():
    from aureon.tui import panels
    from aureon.util import Availability, Result

    result = Result(None, "smartctl", Availability.UNAVAILABLE, "not installed")
    assert panels.panel(result, lambda _v: panels.empty_state("unused")) is not None
    denied = Result(None, "fail2ban-client", Availability.DENIED, "root required")
    assert panels.panel(denied, lambda _v: panels.empty_state("unused")) is not None
    errored = Result(None, "journalctl", Availability.ERROR, "boom")
    assert panels.panel(errored, lambda _v: panels.empty_state("unused")) is not None


def test_every_panel_renderer_survives_empty_input():
    from aureon.collectors.docker import DockerInfo
    from aureon.collectors.logs import LogsInfo
    from aureon.collectors.network import NetworkInfo
    from aureon.collectors.sensors import SensorInfo
    from aureon.collectors.services import ServicesInfo
    from aureon.collectors.storage import StorageInfo
    from aureon.fail2ban.detect import Fail2banStatus
    from aureon.tui import panels

    from datetime import datetime, timezone

    assert panels.render_storage(StorageInfo()) is not None
    assert panels.render_network(NetworkInfo()) is not None
    assert panels.render_services(ServicesInfo()) is not None
    assert panels.render_logs(LogsInfo()) is not None
    assert panels.render_docker(DockerInfo()) is not None
    assert panels.render_docker(DockerInfo(permissions_ok=False)) is not None
    assert panels.render_sensors(SensorInfo()) is not None
    assert panels.render_tools([]) is not None
    assert panels.render_fail2ban_status(Fail2banStatus(installed=False)) is not None
    assert panels.render_banned_ips([], {}, True) is not None
    from aureon.models import PeriodStats

    now = datetime.now(timezone.utc)
    stats = PeriodStats("today", now, now, "UTC", data_available=False)
    assert panels.render_security_periods({"today": stats}, "no data") is not None


def test_cells_containing_square_brackets_are_not_parsed_as_markup():
    """systemd cgroup paths look like Rich markup and used to crash the UI."""
    from aureon.collectors.services import ServiceInfo, ServicesInfo
    from aureon.tui import panels

    info = ServicesInfo(
        backend="systemd",
        services=[
            ServiceInfo(
                unit="/sys/fs/cgroup/azure.slice/walinuxagent.service",
                active_state="active",
                sub_state="running",
                description="[not-a-markup-tag] agent",
            )
        ],
    )
    assert panels.render_services(info) is not None


def test_log_lines_with_brackets_do_not_crash():
    from aureon.collectors.logs import LogLine, LogsInfo
    from aureon.tui import panels

    info = LogsInfo(backend="journald", lines=[LogLine(None, unit="sshd", message="[/a/b] closed")])
    assert panels.render_logs(info) is not None
