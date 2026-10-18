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
            assert app.query_one("#aureon-content"), f"panel {key} produced no content"


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
        for panel in ("dashboard", "storage", "network", "services", "logs", "security", "sensors"):
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
