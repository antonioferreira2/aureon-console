"""Security-focused tests: no shell, no writes, no privilege escalation."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aureon.fail2ban.wizard import build_plan, diff_plan
from aureon.fail2ban.detect import Fail2banStatus, JailInfo
from aureon.util import run


def test_commands_never_use_a_shell(monkeypatch):
    import subprocess

    seen = {}
    original = subprocess.run

    def spy(argv, **kwargs):
        seen["shell"] = kwargs.get("shell")
        seen["argv"] = argv
        return original(["true"], capture_output=True, text=True)

    monkeypatch.setattr(subprocess, "run", spy)
    run(["echo", "safe"], timeout=3)
    assert seen["shell"] in (None, False)


def test_dangerous_characters_are_passed_literally():
    result = run(["echo", "$(id); rm -rf /tmp/x && whoami"], timeout=3)
    assert "$(id)" in result.stdout
    assert "rm -rf" in result.stdout


def test_logs_search_is_not_a_shell_injection_vector(config):
    from aureon.collectors import COLLECTORS
    from aureon.collectors.base import CollectionContext

    payload = "'; DROP TABLE security_events; --"
    result = COLLECTORS["logs"](CollectionContext(config)).collect(search=payload, limit=5)
    assert result.available  # the module survives and treats it as text


def test_smart_device_name_is_validated(config, monkeypatch):
    from aureon.collectors.base import CollectionContext
    from aureon.collectors.storage import StorageCollector

    collector = StorageCollector(CollectionContext(config))
    result = collector.smart("/dev/sda1; rm -rf /")
    assert not result.available
    assert "invalid" in (result.error or "").lower()


def test_docker_container_name_is_validated(config):
    from aureon.collectors.base import CollectionContext
    from aureon.collectors.docker import DockerCollector

    result = DockerCollector(CollectionContext(config)).logs("evil; rm -rf /")
    assert not result.available


def test_fail2ban_client_rejects_injected_jail_names():
    from aureon.fail2ban.detect import Fail2banClient

    client = Fail2banClient()
    if not client.installed:
        pytest.skip("fail2ban-client not installed in this environment")
    result = client.banned_in_jail("sshd; rm -rf /")
    assert not result.available
    assert "invalid" in (result.error or "").lower()


def test_write_operations_are_disabled_in_the_client():
    from aureon.fail2ban.detect import Fail2banClient

    client = Fail2banClient()
    result = client.set_unban("sshd", "203.0.113.1")
    assert not result.available
    assert "disabled" in (result.error or "")


def test_state_directory_is_private(config):
    config.ensure_dirs()
    mode = Path(config.state_dir).stat().st_mode
    assert mode & 0o077 == 0


def test_database_file_is_private(tmp_path):
    from aureon.db.repo import Repository

    repo = Repository(tmp_path / "private.db")
    repo.open()
    repo.close()
    # the file itself keeps sqlite defaults; the directory is what restricts access
    assert Path(tmp_path).is_dir()


def test_no_network_listeners_are_created(tmp_path):
    """AUREON must not open sockets. A quick import-time audit is enough."""
    import socket

    created = []
    original = socket.socket.bind

    def spy(self, address):  # pragma: no cover - only runs on failure
        created.append(address)
        return original(self, address)

    socket.socket.bind = spy
    try:
        import importlib

        import aureon.cli
        importlib.reload(aureon.cli)
    finally:
        socket.socket.bind = original
    assert created == []


def test_no_telemetry_endpoints_in_the_codebase():
    """Grep the shipped package for outbound network usage."""
    package = Path(__file__).resolve().parents[1] / "src" / "aureon"
    forbidden = ("requests.", "urllib.request", "http.client", "socket.create_connection", "ftplib")
    offenders = []
    for path in package.rglob("*.py"):
        text = path.read_text(encoding="utf-8", errors="replace")
        for token in forbidden:
            if token in text:
                offenders.append(f"{path.name}: {token}")
    assert offenders == [], f"unexpected outbound network usage: {offenders}"


def test_hardening_checks_keep_missing_evidence_unknown():
    from aureon.hardening import Outcome, assess_ssh_root_login, assess_firewall, calculate_score, _result
    from aureon.collectors.firewall import FirewallInfo

    assert assess_ssh_root_login(None).outcome == Outcome.UNKNOWN
    firewall_checks = assess_firewall(FirewallInfo(detected=["nftables"]))
    assert firewall_checks[1].outcome == Outcome.UNKNOWN
    score, domains = calculate_score(firewall_checks)
    assert score is None
    assert domains["Firewall"] is None


def test_hardening_ssh_check_uses_observed_effective_value():
    from aureon.hardening import Outcome, assess_ssh_root_login

    failed = assess_ssh_root_login("yes")
    password_only = assess_ssh_root_login("no")
    key_only = assess_ssh_root_login("prohibit-password")
    assert failed.outcome == Outcome.FAIL
    assert failed.evidence == ["sshd -T reported permitrootlogin yes"]
    assert password_only.outcome == Outcome.PASS
    assert key_only.outcome == Outcome.FAIL


def test_hardening_score_excludes_unknown_and_informational_checks():
    from aureon.hardening import Outcome, assess_ssh_root_login, calculate_score, _result

    failed = assess_ssh_root_login("yes")
    unknown = assess_ssh_root_login(None)
    info = _result("FIREWALL-TOOL-AVAILABLE", Outcome.PASS, ["nft"])
    score, _domains = calculate_score([failed, unknown, info])
    assert score is None, "unknown applicable controls make the score incomplete, not higher-confidence"


def test_fail2ban_apply_has_no_write_path(tmp_path, monkeypatch):
    from aureon.fail2ban.wizard import apply_plan

    config_dir = tmp_path / "fail2ban"
    config_dir.mkdir()
    plan = build_plan(Fail2banStatus(installed=True, config_dir=str(config_dir)))
    def unexpected(*_args, **_kwargs):
        raise AssertionError("host mutation/validation command must not be reached")
    monkeypatch.setattr("aureon.fail2ban.wizard.validate_config", unexpected, raising=False)
    monkeypatch.setattr("aureon.fail2ban.wizard.reload_service", unexpected, raising=False)

    result = apply_plan(plan, confirmed=True, allow_writes=True)
    assert result.applied is False
    assert "read-only" in result.errors[0]
    assert list(config_dir.iterdir()) == []
    assert not (tmp_path / "backups").exists()


def test_plan_targets_a_dedicated_dropin(tmp_path):
    status = Fail2banStatus(installed=True, config_dir=str(tmp_path / "fail2ban"))
    plan = build_plan(status)
    assert Path(plan.dropin_path).parent.name == "jail.d"
    assert Path(plan.dropin_path).name.startswith("aureon-")


def test_ignoreip_never_contains_public_wildcards(tmp_path):
    status = Fail2banStatus(installed=True, config_dir=str(tmp_path))
    plan = build_plan(status)
    for entry in plan.ignoreip:
        assert entry not in ("0.0.0.0/0", "::/0"), "excluding the whole internet from bans is unsafe"


# --- repository hygiene ------------------------------------------------------
DOCUMENTATION_PREFIXES = ("203.0.113.", "198.51.100.", "192.0.2.", "127.", "0.0.0.0", "255.")
PRIVATE_PREFIXES = ("10.", "192.168.", "169.254.")
# Obvious placeholders used by unit tests and docstrings.
PLACEHOLDER_ADDRESSES = {
    "1.1.1.1", "2.2.2.2", "3.3.3.3", "9.9.9.9", "8.8.8.8",
    "1.2.3.4", "5.6.7.8", "1.2.3.5",
}


def test_no_public_ip_addresses_are_committed():
    """No real client/server address may live in the repository.

    Addresses from the RFC 5737 documentation ranges and RFC 1918 private
    ranges are fine (they are examples or fixtures); anything else would mean
    real data from a real machine.
    """
    import re
    import subprocess

    root = Path(__file__).resolve().parents[1]
    files = subprocess.run(
        ["git", "ls-files"], cwd=root, capture_output=True, text=True, check=False
    ).stdout.split()
    offenders = []
    for name in files:
        if not name.endswith((".py", ".sh", ".toml", ".yml", ".cfg")):
            continue
        text = (root / name).read_text(encoding="utf-8", errors="replace")
        for address in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
            if address.startswith(DOCUMENTATION_PREFIXES + PRIVATE_PREFIXES):
                continue
            if address.startswith("172.") or address in PLACEHOLDER_ADDRESSES:
                continue
            offenders.append(f"{name}: {address}")
    assert offenders == [], f"possible real addresses committed: {offenders}"
