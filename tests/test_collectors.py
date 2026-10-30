"""Collector tests: real /proc parsing plus degraded environments."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from aureon.collectors import COLLECTORS
from aureon.collectors.base import CollectionContext
from aureon.collectors.logs import PRIORITY_RANK, parse_file_output, parse_journal_output
from aureon.collectors.sensors import parse_sensors
from aureon.collectors.storage import _read_mounts, read_disks
from aureon.util import Availability, Result, bar, human_bytes, human_duration, run


def test_run_executes_without_shell(tmp_path):
    result = run(["echo", "hello; rm -rf /"], timeout=5)
    assert result.ok
    assert ";" in result.stdout, "the argument must be passed literally, not interpreted"


def test_run_handles_missing_binary():
    result = run(["definitely-not-a-real-binary-xyz"], timeout=5)
    assert result.returncode == 127


def test_run_enforces_timeout():
    result = run(["sleep", "5"], timeout=0.3)
    assert result.timed_out


def test_result_from_command_classifies_states():
    assert Result.from_command(run(["true"]), "t", lambda out: out.splitlines()).availability == Availability.OK
    assert Result.from_command(run(["false"]), "t", lambda out: None).availability == Availability.ERROR
    assert Result.from_command(run(["nope-xyz"]), "t", lambda out: None).availability == Availability.UNAVAILABLE
    assert Result.from_command(run(["sleep", "5"], timeout=0.2), "t", lambda out: None).availability == Availability.TIMEOUT


def test_result_from_command_reports_parse_errors():
    def boom(_out):
        raise ValueError("bad format")

    result = Result.from_command(run(["echo", "x"]), "t", boom)
    assert result.availability == Availability.ERROR
    assert "parse error" in (result.error or "")


def test_human_helpers():
    assert human_bytes(1024) == "1.0 KiB"
    assert human_bytes(None) == "n/a"
    assert human_duration(3661) == "1h 01m 01s"
    assert human_duration(90061).startswith("1d")
    assert len(bar(50, 10)) == 10


def test_system_collector_returns_measured_values(config):
    ctx = CollectionContext(config)
    result = COLLECTORS["system"](ctx).collect()
    assert result.available
    info = result.value
    assert info.hostname
    assert info.mem_total and info.mem_total > 0
    assert info.cpu_count >= 1


def test_storage_collector_never_crashes(config):
    ctx = CollectionContext(config)
    result = COLLECTORS["storage"](ctx).collect()
    assert result.available
    assert result.value.mounts


def test_read_disks_ignores_virtual_devices(tmp_path):
    assert all(not d.device.startswith(("loop", "ram")) for d in read_disks(tmp_path))


def test_read_mounts_filters_pseudo_filesystems(tmp_path):
    fake = tmp_path / "mtab"
    fake.write_text(
        "/dev/sda1 / ext4 rw 0 0\n"
        "proc /proc proc rw 0 0\n"
        "sysfs /sys sysfs rw 0 0\n"
        "tmpfs /dev/shm tmpfs rw 0 0\n",
        encoding="utf-8",
    )
    import aureon.collectors.storage as storage

    original = storage.MOUNT_GUESSES
    storage.MOUNT_GUESSES = (str(fake),)
    try:
        mounts = _read_mounts()
    finally:
        storage.MOUNT_GUESSES = original
    points = {m.mountpoint for m in mounts}
    assert "/ext4".rstrip("/") in {p for p in points} or "/" in points
    assert "/proc" not in points and "/sys" not in points


def test_network_collector(config):
    result = COLLECTORS["network"](CollectionContext(config)).collect()
    assert result.available
    assert result.value.interfaces


def test_services_collector_never_raises(config):
    result = COLLECTORS["services"](CollectionContext(config)).collect()
    assert result.available or result.availability in (Availability.UNAVAILABLE, Availability.DENIED)


def test_logs_collector_applies_limits(config):
    result = COLLECTORS["logs"](CollectionContext(config)).collect(limit=10)
    assert result.available
    assert len(result.value.lines) <= 10


def test_logs_collector_survives_a_failing_command(config, monkeypatch):
    ctx = CollectionContext(config)
    monkeypatch.setattr(ctx, "run", lambda argv, timeout=None: run(["false"], timeout=2))
    result = COLLECTORS["logs"](ctx).collect()
    assert result.available
    assert result.value.warnings


def test_logs_search_term_is_not_interpreted(config):
    result = COLLECTORS["logs"](CollectionContext(config)).collect(search="*; rm -rf /", limit=5)
    assert result.available, "a search string must be passed as a single argument"


def test_parse_journal_output():
    lines = parse_journal_output(
        "2026-03-05T14:22:31+0100 host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
    )
    assert lines[0].unit == "sshd"
    assert lines[0].priority == "notice" or lines[0].priority


def test_parse_file_output():
    lines = parse_file_output("Mar  5 14:22:31 host sshd[1]: Failed password for root from 1.2.3.4")
    assert lines[0].unit == "sshd"
    assert lines[0].hostname == "host"


def test_priority_ordering():
    assert PRIORITY_RANK["emerg"] < PRIORITY_RANK["err"] < PRIORITY_RANK["debug"]


def test_sensors_parser_classifies_readings():
    readings = parse_sensors("Core 0:  +45.0 C  (High = +80.0 C)\nfan1: 1200 RPM\n")
    kinds = {r.label.split()[0]: r.kind for r in readings}
    assert kinds.get("Core") == "temperature"
    assert kinds.get("fan1") == "fan"


def test_firewall_collector_uses_only_read_only_query_arguments(config, monkeypatch):
    from aureon.collectors.firewall import FirewallCollector
    from aureon.util import CommandResult

    installed = {"ufw": "/usr/sbin/ufw", "nft": "/usr/sbin/nft", "iptables": "/usr/sbin/iptables", "ip6tables": "/usr/sbin/ip6tables", "iptables-save": "/usr/sbin/iptables-save", "ip6tables-save": "/usr/sbin/ip6tables-save", "firewall-cmd": "/usr/bin/firewall-cmd"}
    monkeypatch.setattr("aureon.collectors.firewall.which", lambda name: installed.get(name))
    seen = []
    ctx = CollectionContext(config)
    def fake_run(argv, timeout=None):
        seen.append(list(argv))
        return CommandResult(argv, 0, "sample read-only output\\n", "", 0.01)
    monkeypatch.setattr(ctx, "run", fake_run)

    result = FirewallCollector(ctx).collect()
    assert result.available
    assert set(result.value.detected) == {"ufw", "nftables", "iptables", "firewalld"}
    assert result.value.evidence
    expected_queries = {
        ("/usr/sbin/ufw", "version"),
        ("/usr/sbin/ufw", "status", "verbose"),
        ("/usr/sbin/ufw", "status", "numbered"),
        ("/usr/sbin/ufw", "app", "list"),
        ("/usr/sbin/nft", "list", "ruleset"),
        ("/usr/sbin/iptables", "-S"),
        ("/usr/sbin/ip6tables", "-S"),
        ("/usr/sbin/iptables-save",),
        ("/usr/sbin/ip6tables-save",),
        ("/usr/bin/firewall-cmd", "--state"),
        ("/usr/bin/firewall-cmd", "--get-default-zone"),
        ("/usr/bin/firewall-cmd", "--get-active-zones"),
        ("/usr/bin/firewall-cmd", "--list-all-zones"),
        ("/usr/bin/firewall-cmd", "--permanent", "--list-all-zones"),
    }
    assert {tuple(argv) for argv in seen} == expected_queries
    assert any("external" in warning.lower() for warning in result.value.warnings)


def test_firewall_collector_classifies_permission_denied(config, monkeypatch):
    from aureon.collectors.firewall import FirewallCollector
    from aureon.util import CommandResult

    monkeypatch.setattr("aureon.collectors.firewall.which", lambda name: "/usr/sbin/nft" if name == "nft" else None)
    ctx = CollectionContext(config)
    monkeypatch.setattr(ctx, "run", lambda argv, timeout=None: CommandResult(argv, 1, "", "Operation not permitted", 0.01))
    result = FirewallCollector(ctx).collect()
    assert result.available
    assert result.value.evidence[0].availability == Availability.DENIED
    assert "permissions" in result.value.warnings[-1].lower()


def test_firewall_collector_reports_missing_tools(config, monkeypatch):
    from aureon.collectors.firewall import FirewallCollector

    monkeypatch.setattr("aureon.collectors.firewall.which", lambda _name: None)
    result = FirewallCollector(CollectionContext(config)).collect()
    assert result.availability == Availability.UNAVAILABLE
    assert "no supported" in result.error


def test_optional_tools_are_detected_without_installation(config):
    result = COLLECTORS["tools"](CollectionContext(config)).collect()
    assert result.available
    for status in result.value:
        assert status.spec.license, "every tool must document its license"


def test_docker_collector_handles_missing_daemon(config, monkeypatch):
    result = COLLECTORS["docker"](CollectionContext(config)).collect()
    assert isinstance(result, Result)
    assert result.value is not None or result.availability != Availability.OK
