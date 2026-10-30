"""Fail2ban detection, jail config parsing and wizard tests (synthetic data only)."""

from __future__ import annotations

from pathlib import Path

import pytest

from aureon.fail2ban.detect import (
    Fail2banStatus,
    JailInfo,
    _validate,
    load_jails,
    parse_jail_config,
)
from aureon.fail2ban.wizard import (
    POLICY_PRESETS,
    build_plan,
    diff_plan,
    render_dropin,
)


def test_parse_jail_config_reads_sections(fail2ban_conf_dir):
    sections, includes = parse_jail_config(fail2ban_conf_dir / "jail.conf")
    assert sections["sshd"]["enabled"] == "true"
    assert sections["sshd"]["port"] == "2222"
    assert sections["DEFAULT"]["bantime"] == "600"
    assert includes == []


def test_load_jails_merges_local_over_defaults(fail2ban_conf_dir):
    jails, files, base = load_jails(str(fail2ban_conf_dir))
    by_name = {jail.name: jail for jail in jails}
    assert base == str(fail2ban_conf_dir)
    assert "sshd" in by_name
    sshd = by_name["sshd"]
    assert sshd.enabled is True
    assert sshd.port == "2222"          # from jail.conf (not overridden)
    assert sshd.bantime == 3600         # overridden by jail.local
    assert sshd.maxretry == 3           # overridden by jail.local
    assert "10.0.0.0/8" in sshd.ignoreip


def test_load_jails_includes_jail_d(fail2ban_conf_dir):
    jails, files, _ = load_jails(str(fail2ban_conf_dir))
    assert any(jail.name == "apache-auth" and jail.enabled for jail in jails)
    assert any(path.endswith("apache-auth.local") for path in files)


def test_load_jails_without_configuration(tmp_path):
    jails, files, base = load_jails(str(tmp_path / "nope"))
    assert jails == [] and files == [] and base == ""


def test_default_jails_without_enabled_are_templates(tmp_path):
    base = tmp_path / "f2b"
    base.mkdir()
    (base / "jail.conf").write_text("[DEFAULT]\nbantime = 600\n\n[sshd]\nport = 22\n", encoding="utf-8")
    jails, _, _ = load_jails(str(base))
    assert jails == [], "a jail without enabled= is a template, not an active jail"


def test_validate_reports_missing_ssh_jail():
    status = Fail2banStatus(installed=True, service_state="active")
    _validate(status)
    assert any("SSH jail" in problem for problem in status.problems)


def test_validate_reports_disabled_ssh_jail():
    status = Fail2banStatus(installed=True, service_state="active", jails=[JailInfo(name="sshd", enabled=False)])
    _validate(status)
    assert any("disabled" in problem for problem in status.problems)


def test_validate_reports_failed_service():
    status = Fail2banStatus(installed=True, service_state="failed", jails=[JailInfo(name="sshd", enabled=True, runtime=True)])
    _validate(status)
    assert any("failed state" in problem for problem in status.problems)


def test_validate_warns_when_running_but_silent():
    status = Fail2banStatus(
        installed=True,
        service_state="active",
        jails=[JailInfo(name="sshd", enabled=True, runtime=True, currently_banned=0, total_banned=0, currently_failed=0)],
    )
    _validate(status)
    assert any("no ban/fail events" in warning for warning in status.warnings)


def test_validate_flags_root_requirement():
    status = Fail2banStatus(installed=True, service_state="active", root_required=True)
    _validate(status)
    assert any("root" in warning for warning in status.warnings)


def test_validate_not_installed():
    status = Fail2banStatus(installed=False)
    _validate(status)
    assert status.problems and "not installed" in status.problems[0]


# --- wizard ---------------------------------------------------------------
def test_dropin_content_is_valid_ini_shape():
    content = render_dropin("sshd", "systemd", "22", "/var/log/auth.log", POLICY_PRESETS["balanced"], ["127.0.0.1/8"])
    assert "[sshd]" in content
    assert "enabled  = true" in content
    assert "bantime  = 3600" in content


def test_plan_is_read_only_by_default(fail2ban_conf_dir, tmp_path, monkeypatch):
    status = Fail2banStatus(installed=True, service_state="active", config_dir=str(fail2ban_conf_dir))
    plan = build_plan(status, policy="balanced")
    assert plan.dropin_path.endswith("aureon-sshd.local")
    assert "jail.d" in plan.dropin_path
    # nothing written
    assert not list(fail2ban_conf_dir.rglob("aureon-sshd.local"))
    assert plan.safe_to_apply or plan.blockers


def test_plan_never_overwrites_jail_local(fail2ban_conf_dir):
    status = Fail2banStatus(installed=True, config_dir=str(fail2ban_conf_dir))
    plan = build_plan(status)
    assert Path(plan.dropin_path).name != "jail.local"
    assert Path(plan.dropin_path).name != "jail.conf"


def test_plan_detects_non_default_ssh_port(monkeypatch, tmp_path):
    sshd = tmp_path / "sshd_config"
    sshd.write_text("# comment\nPort 2222\n", encoding="utf-8")
    monkeypatch.setattr("aureon.fail2ban.wizard.detect_ssh_port", lambda: ("2222", str(sshd)))
    status = Fail2banStatus(installed=True, config_dir=str(tmp_path))
    plan = build_plan(status)
    assert plan.ssh_port == "2222"
    assert "port     = 2222" in plan.content


def test_plan_flags_unknown_admin_address(monkeypatch, tmp_path):
    monkeypatch.delenv("SSH_CLIENT", raising=False)
    monkeypatch.delenv("SSH_CONNECTION", raising=False)
    status = Fail2banStatus(installed=True, config_dir=str(tmp_path))
    plan = build_plan(status)
    assert plan.admin_ip is None
    assert any("could not be determined" in warning for warning in plan.warnings)


def test_plan_warns_when_admin_ip_is_known_but_not_added(monkeypatch, tmp_path):
    monkeypatch.setenv("SSH_CLIENT", "203.0.113.5 50000 22")
    status = Fail2banStatus(installed=True, config_dir=str(tmp_path))
    plan = build_plan(status)
    assert plan.admin_ip == "203.0.113.5"
    assert "203.0.113.5" not in plan.ignoreip


def test_plan_flags_broad_ignoreip(monkeypatch, tmp_path):
    monkeypatch.setenv("SSH_CLIENT", "203.0.113.5 50000 22")
    status = Fail2banStatus(installed=True, config_dir=str(tmp_path))
    plan = build_plan(status, ignoreip=["10.0.0.0/8"])
    assert any("never blocked" in warning or "broad" in warning for warning in plan.warnings)


def test_diff_is_shown_for_a_new_dropin(tmp_path):
    status = Fail2banStatus(installed=True, config_dir=str(tmp_path))
    plan = build_plan(status)
    diff = diff_plan(plan)
    assert "aureon-sshd.local" in diff
    assert "+enabled" in diff


@pytest.mark.parametrize("confirmed,allow_writes", [(False, False), (True, False), (False, True), (True, True)])
def test_apply_is_permanently_refused_and_never_writes(tmp_path, confirmed, allow_writes):
    from aureon.fail2ban.wizard import apply_plan

    config_dir = tmp_path / "fail2ban"
    config_dir.mkdir()
    status = Fail2banStatus(installed=True, config_dir=str(config_dir))
    plan = build_plan(status)
    result = apply_plan(plan, confirmed=confirmed, allow_writes=allow_writes)
    assert result.applied is False
    assert any("read-only" in error for error in result.errors)
    assert not list(tmp_path.rglob("aureon-sshd.local"))
    assert not list(tmp_path.rglob("*.bak"))


def test_apply_refuses_when_blocked(tmp_path):
    from aureon.fail2ban.wizard import apply_plan

    status = Fail2banStatus(installed=False, config_dir=str(tmp_path))
    plan = build_plan(status)
    result = apply_plan(plan, confirmed=True, allow_writes=True)
    assert result.applied is False
    assert any("read-only" in error for error in result.errors)


def test_policies_differ():
    values = {name: preset["maxretry"] for name, preset in POLICY_PRESETS.items()}
    assert len(set(values.values())) > 1


# --- real fail2ban-client output shapes --------------------------------------
def test_runtime_jail_names_from_the_real_client_tree():
    """`fail2ban-client status` prints a tree, so the line carries a `|- ` prefix."""
    from aureon.fail2ban.detect import _runtime_jail_names

    output = "Status\n|- Number of jail:\t2\n`- Jail list:\trecidiva, sshd\n"
    assert _runtime_jail_names(output) == ["recidiva", "sshd"]


def test_runtime_jail_names_without_prefix():
    from aureon.fail2ban.detect import _runtime_jail_names

    assert _runtime_jail_names("Jail list:\tsshd\n") == ["sshd"]
    assert _runtime_jail_names("Status\n|- Number of jail:\t0\n") == []


@pytest.mark.parametrize(
    "value,expected",
    [
        ("600", 600),
        ("10m", 600),
        ("1h", 3600),
        ("7d", 604800),
        ("2w", 1209600),
        ("45s", 45),
        ("604800", 604800),
        ("  10m  # comment", 600),
        ("-1", None),          # permanent: not a number of seconds
        ("auto", None),
        ("", None),
        (None, None),
    ],
)
def test_duration_parsing(value, expected):
    from aureon.fail2ban.detect import _as_int

    assert _as_int(value) == expected


def test_jail_duration_values_are_parsed_from_config(fail2ban_conf_dir):
    jails, _, _ = load_jails(str(fail2ban_conf_dir))
    sshd = {jail.name: jail for jail in jails}["sshd"]
    assert sshd.bantime == 3600
    assert sshd.findtime == 600
    assert sshd.maxretry == 3


def test_config_file_with_human_durations(tmp_path):
    base = tmp_path / "f2b"
    base.mkdir()
    (base / "jail.conf").write_text(
        "[DEFAULT]\nbantime = 604800\nfindtime = 10m\nmaxretry = 3\n\n[sshd]\nenabled = true\nport = 22 2244\n",
        encoding="utf-8",
    )
    jails, _, _ = load_jails(str(base))
    sshd = jails[0]
    assert sshd.bantime == 604800
    assert sshd.findtime == 600
    assert sshd.port == "22 2244"


@pytest.mark.parametrize(
    "raw",
    [
        "1.2.3.4\n5.6.7.8\n",
        "['1.2.3.4', '5.6.7.8', '2001:db8::1']",
        "1.2.3.4   since 3 minutes ago\n",
    ],
)
def test_banned_list_output_shapes(raw):
    from aureon.fail2ban.detect import parse_banned_list

    entries = parse_banned_list(raw)
    assert [entry["ip"] for entry in entries][0] == "1.2.3.4"


def test_banned_list_keeps_the_timestamp():
    from aureon.fail2ban.detect import parse_banned_list

    entries = parse_banned_list("1.2.3.4   since 3 minutes ago")
    assert entries[0]["when"].startswith("since")


def test_banned_list_ignores_non_addresses():
    from aureon.fail2ban.detect import parse_banned_list

    entries = parse_banned_list("['Status', 'no jail', '1.2.3.4']")
    assert [entry["ip"] for entry in entries] == ["1.2.3.4"]


def test_banned_list_deduplicates():
    from aureon.fail2ban.detect import parse_banned_list

    assert len(parse_banned_list("1.2.3.4\n1.2.3.4\n")) == 1


def test_empty_banned_list():
    from aureon.fail2ban.detect import parse_banned_list

    assert parse_banned_list("") == []


def test_current_banned_prefers_the_daemon_count():
    from aureon.fail2ban.detect import JailInfo
    from aureon.fail2ban.stats import SecurityStatsService

    status = Fail2banStatus(
        installed=True,
        jails=[JailInfo(name="sshd", enabled=True, runtime=True, currently_banned=488)],
        banned_ips={"sshd": [{"ip": "1.2.3.4", "when": ""}]},
        banned_total=1,
    )
    service = SecurityStatsService(None, __import__("datetime").timezone.utc, status)
    assert service.current_banned() == 488


def test_current_banned_is_unverified_without_live_data():
    from aureon.fail2ban.detect import JailInfo
    from aureon.fail2ban.stats import SecurityStatsService
    from datetime import timezone

    status = Fail2banStatus(installed=True, jails=[JailInfo(name="sshd", enabled=True, runtime=False)])
    assert SecurityStatsService(None, timezone.utc, status).current_banned() is None


# --- wizard: runtime placeholders and multi-port jails ----------------------
def test_unresolved_placeholders_are_detected():
    from aureon.fail2ban.wizard import is_unresolved

    assert is_unresolved("%(sshd_log)s")
    assert is_unresolved("%(sshd_backend)s")
    assert not is_unresolved("/var/log/auth.log")
    assert not is_unresolved("")


def test_dropin_never_contains_a_placeholder():
    from aureon.fail2ban.wizard import POLICY_PRESETS, render_dropin

    content = render_dropin("sshd", "%(sshd_backend)s", "22", "%(sshd_log)s", POLICY_PRESETS["balanced"], [])
    assert "%(" not in content
    assert "backend" not in content
    assert "logpath" not in content
    assert "port     = 22" in content


def test_plan_keeps_a_multi_port_jail(monkeypatch, tmp_path):
    from aureon.fail2ban.wizard import build_plan

    monkeypatch.delenv("SSH_CLIENT", raising=False)
    status = Fail2banStatus(
        installed=True,
        config_dir=str(tmp_path),
        jails=[JailInfo(name="sshd", enabled=True, port="22 2244", logpath=["%(sshd_log)s"], backend="%(sshd_backend)s")],
    )
    plan = build_plan(status)
    assert "port     = 22 2244" in plan.content
    assert "%(sshd_log)s" not in plan.content
    assert any("several ports" in warning for warning in plan.warnings)
    assert any("placeholder" in warning for warning in plan.warnings)
