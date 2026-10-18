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


def test_apply_requires_confirmation(tmp_path):
    from aureon.fail2ban.wizard import apply_plan

    status = Fail2banStatus(installed=True, config_dir=str(tmp_path))
    plan = build_plan(status)
    result = apply_plan(plan, confirmed=False, allow_writes=True)
    assert result.applied is False
    assert any("confirmation" in error for error in result.errors)


def test_apply_requires_opt_in_flag(tmp_path):
    from aureon.fail2ban.wizard import apply_plan

    status = Fail2banStatus(installed=True, config_dir=str(tmp_path))
    plan = build_plan(status)
    result = apply_plan(plan, confirmed=True, allow_writes=False)
    assert result.applied is False
    assert any("writes are disabled" in error for error in result.errors)
    assert not list(tmp_path.rglob("aureon-sshd.local"))


def test_apply_refuses_when_blocked(tmp_path):
    from aureon.fail2ban.wizard import apply_plan

    status = Fail2banStatus(installed=False, config_dir=str(tmp_path))
    plan = build_plan(status)
    result = apply_plan(plan, confirmed=True, allow_writes=True)
    assert result.applied is False
    assert result.errors


def test_policies_differ():
    values = {name: preset["maxretry"] for name, preset in POLICY_PRESETS.items()}
    assert len(set(values.values())) > 1
