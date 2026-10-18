"""Configuration, CLI, export and security-service tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aureon.cli import build_parser, main
from aureon.config import Config, load_config


# --- configuration --------------------------------------------------------
def test_config_defaults_are_safe():
    cfg = Config()
    assert cfg.redact_usernames is True
    assert cfg.allow_service_control is False
    assert cfg.allow_fail2ban_writes is False


def test_config_roundtrip(tmp_path, monkeypatch):
    monkeypatch.delenv("AUREON_REFRESH", raising=False)
    cfg = Config()
    cfg.config_dir = str(tmp_path)
    cfg.refresh_seconds = 7.5
    cfg.retention_days = 30
    cfg.save()
    loaded = load_config(Path(tmp_path) / "config.toml")
    assert loaded.refresh_seconds == 7.5
    assert loaded.retention_days == 30


def test_config_file_is_private(tmp_path):
    cfg = Config()
    cfg.config_dir = str(tmp_path)
    path = cfg.save()
    assert path.stat().st_mode & 0o077 == 0, "config must not be world readable"


def test_environment_overrides_file(tmp_path, monkeypatch):
    monkeypatch.setenv("AUREON_REFRESH", "12")
    monkeypatch.setenv("AUREON_ALLOW_F2B_WRITES", "true")
    cfg = load_config(tmp_path / "config.toml")
    assert cfg.refresh_seconds == 12
    assert cfg.allow_fail2ban_writes is True


def test_invalid_environment_values_are_ignored(tmp_path, monkeypatch):
    monkeypatch.setenv("AUREON_REFRESH", "not-a-number")
    cfg = load_config(tmp_path / "config.toml")
    assert cfg.refresh_seconds != "not-a-number"


def test_ensure_dirs_creates_private_directories(tmp_path):
    cfg = Config()
    cfg.state_dir = str(tmp_path / "state")
    cfg.config_dir = str(tmp_path / "config")
    cfg.ensure_dirs()
    assert Path(cfg.state_dir).is_dir()
    assert (Path(cfg.state_dir).stat().st_mode & 0o077) == 0


def test_missing_config_file_is_not_an_error(tmp_path):
    assert load_config(tmp_path / "does-not-exist.toml").refresh_seconds > 0


# --- CLI ------------------------------------------------------------------
def test_parser_has_read_only_defaults():
    parser = build_parser()
    args = parser.parse_args([])
    assert args.command is None


def test_doctor_runs(config, monkeypatch, capsys):
    monkeypatch.setattr("aureon.cli.load_config", lambda path=None: config)
    assert main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "collectors" in out


def test_modules_command(config, monkeypatch, capsys):
    monkeypatch.setattr("aureon.cli.load_config", lambda path=None: config)
    assert main(["modules", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert "system" in payload
    assert "state" in payload["system"]


def test_stats_command_reports_unavailable_without_data(config, monkeypatch, capsys):
    monkeypatch.setattr("aureon.cli.load_config", lambda path=None: config)
    assert main(["stats", "--period", "today", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["data_available"] is False
    assert payload["warnings"], "no-data periods must be explained"


def test_stats_custom_range_requires_iso_dates(config, monkeypatch, capsys):
    monkeypatch.setattr("aureon.cli.load_config", lambda path=None: config)
    assert main(["stats", "--period", "custom", "--from", "not-a-date"]) == 2


def test_db_info_command(config, monkeypatch, capsys):
    monkeypatch.setattr("aureon.cli.load_config", lambda path=None: config)
    assert main(["db", "info"]) == 0
    assert "database" in capsys.readouterr().out


def test_db_backup_and_integrity(config, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("aureon.cli.load_config", lambda path=None: config)
    assert main(["ingest"]) in (0, 1)
    assert main(["db", "integrity"]) == 0
    assert main(["db", "backup", "--path", str(tmp_path / "backups")]) == 0
    assert (tmp_path / "backups" / "aureon-backup.db").exists()


def test_export_command(config, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("aureon.cli.load_config", lambda path=None: config)
    target = tmp_path / "summary.csv"
    assert main(["export", "--output", str(target)]) == 0
    assert target.exists()
    assert "period" in target.read_text()


def test_f2b_status_command_never_writes(config, monkeypatch, capsys):
    monkeypatch.setattr("aureon.cli.load_config", lambda path=None: config)
    assert main(["f2b", "status"]) in (0, 1)
    assert "installed" in capsys.readouterr().out


def test_f2b_plan_does_not_write(config, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr("aureon.cli.load_config", lambda path=None: config)
    monkeypatch.setenv("AUREON_STATE_DIR", str(tmp_path))
    assert main(["f2b", "plan"]) == 0
    out = capsys.readouterr().out
    assert "Nothing was changed" in out


def test_f2b_plan_apply_requires_opt_in(config, monkeypatch, capsys):
    monkeypatch.setattr("aureon.cli.load_config", lambda path=None: config)
    config.allow_fail2ban_writes = False
    assert main(["f2b", "plan", "--apply", "--yes"]) == 1
    assert "refused" in capsys.readouterr().out


# --- export ---------------------------------------------------------------
def test_export_json_is_private(tmp_path, repo):
    from aureon.export import export_json
    from aureon.models import PeriodStats
    from datetime import datetime, timezone

    stats = PeriodStats("today", datetime.now(timezone.utc), datetime.now(timezone.utc), "UTC")
    path = export_json(stats, tmp_path / "out.json")
    assert path.exists()
    assert path.stat().st_mode & 0o077 == 0


def test_export_period_summary(repo, tmp_path):
    from aureon.export import export_period_summary

    path = export_period_summary(repo, path=tmp_path / "summary.csv")
    lines = path.read_text().splitlines()
    assert lines[0].startswith("period,")
    assert len(lines) == 6  # header + five periods
