"""Shared pytest fixtures. All data is synthetic; no real server data is used."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

TZ = timezone(timedelta(hours=1), name="TEST+1")

SAMPLE_FAIL2BAN_LOG = """\
2026-03-05 14:22:31,123 fail2ban.actions [1201]: NOTICE [sshd] Ban 203.0.113.10
2026-03-05 14:22:31,200 fail2ban.actions [1201]: NOTICE [sshd] Ban 203.0.113.11
2026-03-05 14:31:02,001 fail2ban.actions [1201]: NOTICE [sshd] Unban 203.0.113.10
2026-03-06 09:00:00,500 fail2ban.actions [1201]: NOTICE [sshd] Ban 198.51.100.7
2026-03-06 09:00:01,500 fail2ban.actions [1201]: NOTICE [sshd] Ban 198.51.100.7
2026-03-06 09:05:00,000 fail2ban.filter [1200]: INFO [sshd] Found 203.0.113.55
2026-03-07 11:11:11,111 fail2ban.actions [1201]: NOTICE [sshd] Ban 203.0.113.12
"""

# RFC3339 form, as written by rsyslog >= 8 and systemd on modern distributions.
SAMPLE_AUTH_LOG = """\
2026-03-05T14:20:00.001000+01:00 afia01 sshd[900]: Failed password for invalid user admin from 203.0.113.10 port 51234 ssh2
2026-03-05T14:20:05.001000+01:00 afia01 sshd[901]: Failed password for root from 203.0.113.10 port 51235 ssh2
2026-03-05T14:20:09.001000+01:00 afia01 sshd[902]: Invalid user oracle from 203.0.113.10 port 51236 ssh2
2026-03-06T09:01:00.001000+01:00 afia01 CRON[77]: session opened for user root
2026-03-07T08:00:00.000000+01:00 afia01 sshd[903]: Accepted publickey for deploy from 10.0.0.5 port 4000 ssh2
"""

# Classic BSD syslog form, still produced by many rsyslog installations.
SAMPLE_AUTH_LOG_CLASSIC = """\
Mar  5 14:20:00 afia01 sshd[900]: Failed password for invalid user admin from 203.0.113.10 port 51234 ssh2
Mar  5 14:20:05 afia01 sshd[901]: Failed password for root from 203.0.113.10 port 51235 ssh2
"""

SAMPLE_JOURNAL = """\
2026-03-06T09:00:00+0100 afia01 fail2ban.actions[1201]: NOTICE [sshd] Ban 198.51.100.7
2026-03-06T09:00:01+0100 afia01 fail2ban.filter[1200]: INFO [sshd] Found 198.51.100.7
"""

SAMPLE_JAIL_CONF = """\
[DEFAULT]
bantime = 600
findtime = 600
maxretry = 5

[sshd]
port = 2222
enabled = true
logpath = /var/log/auth.log
backend = systemd
"""

SAMPLE_JAIL_LOCAL = """\
[sshd]
bantime = 3600
maxretry = 3
ignoreip = 127.0.0.1/8 10.0.0.0/8
"""


@pytest.fixture
def tzinfo():
    return TZ


@pytest.fixture
def sample_fail2ban_log() -> str:
    return SAMPLE_FAIL2BAN_LOG


@pytest.fixture
def sample_auth_log() -> str:
    return SAMPLE_AUTH_LOG


@pytest.fixture
def sample_auth_log_classic() -> str:
    return SAMPLE_AUTH_LOG_CLASSIC


@pytest.fixture
def fail2ban_conf_dir(tmp_path: Path) -> Path:
    """A synthetic /etc/fail2ban layout."""
    base = tmp_path / "fail2ban"
    base.mkdir()
    (base / "jail.conf").write_text(SAMPLE_JAIL_CONF, encoding="utf-8")
    (base / "jail.local").write_text(SAMPLE_JAIL_LOCAL, encoding="utf-8")
    jail_d = base / "jail.d"
    jail_d.mkdir()
    (jail_d / "apache-auth.local").write_text(
        "[apache-auth]\nenabled = true\nport = http,https\n", encoding="utf-8"
    )
    return base


@pytest.fixture
def repo(tmp_path: Path):
    from aureon.db.repo import Repository

    repository = Repository(tmp_path / "aureon.db")
    repository.open()
    yield repository
    repository.close()


@pytest.fixture
def config(tmp_path: Path):
    from aureon.config import Config

    cfg = Config()
    cfg.state_dir = str(tmp_path / "state")
    cfg.config_dir = str(tmp_path / "config")
    cfg.refresh_seconds = 3600.0   # tests never rely on the auto-refresh timer
    cfg.timezone = "UTC"
    cfg.ensure_dirs()
    return cfg


@pytest.fixture
def base_time():
    return datetime(2026, 3, 7, 12, 0, 0, tzinfo=TZ)
