"""Configuration and preferences.

Precedence (highest first):
  1. command line flags
  2. environment variables (``AUREON_*``)
  3. user config file (``$XDG_CONFIG_HOME/aureon/config.toml``)
  4. built-in defaults

Nothing here is required to run the console: every value has a safe default and
the config file is optional.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_TIMEOUT = 8.0

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _config_home() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "aureon"


def _data_home() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "aureon"


def _default_state_dir(is_root: Optional[bool] = None, system_dir: Optional[str] = None) -> Path:
    """Writable state directory.

    Root sessions use ``/var/lib/aureon`` (the system-wide install), everyone
    else gets their own XDG data directory. A non-root user must never be
    dropped into a world-readable system path, so the root check is explicit
    instead of relying on a writability test.
    """
    override = os.environ.get("AUREON_STATE_DIR")
    if override:
        return Path(override)
    system = Path(system_dir or "/var/lib/aureon")
    if is_root is None:
        try:
            is_root = os.geteuid() == 0
        except AttributeError:  # pragma: no cover - non-POSIX
            is_root = False
    if is_root and system.is_dir() and os.access(system, os.W_OK):
        return system
    return _data_home()


@dataclass
class Config:
    # Paths
    state_dir: str = field(default_factory=lambda: str(_default_state_dir()))
    config_dir: str = field(default_factory=lambda: str(_config_home()))

    # Behaviour
    timezone: str = ""            # empty = follow server /etc/timezone
    language: str = "en"          # en, pt, es, fr, de, it, nl
    refresh_seconds: float = 3.0
    command_timeout: float = DEFAULT_TIMEOUT
    max_log_lines: int = 500
    theme: str = "aureon-dark"
    show_username: bool = False   # privacy: never render usernames by default
    redact_usernames: bool = True

    # Persistence
    retention_days: int = 180
    auto_ingest_on_start: bool = True
    ingest_max_bytes_per_file: int = 32 * 1024 * 1024

    # Fail2ban
    f2b_enabled: bool = True
    f2b_jail_filter: str = "sshd"

    # Deprecated compatibility flags: operational writes are never allowed.
    allow_service_control: bool = False
    allow_fail2ban_writes: bool = False

    version: int = 1

    # ------------------------------------------------------------------
    @property
    def db_path(self) -> Path:
        return Path(self.state_dir) / "aureon.db"

    @property
    def backup_dir(self) -> Path:
        return Path(self.state_dir) / "backups"

    @property
    def config_file(self) -> Path:
        return Path(self.config_dir) / "config.toml"

    def ensure_dirs(self) -> None:
        for path in (Path(self.state_dir), self.backup_dir, Path(self.config_dir)):
            try:
                path.mkdir(parents=True, exist_ok=True)
                os.chmod(path, 0o700)
            except OSError:
                # Read-only or unprivileged environment: keep going, the UI
                # will report the source as unavailable.
                pass

    # ------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def save(self) -> Path:
        target = self.config_file
        target.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "# AUREON Console configuration",
            "# Author: Antonio Lourenco Ferreira - https://github.com/aureon-console",
            "# Read-only defaults; see docs/CONFIGURATION.md",
        ]
        for key, value in self.to_dict().items():
            if key in ("state_dir", "config_dir"):
                continue
            lines.append(f"{key} = {_toml_value(value)}")
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            os.chmod(target, 0o600)
        except OSError:  # pragma: no cover - platform dependent
            pass
        return target

    def apply_overrides(self, overrides: Dict[str, Any]) -> "Config":
        known = {f.name for f in fields(self)}
        for key, value in overrides.items():
            if key in known and value is not None:
                setattr(self, key, value)
        return self


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return f'"{value}"'  # pragma: no cover - defensive


def _parse_toml_scalar(raw: str) -> Any:
    raw = raw.strip()
    if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
        return raw[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    low = raw.lower()
    if low in _TRUE:
        return True
    if low in _FALSE:
        return False
    try:
        if "." in raw:
            return float(raw)
        return int(raw)
    except ValueError:
        return raw


def load_config(path: Optional[Path] = None) -> Config:
    """Load configuration from file then environment. Never raises."""
    cfg = Config()
    target = Path(path) if path else cfg.config_file
    try:
        raw = target.read_text(encoding="utf-8")
    except OSError:
        raw = ""
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        cfg.apply_overrides({key.strip(): _parse_toml_scalar(value)})

    env_map = {
        "AUREON_STATE_DIR": "state_dir",
        "AUREON_CONFIG_DIR": "config_dir",
        "AUREON_TZ": "timezone",
        "AUREON_LANGUAGE": "language",
        "AUREON_REFRESH": "refresh_seconds",
        "AUREON_TIMEOUT": "command_timeout",
        "AUREON_THEME": "theme",
        "AUREON_RETENTION_DAYS": "retention_days",
        "AUREON_ALLOW_SERVICE_CONTROL": "allow_service_control",
        "AUREON_ALLOW_F2B_WRITES": "allow_fail2ban_writes",
        "AUREON_SHOW_USERNAME": "show_username",
        "AUREON_DB": None,
    }
    for env_key, field_name in env_map.items():
        raw_value = os.environ.get(env_key)
        if raw_value is None or field_name is None:
            continue
        current = getattr(cfg, field_name)
        value: Any = raw_value
        if isinstance(current, bool):
            value = raw_value.lower() in _TRUE
        elif isinstance(current, float):
            try:
                value = float(raw_value)
            except ValueError:
                continue
        elif isinstance(current, int):
            try:
                value = int(raw_value)
            except ValueError:
                continue
        cfg.apply_overrides({field_name: value})

    db_override = os.environ.get("AUREON_DB")
    if db_override:
        cfg.state_dir = str(Path(db_override).parent)
    return cfg
