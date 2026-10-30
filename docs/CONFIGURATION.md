# Configuration

Author: António Lourenço Ferreira

AUREON runs with no configuration at all. Everything below is optional.

## 1. Precedence

1. Command line flags (`--tz`, `--refresh`, `--state-dir`, `--config`)
2. Environment variables (`AUREON_*`)
3. Config file (`$XDG_CONFIG_HOME/aureon/config.toml`)
4. Built-in defaults

## 2. Config file

```bash
mkdir -p ~/.config/aureon
$EDITOR ~/.config/aureon/config.toml
```

| Key | Default | Meaning |
|---|---|---|
| `timezone` | `""` | Empty = follow the server (`/etc/timezone`, then `/etc/localtime`). Set e.g. `Europe/Lisbon`. |
| `language` | `en` | Terminal navigation and assessment labels: `en`, `pt`, `es`, `fr`, `de`, `it`, `nl`; other values fall back to English. |
| `refresh_seconds` | `3.0` | Auto-refresh interval of the console. |
| `command_timeout` | `8.0` | Hard timeout for every external command. |
| `max_log_lines` | `500` | Upper bound for any log query. |
| `theme` | `aureon-dark` | Interface theme. |
| `redact_usernames` | `true` | Usernames are shown as `<redacted>` in the process list. |
| `show_username` | `false` | Reserved for future use; keep `false` unless you understand the privacy impact. |
| `retention_days` | `180` | Events older than this are removed by `aureon db prune`. |
| `auto_ingest_on_start` | `true` | Reserved for the optional collector service; unused in 0.1.0. |
| `ingest_max_bytes_per_file` | `33554432` | Maximum bytes read from a log file per ingestion run. |
| `f2b_enabled` | `true` | Enables the Fail2ban module. |
| `f2b_jail_filter` | `sshd` | Jail name treated as the SSH jail when auto-detecting. |
| `allow_service_control` | `false` | **Read-only build:** service control is not implemented; the flag exists so an operator can verify it stays off. |
| `allow_fail2ban_writes` | `false` | Deprecated compatibility key. AUREON always refuses audited-host writes, regardless of this value. |

The file is created with mode `0600`.

## 3. Environment variables

| Variable | Effect |
|---|---|
| `AUREON_STATE_DIR` | Where the database and backups live |
| `AUREON_DB` | Full path to the SQLite file (overrides `state_dir`) |
| `AUREON_CONFIG_DIR` | Config directory |
| `AUREON_TZ` | Timezone name |
| `AUREON_LANGUAGE` | UI language (`en`, `pt`, `es`, `fr`, `de`, `it`, `nl`) |
| `AUREON_REFRESH` | Refresh interval |
| `AUREON_TIMEOUT` | Command timeout |
| `AUREON_THEME` | Theme name |
| `AUREON_RETENTION_DAYS` | Retention window |
| `AUREON_ALLOW_SERVICE_CONTROL` | Keep `false` |
| `AUREON_ALLOW_F2B_WRITES` | Deprecated compatibility variable; cannot enable host writes. |
| `AUREON_SHOW_USERNAME` | Privacy opt-in; defaults to redacting |

## 4. State directory resolution

1. `AUREON_STATE_DIR` if set
2. `/var/lib/aureon` if it exists and is writable (root sessions)
3. `$XDG_DATA_HOME/aureon` or `~/.local/share/aureon`

Directories are created with mode `0700`.

## 5. Writing the config

There is no `aureon config set` command in 0.1.0: edit the TOML file, or set
environment variables in the shell profile. Both are auditable in a way an
interactive prompt is not.
