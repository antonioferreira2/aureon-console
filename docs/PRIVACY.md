# Privacy

Author: António Lourenço Ferreira

## 1. Principles

- **Privacy by design.** AUREON collects the minimum needed to answer
  "what happened on this server".
- **No telemetry.** Nothing is sent anywhere. AUREON has no network client.
- **Local only.** All data stays in the state directory of the machine it runs on.

## 2. Data processed

| Category | Examples | Personal data? |
|---|---|---|
| System metrics | CPU, memory, disks, uptime, interfaces | No |
| Service inventory | Unit names, states | No |
| Log lines shown on request | Whatever the operator filters | Potentially |
| Security events stored | Event time, IP, jail, event kind, optional username | Yes (IP address and username are personal data under GDPR) |
| Configuration | Preferences, timezone | No |

## 3. Data stored on disk

Only one file is written by normal operation:

```
<state dir>/aureon.db      SQLite: normalised security events
<state dir>/backups/       only when `aureon db backup` is run
<config dir>/config.toml   preferences (0600)
```

The database stores: `occurred_at`, `kind` (ban/unban/fail/auth_failure),
`jail`, `ip`, `username` (empty when redaction is on), `source`, and a short
technical metadata blob. It does **not** store raw log lines.

## 4. Retention

- Default: 180 days (`retention_days`).
- Applied by `aureon db prune`, which deletes older rows and frees space with
  `VACUUM` (`aureon db vacuum`).
- Uninstalling without `--purge-data` keeps the data. Removing it requires an
  explicit flag and a confirmation prompt.

## 5. Usernames

`redact_usernames = true` by default: process owners are displayed as
`<redacted>`. Failed SSH logins do store the attempted username because it is
operationally relevant for intrusion triage; set `show_username = false`
(default) to keep the console from rendering it.

## 6. Sharing reports

`aureon export` writes CSV with `0600` permissions and, by default, contains
aggregate counters only. Any IP-level export should be treated as personal data
and shared only where it is lawful to do so.

## 7. Third parties

None. Optional tools (docker, smartctl, sensors...) run locally, are never
installed automatically, and never receive data from AUREON.
