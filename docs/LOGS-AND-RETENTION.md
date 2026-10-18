# Logs, storage and retention

Author: António Lourenço Ferreira

## 1. Log sources and priority

| Module | Primary | Fallback |
|---|---|---|
| System logs | `journalctl` | `/var/log/syslog`, `/var/log/messages`, `/var/log/auth.log` |
| Fail2ban history | `/var/log/fail2ban.log` | `journalctl -u fail2ban` |
| SSH failures | auth log | `journalctl -u sshd` |

Timestamp formats understood: classic syslog (`Mar  5 14:22:31`) and RFC3339
(`2026-03-05T14:20:00.001000+01:00`).

## 2. Volume limits

| Control | Value |
|---|---|
| `max_log_lines` | 500 lines per query (configurable) |
| `command_timeout` | 8 s per command (configurable) |
| journal ingestion per run | `--lines 20000` per unit |
| file ingestion per run | `ingest_max_bytes_per_file` (32 MiB) |
| TUI log view | last 200 lines rendered |

When a limit truncates results the UI says so; a truncated view is never
presented as complete.

## 3. Stored schema

```sql
security_events(id, occurred_at, occurred_ts, kind, jail, ip, username,
                source, source_id, dedup_key UNIQUE, host_id,
                ingested_at, collection_state, meta)
ingest_sources(source_key PK, path, inode, device, size, offset, line,
               last_event_ts, last_scan, state, note)
collection_runs(id, started_at, finished_at, source, events_seen,
                events_added, duplicates, state, note)
```

Indexes: `occurred_ts`, `ip`, `jail`, `(kind, occurred_ts)`, `(ip, kind, occurred_ts)`.
Period queries are always bounded by an epoch range, so they never scan the
whole table.

## 4. Retention and space

- Default retention: **180 days** (`retention_days`).
- Apply it manually:
  ```bash
  aureon db prune      # delete older rows
  aureon db vacuum    # return space to the filesystem
  ```
- Typical size: ~200 bytes/event; 10 000 events ≈ 2 MB.
- Set up a periodic maintenance command if you want it automatic:
  ```bash
  # example crontab line - run it yourself, AUREON installs nothing
  30 4 * * * aureon db prune && aureon db vacuum
  ```

## 5. Continuous collection (requires your approval)

0.1.0 installs no service. If you want continuous collection, the honest
options are:

| Option | Effect | Trade-off |
|---|---|---|
| Run `aureon ingest` periodically (cron / systemd timer, created by you) | Events collected every N minutes | You own the timer |
| Start the console regularly (many admins already do) | Collection only while open | No guarantee |
| Install a dedicated AUREON collector service | Continuous | **Not implemented in 0.1.0** - request it and it can be added, reviewed and versioned |

AUREON will not install a systemd unit or cron job on its own.

## 6. Rotation and truncation

Per-file cursors detect:

- **rotation** - inode changes (logrotate rename/create);
- **truncation** - file smaller than the stored offset (`copytruncate`);
- **replacement** - both at once.

On any of these the file is rescanned from byte 0 and the report contains a
`rescanning` note. Events re-read from an already-ingested region are discarded
by the dedup index, so re-scans are safe.

## 7. Backups

```bash
aureon db backup                       # <state dir>/backups/aureon-backup.db
aureon db backup --path /var/backups/aureon
aureon db integrity                    # PRAGMA integrity_check
```

Backups use SQLite's online backup API, so they are consistent even while the
console is running, and are created with mode `0600`.

## 8. Corruption and recovery

| Situation | Recovery |
|---|---|
| `integrity_check` reports problems | Restore the most recent backup with `cp backup.db <state dir>/aureon.db`, then `aureon db integrity` |
| Database file unusable and no backup | `aureon ingest --import-history` rebuilds from `fail2ban.log` |
| Wrong timezone in existing data | Timestamps are stored as reported by the source; re-import after fixing the config if needed |
