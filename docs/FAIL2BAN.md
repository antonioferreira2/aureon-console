# The Fail2ban module

Author: António Lourenço Ferreira

This is the module AUREON was built around. It answers one question honestly:
**what protection exists, what did it observe, and how complete is the record?**

## 1. The three kinds of truth

| Kind | Source | What it can and cannot tell you |
|---|---|---|
| **Live state** | `fail2ban-client status <jail>` / `get <jail> banned` (root) | Which IPs are blocked *right now*. Says nothing about when the ban started, nor about bans that already expired. |
| **Configuration** | `jail.conf`, `jail.local`, `jail.d/*`, `systemctl` | What the system declares. A declared jail that is not loaded is *not* protection. |
| **History** | AUREON's own SQLite store, seeded from `fail2ban.log`/journal | What was observed while collection ran. Coverage is always reported explicitly. |

They are never merged into a single "number of banned IPs" without labelling.

## 2. Detection (`fail2ban/detect.py`)

Determined automatically:

- installation (`fail2ban-client` / `fail2ban-server` present, version string);
- service state (`active`, `inactive`, `failed`, `not-found`);
- enablement at boot (`systemctl is-enabled`);
- the effective configuration directory and the files that were read;
- every jail defined in `jail.conf` + `jail.local` + `jail.d/*`, with
  `enabled`, `backend`, `port`, `logpath`, `maxretry`, `findtime`, `bantime`,
  `ignoreip`, `action`, and the file each value came from;
- which jails the running daemon actually loaded;
- per jail: currently banned, total banned since start, currently failed;
- the log source used for history and whether it is readable.

`_validate()` then converts observations into explicit findings:

| Finding | Condition |
|---|---|
| PROBLEM | Fail2ban not installed |
| PROBLEM | service failed |
| PROBLEM | no SSH jail defined |
| PROBLEM | SSH jail disabled in configuration |
| PROBLEM | SSH jail configured but not loaded by the daemon |
| PROBLEM | no readable Fail2ban log source |
| WARN | service inactive / not enabled at boot |
| WARN | jail running but produced zero bans *and* zero fails (usually a wrong log path) |
| WARN | live ban list requires root |
| WARN | running but backend/logpath may be incompatible |

"Jail SSH disabled" is therefore never reported as a healthy system, and a
running service is never reported as working protection without evidence.

## 3. Statistics (`fail2ban/stats.py`, `db/repo.py`)

For each of `24h`, `today`, `week`, `month`, `year`:

| Indicator | Meaning |
|---|---|
| Unique banned IPs | distinct addresses with ≥1 ban in the window |
| Ban events | total bans in the window, **including repeats** |
| IPs with unban events | distinct addresses that were released in the window |
| Currently banned | live value from the daemon; `unverified` when not readable |
| Failed SSH attempts | `auth_failure` events parsed from the auth log; `no data` when the source is missing |
| Recurrent IPs | addresses with ≥2 events in the window |
| Last event | timestamp of the most recent stored event |
| Data coverage | first and last timestamp actually present in the store |
| Warnings | gaps, partial sources, live/history mismatches |

`docs/DATA-ACCURACY.md` defines every boundary precisely.

## 4. Historical collection (`ingest.py`)

- Reads `fail2ban.log` (Ban/Unban/Found) and the auth log (failures only).
- Falls back to `journalctl -o short-iso` for `fail2ban` and `sshd` units when
  no usable log file exists.
- **Cursors**: `(st_dev, st_ino, offset, line)` are stored per file in
  `ingest_sources`.
- **Rotation** (new inode) and **truncation** (shrink, i.e. `copytruncate`) are
  detected and noted in the report; the file is rescanned from the beginning.
- **Idempotent**: every event has a deterministic `dedup_key` with a UNIQUE
  index. Re-running ingestion over the same bytes inserts nothing new.
- **Partial lines** are never consumed until the newline arrives.
- **Crash safety**: the cursor advances only after a successful insert.

Import on a machine that already ran Fail2ban:

```bash
aureon ingest --import-history
```

The output states exactly which file was read, how many events were recovered
and which date range they cover.

## 5. Assisted configuration (`fail2ban/wizard.py`)

```bash
aureon f2b status
aureon f2b plan                     # proposal + steps, nothing written
aureon f2b plan --policy strict --diff
aureon f2b plan --apply --yes       # requires AUREON_ALLOW_F2B_WRITES=1
```

The wizard:

1. detects the distribution and package manager;
2. reads the SSH port from `sshd_config` (last `Port` directive wins, like
   sshd), and says when it fell back to 22;
3. selects the log backend (`auto`, `systemd`) from what the system actually has;
4. reads the current jail values (including `ignoreip`);
5. builds a proposal from a named policy (`conservative`, `balanced`, `strict`)
   or from the existing values;
6. prints a unified diff against the file it would create;
7. lists the exact commands with a risk level each;
8. **stops here** unless `--apply --yes` and `AUREON_ALLOW_F2B_WRITES=1`;
9. on apply: backs up (dated, `/var/backups/aureon`), writes the single drop-in,
   runs `fail2ban-client -t`, and only then reloads the service;
10. prints how to revert (delete the drop-in, restore the backup).

Policies are policy choices, not universal truths - the help text states what
each one trades off. The wizard never adds whole networks or `0.0.0.0/0` to
`ignoreip`, and never adds your own address without you typing it.

## 6. Banned IPs view

- Live list per jail with the ban instant reported by Fail2ban.
- Historical list from the store for the current week, with event counts.
- Sorting/filtering is available in the `aureon stats --top` headless output and
  in the exported CSV.
- **Unban is not implemented in 0.1.0.** The client methods return "disabled".
  If you need it, use `fail2ban-client set <jail> unbanip <ip>` yourself, with
  the same privileges and care.

## 7. Testing

All Fail2ban tests use synthetic logs and synthetic configuration trees under
`tmp_path`; no test touches the real `/etc/fail2ban`, never calls
`fail2ban-client set`, and never bans a real address. See `tests/test_fail2ban.py`,
`tests/test_ingest.py` and `tests/test_stats.py`.
