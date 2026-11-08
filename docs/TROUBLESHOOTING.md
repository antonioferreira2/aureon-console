# Troubleshooting

Author: António Lourenço Ferreira

Start here:

```bash
aureon doctor
aureon modules
aureon f2b status
```

## Console

| Symptom | Cause | Fix |
|---|---|---|
| `the Textual UI is not available` | `textual`/`rich` missing from the venv | Reinstall: `./install.sh --force`, or `pip install textual rich` |
| Garbled characters over SSH | `TERM` is `dumb` | `export TERM=xterm-256color` |
| Tables cut off | Narrow terminal | Widen the terminal; AUREON truncates rather than wraps |
| UI slow on first refresh | Cold caches, first `journalctl` | Normal; the refresh interval avoids repeating it |
| Blank panels | Module unavailable | `aureon modules` shows the exact state and source |

## Fail2ban

| Symptom | Cause | Fix |
|---|---|---|
| "Fail2ban is not installed" | Package absent | Install it with your package manager (AUREON will not) |
| "live ban list requires root" | Fail2ban socket permissions | Run `sudo aureon` only if you need the live list; every other module works unprivileged |
| SSH jail reported as PROBLEM | disabled or not loaded | `aureon f2b status`, then `fail2ban-client status sshd` |
| Jail running but zero events | wrong `logpath`/`backend` | Compare `jail.local` with `journalctl -u sshd -n 20` |
| Statistics say "no data" | collection has not run | `aureon ingest`, then `aureon ingest --import-history` |
| Counts lower than expected | retention or coverage | `aureon stats --period year` shows the coverage window |
| Legacy `f2b plan --apply` refuses | Expected: audited-host remediation is not supported | Review the generated proposal and apply any change separately under your own change control. |

## Storage and permissions

| Symptom | Cause | Fix |
|---|---|---|
| Database not created | state dir not writable | `AUREON_STATE_DIR=$HOME/.local/share/aureon aureon db info` |
| `permission denied` on logs | running as non-root | Prefer granting read access to a dedicated group; `sudo aureon` is the fallback |
| Docker "access denied" | socket group | Add the user to `docker` (or rootless Podman) and review the security trade-off before running as root |

## Database

| Symptom | Fix |
|---|---|
| `database is locked` | Another AUREON is writing; wait for it to finish |
| `corrupt or unreadable database` | Restore a backup, or `rm` the file and `aureon ingest --import-history` |
| Disk full | `aureon db prune && aureon db vacuum` |

## Statistics

| Symptom | Cause | Fix |
|---|---|---|
| "today" differs from `journalctl --since today` | Different timezone interpretation | `aureon --tz <zone>`, see `docs/DATA-ACCURACY.md` |
| Week starts on Sunday | Not possible by design | AUREON uses ISO weeks (Monday); see the tests |
| A ban counted twice | Genuine repeat ban | Counters distinguish *events* from *unique IPs* |
