# AUREON Console

Read-only terminal console for Linux servers: system monitoring, diagnostics,
logs and **Fail2ban security insights** - all in one SSH session.

Author: **António Lourenço Ferreira** · License: **MIT** · Version: **0.2.0**

> AUREON Console never changes your server. It reads, it reports, it stores its
> own history locally, and it tells you where a number came from.

---

## What it does

| Module | Contents |
|---|---|
| Dashboard | Host, OS, kernel, uptime, CPU, load, memory, swap, health indicators |
| Processes | Top CPU/RAM consumers (never terminates anything) |
| Storage | Filesystems, usage, block devices, LVM, disk inventory |
| Network | Interfaces, addresses, traffic rates, listening sockets, established connections |
| Services | systemd units (and a SysV fallback), failed units, restart counts |
| Logs | `journalctl` with unit / priority / time / text filters, bounded |
| Security (Fail2ban) | Install & service state, jail inventory, ban history by period, IP recurrence |
| Firewall audit | Read-only UFW, nftables, iptables/ip6tables and firewalld query output with per-query availability |
| Hardening assessment | Read-only checks across SSH, accounts/sudo, filesystem metadata, mounts, journald/audit, host protections, Fail2ban, bounded Docker/Podman inspection (including stopped containers), cache-only security-update queries for APT/DNF/zypper, network listeners, kernel settings, time sync, backups and firewall; incomplete evidence remains UNKNOWN |
| Banned IPs | Live list (root) and historical bans from AUREON's own store |
| F2B recommendations | Read-only configuration proposal and diff; AUREON never applies it |
| Containers | Docker/Podman state, restart loops, local images |
| Sensors | Temperatures, fans, NVIDIA GPU telemetry (only what really exists) |
| Tools | Inventory of optional third-party tools, licenses, and how AUREON uses them |

## Requirements

- Linux, Python **3.9+**, a terminal over SSH (80x24 works; wider is better).
- Read access to `/proc`, `/sys`, `/var/log`; optional root for the live
  Fail2ban ban list and `systemd`/Docker details.
- Runtime dependencies: `textual`, `rich` (both MIT). No database server, no web
  server, no network port.

## Install

```bash
git clone <repository-url> aureon-console
cd aureon-console

./install.sh                 # per-user install into ~/.local
sudo ./install.sh            # system-wide (root-owned venv, /var/lib/aureon)

export PATH="$HOME/.local/bin:$PATH"
aureon
```

Recommended for the security module:

```bash
sudo aureon
```

Uninstall (the history database is **kept** unless you ask for it):

```bash
./install.sh --uninstall
./install.sh --uninstall --purge-data    # deletes AUREON data after confirmation
```

Details: [`docs/INSTALLATION.md`](docs/INSTALLATION.md). Language: set `language = "pt"` or `AUREON_LANGUAGE=pt` for Portuguese; supported values are `en`, `pt`, `es`, `fr`, `de`, `it`, `nl`.

Hardening checks, limitations and assessment history: [`docs/HARDENING.md`](docs/HARDENING.md), with six translated editions linked there.

## Screenshots

Real screenshots captured from the running terminal UI. Host identity is
anonymized. Click each image to open it at its full available size.

### Dashboard

[![AUREON Console dashboard — host, resource and health overview](assets/screenshots/dashboard.jpg)](assets/screenshots/dashboard.jpg)

### Firewall audit

[![AUREON Console firewall audit — local query status and evidence](assets/screenshots/firewall.jpg)](assets/screenshots/firewall.jpg)

### Hardening assessment

[![AUREON Console hardening assessment — check outcomes and evidence](assets/screenshots/assessment.jpg)](assets/screenshots/assessment.jpg)

## Headless use

Every feature has a scripting entry point - useful over SSH without a TTY, in
cron, or in CI:

```bash
aureon doctor                       # environment and requirement check
aureon modules --json               # probe every collector, print availability
aureon stats --period today         # security statistics
aureon stats --period month --json  # machine readable
aureon ingest                       # collect events into the local store
aureon ingest --import-history      # import everything still in fail2ban.log
aureon db info | backup | integrity | vacuum | prune
aureon export --output summary.csv
aureon f2b status
aureon f2b plan                     # advisory proposal only; no host writes
aureon f2b plan --diff              # unified diff of the advisory proposal
aureon firewall --json              # local firewall evidence (if query tools are installed)
aureon assess --json                # run and save a full local hardening assessment
aureon assess --format csv --output assessment.csv
aureon assess-history --json         # list saved assessment snapshots
aureon assess-compare 1 2 --json     # compare outcomes by stable check ID
```

## What is stored on your server

| Data | Location | Notes |
|---|---|---|
| Configuration | `~/.config/aureon/config.toml` (0600) | optional |
| History database | `~/.local/share/aureon/aureon.db` or `/var/lib/aureon/aureon.db` | normalised security events only |
| Backups | `<state dir>/backups` | created only by `aureon db backup` |

**No telemetry, no outbound connections, no log uploads.** The historical store
contains event timestamps, IPs, jail names and (optionally, off by default)
usernames. See [`docs/PRIVACY.md`](docs/PRIVACY.md).

## Safety model

- **Read-only with respect to the audited host.** No service restarts, no firewall edits, no SSH
  config changes, no process kills, no automatic updates.
- **Every number shows its source.** "0 events" and "no data collected" are
  never conflated.
- **Audited-host writes are not supported.** The Fail2ban wizard can show a proposal and diff only. Legacy `--apply`, `--yes`, and write-enable configuration are accepted for compatibility but always refused; no file is written and no service is reloaded.
- **Root is never assumed.** Without it, live ban lists are reported as
  unavailable instead of being guessed.

See [`docs/SECURITY.md`](docs/SECURITY.md).

## Data accuracy (read this before trusting a number)

Fail2ban does not keep a durable history of bans. AUREON therefore builds its
own store while the console runs, imports what already exists in
`fail2ban.log`, and states the exact coverage window of the data. Statistics
for a period with no coverage are labelled *unavailable*, never zero. Full
methodology: [`docs/DATA-ACCURACY.md`](docs/DATA-ACCURACY.md).

## Documentation index

| Document | Purpose |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Layers, data flow, extension points |
| [INSTALLATION.md](docs/INSTALLATION.md) | Install, update, uninstall, recovery |
| [CONFIGURATION.md](docs/CONFIGURATION.md) | Every option and environment variable |
| [COMPATIBILITY.md](docs/COMPATIBILITY.md) | Distributions, init systems, terminals |
| [SECURITY.md](docs/SECURITY.md) | Threat model, controls, residual risks |
| [PRIVACY.md](docs/PRIVACY.md) | Data collected, retention, deletion |
| [DEPENDENCIES.md](docs/DEPENDENCIES.md) | Direct/transitive deps and licenses |
| [FAIL2BAN.md](docs/FAIL2BAN.md) | The security module in depth |
| [LOGS-AND-RETENTION.md](docs/LOGS-AND-RETENTION.md) | Log sources, storage, retention |
| [DATA-ACCURACY.md](docs/DATA-ACCURACY.md) | Period definitions and guarantees |
| [HARDENING.md](docs/HARDENING.md) | Assessment checks, scoring, local history and report exports (English) |
| [HARDENING.pt.md](docs/HARDENING.pt.md) | Avaliação de hardening (português) |
| [HARDENING.es.md](docs/HARDENING.es.md) | Evaluación de hardening (español) |
| [HARDENING.fr.md](docs/HARDENING.fr.md) | Évaluation du durcissement (français) |
| [HARDENING.de.md](docs/HARDENING.de.md) | Hardening-Bewertung (Deutsch) |
| [HARDENING.it.md](docs/HARDENING.it.md) | Valutazione hardening (italiano) |
| [HARDENING.nl.md](docs/HARDENING.nl.md) | Hardeningbeoordeling (Nederlands) |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common failures and fixes |
| [VIDEO-REFERENCE.md](docs/VIDEO-REFERENCE.md) | Analysis of the reference video (not accessible) |
| [RELEASE-CHECKLIST.md](docs/RELEASE-CHECKLIST.md) | What must be true before a release |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Contributing

Issues, bug reports and pull requests are welcome - read
[CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
first. Security issues: see [SECURITY.md](SECURITY.md).

## Status

Pre-release (`0.2.0`). The repository remains **private**. No public
release, announcement or mirror has been made.
