# Changelog

All notable changes to AUREON Console. Format based on
[Keep a Changelog](https://keepachangelog.com/). Licensed under MIT.

Author: António Lourenço Ferreira.

## [Unreleased]

Nothing yet.

## [0.1.0] - 2026-10-18

First working version, prepared for private review.

### Added

- Textual/Rich terminal console with keyboard navigation, integrated help and
  adaptive layout.
- Modules: dashboard, processes, storage, network, systemd services, system logs,
  containers, sensors/GPU, optional-tool inventory.
- Fail2ban module: installation/service/enablement detection, jail inventory
  with effective configuration, live banned-IP query (root), problem and warning
  classification.
- Historical event store (SQLite, WAL, migrations, UNIQUE dedup keys, indexes)
  with cursor-based, rotation-aware, idempotent ingestion from `fail2ban.log`,
  auth logs and `journalctl`.
- Security statistics for 24h/today/week/month/year plus custom ranges, in the
  server's local timezone, with explicit data-coverage reporting.
- `aureon ingest --import-history` to bootstrap history on existing servers.
- Assisted Fail2ban configuration: plan, unified diff, risk-labelled steps,
  validation with `fail2ban-client -t`, dated backups, drop-in-only writes,
  double opt-in gate.
- Headless CLI: `doctor`, `modules`, `stats`, `ingest`, `db`, `export`, `f2b`.
- Idempotent installer with `--force`, `--dev`, `--prefix`, `--uninstall` and
  `--purge-data` (data is never silently deleted).
- Test suite covering periods/timezones/year rollover, parsing, ingestion
  idempotency, rotation, truncation, duplicates, statistics, configuration,
  CLI, security invariants and the TUI.

### Not implemented in 0.1.0

- Ban/unban operations (explicitly disabled)
- Service control (explicitly disabled)
- Continuous background collection daemon (requires explicit approval)
- IPv6 support in some optional collectors

### Notes

- The reference video could not be accessed from the development environment;
  see `docs/VIDEO-REFERENCE.md`.
- No public release has been made.
