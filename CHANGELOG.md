# Changelog

## [Unreleased]

## [0.2.0] - 2026-10-29

### Added

- Expanded the read-only assessment to 25 checks across SSH, accounts/sudo, sensitive-file metadata, filesystems, journald/audit, SELinux/AppArmor, Fail2ban, running and stopped Docker/Podman containers, cache-only security-update queries for APT/DNF/zypper, sockets, kernel settings, time sync, backups and firewall evidence; incomplete interpretation remains UNKNOWN (definition v6).
- Added local assessment snapshots, history, stable-ID comparisons and complete private JSON/CSV exports.
- Added seven-language UI catalogue (`en`, `pt`, `es`, `fr`, `de`, `it`, `nl`) with English fallback, translated help/proposal panels, and translated hardening guides.
- Added a repeatable `pip-audit` CI check; no scanner dependency is required at runtime.

All notable changes to AUREON Console. Format based on
[Keep a Changelog](https://keepachangelog.com/). Licensed under MIT.

Author: António Lourenço Ferreira.

### Changed

- Improved SSH Match sampling to report only effective `sshd -T -C` behavior as a confirmed result; raw directives do not create false positives where OpenSSH precedence overrides them.
- Restricted the test suite's locale assertion to identify untranslated UI copy without rejecting short words legitimately shared across languages.
- Corrected conservative iptables rule parsing and clarified that complex ordered rules remain UNKNOWN.
- Removed Fail2ban apply, config-write, validation-after-write, rollback and service-reload behavior. Legacy apply flags now always refuse, preserving CLI compatibility while enforcing read-only behavior.
- Updated security documentation to describe the actual no-remediation boundary and assessment limitations.

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
