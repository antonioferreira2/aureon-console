# Hardening assessment

Translated guides: [Português europeu](HARDENING.pt.md) · [Español](HARDENING.es.md) · [Français](HARDENING.fr.md) · [Italiano](HARDENING.it.md) · [简体中文](HARDENING.zh_CN.md) · [Русский](HARDENING.ru.md).

AUREON assessments are local, read-only observations—not a certification, penetration test, or proof of external exposure. The application does not apply recommendations or change audited-host operational state. Only its own history database and explicitly requested report files are written.

## Current checks

The check catalogue covers effective SSH settings and representative `Match` contexts; local firewall evidence; UID 0, sudo-path permissions and default password aging; metadata-only checks of sensitive account/SSH host-key files; `/tmp` mount options; explicit journald storage, audit subsystem and log rotation; SELinux/AppArmor and selected kernel sysctls; Fail2ban jail inventory; bounded Docker/Podman inspection of running and stopped containers; reboot markers and cache-only security-update queries for supported APT, DNF and zypper distributions; local wildcard listeners; time synchronization; and limited backup evidence.

Every check has a stable ID, domain, expected state, severity/weight, data sources, reason/evidence, limitations, recommendation, and verification guidance. Outcomes are `PASS`, `FAIL`, `UNKNOWN`, `NOT_APPLICABLE`, or `ERROR`. Missing/unreadable data is never considered secure. Several important controls—security-update availability, effective firewall policy, backup freshness/recoverability, and SSH Match-specific behavior—remain unknown unless authoritative evidence is locally available. A score is withheld whenever any applicable non-informational check is unknown or errored; this is intentionally strict.

Thresholds such as `MaxAuthTries <= 6` and `/tmp` mount flags are heuristics, not universal policy. Review evidence and operational requirements before making independent changes. Checks do not inspect private-key contents, refresh package metadata, install packages, reload services, or elevate privileges. Update queries use existing local indexes only: APT `apt list --upgradable` plus `apt-cache policy`, DNF `repoquery --cacheonly --security`, and zypper `--no-refresh patch-check`; index age is a 14-day heuristic. Alpine `apk` can simulate general upgrades offline but does not identify security advisories, so its result remains `UNKNOWN`. Container inspection is bounded to 100 combined running and stopped containers across detected Docker/Podman runtimes and accepts only hexadecimal IDs. Firewall parsing classifies only narrow complete subsets; complex nftables rules, ordered iptables verdicts, SSH wildcard/group/overlapping `Match` coverage, and backup recoverability remain `UNKNOWN` unless proven by collected evidence.

## Commands and history

```bash
aureon assess --json
aureon assess --output assessment.json
aureon assess --format csv --output assessment.csv
aureon assess-history --json
aureon assess-compare 1 2 --json
```

Each CLI `aureon assess` invocation stores a snapshot in AUREON's SQLite history database; opening or refreshing the TUI assessment panel does not create history records. `assess-history` lists snapshots. Comparison uses stable check IDs and reports changes; missing checks or unavailable scores are not interpreted as improvement. Report exports include check definitions, outcome, evidence, limitations, remediation and verification guidance and are created with mode `0600` where supported.

The database migration to schema version 2 adds the `assessments` table and preserves existing event history; the current check-definition version is 6. Back up the local database before upgrades as normal; no audited-host data is modified.

## Language

The terminal navigation, panel chrome and assessment labels support English (`en`), European Portuguese (`pt_PT`, with `pt` accepted as an alias), Spanish (`es`), French (`fr`), Italian (`it`), Simplified Chinese (`zh_CN`) and Russian (`ru`). Set `language` in `config.toml` or `AUREON_LANGUAGE`; unsupported values safely fall back to English. Check evidence and host-provided strings remain in their source language to preserve accuracy. Translation coverage of all fixed labels in the panels and main app is asserted by the test suite. The hardening guide is translated into the six non-English locales; the rest of the project documentation remains canonical in English.
