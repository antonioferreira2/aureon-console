# Security

Author: António Lourenço Ferreira

## 1. Threat model

AUREON runs on a server, usually as root over SSH. The assets at risk are:

| Asset | Threat |
|---|---|
| The server itself | A monitoring tool used to change services, firewall, SSH or storage |
| Stored security history | IP addresses and login metadata; personal data under GDPR-style rules |
| Credentials | Any attempt to store or leak secrets |
| The host's supply chain | Installing third-party agents or updating packages automatically |

Explicit non-goals: AUREON is not a SIEM, not an IDS, not a vulnerability
scanner, and performs no network scanning of any kind.

## 2. Controls implemented

### 2.1 Read-only by default

- AUREON never changes firewall rules, Fail2ban jails, SSH settings, accounts, packages, services or kernel state. Its only writes are to its explicitly scoped local configuration, history store, backups and exports.
- The legacy Fail2ban `--apply`/`--yes` CLI flags and write-enable setting are retained only for compatibility and are always refused; no operation can write an audited host configuration file or reload a host service.
- Firewall inspection is a fixed allowlist of query commands only. Hardening assessment checks use fixed query vectors and bounded read-only filesystem metadata; missing, incomplete, or complex evidence remains UNKNOWN/ERROR rather than a pass. No package metadata refresh, package manager, firewall change, service control, or container mutation is performed by assessment. Local evidence does not prove external exposure or compliance.
- Assessment history is written only to AUREON's own SQLite database; requested report exports are private (`0600` where supported). Sensitive file contents are not read during permission checks.
- The TUI test `test_refresh_only_ever_issues_read_only_commands` asserts that no
  mutating token (`start`, `stop`, `restart`, `reload`, `set`, `unban`, `ban`,
  `kill`, `rm`, `mv`, `install`) ever reaches an external command.
- Ban/unban operations are explicitly stubbed out and return "disabled in this
  release".

### 2.2 Command execution

- Every external command is an argument vector executed with `shell=False`
  (`aureon.util.run`). No string interpolation into a shell exists in the code.
- Hard timeout and 4 MiB output cap on every invocation.
- Inputs that reach command arguments are validated first: SMART device names,
  container names, Fail2ban jail names, `systemctl` units.

### 2.3 No remediation mode

AUREON has no host remediation or write-capable helper. `f2b plan` renders
suggestions and a diff only. Legacy write-related config/environment flags and
CLI arguments cannot enable writes and are documented as deprecated.

### 2.4 Lockout avoidance

- The SSH port is detected from `sshd_config`, not assumed to be 22.
- The operator's own address is **detected but never added automatically**.
- Broad `ignoreip` entries are flagged with an explicit warning; `0.0.0.0/0` is
  refused by the rendering path.
- When the client address cannot be determined, the advisory says so instead of guessing.

### 2.5 Data at rest

- Config file `0600`; state directories `0700`; exports `0600`; backups `0600`.
- Usernames are redacted by default (`redact_usernames = true`).
- The database stores only event metadata, not raw log dumps.

### 2.6 No hidden behaviour

- No telemetry, no analytics, no phone-home, no update check.
  `tests/test_security.py::test_no_telemetry_endpoints_in_the_codebase` greps the
  shipped package for HTTP/FTP client usage.
- No listening socket is created (`test_no_network_listeners_are_created`).
- No system package installation, no third-party agent installation.

## 3. Residual risks (documented, not eliminated)

| Risk | Why it remains | Mitigation |
|---|---|---|
| Running as root | Optional elevation adds the live ban list and systemd/Docker details | The installer and the documented default are unprivileged; AUREON reports what it cannot read instead of guessing |
| Local file tampering of the venv | Anything the user can write, the user can run | Install into a root-owned prefix; verify the install path permissions |
| Log content can contain personal data | Inherent to `/var/log` | Redaction by default; retention limit; documented deletion |
| Integrity of read data | AUREON trusts `/proc`, `journalctl` and the config files | A root attacker can already do anything; AUREON is not a trust anchor |
| Denial of service by log volume | Large logs are bounded by caps and timeouts | Tunable `max_log_lines`, `command_timeout` |
| Optional tool behaviour | A compromised `smartctl`/`docker` would be invoked | Optional tools are detected, never installed; the core does not depend on them |

## 4. Reporting a vulnerability

Report privately to the maintainer (António Lourenço Ferreira). Please include
reproduction steps and the AUREON version. Do not open a public issue for a
security problem until a fix exists. See [../SECURITY.md](../SECURITY.md).

## 5. Security self-check before each release

See [`RELEASE-CHECKLIST.md`](RELEASE-CHECKLIST.md).
