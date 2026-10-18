# Security policy

Author: António Lourenço Ferreira

## Reporting a vulnerability

Report privately to the maintainer. Include the version, reproduction steps and
the impact. Do not open a public issue or a public pull request before a fix
exists.

## What AUREON will never do

- Open a network port or install a web interface
- Telemetry, analytics or remote logging
- Automatic system updates or third-party agent installation
- Firewall, SSH configuration or service changes without explicit opt-in
- Store credentials

The full threat model, the implemented controls and the residual risks are in
[`docs/SECURITY.md`](docs/SECURITY.md).

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| < 0.1 | No |

## Disclosure

Fixes are documented in `CHANGELOG.md`. The maintainer will credit reporters
unless anonymity is requested.
