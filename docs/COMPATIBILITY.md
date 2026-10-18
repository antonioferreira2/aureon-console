# Compatibility

Author: António Lourenço Ferreira

## Tested during development (0.1.0)

| Environment | Result |
|---|---|
| Ubuntu 24.04 LTS, Python 3.12, systemd, journald | Fully exercised by the development test-suite and manual runs |
| Any Linux with Python 3.9+ | Expected to work; see the degradation rules below |

CI additionally runs the suite on Ubuntu 22.04 and 24.04 with Python 3.9-3.12.

## Distributions

| Family | Expected behaviour |
|---|---|
| Debian / Ubuntu | `apt`; `/var/log/auth.log`; systemd |
| RHEL / Rocky / AlmaLinux / Fedora | `dnf`; `/var/log/secure`; systemd |
| Arch | `pacman`; systemd |
| openSUSE | `zypper`; systemd |
| Alpine | `apk`; OpenRC (SysV fallback); BusyBox `df`/`free` are not used - AUREON reads `/proc` directly |

AUREON reads `/proc` and `/sys` directly, so it does not depend on GNU coreutils
being present.

## Init systems

- **systemd**: full data via `systemctl list-units`; a fallback parser is used
  when the installed systemd is too old for `--output=` properties.
- **SysV**: limited service information (`service --status-all`). Units are
  reported with fewer fields and this is stated in the UI.

## Log sources

| Source | Used when |
|---|---|
| `journalctl` | present (preferred) |
| `/var/log/auth.log`, `/var/log/secure`, `/var/log/messages`, `/var/log/syslog` | journalctl absent |
| `fail2ban.log` | present (historical bans/unbans) |

Both timestamp conventions are supported: classic `Mmm dd HH:MM:SS` syslog and
RFC3339 (`2026-03-05T14:20:00.001000+01:00`).

## Terminals

| Terminal | Notes |
|---|---|
| Any with true colour (`xterm-256color`, `alacritty`, `kitty`, `wezterm`, Windows Terminal, iTerm2, GNOME Terminal) | Reference experience |
| 80x24 | Supported; tables truncate gracefully |
| < 70 columns | Usable but cramped |
| `dumb`, no colour | Degraded palette; still readable |
| tmux/screen | Supported; use `TERM=screen-256color` or `tmux-256color` |

Colour is never the only signal: every status also carries a symbol
(`● OK`, `▲ WARN`, `✖ ERROR`, `○ UNVERIFIED`, `– N/A`).

## Python

3.9 or newer (3.9/3.10/3.11/3.12 exercised). Standard library only outside of
`textual` and `rich`.

## Not supported

- Non-Linux (macOS/BSD): the collectors depend on `/proc` and systemd.
- Containers where `/proc` is masked: modules report *unavailable*.
- `busybox`-only init without `/proc/net/dev` content: network module degrades.
