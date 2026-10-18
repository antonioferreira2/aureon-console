# Installation and removal

Author: António Lourenço Ferreira

## 1. Requirements check

```bash
aureon doctor
```

Reports Python version, state directory, availability of every collector, and
whether Fail2ban is installed. Nothing is installed or changed by `doctor`.

## 2. Supported environments

See [`COMPATIBILITY.md`](COMPATIBILITY.md). In short: any Linux with Python
3.9+, `systemd`-based or SysV, `journalctl` and/or traditional log files.

## 3. Automated install

```bash
./install.sh                    # per-user: ~/.local/share/aureon/venv, ~/.local/bin/aureon
sudo ./install.sh               # system-wide: /usr/local/share/aureon/venv, /var/lib/aureon
./install.sh --dev              # also install pytest (for development)
./install.sh --prefix /opt/aureon
./install.sh --force            # replace an existing install (old venv is kept as .bak.<timestamp>)
```

Properties:

- **Idempotent.** Re-running without `--force` refuses and tells you what to do.
- **No silent overwrite.** `--force` moves the previous installation aside
  instead of deleting it.
- **No system package installation.** `pip` runs inside a private virtualenv;
  distributions' package managers are never invoked.

## 4. Manual install

```bash
python3 -m venv ~/.local/share/aureon/venv
~/.local/share/aureon/venv/bin/pip install ./aureon-console
ln -s ~/.local/share/aureon/venv/bin/aureon ~/.local/bin/aureon
```

Or, system-wide:

```bash
sudo python3 -m venv /usr/local/share/aureon/venv
sudo /usr/local/share/aureon/venv/bin/pip install ./aureon-console
sudo ln -s /usr/local/share/aureon/venv/bin/aureon /usr/local/bin/aureon
```

## 5. Running

```bash
aureon            # interactive console
sudo aureon       # needed for: live Fail2ban bans, some systemd details, Docker socket
```

Root is **recommended for the security module**, not required to start.

Over SSH:

```
TERM=xterm-256color aureon
```

The interface adapts to the terminal width; below ~70 columns the tables are
truncated rather than broken. See
[`COMPATIBILITY.md`](COMPATIBILITY.md) for terminals with limited colour.

## 6. Updating

```bash
sudo ./install.sh --force
```

The venv is replaced; the state directory (`/var/lib/aureon` or
`~/.local/share/aureon`) is untouched, and the schema migrates automatically on
the next run.

Recommended before an update on a live server:

```bash
aureon db backup --path /var/backups/aureon
```

## 7. Uninstalling

```bash
./install.sh --uninstall            # removes the app, keeps data
./install.sh --uninstall --purge-data   # also deletes the database (asks first)
```

Guarantees:

- **Your history is never silently deleted.** Without `--purge-data`, the
  database and backups remain and are reported in the output.
- **Other services' dependencies are untouched.** AUREON installs nothing
  outside its own virtualenv, so there is nothing to unwind.
- After removing a drop-in written by the wizard (`jail.d/aureon-sshd.local`),
  run `fail2ban-client -t && systemctl reload fail2ban`.

## 8. Recovery

| Situation | Action |
|---|---|
| Install interrupted | Re-run `./install.sh --force` |
| Console will not start | `aureon doctor`; run with `AUREON_STATE_DIR=/tmp/aureon-test aureon doctor` |
| Database corrupt | `aureon db integrity`; restore with `aureon db backup` output or re-import: `aureon ingest --import-history` |
| Suspected partial ingest | `aureon ingest` is idempotent: just run it again |
| Wrong timezone | `aureon --tz Europe/Lisbon` or set `timezone` in the config |

## 9. What the installer never does

- No port is opened; no HTTP or web component is installed.
- No system package is installed, upgraded or removed.
- No `systemd` unit, timer or cron job is created.
- No file outside the prefix, the state directory and the user's config is
  written.
