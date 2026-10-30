# Release checklist

Author: António Lourenço Ferreira

Nothing is published without an explicit approval from António Lourenço Ferreira.

## 1. Code

- [ ] `python -m pytest` green (unit + integration + TUI)
- [ ] `aureon doctor`, `aureon modules` reviewed on a clean machine
- [ ] no new dependency without a license check
- [ ] every collector has: availability probe, timeout, error handling, source label, tests

## 2. Security

- [ ] read-only default confirmed (`test_refresh_only_ever_issues_read_only_commands`)
- [ ] Fail2ban apply attempts are always refused, even with legacy opt-ins
- [ ] firewall audit executes only static read-only queries
- [ ] UNKNOWN/ERROR applicable assessment checks never increase the score
- [ ] no listening sockets, no telemetry (tests)
- [ ] `docs/SECURITY.md` updated with any new capability
- [ ] dependency advisory review

## 3. Data accuracy

- [ ] period boundaries still match `docs/DATA-ACCURACY.md`
- [ ] zero is still distinguishable from "no data"
- [ ] coverage reporting unchanged for new event kinds

## 4. Documentation

- [ ] `README.md` reflects real behaviour
- [ ] install/uninstall verified on a clean system
- [ ] changelog updated
- [ ] screenshots taken from a real run (no mockups)

## 5. Repository and publication

- [ ] no real host data, IPs of clients, logs or credentials in history
- [ ] `git log` reviewed before the first push
- [ ] private repository created first
- [ ] **explicit written approval from the author before any public release**
