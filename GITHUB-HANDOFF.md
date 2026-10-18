# GitHub handoff packet - AUREON Console

Prepared for handing the repository over to an assistant (e.g. FreeBuff) that
has authorised GitHub access, to create a **new private project repository**.

Nothing here has been published. The repository exists locally only.

---

## 1. Request (paste this verbatim to the assistant)

```
Create a NEW PRIVATE GitHub repository named exactly:  aureon-console

Owner/account:                 <YOUR_GITHUB_ACCOUNT>
Visibility:                    PRIVATE  (not public, no "public" flag)
Description:                   Read-only TUI console for Linux servers: monitoring,
                               diagnostics, logs and Fail2ban security insights.
                               Open source (MIT). Author: Antonio Lourenco Ferreira.
Default branch:                main
Topics (optional):             linux, tui, monitoring, fail2ban, security,
                               server-administration, terminal, python, mit-license

Source of the code:            local Git repository already prepared at
                               /home/adminpc/OPENCODE_HOME/aureon-console
                               (single commit on branch `main`, clean working tree)
                               OR the bundle file  aureon-console.bundle

Instructions:
 1. Do NOT create any public repository, release, tag, gist or Pages site.
 2. Do NOT change the commit history, rewrite commits or amend the commit.
 3. Do NOT upload secrets, credentials, logs, databases, screenshots or any
    real server data. The repository is already clean; if any file matching
    *.db, *.log, docs/screenshots/ or a credential file appears, stop and report.
 4. Push exactly one branch (main) and nothing else. No tags, no extra branches.
 5. Leave repository settings as: private, no wiki, no issues enabled by default
    is fine either way, branch protection off, actions enabled (the CI workflow
    will run automatically).
 6. Report back the repository URL, the commit SHA and the output of the CI run.
 7. Stop after the push. Do not publish a release, announcement or mirror.

How to push (if the assistant works on this machine):

    cd /home/adminpc/OPENCODE_HOME/aureon-console
    git remote add origin https://github.com/<YOUR_ACCOUNT>/aureon-console.git
    git push -u origin main

Or from the bundle:

    git clone aureon-console.bundle aureon-console
    cd aureon-console
    git remote add origin https://github.com/<YOUR_ACCOUNT>/aureon-console.git
    git push -u origin main
```

## 2. Repository facts

| Item | Value |
|---|---|
| Local path | `/home/adminpc/OPENCODE_HOME/aureon-console` |
| Branch | `main` |
| Commits | 1 (`aure75358...`, see `git log --oneline`) |
| Working tree | clean |
| Bundle (transfer file) | `/home/adminpc/OPENCODE_HOME/aureon-console.bundle` (123 KB, single branch) |
| Files tracked | 69 (source, tests, docs, workflows, installer) |
| Python | >= 3.9 (CI: 3.9, 3.11, 3.12 on Ubuntu 22.04 / 24.04) |
| Dependencies | `textual`, `rich` (both MIT); dev: `pytest`, `pytest-asyncio` |
| Entry point | console script `aureon` (`aureon.cli:main`) |
| Tests | 150 passed, 1 skipped (`python -m pytest`) |
| License | MIT (`LICENSE`, copyright António Lourenço Ferreira, 2026) |
| Version | 0.1.0 (pre-release) |

## 3. What must never be pushed

- `docs/screenshots/*.svg` - real captures of this machine (already git-ignored).
- `*.db`, `*.db-wal`, `*.db-shm`, `*.log` - runtime data (already git-ignored).
- `.devvenv/`, `__pycache__/`, `*.egg-info/`, `.pytest_cache/` (already git-ignored).
- Any credential file (`cred*`, `*_credentials*`, `.env`, `id_*`) - none is in the
  repository; verify with:
  `git ls-files | grep -Ei 'cred|secret|token|\.env$|\.db$|\.log$|^docs/screenshots/'`
  (expected output: empty).

## 4. Project description (for the repository "About" section)

```
AUREON Console
Author: Antonio Lourenco Ferreira   |   License: MIT   |   Version: 0.1.0

A read-only terminal console for Linux servers, reached over SSH. It brings
system monitoring, diagnostics, service and log inspection, and Fail2ban
security intelligence into one interface.

Highlights
- Dashboard, processes, storage, network, systemd services, system logs,
  containers, sensors/GPU and an inventory of optional third-party tools.
- Fail2ban module: installation/service detection, effective jail inventory,
  live banned-IP query, historical ban statistics by period (24h/today/week/
  month/year) and an assisted, reversible, opt-in configuration wizard.
- Honest data: every figure shows its source; "no data collected" is never
  displayed as zero, and Fail2ban history gaps are reported explicitly.
- Read-only by default: no service restarts, no firewall or SSH changes, no
  telemetry, no network listener, no automatic system changes.

Install:  ./install.sh && export PATH="$HOME/.local/bin:$PATH" && aureon
Docs:     docs/ARCHITECTURE.md, docs/FAIL2BAN.md, docs/SECURITY.md,
          docs/DATA-ACCURACY.md
Note:     the referenced reference video could not be accessed; see
          docs/VIDEO-REFERENCE.md
```

## 5. Post-push checklist (for the human author)

1. Confirm the repository shows as **Private** on GitHub.
2. Confirm the Actions run passed (`150 passed, 1 skipped`).
3. Confirm the "About" fields and topics are set.
4. Do not add a release, tag, README badge pointing to a public mirror, or any
   announcement until António Lourenço Ferreira gives explicit approval.

## 6. Open items the assistant should NOT resolve on its own

- Do not enable public visibility "temporarily".
- Do not create GitHub Pages, a website, or a Docker Hub image.
- Do not add a `SECURITY.md` contact other than the author.
- Do not push the screenshots unless the author explicitly asks.
