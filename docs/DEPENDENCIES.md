# Dependencies and licenses

Author: António Lourenço Ferreira

## 1. Direct runtime dependencies

| Package | License | Why | Verified version during development |
|---|---|---|---|
| textual | MIT | TUI framework | 8.2.8 |
| rich | MIT | Tables, text rendering (transitive via textual) | 13.x |

## 2. Development dependencies

| Package | License |
|---|---|
| pytest | MIT |
| pytest-asyncio | MIT |

## 3. External tools (optional, never installed by AUREON)

Invoked as separate processes; their code is **not** linked into AUREON, so the
MIT licence of AUREON is unaffected by their GPL terms.

| Tool | License | Integration |
|---|---|---|
| fail2ban-client | GPL-2.0 | native |
| systemctl (systemd) | LGPL-2.1+ | native |
| journalctl (systemd) | LGPL-2.1+ | native |
| docker / podman | Apache-2.0 | native |
| sensors (lm-sensors) | GPL-2.0 | native |
| smartctl (smartmontools) | GPL-2.0 | native (opt-in) |
| nvidia-smi | NVIDIA proprietary terms | native (only if present) |
| lvs (lvm2) | GPL-2.0 | native (read-only) |
| btop, htop, glances, nvtop, ncdu | GPL-2.0/3.0 | detection only |
| fastfetch | MIT | detection only |
| iftop, nload, tree | GPL-2.0 | detection only |
| sysstat (`sar`) | GPL-2.0 | detection only |

## 4. Licence decision

**MIT** was chosen over Apache-2.0 because:

- AUREON links only MIT-licensed libraries, so the patent clause of Apache-2.0
  adds no practical protection here;
- MIT is shorter and easier for small servers and distributions to audit;
- the permissive terms maximise the chance that a busy sysadmin will actually
  run it.

The choice is compatible with every dependency listed above because none of
them is vendored.

## 5. Transitive dependencies

`textual` pulls a small set of MIT-licensed packages (`markdown-it-py`,
`mdurl`, `platformdirs`, `typing-extensions`, `linkify-it-py`, `mdit-py-plugins`).
The exact list for a given install can be inspected with:

```bash
pip show textual | grep -i requires
pip-licenses --from=mixed --summary
```

## 6. Updating dependencies

```bash
pip install --upgrade textual
python -m pytest
```

AUREON pins only a lower bound (`textual>=0.60`) so distribution packages can
ship their own tested version.
