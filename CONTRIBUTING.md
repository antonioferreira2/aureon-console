# Contributing to AUREON Console

Thank you. Author/maintainer: António Lourenço Ferreira. Licensed under MIT.

## Ground rules

1. **Read-only stays read-only.** A pull request that makes the console change
   server state by default will not be merged. New write capabilities must be
   opt-in, validated, reversible and documented in `docs/SECURITY.md`.
2. **Honesty about data.** Never render an estimate as a measurement, and never
   render "no data" as zero. See `docs/DATA-ACCURACY.md`.
3. **No telemetry, ever.**
4. **No proprietary code, branding or UI copies.**

## Workflow

```bash
git clone <repo> && cd aureon-console
python3 -m venv .devvenv && .devvenv/bin/pip install -e ".[dev]"
.devvenv/bin/python -m pytest
```

Before opening a pull request:

- add tests for the new behaviour (normal, missing dependency, failing command,
  timeout);
- update the relevant document in `docs/`;
- update `CHANGELOG.md` under *Unreleased*;
- keep commits focused, with a clear message.

## Adding a collector

```python
class MyCollector(Collector):
    key = "mine"
    title = "Mine"
    source = "my-tool --json"

    def available(self) -> bool:
        return bool(which("my-tool"))

    def collect(self) -> Result:
        return self.run_result(["my-tool", "--json"], parse, self.source)
```

Then register it in `collectors/__init__.py`, add a render function in
`tui/panels.py` and a navigation entry in `tui/app.py`.

## Code style

- Python 3.9 compatible syntax; type hints on public functions.
- Docstrings that explain *why*, not *what*.
- No new mandatory dependencies without discussion; prefer the standard library.
- Run the test suite before pushing.

## Reporting bugs

Include: AUREON version, distribution, whether root, the exact command, and the
output of `aureon doctor`. Security issues go through `SECURITY.md`, not the
public tracker.
