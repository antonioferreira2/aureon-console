#!/usr/bin/env python
"""Capture real SVG screenshots of the console (Textual headless driver).

Usage:
    python scripts/capture_screenshots.py [output-dir]

The images are produced from the *actual* running application against the
*actual* machine, so they always reflect real behaviour. On a server without a
TUI the generated SVGs show whatever data is really available - including
"unavailable" states, which is exactly what should be documented.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aureon.config import Config  # noqa: E402
from aureon.tui.app import AureonApp  # noqa: E402
from aureon.i18n import navigation  # noqa: E402
from textual.widgets import ListView  # noqa: E402

PANELS = ["dashboard", "firewall", "assessment"]


async def capture(output: Path) -> None:
    from collections import namedtuple

    with tempfile.TemporaryDirectory(prefix="aureon-screenshot-") as temporary:
        config = Config()
        config.state_dir = str(Path(temporary) / "state")
        config.config_dir = str(Path(temporary) / "config")
        config.ensure_dirs()
        original_uname = os.uname
        Uname = namedtuple("Uname", "sysname nodename release version machine")

        def anonymized_uname():
            observed = original_uname()
            return Uname(observed.sysname, "linux-server", observed.release, observed.version, observed.machine)

        # Screenshots are destined for repository documentation: keep the
        # actual application and measurements, but never publish this runner's
        # hostname or its persistent local state.
        os.uname = anonymized_uname
        try:
            app = AureonApp(config)
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                await pilot.pause()
                nav = app.query_one("#aureon-nav", ListView)
                for panel in PANELS:
                    app.current = panel
                    nav.index = next(index for index, (key, _label) in enumerate(navigation(config.language)) if key == panel)
                    await pilot.pause()
                    app.action_refresh()
                    await asyncio.sleep(2.0)
                    await pilot.pause()
                    target = output / f"{panel}.svg"
                    app.save_screenshot(str(target))
                    print(f"wrote {target}")
        finally:
            os.uname = original_uname


def main() -> int:
    output = Path(sys.argv[1] if len(sys.argv) > 1 else "assets/screenshots")
    output.mkdir(parents=True, exist_ok=True)
    asyncio.run(capture(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
