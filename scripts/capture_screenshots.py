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
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aureon.config import Config  # noqa: E402
from aureon.tui.app import AureonApp  # noqa: E402

PANELS = ["dashboard", "storage", "network", "services", "logs", "security", "banned", "sensors"]


async def capture(output: Path) -> None:
    config = Config()
    config.ensure_dirs()
    app = AureonApp(config)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        await pilot.pause()
        # The app runs on its own thread: everything must be triggered through
        # run_worker/pilot so widgets are created on the app thread.
        for panel in PANELS:
            app.current = panel
            app.action_refresh()
            await asyncio.sleep(2.0)
            await pilot.pause()
            target = output / f"{panel}.svg"
            app.save_screenshot(str(target))
            print(f"wrote {target}")


def main() -> int:
    output = Path(sys.argv[1] if len(sys.argv) > 1 else "docs/screenshots")
    output.mkdir(parents=True, exist_ok=True)
    asyncio.run(capture(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
