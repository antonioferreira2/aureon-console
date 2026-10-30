# Scripts

## capture_screenshots.py

Captures the real Textual UI with a local headless driver and synthetic,
non-host-specific fixtures; no host collectors or system commands are queried.
Writes SVG files to the requested directory (default: `assets/screenshots`).
The repository README keeps raster JPEG exports of the same captures.

```bash
python scripts/capture_screenshots.py [output-dir]
```
