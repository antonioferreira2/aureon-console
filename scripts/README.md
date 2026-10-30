# Scripts

## capture_screenshots.py

Captures the real Textual UI with a local headless driver and writes SVG files
to the requested directory (default: `assets/screenshots`). Host identity is
anonymized. SVG-to-PNG conversion is deliberately separate so the repository
can publish real raster screenshots without adding a runtime dependency.

```bash
python scripts/capture_screenshots.py [output-dir]
```
