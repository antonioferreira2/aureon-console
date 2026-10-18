# Scripts

## capture_screenshots.py

Renders the real application headlessly and writes SVG screenshots to
`docs/screenshots/`. The captures contain this machine's hostname and real
metrics, so the directory is **git-ignored** by design; regenerate it locally
whenever documentation needs an image.

```bash
python scripts/capture_screenshots.py [output-dir]
```
