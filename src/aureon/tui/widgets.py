"""Reusable Textual widgets and styling helpers."""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence

from rich.table import Table
from rich.text import Text
from textual.containers import Vertical
from textual.widgets import DataTable, Static

from ..models import Health
from ..util import Availability

THEME = "aureon-dark"

HEALTH_STYLE = {
    Health.OK: "bold #4ec9a8",
    Health.WARN: "bold #e5c07b",
    Health.ERROR: "bold #e06c75",
    Health.UNKNOWN: "#9aa4b2",
    Health.UNAVAILABLE: "#6b7280",
}


AUREON_CSS = """
Screen {
    background: #0d1117;
    color: #c9d1d9;
}

#aureon-header {
    dock: top;
    height: 4;
    background: #161b22;
    color: #e6edf3;
    padding: 0 1;
    /* Keep identity, host and health readable at any width. */
    text-align: left;
    content-align: left top;
}

#aureon-layout {
    height: 1fr;
}

#aureon-nav {
    width: 24;
    height: 1fr;
    background: #10151c;
    border-right: solid #30363d;
}

#aureon-main {
    width: 1fr;
    height: 1fr;
    padding: 0 2;
}

#aureon-title {
    height: 1;
}

#aureon-body {
    height: 1fr;
}

#aureon-status {
    dock: bottom;
    height: 1;
    background: #161b22;
    color: #8b949e;
}

.aureon-title {
    text-style: bold;
    color: #58a6ff;
}

.aureon-nav-list > ListItem {
    height: 1;
}

.aureon-panel-title {
    text-style: bold;
    color: #e6edf3;
    padding: 0 0 1 0;
}

.aureon-source {
    color: #6e7681;
    text-style: italic;
}

.aureon-warn { color: #e5c07b; }
.aureon-error { color: #e06c75; }
.aureon-ok { color: #4ec9a8; }
.aureon-dim { color: #6e7681; }
"""


def health_text(health: Health, label: Optional[str] = None) -> Text:
    return Text(f"{health.symbol} {label or health.label}", style=HEALTH_STYLE[health])


def availability_note(state: str, error: Optional[str] = None) -> Text:
    """Render provenance: what a number means, or why there is no number."""
    label = Availability.LABELS.get(state, state)
    style = {
        Availability.OK: "#4ec9a8",
        Availability.EMPTY: "#6e7681",
        Availability.UNAVAILABLE: "#6e7681",
        Availability.DENIED: "#e5c07b",
        Availability.TIMEOUT: "#e5c07b",
        Availability.ERROR: "#e06c75",
    }.get(state, "#6e7681")
    text = Text(f"source: {label}")
    if error:
        text.append(f" ({error})", style="#6e7681")
    return text


def source_text(state: str, source: str = "", error: Optional[str] = None) -> Text:
    """Provenance strip shown under every panel."""
    text = Text()
    if source:
        text.append(str(source), style="#6e7681")
        text.append("  |  ")
    text.append_text(availability_note(state, error))
    return text


class StatTable(Static):
    """Compact key/value table used by the dashboards."""

    def __init__(self, rows: Sequence[Sequence[str]], title: str = "", **kwargs):
        super().__init__(**kwargs)
        self.set_rows(rows, title)

    def set_rows(self, rows: Sequence[Sequence[str]], title: str = "") -> None:
        table = Table(box=None, expand=True, pad_edge=False, padding=(0, 2, 0, 0))
        table.add_column("Metric", style="bold", no_wrap=True)
        table.add_column("Value")
        for row in rows:
            table.add_row(*[_cell(cell) for cell in row])
        self.update(table)


def make_table(columns: Sequence[str], rows: Iterable[Sequence[str]], expand: bool = True) -> Table:
    """Build a table whose cells can never be interpreted as Rich markup.

    Unit names such as ``/sys/fs/cgroup/azure.slice/walinuxagent.service`` and
    raw log lines contain square brackets, which Rich would treat as markup and
    raise ``MarkupError`` on. Wrapping every cell in ``Text`` disables markup
    parsing while keeping colours from ``Text`` cells intact.
    """
    table = Table(box=None, expand=expand, pad_edge=False, padding=(0, 2, 0, 0))
    for column in columns:
        table.add_column(column, no_wrap=False)
    for row in rows:
        table.add_row(*[_cell(cell) for cell in row])
    return table


def _cell(value) -> Text:
    return value if isinstance(value, Text) else Text(str(value))


def empty_state(message: str, hint: str = "") -> Text:
    """A dim message with an optional hint. Returns a *renderable*, not a widget,
    so it can be composed inside tables and groups."""
    text = Text(message, style="#6e7681")
    if hint:
        text.append("\n")
        text.append(hint, style="#e5c07b")
    return text
