"""Shared primitives: safe command execution, formatting and result envelopes.

Design rules enforced here (see docs/SECURITY.md):
  * No shell interpolation. Every external command is executed as an argument
    vector, never through a shell, so user supplied values can never be
    interpreted as shell syntax.
  * Every external call has a hard timeout and an output size cap.
  * Every result carries its provenance (``source``) and its availability state
    so the UI can tell "0 events" apart from "data unavailable".
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

DEFAULT_TIMEOUT = 8.0
MAX_OUTPUT_BYTES = 4 * 1024 * 1024


class Availability:
    """Availability state of a data source."""

    OK = "ok"
    EMPTY = "empty"
    UNAVAILABLE = "unavailable"
    DENIED = "denied"
    TIMEOUT = "timeout"
    ERROR = "error"

    LABELS = {
        OK: "OK",
        EMPTY: "no data",
        UNAVAILABLE: "unavailable",
        DENIED: "permission denied",
        TIMEOUT: "timeout",
        ERROR: "error",
    }


@dataclass
class CommandResult:
    argv: Sequence[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def lines(self) -> List[str]:
        return [ln for ln in self.stdout.splitlines() if ln.strip()]


def run(
    argv: Sequence[str],
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = MAX_OUTPUT_BYTES,
    env: Optional[Dict[str, str]] = None,
) -> CommandResult:
    """Run *argv* without a shell, enforcing a timeout and an output cap."""
    argv = [str(a) for a in argv]
    started = time.monotonic()
    full_env = None
    if env is not None:
        full_env = dict(os.environ)
        full_env.update(env)
    try:
        proc = subprocess.run(  # noqa: S603 - argv vector, shell=False
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=full_env,
            check=False,
        )
    except FileNotFoundError as exc:
        return CommandResult(argv, 127, "", str(exc), time.monotonic() - started)
    except PermissionError as exc:
        return CommandResult(argv, 126, "", str(exc), time.monotonic() - started)
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        if isinstance(out, bytes):  # pragma: no cover - defensive
            out = out.decode("utf-8", "replace")
        err = exc.stderr or ""
        if isinstance(err, bytes):  # pragma: no cover - defensive
            err = err.decode("utf-8", "replace")
        return CommandResult(argv, 124, out[:max_bytes], err, time.monotonic() - started, timed_out=True)

    truncated = False
    stdout = proc.stdout
    if len(stdout) > max_bytes:
        stdout = stdout[:max_bytes]
        truncated = True
    return CommandResult(argv, proc.returncode, stdout, proc.stderr, time.monotonic() - started, truncated=truncated)


@dataclass
class Result:
    """Envelope carrying a payload plus its provenance and availability."""

    value: object = None
    source: str = ""
    availability: str = Availability.OK
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.availability in (Availability.OK, Availability.EMPTY)

    @property
    def available(self) -> bool:
        return self.availability in (Availability.OK, Availability.EMPTY)

    @classmethod
    def ok_result(cls, value: object, source: str = "") -> "Result":
        return cls(value=value, source=source, availability=Availability.OK)

    @classmethod
    def empty(cls, source: str = "") -> "Result":
        return cls(value=None, source=source, availability=Availability.EMPTY)

    @classmethod
    def unavailable(cls, source: str = "", error: Optional[str] = None) -> "Result":
        return cls(value=None, source=source, availability=Availability.UNAVAILABLE, error=error)

    @classmethod
    def from_command(cls, res: CommandResult, source: str, parser) -> "Result":
        if res.timed_out:
            return cls(None, source, Availability.TIMEOUT, "command timed out")
        if res.returncode == 127:
            return cls(None, source, Availability.UNAVAILABLE, "command not installed")
        if res.returncode == 126:
            return cls(None, source, Availability.DENIED, "permission denied")
        if res.returncode != 0:
            msg = (res.stderr or res.stdout or "").strip().splitlines()
            return cls(None, source, Availability.ERROR, msg[0] if msg else f"exit {res.returncode}")
        try:
            value = parser(res.stdout)
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            return cls(None, source, Availability.ERROR, f"parse error: {exc}")
        if value is None:
            return cls.empty(source)
        return cls.ok_result(value, source)


def which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def read_text(path: str | Path, limit: int = 1024 * 1024) -> Optional[str]:
    """Read a file safely, returning None when it is missing or unreadable."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except (OSError, ValueError):
        return None


def human_bytes(value: Optional[float]) -> str:
    if value is None:
        return "n/a"
    units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
    number = float(value)
    for unit in units:
        if abs(number) < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(number)} {unit}"
            return f"{number:.1f} {unit}"
        number /= 1024.0
    return f"{number:.1f} PiB"  # pragma: no cover - unreachable


def human_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "n/a"
    seconds = int(max(0, seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours:02d}h {minutes:02d}m"
    if hours:
        return f"{hours}h {minutes:02d}m {secs:02d}s"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def pct(used: float, total: float) -> float:
    if total <= 0:
        return 0.0
    return max(0.0, min(100.0, used / total * 100.0))


def bar(percentage: float, width: int = 20) -> str:
    """Plain-text proportional bar (no escape sequences, safe over SSH)."""
    percentage = max(0.0, min(100.0, percentage))
    filled = int(round(percentage / 100.0 * width))
    return "#" * filled + "." * (width - filled)


def truncate(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    if width <= 1:
        return text[:width]
    return text[: width - 1] + "\u2026"


def is_root() -> bool:
    return os.geteuid() == 0


def unique(seq: Iterable[str]) -> List[str]:
    seen = set()
    out = []
    for item in seq:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out
