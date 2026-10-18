"""Collector base class: uniform availability reporting and error containment."""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

from ..util import Availability, Result


class Collector:
    """Base class for every data source.

    Subclasses implement :meth:`collect` and must never raise: any exception is
    converted into an ``unavailable`` :class:`Result` so one broken source can
    never take the console down.
    """

    key: str = "base"
    title: str = "Base"
    source: str = ""

    def __init__(self, ctx: "CollectionContext") -> None:
        self.ctx = ctx

    # -- API -----------------------------------------------------------
    def collect(self) -> Result:  # pragma: no cover - abstract
        raise NotImplementedError

    def available(self) -> bool:
        """Cheap availability probe used by the navigation bar."""
        return True

    # -- helpers --------------------------------------------------------
    def unavailable(self, reason: str) -> Result:
        return Result.unavailable(self.source or self.key, reason)

    def empty(self) -> Result:
        return Result.empty(self.source or self.key)

    def ok(self, value: Any) -> Result:
        return Result.ok_result(value, self.source or self.key)

    def timeout(self) -> float:
        return float(self.ctx.config.command_timeout)


class CollectionContext:
    """Everything a collector may need: config, cache, helper runners."""

    def __init__(self, config, cache: Optional[Dict[str, tuple]] = None) -> None:
        self.config = config
        self.cache = cache if cache is not None else {}
        self._mem: Dict[str, float] = {}

    # -- caching --------------------------------------------------------
    def cached(self, key: str, ttl: float, producer):
        """Memoise ``producer()`` for ``ttl`` seconds (keys include args)."""
        now = time.monotonic()
        entry = self.cache.get(key)
        if entry and now - entry[0] < ttl:
            return entry[1]
        value = producer()
        self.cache[key] = (now, value)
        return value

    def invalidate(self, prefix: str = "") -> None:
        for key in list(self.cache):
            if key.startswith(prefix):
                self.cache.pop(key, None)

    # -- process helpers -------------------------------------------------
    def run(self, argv, timeout: Optional[float] = None):
        from ..util import run

        return run(argv, timeout=timeout or self.config.command_timeout)

    def run_result(self, argv, parser, source: str, timeout: Optional[float] = None) -> Result:
        res = self.run(argv, timeout=timeout)
        return Result.from_command(res, source, parser)

    @staticmethod
    def availability_label(state: str) -> str:
        return Availability.LABELS.get(state, state)
