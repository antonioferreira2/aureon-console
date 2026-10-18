"""Collector registry."""

from __future__ import annotations

from typing import Dict, List, Type

from .base import CollectionContext, Collector
from .docker import DockerCollector
from .logs import LogCollector
from .network import NetworkCollector
from .sensors import SensorCollector
from .services import ServiceCollector
from .storage import StorageCollector
from .system import SystemCollector
from .tools import ToolCollector

COLLECTORS: Dict[str, Type[Collector]] = {
    "system": SystemCollector,
    "processes": SystemCollector,
    "storage": StorageCollector,
    "network": NetworkCollector,
    "services": ServiceCollector,
    "logs": LogCollector,
    "docker": DockerCollector,
    "sensors": SensorCollector,
    "tools": ToolCollector,
}


def build(key: str, ctx: CollectionContext) -> Collector:
    return COLLECTORS[key](ctx)


def keys() -> List[str]:
    return list(COLLECTORS)


__all__ = [
    "COLLECTORS",
    "CollectionContext",
    "Collector",
    "DockerCollector",
    "LogCollector",
    "NetworkCollector",
    "SensorCollector",
    "ServiceCollector",
    "StorageCollector",
    "SystemCollector",
    "ToolCollector",
    "build",
    "keys",
]
