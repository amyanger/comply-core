"""Evidence collectors registry."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from comply_core.collectors.base import BaseCollector

_REGISTRY: dict[str, type[BaseCollector]] = {}


def register_collector(cls: type[BaseCollector]) -> type[BaseCollector]:
    """Register a collector class by its source_id."""
    _REGISTRY[cls.source_id.fget(cls)] = cls  # type: ignore[attr-defined]
    return cls


def get_collector(source_id: str) -> type[BaseCollector] | None:
    """Look up a registered collector by source_id."""
    return _REGISTRY.get(source_id)


def all_collectors() -> dict[str, type[BaseCollector]]:
    """Return all registered collectors."""
    return dict(_REGISTRY)
