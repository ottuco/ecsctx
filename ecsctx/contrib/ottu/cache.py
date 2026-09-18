"""Shared ``cache.*`` domain: cache reads, writes, invalidations, failures.

Transcribed from ticket #159487 (Event catalogue, ``cache`` table).
"""

from ecsctx.events.spec import EventSpec

CACHE_READ = EventSpec(
    action="cache.read",
    level="debug",
    terminal=True,
    type=("info",),
    required=("event.outcome", "labels.cache", "labels.cache_hit"),
)

CACHE_WRITTEN = EventSpec(
    action="cache.written",
    level="debug",
    terminal=True,
    type=("info",),
    reasons=("expired", "serialization_failed", "backend_unavailable"),
    required=("event.outcome", "labels.cache"),
)

CACHE_INVALIDATED = EventSpec(
    action="cache.invalidated",
    terminal=True,
    type=("info",),
    required=("event.outcome", "labels.cache", "labels.trigger"),
)

CACHE_OPERATION_FAILED = EventSpec(
    action="cache.operation_failed",
    level="error",
    terminal=True,
    type=("error",),
    required=("event.outcome", "labels.cache", "labels.operation", "error.type"),
)

SPECS: tuple[EventSpec, ...] = (
    CACHE_READ,
    CACHE_WRITTEN,
    CACHE_INVALIDATED,
    CACHE_OPERATION_FAILED,
)
