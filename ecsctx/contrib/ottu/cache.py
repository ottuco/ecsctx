"""Shared ``cache.*`` domain: cache reads, writes, invalidations, failures.

Transcribed from ticket #159487 (Event catalogue, ``cache`` table).
"""

from ecsctx.events.spec import EventSpec

CACHE_READ = EventSpec(
    action="cache.read",
    level="debug",
    terminal=True,
    required=("labels.store", "labels.result"),
)

CACHE_WRITTEN = EventSpec(
    action="cache.written",
    level="debug",
    terminal=True,
    required=("labels.store",),
)

CACHE_INVALIDATED = EventSpec(
    action="cache.invalidated",
    terminal=True,
    required=("labels.store", "labels.scope"),
)

CACHE_OPERATION_FAILED = EventSpec(
    action="cache.operation_failed",
    level="error",
    terminal=True,
    required=("event.outcome", "labels.store", "labels.operation", "error.type"),
)

SPECS: tuple[EventSpec, ...] = (
    CACHE_READ,
    CACHE_WRITTEN,
    CACHE_INVALIDATED,
    CACHE_OPERATION_FAILED,
)
