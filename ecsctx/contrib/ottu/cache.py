"""Shared ``cache.*`` domain: cache reads, writes, invalidations, failures.

Transcribed from ticket #159487 (Event catalogue, ``cache`` table).
"""

from ecsctx.events.spec import EventSpec, Reason

CACHE_READ = EventSpec(
    action="cache.read",
    description=(
        "A cache lookup; labels.cache_hit says whether it hit. Debug, because it fires "
        "on every read."
    ),
    level="debug",
    terminal=True,
    type=("info",),
    required=("event.outcome", "labels.cache", "labels.cache_hit"),
)


class CacheWriteFailure(Reason):
    """Why a cache write did not happen."""

    EXPIRED = "expired"
    SERIALIZATION_FAILED = "serialization_failed"
    BACKEND_UNAVAILABLE = "backend_unavailable"


CACHE_WRITTEN = EventSpec(
    action="cache.written",
    description=(
        "A value was written to a cache. A failure means it was not stored; the reason "
        "says why."
    ),
    level="debug",
    terminal=True,
    type=("info",),
    reasons=CacheWriteFailure,
    required=("event.outcome", "labels.cache"),
)

CACHE_INVALIDATED = EventSpec(
    action="cache.invalidated",
    description="Cache entries were dropped; labels.trigger says what caused it.",
    terminal=True,
    type=("info",),
    required=("event.outcome", "labels.cache", "labels.trigger"),
)

CACHE_OPERATION_FAILED = EventSpec(
    action="cache.operation_failed",
    description=(
        "A cache operation (labels.operation) raised, so the caller fell back or "
        "failed."
    ),
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
