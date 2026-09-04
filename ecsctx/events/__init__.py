"""Declared log events: the mechanism, not a vocabulary.

ecsctx is public and MIT licensed, so it ships how an event is declared, how a
domain registers, and where a field lands. Ottu's business vocabulary — `pg.*`,
`payment.*`, `wallet.*` — stays private to its services and registers at startup:

    from ecsctx.events import EventSpec, register_domain

    PG_REQUEST_SENT = EventSpec(
        action="pg.request_sent",
        category=("network",),
        type=("connection",),
        required=("pg_code", "session_id"),
    )

    register_domain("pg", [PG_REQUEST_SENT, ...])

and then, at any call site:

    emit(logger, PG_REQUEST_SENT, "Calling %s", pg, pg_code="mpgs")
"""

from ecsctx.events.emit import UnknownEventError, emit
from ecsctx.events.fields import FIELD_PATHS, route
from ecsctx.events.registry import (
    RESERVED_PREFIXES,
    RegistryFrozenError,
    all_events,
    domains,
    freeze,
    is_frozen,
    register_aliases,
    register_domain,
    resolve,
)
from ecsctx.events.spec import ECS_OUTCOMES, EventSpec

__all__ = [
    "ECS_OUTCOMES",
    "FIELD_PATHS",
    "RESERVED_PREFIXES",
    "EventSpec",
    "RegistryFrozenError",
    "UnknownEventError",
    "all_events",
    "domains",
    "emit",
    "freeze",
    "is_frozen",
    "register_aliases",
    "register_domain",
    "resolve",
    "route",
]
