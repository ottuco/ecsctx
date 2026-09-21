"""Declared log events: the mechanism, not a vocabulary.

ecsctx is public and MIT licensed, so it ships how an event is declared, how a
domain registers, and where a field lands. Vendor vocabularies live under
`ecsctx.contrib` (e.g. `ecsctx.contrib.ottu` for the shared Ottu
catalogue); the core stays noun-free. A service registers its domains at
startup:

    from ecsctx.events import EventSpec, register_domain

    PG_REQUEST_SENT = EventSpec(
        action="pg.request_sent",
        category=("network",),
        type=("connection",),
        required=("pg_code", "session_id"),
    )

    register_domain("pg", [PG_REQUEST_SENT, ...])

and then, at any call site, logs through its own logger:

    logger.info("Calling %s", pg, ecs_event=PG_REQUEST_SENT.ecs(),
                payment={"pg_code": "mpgs"})
"""

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
from ecsctx.events.spec import ECS_OUTCOMES, EventSpec, Outcome, Reason
from ecsctx.events.timing import Timer, timed
from ecsctx.events.validator import (
    MODE_REPAIR,
    MODE_STRICT,
    EventContractError,
    configure_event_contract,
    event_contract,
    get_mode,
    reset_event_contract,
)

__all__ = [
    "ECS_OUTCOMES",
    "MODE_REPAIR",
    "MODE_STRICT",
    "RESERVED_PREFIXES",
    "EventContractError",
    "EventSpec",
    "Outcome",
    "Reason",
    "RegistryFrozenError",
    "Timer",
    "all_events",
    "configure_event_contract",
    "domains",
    "event_contract",
    "freeze",
    "get_mode",
    "is_frozen",
    "register_aliases",
    "register_domain",
    "reset_event_contract",
    "resolve",
    "timed",
]
