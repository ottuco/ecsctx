"""One way to emit a declared event.

    emit(logger, PG_RESPONSE_RECEIVED, "PG replied",
         outcome="success", duration_ns=elapsed, pg_code="mpgs", status_code=200)

builds the `ecs_event=` payload, routes the fields to their ECS paths, picks the
level from the outcome, and calls the logger.
"""

from typing import Any

from ecsctx.events import fields as field_table
from ecsctx.events.registry import resolve
from ecsctx.events.spec import EventSpec


class UnknownEventError(LookupError):
    """A name that is neither a registered event nor a known retired one."""


def emit(
    logger,
    event,
    message: str,
    *args: Any,
    outcome: str | None = None,
    reason: str | None = None,
    duration_ns: int | None = None,
    level: str | None = None,
    **fields: Any,
):
    """Log `event` on `logger`.

    `event` is an `EventSpec`, or its action as a string — resolved through the
    registry and the alias map, so a call site can migrate off raw names before
    it imports constants.

    `*args` passes through untouched: `emit(log, SPEC, "took %s", elapsed)` keeps
    structlog's lazy formatting, and an API that forced eager formatting would
    quietly defeat the rule against f-strings in log calls.
    """
    spec = resolve(event)
    if spec is None:
        raise UnknownEventError(
            f"{event!r} is not a registered event. Register its domain with "
            f"register_domain(), or add it to the alias map if it is a retired name."
        )
    if not isinstance(spec, EventSpec):  # pragma: no cover - defensive
        raise TypeError(f"expected an EventSpec, got {type(spec).__name__}")

    chosen = level or (spec.level_on_failure if outcome == "failure" else spec.level)
    payload = field_table.route(fields)
    payload["ecs_event"] = spec.ecs(
        outcome=outcome, reason=reason, duration_ns=duration_ns
    )
    return getattr(logger, chosen)(message, *args, **payload)
