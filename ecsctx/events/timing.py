"""Measuring how long something took, in the unit ECS actually wants.

`event.duration` is on 0.0% of application logs across the production index —
all 1,150,892 documents carrying it are nginx's. The library shipped no timer,
so every service either wrote its own or, more often, computed the elapsed time
and threw it away (#159492).

**`event.duration` is nanoseconds.** It is the single most likely thing to get
wrong here: a millisecond value is accepted, indexes cleanly, and misreports by
six orders of magnitude while looking entirely plausible on a dashboard. That
is why the timer exposes `.ns` and `.ms` as separate, explicitly named
properties and why the emit parameter is `duration_ns` — there is no unit-less
`duration` anywhere in this package to pass by accident.
"""

import time
from contextlib import contextmanager
from typing import Any

from ecsctx.events.emit import emit


class Timer:
    """Elapsed time, live while the block runs and frozen once it exits."""

    __slots__ = ("_started", "_stopped")

    def __init__(self) -> None:
        # Monotonic: a clock adjustment mid-request must not produce a negative
        # duration, which `EventSpec.ecs()` would then reject at the call site.
        self._started = time.perf_counter_ns()
        self._stopped: int | None = None

    def _stop(self) -> None:
        if self._stopped is None:
            self._stopped = time.perf_counter_ns()

    @property
    def ns(self) -> int:
        """Nanoseconds — what ECS `event.duration` expects."""
        end = self._stopped if self._stopped is not None else time.perf_counter_ns()
        return end - self._started

    @property
    def ms(self) -> float:
        """Milliseconds, for a human-readable message. Never for event.duration."""
        return self.ns / 1_000_000


@contextmanager
def timed():
    """Time a block.

        with timed() as t:
            response = call_gateway()
        emit(logger, PG_RESPONSE_RECEIVED, "Gateway replied in %.1f ms", t.ms,
             outcome="success", duration_ns=t.ns)

    The timer stops on the way out whether the block succeeded or raised, so a
    failure path reports how long it took to fail — usually the more interesting
    number of the two.
    """
    timer = Timer()
    try:
        yield timer
    finally:
        timer._stop()


# `emit_pair` passes these to the closing `emit()` itself. A field of the same
# name would arrive twice and raise TypeError from inside the except handler —
# which on the failure path demotes the real exception to __context__ and
# propagates a kwargs error instead, at exactly the moment the feature exists
# to help. `reason` is the easy one to hit, because Call exposes `.reason` as
# an attribute, so `call.set(reason=...)` is a natural thing to reach for.
RESERVED_FIELDS = frozenset(
    {
        "outcome",
        "reason",
        "duration_ns",
        "exc_info",
        "level",
    }
)


def _reject_reserved(fields, where: str) -> None:
    clashing = sorted(RESERVED_FIELDS & set(fields))
    if not clashing:
        return
    raise TypeError(
        f"{', '.join(clashing)} cannot be passed as {where}: emit_pair sets "
        f"them on the closing event itself. Use call.outcome = ... and "
        f"call.reason = ... inside the block instead."
    )


class Call:
    """The in-flight half of an `emit_pair` block."""

    __slots__ = ("fields", "outcome", "reason", "timer")

    def __init__(self, timer: Timer, fields: dict[str, Any]) -> None:
        self.timer = timer
        self.outcome: str | None = None
        self.reason: str | None = None
        self.fields = fields

    @property
    def ns(self) -> int:
        return self.timer.ns

    @property
    def ms(self) -> float:
        return self.timer.ms

    def set(self, **fields: Any) -> None:
        """Add fields to the closing event — a status code, a byte count.

        Not the outcome or the reason: those are attributes (`call.outcome`),
        because emit_pair passes them to the closing event itself.
        """
        _reject_reserved(fields, "a call.set() field")
        self.fields.update(fields)


@contextmanager
def emit_pair(logger, start, end, message: str, *args: Any, **fields: Any):
    """Emit a request/reply pair, with the reply carrying the duration.

        with emit_pair(logger, PG_REQUEST_SENT, PG_RESPONSE_RECEIVED,
                       "Gateway call", pg_code="mpgs") as call:
            response = call_gateway()
            call.set(status_code=response.status)

    One message serves both lines because `event.action` is what distinguishes
    them — `pg.request_sent` from `pg.response_received` — and making the action
    authoritative rather than the prose is the point of the whole vocabulary.
    For two genuinely different messages, use `timed()` with two `emit()` calls.

    The outcome is inferred: `failure` if the block raised, `success` if it did
    not, unless the block set `call.outcome` itself. An exception also attaches
    `exc_info`, so the traceback reaches `error.*` instead of being lost to a
    duration that says only that it failed quickly.
    """
    _reject_reserved(fields, "an emit_pair field")
    timer = Timer()
    call = Call(timer, dict(fields))
    emit(logger, start, message, *args, **fields)
    failed = False
    try:
        yield call
    except BaseException:
        failed = True
        timer._stop()
        emit(
            logger,
            end,
            message,
            *args,
            outcome=call.outcome or "failure",
            reason=call.reason,
            duration_ns=timer.ns,
            exc_info=True,
            **call.fields,
        )
        raise
    finally:
        if not failed:
            timer._stop()
            emit(
                logger,
                end,
                message,
                *args,
                outcome=call.outcome or "success",
                reason=call.reason,
                duration_ns=timer.ns,
                **call.fields,
            )
