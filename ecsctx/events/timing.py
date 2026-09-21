"""Measuring how long something took, in the unit ECS actually wants.

`event.duration` is on 0.0% of application logs across the production index —
all 1,150,892 documents carrying it are nginx's. The library shipped no timer,
so every service either wrote its own or, more often, computed the elapsed time
and threw it away (#159492).

**`event.duration` is nanoseconds.** It is the single most likely thing to get
wrong here: a millisecond value is accepted, indexes cleanly, and misreports by
six orders of magnitude while looking entirely plausible on a dashboard. That
is why the timer exposes `.ns` and `.ms` as separate, explicitly named
properties and why `EventSpec.ecs()` takes `duration_ns` — there is no unit-less
`duration` anywhere in this package to pass by accident.
"""

import time
from contextlib import contextmanager


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
        logger.info(
            "Gateway replied in %.1f ms", t.ms,
            ecs_event=PG_RESPONSE_RECEIVED.ecs(outcome="success", duration_ns=t.ns),
        )

    The timer stops on the way out whether the block succeeded or raised, so a
    failure path reports how long it took to fail — usually the more interesting
    number of the two.
    """
    timer = Timer()
    try:
        yield timer
    finally:
        timer._stop()
