"""What an event is, before anyone emits one.

`event.action` is the field an agent reads first, and it was the least
disciplined field we had: 34 hand-rolled names in Connect, 88% with no
namespace, two containing a literal space — because writing a log line takes a
string, and a string is always valid (#159490).

`EventSpec` is deliberately a superset of Connect's `utils.log_events.LogEvent`,
with the same `.ecs()` signature and output, so that module can be moved onto
this one mechanically instead of the two drifting apart.
"""

from dataclasses import dataclass
from typing import Any

# ECS closed value set — https://www.elastic.co/docs/reference/ecs/ecs-event
ECS_OUTCOMES = frozenset({"success", "failure", "unknown"})


@dataclass(frozen=True, slots=True)
class EventSpec:
    action: str
    # The SUCCESS path's level. A terminal event's failure branch logs at
    # `failure_level` instead.
    level: str = "info"
    # A terminal event reports whether the thing it names succeeded, so `ecs()`
    # refuses to build one without an outcome.
    terminal: bool = False
    kind: str = "event"
    category: tuple[str, ...] = ()
    type: tuple[str, ...] = ()
    # Bounded set for `event.reason`; free text here would defeat aggregation.
    reasons: tuple[str, ...] = ()
    # Field names this event is expected to carry. Declaration only — the
    # runtime validator (#159491) is what enforces them. Declared here so
    # EventSpec is not reopened for that ticket.
    required: tuple[str, ...] = ()
    optional: tuple[str, ...] = ()
    # Connect's LogEvent carried only `level`, described as "the level of the
    # SUCCESS path". The taxonomy it came from said things like "info on
    # success, error on failure" and the generator kept the first word, so the
    # failure level was lost and `emit()` had no way to know that
    # pg.response_received is info when it works and error when it does not.
    # None means: error if terminal, otherwise same as level.
    failure_level: str | None = None

    def __str__(self) -> str:
        return self.action

    @property
    def domain(self) -> str:
        """The prefix this event registers under — `pg` for `pg.request_sent`."""
        return self.action.partition(".")[0]

    @property
    def level_on_failure(self) -> str:
        if self.failure_level is not None:
            return self.failure_level
        return "error" if self.terminal else self.level

    def ecs(
        self,
        *,
        outcome: str | None = None,
        reason: str | None = None,
        duration_ns: int | None = None,
    ) -> dict[str, Any]:
        """Build the `ecs_event=` payload for this event.

        Duration belongs here rather than in a separate `event=` kwarg: structlog
        takes the message as a positional arg *named* `event`, so `event={...}`
        raises `TypeError: got multiple values for argument 'event'` at call
        time. The parameter is `_ns` because ECS `event.duration` is nanoseconds,
        and a millisecond value misreports by three orders of magnitude while
        looking entirely plausible.
        """
        if self.terminal and outcome is None:
            raise ValueError(f"{self.action} is terminal and needs an outcome")
        if outcome is not None and outcome not in ECS_OUTCOMES:
            raise ValueError(f"{outcome!r} is not a valid ECS event.outcome")
        if reason is not None and self.reasons and reason not in self.reasons:
            raise ValueError(f"{reason!r} is not a declared reason for {self.action}")
        if duration_ns is not None and duration_ns < 0:
            raise ValueError(f"duration_ns must not be negative, got {duration_ns}")
        payload: dict[str, Any] = {"action": self.action, "kind": self.kind}
        if self.category:
            payload["category"] = list(self.category)
        if self.type:
            payload["type"] = list(self.type)
        if outcome is not None:
            payload["outcome"] = outcome
        if reason is not None:
            payload["reason"] = reason
        if duration_ns is not None:
            payload["duration"] = duration_ns
        return payload
