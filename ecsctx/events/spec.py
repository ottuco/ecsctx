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
from enum import Enum
from typing import Any


# `(str, Enum)` rather than `StrEnum`, which needs Python 3.11. A member is a
# `str`, so it compares equal to the plain value and serialises as it.
class Outcome(str, Enum):
    """ECS `event.outcome` — a closed set.

    https://www.elastic.co/docs/reference/ecs/ecs-event
    """

    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"

    def __str__(self) -> str:
        return self.value


class Reason(str, Enum):
    """Base for one event's bounded set of `event.reason` values.

    Declare a subclass next to the event and pass the class as its `reasons`.
    A set with members cannot be subclassed, which is the point: a reason on a
    shared event means the same in every service, so a new one is added where
    the set is declared, not extended locally.
    """

    def __str__(self) -> str:
        return self.value


ECS_OUTCOMES = frozenset(outcome.value for outcome in Outcome)

# Spelled out here because inside `EventSpec` the name `type` is the ECS field.
_ReasonSet = tuple[str, ...] | type[Reason]


# Equality is the dataclass default, so `reasons` compare by value, not by
# class: two specs declared with different `Reason` classes of equal values are
# equal. That is what `register_domain()` needs. Django's autoreload can import
# an AppConfig module twice, re-executing each `Reason` class into a new class
# object, and the re-registration must still read as the same declaration.
# Which set a reason belongs to is `.ecs()`'s question, answered by identity.
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
    # A `Reason` subclass, normalised to its members; a tuple of strings still
    # works for a set nobody passes as an object.
    reasons: _ReasonSet = ()
    # Field names this event is expected to carry. Declaration only — the
    # runtime validator (#159491) is what enforces them. Declared here so
    # EventSpec is not reopened for that ticket.
    required: tuple[str, ...] = ()
    optional: tuple[str, ...] = ()
    # Connect's LogEvent carried only `level`, described as "the level of the
    # SUCCESS path". The taxonomy it came from said things like "info on
    # success, error on failure" and the generator kept the first word, so the
    # failure level was lost and a reader had no way to know that
    # pg.response_received is info when it works and error when it does not.
    # Declared intent for the call site, which picks the level: None means
    # error if terminal, otherwise same as level.
    failure_level: str | None = None
    # When to log this event and what its outcome means, for the developer
    # choosing between events and the reviewer checking the choice. Rendered
    # into the catalogue's reference page.
    description: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.reasons, type) and issubclass(self.reasons, Reason):
            # Frozen dataclass: the one assignment it allows is the normalising one.
            object.__setattr__(self, "reasons", tuple(self.reasons))

    def __str__(self) -> str:
        return self.action

    def _declares(self, reason: str) -> bool:
        if isinstance(reason, Reason) and all(isinstance(r, Reason) for r in self.reasons):
            # Identity, not value: `WebhookFailure.TIMEOUT` equals
            # `OutboundFailure.TIMEOUT` as a string but explains a different event.
            return any(reason is declared for declared in self.reasons)
        return reason in self.reasons

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
        outcome: Outcome | str | None = None,
        reason: Reason | str | None = None,
        duration_ns: int | None = None,
    ) -> dict[str, Any]:
        """Build the `ecs_event=` payload for this event.

        Duration belongs here rather than in a separate `event=` kwarg: structlog
        takes the message as a positional arg *named* `event`, so `event={...}`
        raises `TypeError: got multiple values for argument 'event'` at call
        time. The parameter is `_ns` because ECS `event.duration` is nanoseconds,
        and a millisecond value misreports by six orders of magnitude while
        looking entirely plausible.

        `outcome` and `reason` are best passed as members (`Outcome.FAILURE`,
        a `Reason`); the payload always carries their plain string value.
        """
        if self.terminal and outcome is None:
            raise ValueError(f"{self.action} is terminal and needs an outcome")
        if outcome is not None and outcome not in ECS_OUTCOMES:
            raise ValueError(f"{outcome!r} is not a valid ECS event.outcome")
        if reason is not None and not self.reasons:
            # A reason is a bounded value or it aggregates nothing. An event
            # that needs one declares its `Reason` class first.
            raise ValueError(f"{self.action} declares no reasons; got {reason!r}")
        if reason is not None and not self._declares(reason):
            raise ValueError(f"{reason!r} is not a declared reason for {self.action}")
        if duration_ns is not None and duration_ns < 0:
            raise ValueError(f"duration_ns must not be negative, got {duration_ns}")
        payload: dict[str, Any] = {"action": self.action, "kind": self.kind}
        if self.category:
            payload["category"] = list(self.category)
        if self.type:
            payload["type"] = list(self.type)
        if outcome is not None:
            payload["outcome"] = str(outcome)
        if reason is not None:
            payload["reason"] = str(reason)
        if duration_ns is not None:
            payload["duration"] = duration_ns
        return payload
