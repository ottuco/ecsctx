"""The log-contract processor: catch the silent mistakes before they ship.

The worst of them looks completely correct at the call site:

    logger.info("Payment started", ecs_event="payment.started")

`namespace_ecs_fields` routes a non-dict `ecs_event` to `event.original` — ECS's
field for the *raw unparsed message* — so `event.action` is simply absent and the
line vanishes from every dashboard that filters on it. Six of Ottu PG's most
important events, `payment.started` and `payment.succeeded` among them, are in
that state in production today (#159491).

Two modes:

* **strict** — raise, so it is caught at the desk. For dev and test.
* **repair** — fix what is fixable, stamp `labels.log_contract` with what was
  wrong, and never drop the line. For staging and production.

Repair is the default: a logging library that takes down a service over a
malformed log line has chosen the wrong failure.
"""

import os
import warnings
from typing import Any

from ecsctx import identity
from ecsctx.events.registry import is_frozen, resolve

MODE_STRICT = "strict"
MODE_REPAIR = "repair"
MODES = frozenset({MODE_STRICT, MODE_REPAIR})

# Bounded set, so `labels.log_contract` aggregates. A free-text description of
# each violation would defeat the field's whole purpose.
STRING_ACTION = "string_action"
UNKNOWN_ACTION = "unknown_action"
MISSING_OUTCOME = "missing_outcome"
FAILURE_BELOW_WARNING = "failure_below_warning"
UNBOUNDED_LABEL = "unbounded_label"

_QUIET_LEVELS = frozenset({"debug", "info"})
_SCALARS = (str, int, float, bool, type(None))

_mode: str | None = None


class EventContractError(ValueError):
    """A log call broke the event contract, in strict mode."""


def configure_event_contract(*, mode: str) -> None:
    global _mode
    if mode not in MODES:
        raise ValueError(f"{mode!r} is not a mode; use one of {sorted(MODES)}")
    _mode = mode


def reset_event_contract() -> None:
    """Forget the configured mode. For tests, and a settings change at runtime."""
    global _mode
    _mode = None


def get_mode() -> str:
    """Django setting, then environment, then repair.

    Repair rather than strict, because the default has to be the one that is
    safe in production for a service that has not thought about this yet.
    """
    global _mode
    if _mode is not None:
        return _mode
    declared = identity._from_django("ECSCTX_EVENT_CONTRACT") or _from_env()
    if declared is None:
        _mode = MODE_REPAIR
    elif declared in MODES:
        _mode = declared
    else:
        warnings.warn(
            f"{declared!r} is not an ecsctx event-contract mode; "
            f"using {MODE_REPAIR!r}. Valid modes: {sorted(MODES)}.",
            RuntimeWarning,
            stacklevel=2,
        )
        _mode = MODE_REPAIR
    return _mode


def _from_env() -> str | None:
    return os.environ.get("ECSCTX_EVENT_CONTRACT") or None


def _check_labels(event_dict: dict[str, Any], repair: bool) -> bool:
    labels = event_dict.get("labels")
    if not isinstance(labels, dict):
        return False
    offenders = [k for k, v in labels.items() if not isinstance(v, _SCALARS)]
    if not offenders:
        return False
    if repair:
        for key in offenders:
            labels[key] = str(labels[key])
    return True


def event_contract(_logger, method_name, event_dict):
    """structlog processor. Must run BEFORE `namespace_ecs_fields`.

    Ordering is the whole point: `namespace_ecs_fields` is what turns a string
    `ecs_event` into `event.original`, so running after it would leave nothing
    left to repair.
    """
    mode = get_mode()
    repair = mode == MODE_REPAIR
    violations: list[str] = []

    staged = event_dict.get("ecs_event")
    if isinstance(staged, str):
        violations.append(STRING_ACTION)
        if repair:
            staged = {"action": staged}
            event_dict["ecs_event"] = staged

    if isinstance(staged, dict):
        action = staged.get("action")
        spec = resolve(action) if isinstance(action, str) else None
        # Membership is only checked once the registry is frozen. Before that,
        # a domain that has not registered yet would make every one of its own
        # events look unknown — a startup race reported as a contract breach.
        if action is not None and spec is None and is_frozen():
            violations.append(UNKNOWN_ACTION)
        if spec is not None and spec.terminal and staged.get("outcome") is None:
            violations.append(MISSING_OUTCOME)
            if repair:
                # "unknown" is a real ECS outcome and the honest one here: the
                # line did not say, and this processor cannot know.
                staged["outcome"] = "unknown"
        if staged.get("outcome") == "failure" and method_name in _QUIET_LEVELS:
            # Not repairable: the level was decided before the chain ran. Both
            # audited payment journeys were 100% log.level=info while containing
            # delivery failures, so severity filtering found nothing.
            violations.append(FAILURE_BELOW_WARNING)

    if _check_labels(event_dict, repair):
        violations.append(UNBOUNDED_LABEL)

    if not violations:
        return event_dict

    summary = ",".join(sorted(set(violations)))
    if mode == MODE_STRICT:
        raise EventContractError(
            f"log call breaks the event contract ({summary}); "
            f"ecs_event={event_dict.get('ecs_event')!r}"
        )
    labels = event_dict.get("labels")
    if not isinstance(labels, dict):
        labels = {}
        event_dict["labels"] = labels
    labels["log_contract"] = summary
    return event_dict
