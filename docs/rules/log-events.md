---
# Canonical copy: ecsctx docs/rules/log-events.md. A service copies this file
# to .claude/rules/log-events.md and changes only the local-module path below.
paths:
  - "**/*.py"
---

# Log events: one Ottu vocabulary

Every Ottu service names its events from one vocabulary, so a dashboard, an
alert or an agent reading Elasticsearch finds the same `event.action` for the
same thing whichever service wrote it. Different teams own different services;
this rule is how a name stays shared. A second spelling — `payment.inited`
next to `payment.created`, `notify.message_queued` next to `task.enqueued` —
splits every query that counts that thing, and nothing at the call site looks
wrong.

## Where an event comes from

- **Shared:** `ecsctx.contrib.ottu.<domain>`. Every shared event is listed,
  with when to log it, in ecsctx's
  [`docs/events.md`](https://github.com/ottuco/ecsctx/blob/main/docs/events.md).
- **This service's own:** the service's single events module (Connect:
  `utils/log_events.py`), registered once at startup with
  `register_ottu(local=...)`.

Nothing else defines an event. No `EventSpec(...)` or `Reason` subclass
anywhere else, and no `register_domain()` / `register_aliases()` calls.

## Logging one

```python
from ecsctx.contrib.ottu.net import OutboundFailure
from ecsctx.contrib.ottu.pg import PG_REQUEST_FAILED
from ecsctx.events import Outcome

logger.warning(
    "PSP rejected the call",
    ecs_event=PG_REQUEST_FAILED.ecs(
        outcome=Outcome.FAILURE, reason=OutboundFailure.HTTP_CLIENT_ERROR
    ),
    http={"response": {"status_code": 400}},
)
```

- `ecs_event` is always `<CONSTANT>.ecs(...)`. Never a string, a dict, an
  f-string, or an `EventSpec` built at the call site.
- `outcome` is an `Outcome` member. `reason` is a member of the event's own
  `Reason` class. Never a string literal.
- The call site picks the level. `failure_level` on the spec says what an
  expected failure logs at; an unexpected one is `error`.
- What varies between calls goes in fields (`labels.operation`,
  `payment.pg_code`) or in a declared reason, never in the action.

## Before adding an event

1. Look for the thing that happened in `docs/events.md` and in this service's
   events module. If an event already names it, use that event, and put the
   difference in fields or a reason.
2. Would another service log it too? Then it belongs in the catalogue. Open an
   ecsctx PR, release, then import it. Do not declare it locally "for now".
3. Otherwise declare it in this service's events module with:
   - an action of the form `<domain>.<subject>_<verb>` (or `<domain>.<verb>`);
   - a `description` saying when to log it and what success and failure mean;
   - `terminal`, `level` and `failure_level`;
   - ECS `category` and `type`;
   - a local `Reason` subclass for its reasons;
   - its `required` fields.

   `register_ottu()` refuses, at startup, any local event that breaks the
   naming rules (`ecsctx.contrib.ottu.rules`: a past-tense verb from `VERBS`,
   no known synonym, no negation, a description). So a bad name fails this
   service's tests.
4. A new reason for a *shared* event goes into its catalogue `Reason` class by
   ecsctx PR. A populated enum cannot be extended locally, and a reason on a
   shared event must mean the same in every service.
5. When a second service needs a local event, move it to the catalogue with
   the same action and delete the local copy.

## Reviewing a change that logs

For every new or changed `ecs_event=`:

- The constant comes from `ecsctx.contrib.ottu.*` or this service's events
  module. Anything else is a defect.
- The outcome and reason are members, not strings.
- For a new action:
  - Does a shared or local event already name the same thing with another word
    (created/inited, sent/dispatched, rejected/refused)?
  - Would another service log it, so that it should be shared?
  - Does its description say when to log it?
- An event named after a failure (`*_not_found`, `*_error`) should be the
  attempt with `outcome=Outcome.FAILURE` (`*_lookup_failed`, `*_failed`).
