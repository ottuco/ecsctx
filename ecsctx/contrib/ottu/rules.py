"""The naming rules every Ottu event follows, shared or local.

Services are built by different teams, and a vocabulary is only shared if a
second spelling cannot get in: `payment.created` in one service and
`payment.inited` in another split every dashboard that counts payments, and
nothing at the call site looks wrong. The catalogue is held to these rules by
its tests; a service's own events are checked by `register_ottu()` at startup.

What a rule cannot judge — whether an event already exists under another name,
whether it belongs in the catalogue — is for review; see
``docs/rules/log-events.md``.

An action is ``<domain>.<subject>_<verb>`` (``pg.request_sent``) or
``<domain>.<verb>`` when the domain is the subject (``task.started``), in lower
snake case, ending in a past-tense verb from `VERBS`. Adding a verb is a PR
here, which is the point: it is the moment someone checks it is not a synonym.
"""

import re

from ecsctx.events.spec import EventSpec

_SHAPE = re.compile(r"^[a-z][a-z0-9]*\.[a-z][a-z0-9]*(?:_[a-z][a-z0-9]*)*$")

# What happened, in the past tense. `unavailable` and `required` are the two
# states that are themselves the event (`pg.credentials_unavailable`).
VERBS = frozenset(
    {
        "accepted",
        "added",
        "answered",
        "applied",
        "approved",
        "authenticated",
        "authorized",
        "blacklisted",
        "built",
        "cancelled",
        "captured",
        "changed",
        "closed",
        "completed",
        "confirmed",
        "created",
        "credited",
        "debited",
        "declined",
        "decrypted",
        "deleted",
        "delivered",
        "denied",
        "detected",
        "disabled",
        "downloaded",
        "enabled",
        "encrypted",
        "enqueued",
        "excluded",
        "expired",
        "exported",
        "failed",
        "gated",
        "generated",
        "granted",
        "handled",
        "imported",
        "invalidated",
        "issued",
        "loaded",
        "lost",
        "matched",
        "migrated",
        "opened",
        "paused",
        "processed",
        "provisioned",
        "published",
        "read",
        "received",
        "redirected",
        "refunded",
        "registered",
        "rejected",
        "released",
        "renewed",
        "replayed",
        "requested",
        "required",
        "reserved",
        "resolved",
        "resumed",
        "retried",
        "revoked",
        "rotated",
        "scheduled",
        "selected",
        "sent",
        "settled",
        "signed",
        "skipped",
        "started",
        "stopped",
        "stored",
        "submitted",
        "suppressed",
        "synced",
        "terminated",
        "tokenized",
        "unavailable",
        "updated",
        "uploaded",
        "validated",
        "verified",
        "voided",
        "written",
    }
)

# Spellings that have already drifted somewhere, and the word the vocabulary
# uses instead. A rejection names the replacement, so the fix is one edit.
SYNONYMS: dict[str, str] = {
    "began": "started",
    "begun": "started",
    "canceled": "cancelled",
    "complete": "completed",
    "crashed": "failed",
    "dispatched": "sent",
    "done": "completed",
    "edited": "updated",
    "emitted": "sent",
    "ended": "completed",
    "erased": "deleted",
    "errored": "failed",
    "fetched": "read",
    "finished": "completed",
    "init": "created",
    "inited": "created",
    "initialised": "created",
    "initialized": "created",
    "initiated": "created",
    "modified": "updated",
    "persisted": "stored",
    "purged": "deleted",
    "queued": "enqueued",
    "refused": "rejected",
    "removed": "deleted",
    "retrying": "retried",
    "saved": "stored",
    "succeeded": "completed",
    "timedout": "failed",
}

# A failure is the event's outcome, not part of its name: `session_not_found`
# is `session_lookup_failed` with `event.outcome: failure`, and only the second
# aggregates with every other lookup.
NEGATIONS = frozenset({"no", "non", "not", "never"})


class EventRuleError(ValueError):
    """An event breaks the naming rules."""


def check(spec: EventSpec) -> list[str]:
    """Every rule `spec` breaks, as readable sentences. Empty when it is fine."""
    action = spec.action
    if not _SHAPE.match(action):
        return [
            (
                f"{action!r}: an action is <domain>.<subject>_<verb> "
                f"(or <domain>.<verb>) in lower snake case"
            )
        ]
    problems: list[str] = []
    words = action.partition(".")[2].split("_")
    verb = words[-1]
    if verb in SYNONYMS:
        problems.append(f"{action!r}: use {SYNONYMS[verb]!r}, not {verb!r}")
    elif verb not in VERBS:
        problems.append(
            f"{action!r}: {verb!r} is not an event verb; end with one of "
            f"ecsctx.contrib.ottu.rules.VERBS, or add it there by PR"
        )
    if negation := sorted(NEGATIONS.intersection(words)):
        problems.append(
            f"{action!r}: no negation ({', '.join(negation)}) — name what was "
            f"attempted and report the failure as event.outcome"
        )
    if not spec.description.strip():
        problems.append(f"{action!r}: needs a description saying when to log it")
    return problems


def check_all(specs) -> None:
    """Raise `EventRuleError` listing every rule broken across `specs`."""
    problems = [problem for spec in specs for problem in check(spec)]
    if problems:
        raise EventRuleError(
            "these events break the Ottu naming rules "
            "(docs/rules/log-events.md):\n  " + "\n  ".join(problems)
        )
