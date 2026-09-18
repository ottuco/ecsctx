"""Shared ``card.*`` domain: tokenization and the token vault.

Transcribed from ticket #159487 (Event catalogue, ``card`` table) — this
is also where token lifecycle lives (create/refresh/delete/lookup/dedupe).
``token_deleted`` keeps base level ``info`` (the ticket's success case); a
failed delete overrides the level at the call site.
"""

from ecsctx.events.spec import EventSpec

CARD_TOKENIZATION_COMPLETED = EventSpec(
    action="card.tokenization_completed",
    description=(
        "The gateway was asked to save a card as a token for a session; the outcome "
        "says whether a token came back."
    ),
    terminal=True,
    type=("end",),
    required=("event.outcome", "session_id", "payment.pg_code"),
)

CARD_TOKENIZATION_SKIPPED = EventSpec(
    action="card.tokenization_skipped",
    description=(
        "Card tokenization was not attempted for a session; the reason says why. The "
        "outcome is unknown."
    ),
    terminal=True,
    type=("denied",),
    required=("event.outcome", "event.reason", "session_id"),
)

CARD_TOKEN_UPDATED = EventSpec(
    action="card.token_updated",
    description="A saved card token changed; labels.change says what.",
    terminal=True,
    type=("change",),
    required=("event.outcome", "labels.change", "labels.card_id"),
)

CARD_TOKEN_DELETED = EventSpec(
    action="card.token_deleted",
    description=(
        "A saved card token was deleted; labels.source says who asked. The call site "
        "logs warning when the delete failed."
    ),
    terminal=True,
    type=("deletion",),
    required=("event.outcome", "labels.source"),
)

CARD_TOKEN_LOOKUP_FAILED = EventSpec(
    action="card.token_lookup_failed",
    description="A saved card token could not be found or read; the reason says why.",
    level="warning",
    terminal=True,
    type=("error",),
    failure_level="warning",
    required=("event.outcome", "event.reason"),
)

SPECS: tuple[EventSpec, ...] = (
    CARD_TOKENIZATION_COMPLETED,
    CARD_TOKENIZATION_SKIPPED,
    CARD_TOKEN_UPDATED,
    CARD_TOKEN_DELETED,
    CARD_TOKEN_LOOKUP_FAILED,
)
