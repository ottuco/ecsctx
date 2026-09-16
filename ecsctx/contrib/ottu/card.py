"""Shared ``card.*`` domain: tokenization and the token vault.

Transcribed from ticket #159487 (Event catalogue, ``card`` table) — this
is also where token lifecycle lives (create/refresh/delete/lookup/dedupe).
``token_deleted`` keeps base level ``info`` (the ticket's success case); a
failed delete overrides the level at the call site.
"""

from ecsctx.events.spec import EventSpec

CARD_TOKENIZATION_COMPLETED = EventSpec(
    action="card.tokenization_completed",
    terminal=True,
    required=("event.outcome", "session_id", "payment.pg_code"),
)

CARD_TOKENIZATION_SKIPPED = EventSpec(
    action="card.tokenization_skipped",
    terminal=True,
    required=("event.reason", "session_id"),
)

CARD_TOKEN_UPDATED = EventSpec(
    action="card.token_updated",
    terminal=True,
    required=("labels.change", "labels.card_id"),
)

CARD_TOKEN_DELETED = EventSpec(
    action="card.token_deleted",
    terminal=True,
    required=("event.outcome", "labels.source"),
)

CARD_TOKEN_LOOKUP_FAILED = EventSpec(
    action="card.token_lookup_failed",
    level="warning",
    terminal=True,
    required=("event.outcome", "event.reason"),
)

SPECS: tuple[EventSpec, ...] = (
    CARD_TOKENIZATION_COMPLETED,
    CARD_TOKENIZATION_SKIPPED,
    CARD_TOKEN_UPDATED,
    CARD_TOKEN_DELETED,
    CARD_TOKEN_LOOKUP_FAILED,
)
