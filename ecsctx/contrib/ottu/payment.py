"""Shared ``payment.*`` domain: session/attempt lifecycle, charges, operations.

Transcribed from ticket #159487 (Event catalogue, ``payment`` table).
``state_changed``, ``outcome_resolved``, ``operation_completed`` and
``inquiry_completed`` keep base level ``info`` (the ticket's success case);
a failure-flavoured branch overrides the level at the call site, because
outcome alone cannot distinguish them.
"""

from ecsctx.events.spec import EventSpec

PAYMENT_SESSION_CREATED = EventSpec(
    action="payment.session_created",
    terminal=True,
    required=("event.outcome", "session_id", "merchant_id", "payment.orn"),
)

PAYMENT_ELIGIBILITY_REJECTED = EventSpec(
    action="payment.eligibility_rejected",
    level="warning",
    terminal=True,
    required=("event.outcome", "event.reason", "session_id"),
)

PAYMENT_ATTEMPT_CREATED = EventSpec(
    action="payment.attempt_created",
    terminal=True,
    required=("event.outcome", "session_id", "payment.reference", "payment.pg_code"),
)

PAYMENT_STATE_CHANGED = EventSpec(
    action="payment.state_changed",
    terminal=True,
    required=(
        "event.outcome",
        "session_id",
        "labels.transition",
        "labels.state_from",
        "labels.state_to",
    ),
)

PAYMENT_STATE_CHANGE_SKIPPED = EventSpec(
    action="payment.state_change_skipped",
    level="warning",
    terminal=True,
    required=("event.outcome", "event.reason", "labels.transition", "labels.state_current"),
)

PAYMENT_OUTCOME_RESOLVED = EventSpec(
    action="payment.outcome_resolved",
    terminal=True,
    required=("event.outcome", "labels.resolved_action", "labels.pg_status", "payment.reference"),
)

PAYMENT_CHARGE_REQUESTED = EventSpec(
    action="payment.charge_requested",
    required=("session_id", "payment.reference", "labels.instrument_type"),
)

PAYMENT_CHARGE_COMPLETED = EventSpec(
    action="payment.charge_completed",
    terminal=True,
    required=("event.outcome", "event.duration", "session_id", "labels.instrument_type"),
)

PAYMENT_OPERATION_REQUESTED = EventSpec(
    action="payment.operation_requested",
    required=("labels.operation", "payment.reference"),
)

PAYMENT_OPERATION_COMPLETED = EventSpec(
    action="payment.operation_completed",
    terminal=True,
    required=("event.outcome", "event.duration", "labels.operation", "payment.reference"),
)

PAYMENT_DUPLICATE_SUPPRESSED = EventSpec(
    action="payment.duplicate_suppressed",
    level="warning",
    terminal=True,
    required=("event.outcome", "event.reason", "labels.guard"),
)

PAYMENT_INQUIRY_COMPLETED = EventSpec(
    action="payment.inquiry_completed",
    terminal=True,
    required=("event.outcome", "event.duration", "payment.reference"),
)

SPECS: tuple[EventSpec, ...] = (
    PAYMENT_SESSION_CREATED,
    PAYMENT_ELIGIBILITY_REJECTED,
    PAYMENT_ATTEMPT_CREATED,
    PAYMENT_STATE_CHANGED,
    PAYMENT_STATE_CHANGE_SKIPPED,
    PAYMENT_OUTCOME_RESOLVED,
    PAYMENT_CHARGE_REQUESTED,
    PAYMENT_CHARGE_COMPLETED,
    PAYMENT_OPERATION_REQUESTED,
    PAYMENT_OPERATION_COMPLETED,
    PAYMENT_DUPLICATE_SUPPRESSED,
    PAYMENT_INQUIRY_COMPLETED,
)
