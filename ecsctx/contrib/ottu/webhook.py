"""Shared ``webhook.*`` domain: merchant-facing outbound notification.

Transcribed from ticket #159487 (Event catalogue, ``webhook`` table).
``delivery_completed`` keeps base level ``info`` (the ticket's 2xx case);
retryable/error branches override the level at the call site.
"""

from ecsctx.events.spec import EventSpec

WEBHOOK_DELIVERY_ENQUEUED = EventSpec(
    action="webhook.delivery_enqueued",
    required=("payment.reference", "labels.webhook_type"),
)

WEBHOOK_REQUEST_SENT = EventSpec(
    action="webhook.request_sent",
    required=("url.full", "payment.reference", "labels.attempt"),
)

WEBHOOK_DELIVERY_COMPLETED = EventSpec(
    action="webhook.delivery_completed",
    terminal=True,
    required=("event.outcome", "event.duration", "labels.attempt"),
)

WEBHOOK_DELIVERY_RETRIED = EventSpec(
    action="webhook.delivery_retried",
    required=("labels.attempt", "payment.reference"),
)

WEBHOOK_DELIVERY_SKIPPED = EventSpec(
    action="webhook.delivery_skipped",
    terminal=True,
    required=("event.outcome", "event.reason", "payment.reference"),
)

SPECS: tuple[EventSpec, ...] = (
    WEBHOOK_DELIVERY_ENQUEUED,
    WEBHOOK_REQUEST_SENT,
    WEBHOOK_DELIVERY_COMPLETED,
    WEBHOOK_DELIVERY_RETRIED,
    WEBHOOK_DELIVERY_SKIPPED,
)
