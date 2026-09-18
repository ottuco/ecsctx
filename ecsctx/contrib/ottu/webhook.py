"""Shared ``webhook.*`` domain: merchant-facing outbound notification.

Transcribed from ticket #159487 (Event catalogue, ``webhook`` table).
``delivery_completed`` keeps base level ``info`` (the 2xx case); an error
branch overrides the level at the call site. ``delivery_retried`` is
``warning``: a retry means the merchant's endpoint failed once already.
"""

from ecsctx.events.spec import EventSpec, Reason

WEBHOOK_DELIVERY_ENQUEUED = EventSpec(
    action="webhook.delivery_enqueued",
    category=("network",),
    type=("creation",),
    required=("payment.reference", "labels.webhook_type"),
)

WEBHOOK_REQUEST_SENT = EventSpec(
    action="webhook.request_sent",
    category=("network",),
    type=("connection",),
    required=("url.full", "payment.reference", "labels.attempt"),
)


class WebhookFailure(Reason):
    """Why a delivery to the merchant's endpoint failed.

    Shared by the final attempt and each retry.
    """

    TIMEOUT = "timeout"
    HTTP_ERROR = "http_error"
    CONNECTION_FAILED = "connection_failed"
    INVALID_REQUEST = "invalid_request"
    JOB_TIMEOUT = "job_timeout"
    UNEXPECTED_ERROR = "unexpected_error"


WEBHOOK_DELIVERY_COMPLETED = EventSpec(
    action="webhook.delivery_completed",
    terminal=True,
    category=("network",),
    type=("end",),
    reasons=WebhookFailure,
    required=("event.outcome", "event.duration", "labels.attempt"),
)

WEBHOOK_DELIVERY_RETRIED = EventSpec(
    action="webhook.delivery_retried",
    level="warning",
    category=("network",),
    type=("info",),
    reasons=WebhookFailure,
    required=("labels.attempt", "payment.reference"),
)


class WebhookSkip(Reason):
    """Why no delivery was attempted."""

    OPERATIONS_NOT_CONFIGURED = "operations_not_configured"


WEBHOOK_DELIVERY_SKIPPED = EventSpec(
    action="webhook.delivery_skipped",
    terminal=True,
    category=("network",),
    type=("denied",),
    reasons=WebhookSkip,
    required=("event.outcome", "event.reason", "payment.reference"),
)

SPECS: tuple[EventSpec, ...] = (
    WEBHOOK_DELIVERY_ENQUEUED,
    WEBHOOK_REQUEST_SENT,
    WEBHOOK_DELIVERY_COMPLETED,
    WEBHOOK_DELIVERY_RETRIED,
    WEBHOOK_DELIVERY_SKIPPED,
)
