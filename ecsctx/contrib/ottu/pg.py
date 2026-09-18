"""Shared ``pg.*`` domain: the PSP boundary only.

Transcribed from ticket #159487 (Event catalogue, ``pg`` table). ``category``
is ``network`` throughout — every event here crosses to/from a PSP over the
wire.

``request_failed`` logs at ``warning`` on failure (the expected-4xx case); an
unexpected failure logs at ``error`` at the call site, because outcome alone
cannot distinguish them.
"""

from ecsctx.contrib.ottu.net import OutboundFailure
from ecsctx.events.spec import EventSpec, Reason

PG_REQUEST_SENT = EventSpec(
    action="pg.request_sent",
    category=("network",),
    type=("connection",),
    required=("labels.operation", "payment.pg_code", "http.request.method", "url.full"),
)

PG_RESPONSE_RECEIVED = EventSpec(
    action="pg.response_received",
    terminal=True,
    category=("network",),
    type=("connection",),
    required=(
        "event.outcome",
        "event.duration",
        "labels.operation",
        "http.response.status_code",
    ),
)

PG_REQUEST_FAILED = EventSpec(
    action="pg.request_failed",
    level="warning",
    terminal=True,
    category=("network",),
    type=("error",),
    reasons=OutboundFailure,
    failure_level="warning",
    required=("event.outcome", "event.reason", "error.type", "labels.operation"),
)


class CheckoutFailure(Reason):
    """Why a gateway checkout could not be created."""

    PG_URL_UNAVAILABLE = "pg_url_unavailable"


PG_CHECKOUT_CREATED = EventSpec(
    action="pg.checkout_created",
    terminal=True,
    category=("network",),
    type=("creation",),
    reasons=CheckoutFailure,
    required=("event.outcome", "payment.reference", "payment.pg_code", "session_id"),
)

PG_CALLBACK_RECEIVED = EventSpec(
    action="pg.callback_received",
    category=("network",),
    type=("connection",),
    required=("payment.reference", "payment.pg_code", "url.path"),
)

PG_CALLBACK_ANSWERED = EventSpec(
    action="pg.callback_answered",
    terminal=True,
    category=("network",),
    type=("end",),
    required=("event.outcome", "http.response.status_code", "payment.reference"),
)


class CallbackRejection(Reason):
    """Why a gateway callback was refused."""

    INVALID_SIGNATURE = "invalid_signature"
    DECRYPTION_FAILED = "decryption_failed"
    MISSING_SIGNATURE = "missing_signature"
    ATTEMPT_NOT_FOUND = "attempt_not_found"
    MALFORMED_PAYLOAD = "malformed_payload"


PG_CALLBACK_REJECTED = EventSpec(
    action="pg.callback_rejected",
    level="warning",
    terminal=True,
    category=("network",),
    type=("denied",),
    reasons=CallbackRejection,
    failure_level="warning",
    required=("event.outcome", "event.reason", "url.path"),
)


class CallbackSkip(Reason):
    """Why a valid gateway callback changed nothing."""

    ALREADY_FINAL = "already_final"
    DUPLICATE = "duplicate"
    NOT_APPLICABLE = "not_applicable"


PG_CALLBACK_SKIPPED = EventSpec(
    action="pg.callback_skipped",
    terminal=True,
    category=("network",),
    type=("denied",),
    reasons=CallbackSkip,
    required=("event.outcome", "event.reason", "payment.reference"),
)

PG_SIGNATURE_VERIFICATION_SKIPPED = EventSpec(
    action="pg.signature_verification_skipped",
    level="warning",
    terminal=True,
    category=("network",),
    type=("denied",),
    failure_level="warning",
    required=("event.outcome", "payment.pg_code"),
)

PG_CREDENTIALS_UNAVAILABLE = EventSpec(
    action="pg.credentials_unavailable",
    level="error",
    terminal=True,
    category=("network",),
    type=("error",),
    required=("event.outcome", "event.reason", "payment.pg_code", "error.type"),
)

SPECS: tuple[EventSpec, ...] = (
    PG_REQUEST_SENT,
    PG_RESPONSE_RECEIVED,
    PG_REQUEST_FAILED,
    PG_CHECKOUT_CREATED,
    PG_CALLBACK_RECEIVED,
    PG_CALLBACK_ANSWERED,
    PG_CALLBACK_REJECTED,
    PG_CALLBACK_SKIPPED,
    PG_SIGNATURE_VERIFICATION_SKIPPED,
    PG_CREDENTIALS_UNAVAILABLE,
)
