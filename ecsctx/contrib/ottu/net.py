"""Shared ``net.*`` domain: outbound HTTP to non-PSP upstreams.

Transcribed from ticket #159487 (Event catalogue, ``net`` table).
``response_received`` keeps base level ``info`` (the ticket's 2xx case); a
>=400 branch overrides the level at the call site, because outcome alone
cannot distinguish them.
"""

from ecsctx.events.spec import EventSpec, Reason


class OutboundFailure(Reason):
    """Why an outbound HTTP call failed.

    Shared by `pg.request_failed` and `net.request_failed`: one classifier
    answers for both, and a value that meant something different per domain
    could not be aggregated across them. Ordered from "the upstream said no" to
    "this is our bug".
    """

    HTTP_CLIENT_ERROR = "http_client_error"  # 4xx — the upstream rejected the request
    HTTP_SERVER_ERROR = "http_server_error"  # 5xx — the upstream broke
    TIMEOUT = "timeout"  # connect or read timeout
    CONNECTION_ERROR = "connection_error"  # DNS, TLS, refused
    INVALID_JSON = "invalid_json"  # the body was not the JSON the contract promises
    REQUEST_ERROR = "request_error"  # other requests-level failure (bad URL, redirects)
    UNEXPECTED_ERROR = "unexpected_error"  # anything else: a defect here until proven otherwise


OUTBOUND_FAILURE_REASONS: tuple[OutboundFailure, ...] = tuple(OutboundFailure)

NET_REQUEST_SENT = EventSpec(
    action="net.request_sent",
    description=(
        "An outbound HTTP call to an upstream that is not a PSP (identity provider, PDF "
        "service, another Ottu service) is about to be sent; labels.operation names it."
    ),
    category=("network",),
    type=("connection",),
    required=("labels.operation", "http.request.method", "url.full"),
)

NET_RESPONSE_RECEIVED = EventSpec(
    action="net.response_received",
    description=(
        "The upstream answered; carries the status code and duration. The call site "
        "logs warning from status 400."
    ),
    terminal=True,
    category=("network",),
    type=("connection",),
    required=("event.outcome", "event.duration", "labels.operation", "http.response.status_code"),
)

NET_REQUEST_FAILED = EventSpec(
    action="net.request_failed",
    description=(
        "An outbound call produced no usable answer: a timeout, a connection error, an "
        "error status or invalid JSON."
    ),
    level="error",
    terminal=True,
    category=("network",),
    type=("error",),
    reasons=OutboundFailure,
    required=("event.outcome", "event.reason", "labels.operation", "error.type"),
)

SPECS: tuple[EventSpec, ...] = (
    NET_REQUEST_SENT,
    NET_RESPONSE_RECEIVED,
    NET_REQUEST_FAILED,
)
