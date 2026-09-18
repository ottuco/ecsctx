"""Shared ``net.*`` domain: outbound HTTP to non-PSP upstreams.

Transcribed from ticket #159487 (Event catalogue, ``net`` table).
``response_received`` keeps base level ``info`` (the ticket's 2xx case); a
>=400 branch overrides the level at the call site, because outcome alone
cannot distinguish them.
"""

from ecsctx.events.spec import EventSpec

# Why an outbound HTTP call failed. Shared verbatim by `pg.request_failed` and
# `net.request_failed`: one classifier answers for both, and a value that meant
# something different per domain could not be aggregated across them. Ordered
# from "the upstream said no" to "this is our bug".
OUTBOUND_FAILURE_REASONS: tuple[str, ...] = (
    "http_client_error",  # 4xx — the upstream rejected the request
    "http_server_error",  # 5xx — the upstream broke
    "timeout",  # connect or read timeout
    "connection_error",  # DNS, TLS, refused
    "invalid_json",  # the body was not the JSON the contract promises
    "request_error",  # other requests-level failure (bad URL, too many redirects)
    "unexpected_error",  # anything else: a defect here until proven otherwise
)

NET_REQUEST_SENT = EventSpec(
    action="net.request_sent",
    category=("network",),
    type=("connection",),
    required=("labels.operation", "http.request.method", "url.full"),
)

NET_RESPONSE_RECEIVED = EventSpec(
    action="net.response_received",
    terminal=True,
    category=("network",),
    type=("connection",),
    required=("event.outcome", "event.duration", "labels.operation", "http.response.status_code"),
)

NET_REQUEST_FAILED = EventSpec(
    action="net.request_failed",
    level="error",
    terminal=True,
    category=("network",),
    type=("error",),
    reasons=OUTBOUND_FAILURE_REASONS,
    required=("event.outcome", "event.reason", "labels.operation", "error.type"),
)

SPECS: tuple[EventSpec, ...] = (
    NET_REQUEST_SENT,
    NET_RESPONSE_RECEIVED,
    NET_REQUEST_FAILED,
)
