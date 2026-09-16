"""Shared ``net.*`` domain: outbound HTTP to non-PSP upstreams.

Transcribed from ticket #159487 (Event catalogue, ``net`` table).
``response_received`` keeps base level ``info`` (the ticket's 2xx case); a
>=400 branch overrides the level at the call site, because outcome alone
cannot distinguish them.
"""

from ecsctx.events.spec import EventSpec

NET_REQUEST_SENT = EventSpec(
    action="net.request_sent",
    required=("labels.upstream", "http.request.method", "url.full"),
)

NET_RESPONSE_RECEIVED = EventSpec(
    action="net.response_received",
    terminal=True,
    required=("event.outcome", "event.duration", "labels.upstream", "http.response.status_code"),
)

NET_REQUEST_FAILED = EventSpec(
    action="net.request_failed",
    level="error",
    terminal=True,
    required=("event.outcome", "event.reason", "labels.upstream", "error.type"),
)

SPECS: tuple[EventSpec, ...] = (
    NET_REQUEST_SENT,
    NET_RESPONSE_RECEIVED,
    NET_REQUEST_FAILED,
)
