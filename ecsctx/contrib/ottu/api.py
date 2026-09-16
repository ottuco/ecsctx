"""Shared ``api.*`` domain: inbound HTTP request/response boundary.

Transcribed from ticket #159487 (Event catalogue, ``api`` table).
``response_sent`` keeps base level ``info`` (the ticket's <400 case);
>=400 branches override the level at the call site.
"""

from ecsctx.events.spec import EventSpec

API_REQUEST_RECEIVED = EventSpec(
    action="api.request_received",
    required=("http.request.method", "url.path", "trace.id"),
)

API_RESPONSE_SENT = EventSpec(
    action="api.response_sent",
    terminal=True,
    required=("event.outcome", "event.duration", "http.response.status_code", "url.path"),
)

API_REQUEST_REJECTED = EventSpec(
    action="api.request_rejected",
    level="warning",
    terminal=True,
    required=("event.outcome", "event.reason", "http.response.status_code"),
)

SPECS: tuple[EventSpec, ...] = (
    API_REQUEST_RECEIVED,
    API_RESPONSE_SENT,
    API_REQUEST_REJECTED,
)
