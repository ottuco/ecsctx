"""Shared ``api.*`` domain: inbound HTTP request/response boundary.

These are the specs ``ecsctx.events.http`` defines for ``@api_logging``, the
decorator that emits them in every service. One definition, so registering
the catalogue and calling ``register_http_events()`` claim the same ``api``
domain instead of two conflicting ones.
"""

from ecsctx.events.http import (
    API_REQUEST_RECEIVED,
    API_REQUEST_REJECTED,
    API_RESPONSE_SENT,
    HTTP_EVENTS,
)

SPECS = HTTP_EVENTS

__all__ = ["API_REQUEST_RECEIVED", "API_REQUEST_REJECTED", "API_RESPONSE_SENT", "SPECS"]
