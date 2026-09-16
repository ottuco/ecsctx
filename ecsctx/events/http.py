"""The HTTP boundary events the library emits for itself.

ecsctx ships no business vocabulary — that stays in the services (#159490). These
three are the exception, and the reason is narrow: `api_logging` is a decorator
*in this package* that emits two log lines, and a log line that will not name
itself is the defect this whole programme exists to remove. A service cannot
declare an action for a call site it does not own.

They are generic to any Django/DRF service — an HTTP request arriving,
completing, or being refused in-process. The decorator already hardcoded
`category: ["web"]` and `type: ["access"]` for the same reason.

The domain is **not** registered on import. Nothing here needs the registry, and
auto-claiming the `api` prefix would take it from a service that wants to own it.
Call `register_http_events()` from your AppConfig if you run the contract
validator in strict mode and want these to resolve:

    from ecsctx.events.http import register_http_events
    register_http_events()
"""

from ecsctx.events.registry import register_domain
from ecsctx.events.spec import EventSpec

API_REQUEST_RECEIVED = EventSpec(
    action="api.request_received",
    level="info",
    category=("web",),
    type=("access",),
    required=("method", "path"),
    optional=("session_id", "merchant_id", "user_id"),
)

API_RESPONSE_SENT = EventSpec(
    action="api.response_sent",
    level="info",
    terminal=True,
    category=("web",),
    type=("access",),
    required=("method", "path", "status_code"),
)

API_REQUEST_REJECTED = EventSpec(
    action="api.request_rejected",
    level="warning",
    terminal=True,
    category=("web",),
    type=("denied",),
    # Bounded, so "why were requests refused?" is one aggregation rather than a
    # scan of free text. Both are in-process refusals: the view never ran.
    reasons=("throttled", "validation_failed"),
    required=("method", "path", "status_code"),
)

HTTP_EVENTS = (API_REQUEST_RECEIVED, API_RESPONSE_SENT, API_REQUEST_REJECTED)


def register_http_events() -> None:
    """Claim the `api` domain for the events this package emits."""
    register_domain("api", HTTP_EVENTS)
