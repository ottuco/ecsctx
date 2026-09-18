"""The HTTP boundary events the library emits for itself.

The shared business vocabulary lives in ``ecsctx.contrib.ottu``; these three
are defined here, in the core, for a narrow reason: `api_logging` is a decorator
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
from ecsctx.events.spec import EventSpec, Reason

API_REQUEST_RECEIVED = EventSpec(
    action="api.request_received",
    description=(
        "An inbound request reached the API, before the view runs. Closed by "
        "api.response_sent, or api.request_rejected if it never reaches the view."
    ),
    level="info",
    category=("web",),
    type=("access",),
    required=("http.request.method", "url.path", "trace.id"),
    optional=("session_id", "merchant_id", "user.id"),
)

API_RESPONSE_SENT = EventSpec(
    action="api.response_sent",
    description=(
        "The view answered. Success below status 400, failure from 400; carries the "
        "status code and duration. The call site logs warning from 400 and error from "
        "500."
    ),
    level="info",
    terminal=True,
    category=("web",),
    type=("access",),
    required=("event.outcome", "event.duration", "http.response.status_code", "url.path"),
)


class ApiRejection(Reason):
    """Why a request was refused at the boundary.

    Bounded, so "why were requests refused?" is one aggregation rather than a
    scan of free text. All are in-process refusals: the view never ran. A
    header gate is one more place a request is refused before the view, so it
    reports here rather than under an action of its own.
    """

    THROTTLED = "throttled"
    VALIDATION_FAILED = "validation_failed"
    MISSING_HEADER = "missing_header"  # an integration that never sent it
    INVALID_HEADER = "invalid_header"  # sent, and the validator refused the value


API_REQUEST_REJECTED = EventSpec(
    action="api.request_rejected",
    description=(
        "A request was refused before the view ran: throttled, invalid input, or a "
        "required header missing or invalid. Always a failure."
    ),
    level="warning",
    terminal=True,
    category=("web",),
    type=("denied",),
    reasons=ApiRejection,
    # A refusal is the expected outcome of this event: warning, not error.
    failure_level="warning",
    required=("event.outcome", "event.reason", "http.response.status_code"),
)

HTTP_EVENTS = (API_REQUEST_RECEIVED, API_RESPONSE_SENT, API_REQUEST_REJECTED)


def register_http_events() -> None:
    """Claim the `api` domain for the events this package emits."""
    register_domain("api", HTTP_EVENTS)
