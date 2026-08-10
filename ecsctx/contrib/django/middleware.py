"""
Logging context middleware for request lifecycle.

Binds span_id, user_id, ip to structlog context for all log events.
Request/response logging is handled by the api_logging decorator.

Note: trace_id is handled by CidMiddleware + structlog processor.
      Request timing is handled by nginx access logs.
"""

import uuid

import sentry_sdk
import structlog
from django.utils.deprecation import MiddlewareMixin
from ipware import get_client_ip

from ecsctx import bind_logging_context, get_trace_id, reset_logging_context

logger = structlog.get_logger(__name__)


class LoggingContextMiddleware(MiddlewareMixin):
    """
    Bind logging context for all requests.

    Context binding: span_id -> span.id, ip -> client.ip, user_id -> user.id
    Request/response logging removed - use api_logging decorator on views.
    """

    def process_request(self, request):
        """Bind span_id and client IP to logging context."""
        # Integrations like LogContextBinder bind structlog contextvars with
        # no reset, and stale bindings outlive their request wherever the
        # execution context is long-lived: a WSGI sync worker reuses one
        # context for every request it serves (request N's session_id/customer
        # show up on request N+1), and under ASGI anything bound outside a
        # request task lands in the base context that every request task
        # copies (stale values show up on all requests). merge_contextvars
        # runs before contextvars_injector (first writer wins), so the stale
        # values would even beat a freshly bound ecsctx context. Start every
        # request from a clean structlog slate.
        structlog.contextvars.clear_contextvars()

        span_id = str(uuid.uuid4())
        request._span_id = span_id

        ip, _ = get_client_ip(request)

        request._logging_context_token = bind_logging_context(
            span_id=span_id,
            ip=str(ip) if ip else None,
        )

        # Set trace_id on Sentry scope (synchronous, before any exceptions)
        # Must be done here because before_send runs in background thread without context
        if trace_id := get_trace_id():
            sentry_sdk.set_tag("trace_id", trace_id)

    def process_view(self, request, view_func, view_args, view_kwargs):
        """Bind user_id to context if authenticated."""
        if hasattr(request, "user") and request.user.is_authenticated:
            user_obj = request.user

            # Rebind context with user object
            token = getattr(request, "_logging_context_token", None)
            if token:
                reset_logging_context(token)
                ip, _ = get_client_ip(request)
                request._logging_context_token = bind_logging_context(
                    span_id=request._span_id,
                    ip=str(ip) if ip else None,
                    user_id=user_obj.pk,
                )

    def process_response(self, request, response):
        """Reset logging context."""
        token = getattr(request, "_logging_context_token", None)
        if token:
            reset_logging_context(token)
        return response

    def process_exception(self, request, exception):
        """Log unhandled exceptions and reset context."""
        logger.exception(
            "unhandled_exception",
            error={"message": str(exception), "type": type(exception).__name__},
            http={
                "request": {"method": request.method},
                "response": {"status_code": 500},
            },
            url={"path": request.path},
            exc_info=exception,
        )

        token = getattr(request, "_logging_context_token", None)
        if token:
            reset_logging_context(token)
            request._logging_context_token = None