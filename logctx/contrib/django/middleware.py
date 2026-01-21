"""
Logging context middleware for request lifecycle.

Binds span_id, user_id, ip to structlog context for all log events.
Request/response logging is handled by the api_logging decorator.

Note: trace_id is handled by CidMiddleware + structlog processor.
      Request timing is handled by nginx access logs.
"""

import uuid

from django.utils.deprecation import MiddlewareMixin
from ipware import get_client_ip
import sentry_sdk
import structlog

from logctx import bind_logging_context, get_trace_id, reset_logging_context

logger = structlog.get_logger(__name__)


class LoggingContextMiddleware(MiddlewareMixin):
    """
    Bind logging context for all requests.

    Context binding: span_id -> span.id, ip -> client.ip, user_id -> user.id
    Request/response logging removed - use api_logging decorator on views.
    """

    def process_request(self, request):
        """Bind span_id and client IP to logging context."""
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
        """Bind user object to context if authenticated for automatic serialization."""
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
                    user=user_obj,
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
            f"unhandled_exception {exception}",
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