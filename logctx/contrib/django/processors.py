"""
Django-specific processor wrappers.

Note: merchant_id is injected dynamically via LoggingContext.extra
using bind_logging_context(extra={"merchant_id": "..."})
"""

import contextlib
import os

from structlog.contextvars import get_contextvars

from logctx.context import get_trace_id
from logctx.processors import _detect_service, _inject_logging_context


def contextvars_injector(_logger, _method_name, event_dict):
    """
    Structlog processor that injects context from multiple sources.

    Injection order (later sources don't override earlier ones):
    1. Explicit log parameters (already in event_dict)
    2. LoggingContext from decorators/middleware
    3. Structlog contextvars
    4. CID trace_id
    5. Service metadata
    """

    # 1. Inject from LoggingContext (decorators set this)
    event_dict = _inject_logging_context(event_dict)

    # 2. Add trace.id from CID (parses W3C traceparent format)
    with contextlib.suppress(Exception):
        trace_id = get_trace_id()
        if trace_id and "trace" not in event_dict:
            event_dict["trace"] = {"id": trace_id}

    # 3. Add structlog context vars (skip during early startup)
    with contextlib.suppress(Exception):
        context = get_contextvars()
        if context:
            for key, value in context.items():
                if key not in event_dict:
                    event_dict[key] = value

    # 4. Add service metadata (always injected)
    service_name, service_version = _detect_service()
    event_dict["service"] = {
        "name": service_name,
        "version": service_version,
    }
    event_dict["project"] = {
        "name": os.environ.get("PROJECT_NAME", "connect"),
    }

    return event_dict