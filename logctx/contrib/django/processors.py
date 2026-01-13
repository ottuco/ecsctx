"""
Django-specific processor wrappers that read configuration from Django settings.

These read Django settings lazily to avoid circular imports during Django bootstrap.
"""


def contextvars_injector(_logger, _method_name, event_dict):
    """
    Structlog processor that injects context from multiple sources.

    Reads MERCHANT_ID from Django settings lazily to avoid import-time
    circular dependency issues.
    """
    # Import lazily to avoid circular imports during Django settings load
    from django.conf import settings

    from logctx.context import get_trace_id
    from logctx.processors import _detect_service, _inject_logging_context
    from structlog.contextvars import get_contextvars
    import contextlib
    import os

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

    # Read from Django settings lazily
    merchant_id = getattr(settings, "MERCHANT_ID", None)
    if merchant_id:
        event_dict["merchant_id"] = merchant_id

    return event_dict