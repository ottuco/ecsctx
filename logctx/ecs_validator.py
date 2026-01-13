"""ECS field validation processor for structlog.

Warns about ECS reserved field conflicts without blocking log emission.
Uses minimal field subset (~25 critical fields) for fast validation.
"""

import warnings

# ECS reserved top-level fields that MUST be objects/nested, not flat strings
ECS_RESERVED_FIELDS = frozenset({
    # Network/connection (ECS uses for network-level data)
    "source",
    "destination",
    "server",
    "client",
    # Host/system
    "host",
    "container",
    "process",
    "agent",
    "cloud",
    # Event metadata
    "event",
    "error",
    "log",
    "ecs",
    # HTTP/URL (should use http.*, url.*)
    "http",
    "url",
    # Identity
    "user",
    "group",
    # File/network
    "file",
    "network",
    "dns",
    "tls",
    # Tracing
    "trace",
    "span",
    "transaction",
    # Service
    "service",
})

# Our allowed nested usage (these are OK as dicts)
ALLOWED_NESTED = frozenset({
    "request",  # Our custom: request.source, request.target, request.direction
    "payment",  # Our custom: payment.session_id, payment.orn
    "project",  # Our custom: project.name
})

# Fields to skip validation (structlog internals)
SKIP_VALIDATION = frozenset({
    "event",  # structlog's message key (StructlogFormatter converts to 'message')
})


def ecs_validator(_logger, _method_name, event_dict):
    """
    Validate log fields against ECS reserved names.

    Emits Python warnings for conflicts but does NOT block or modify the log.
    This allows devs to see issues in development without breaking production.
    """
    for key, value in event_dict.items():
        # Skip structlog internals and allowed nested fields
        if key in SKIP_VALIDATION or key in ALLOWED_NESTED:
            continue

        # Check if reserved field is used as flat value (not dict)
        if key in ECS_RESERVED_FIELDS and not isinstance(value, dict):
            warnings.warn(
                f"ECS conflict: '{key}' is a reserved field and should be a nested object, "
                f"got {type(value).__name__}. Use '{key}.xxx' structure instead.",
                UserWarning,
                stacklevel=6,
            )

    return event_dict