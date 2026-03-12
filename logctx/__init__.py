"""
logctx - Context-aware structured logging with ECS compliance and distributed tracing.

This package provides framework-agnostic logging utilities:
- Automatic context injection (request_id, user_id, ip, trace_id)
- ECS-compliant output for Elasticsearch compatibility
- PII masking via tokenization
- W3C Trace Context support for distributed tracing

For Django integration, use logctx.contrib.django.
"""

from logctx.context import (
    LoggingContext,
    bind_logging_context,
    build_traceparent,
    get_logging_context,
    get_trace_id,
    logging_context,
    reset_logging_context,
)
from logctx.ecs_validator import ecs_validator
from logctx.formatters import ECSFormatter
from logctx.pii import (
    PIIAccessDeniedError,
    configure_pii,
    configure_pii_from_env,
    protect,
    reveal,
    tokenize,
)
from logctx.pii import is_configured as pii_configured
from logctx.processors import (
    contextvars_injector,
    mask_sensitive_data,
    namespace_ecs_fields,
)

__version__ = "0.4.0"

__all__ = [
    # Context
    "LoggingContext",
    "get_logging_context",
    "get_trace_id",
    "bind_logging_context",
    "reset_logging_context",
    "build_traceparent",
    "logging_context",
    # Formatters
    "ECSFormatter",
    # Processors
    "contextvars_injector",
    "mask_sensitive_data",
    "namespace_ecs_fields",
    "ecs_validator",
    # PII
    "configure_pii",
    "configure_pii_from_env",
    "pii_configured",
    "tokenize",
    "protect",
    "reveal",
    "PIIAccessDeniedError",
    # Version
    "__version__",
]
