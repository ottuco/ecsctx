"""
ecsctx - Context-aware structured logging with ECS compliance and distributed tracing.

This package provides framework-agnostic logging utilities:
- Automatic context injection (request_id, user_id, ip, trace_id)
- ECS-compliant output for Elasticsearch compatibility
- PII masking via tokenization
- W3C Trace Context support for distributed tracing

For Django integration, use ecsctx.contrib.django.
"""

from ecsctx.context import (
    LoggingContext,
    bind_logging_context,
    build_traceparent,
    get_logging_context,
    get_trace_id,
    logging_context,
    reset_logging_context,
)
from ecsctx.ecs_validator import ecs_validator
from ecsctx.formatters import ECSFormatter
from ecsctx.pii import (
    PIIAccessDeniedError,
    configure_pii,
    configure_pii_from_env,
    protect,
    reveal,
    tokenize,
)
from ecsctx.pii import is_configured as pii_configured
from ecsctx.processors import (
    configure_masking,
    configure_masking_from_env,
    contextvars_injector,
    mask_sensitive_data,
    namespace_ecs_fields,
    safe_tokenize,
)

__version__ = "0.5.4"

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
    # Masking config
    "configure_masking",
    "configure_masking_from_env",
    "safe_tokenize",
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
