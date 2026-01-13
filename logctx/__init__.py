"""
logctx - Context-aware structured logging for Django with ECS compliance and distributed tracing.

This package provides:
- Automatic context injection via middleware (request_id, user_id, ip, trace_id)
- ECS-compliant output for Elasticsearch compatibility
- PII masking via tokenization
- W3C Trace Context support for distributed tracing
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
from logctx.enums import APIType, Entity, Event, RequestDirection
from logctx.middleware import LoggingContextMiddleware
from logctx.structlog.ecs_validator import ecs_validator
from logctx.structlog.formatters import OttuECSFormatter
from logctx.structlog.loggers import get_logger, ottu_logger
from logctx.structlog.processors import (
    contextvars_injector,
    mask_sensitive_data,
    namespace_ecs_fields,
)

__version__ = "0.1.0"

__all__ = [
    # Context
    "LoggingContext",
    "get_logging_context",
    "get_trace_id",
    "bind_logging_context",
    "reset_logging_context",
    "build_traceparent",
    "logging_context",
    # Enums
    "Entity",
    "Event",
    "RequestDirection",
    "APIType",
    # Middleware
    "LoggingContextMiddleware",
    # Structlog
    "ottu_logger",
    "get_logger",
    "contextvars_injector",
    "mask_sensitive_data",
    "namespace_ecs_fields",
    "OttuECSFormatter",
    "ecs_validator",
    # Version
    "__version__",
]
