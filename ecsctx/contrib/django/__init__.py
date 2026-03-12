"""Django-specific integrations for ecsctx."""

from ecsctx.contrib.django.decorators import api_logging
from ecsctx.contrib.django.logging import (
    CELERY_LOGGERS,
    CELERY_LOGGERS_DEBUG,
    RQ_LOGGERS,
    RQ_LOGGERS_DEBUG,
    configure_structlog,
    get_logging_config,
    setup_logging,
)
from ecsctx.contrib.django.middleware import LoggingContextMiddleware
from ecsctx.contrib.django.processors import contextvars_injector

# LogContextBinder is not imported here to avoid circular imports during Django setup.
# Import it explicitly: from ecsctx.contrib.django.context_binder import LogContextBinder

__all__ = [
    # Middleware
    "LoggingContextMiddleware",
    # Processors
    "contextvars_injector",
    # Logging config
    "get_logging_config",
    "setup_logging",
    "configure_structlog",
    # Logger presets
    "RQ_LOGGERS",
    "RQ_LOGGERS_DEBUG",
    "CELERY_LOGGERS",
    "CELERY_LOGGERS_DEBUG",
    # Decorators
    "api_logging",
]
