"""
Pre-built Django LOGGING configuration for plug-and-play setup.

Usage in settings.py:
    from ecsctx.contrib.django.logging import get_logging_config, setup_logging
    LOGGING = get_logging_config()
    setup_logging()

    # With RQ task queue:
    from ecsctx.contrib.django.logging import (
        get_logging_config, setup_logging, RQ_LOGGERS,
    )
    LOGGING = get_logging_config(loggers=RQ_LOGGERS)
    setup_logging()

    # With Celery:
    from ecsctx.contrib.django.logging import (
        get_logging_config, setup_logging, CELERY_LOGGERS,
    )
    LOGGING = get_logging_config(loggers=CELERY_LOGGERS)
    setup_logging()

    # Custom loggers:
    LOGGING = get_logging_config(loggers={
        "myapp": {"level": "DEBUG", "propagate": True},
        **RQ_LOGGERS,
    })
"""

from __future__ import annotations

import logging
from typing import Protocol

import structlog

from ecsctx import (
    ECSFormatter,
    callsite_ecs_fields,
    error_ecs_fields,
    ecs_validator,
    mask_sensitive_data,
    namespace_ecs_fields,
)
from ecsctx.contrib.django.processors import contextvars_injector
from ecsctx.masking.install import install_maskers_in_config

# =============================================================================
# LOGGER PRESETS
# =============================================================================

RQ_LOGGERS: dict = {
    "rq": {
        "level": "WARNING",
        "propagate": True,
    },
    "rq.worker": {
        "level": "WARNING",
        "propagate": True,
    },
}

RQ_LOGGERS_DEBUG: dict = {
    "rq": {
        "level": "INFO",
        "propagate": True,
    },
    "rq.worker": {
        "level": "INFO",
        "propagate": True,
    },
}

CELERY_LOGGERS: dict = {
    "celery": {
        "level": "WARNING",
        "propagate": True,
    },
    "celery.task": {
        "level": "WARNING",
        "propagate": True,
    },
    "celery.worker": {
        "level": "WARNING",
        "propagate": True,
    },
}

CELERY_LOGGERS_DEBUG: dict = {
    "celery": {
        "level": "INFO",
        "propagate": True,
    },
    "celery.task": {
        "level": "INFO",
        "propagate": True,
    },
    "celery.worker": {
        "level": "INFO",
        "propagate": True,
    },
}


# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

def get_logging_config(
    root_level: str = "INFO",
    handler_level: str = "DEBUG",
    use_cid_filter: bool = True,
    loggers: dict | None = None,
) -> dict:
    """
    Returns a complete Django LOGGING configuration dict.

    Args:
        root_level: Log level for root logger (default: INFO)
        handler_level: Minimum level for console handler (default: DEBUG)
        use_cid_filter: Whether to add CID correlation filter (default: True)
        loggers: Additional logger configurations to merge (use presets like
            RQ_LOGGERS, CELERY_LOGGERS)

    Returns:
        Complete LOGGING dict ready to use in Django settings. "mask_pii_filter"
        is wired into LOGGING["filters"] and every handler built here (via
        ecsctx.masking.install_maskers_in_config) — masking already runs twice
        over for records this config's own console handler emits (once via
        this filter, once via the mask_sensitive_data processor already in
        the formatter chain — proven idempotent, not a bug), but it's what
        makes ecsctx.contrib.django.checks' boot-time system check pass
        without an extra install_maskers() call, and it's the only masking
        layer that reaches a handler this LOGGING dict builds if a project
        later swaps in a different formatter.

    Example:
        # Basic usage
        LOGGING = get_logging_config()

        # With RQ
        LOGGING = get_logging_config(loggers=RQ_LOGGERS)

        # With Celery in debug mode
        LOGGING = get_logging_config(loggers=CELERY_LOGGERS_DEBUG)

        # Multiple presets + custom
        LOGGING = get_logging_config(loggers={
            **RQ_LOGGERS,
            "myapp.api": {"level": "DEBUG", "propagate": True},
        })
    """
    filters = {}
    handler_filters = []

    if use_cid_filter:
        filters["correlation"] = {"()": "cid.log.CidContextFilter"}
        handler_filters = ["correlation"]

    config = {
        "version": 1,
        "disable_existing_loggers": False,
        "filters": filters,
        "formatters": {
            "structlog_formatter": {
                "()": structlog.stdlib.ProcessorFormatter,
                "processors": [
                    structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                    structlog.processors.ExceptionRenderer(),
                    namespace_ecs_fields,
                    mask_sensitive_data,
                    ecs_validator,
                    ECSFormatter(),
                ],
                "foreign_pre_chain": [
                    structlog.contextvars.merge_contextvars,
                    structlog.processors.TimeStamper(fmt="iso"),
                    structlog.stdlib.add_logger_name,
                    structlog.stdlib.PositionalArgumentsFormatter(),
                    structlog.processors.CallsiteParameterAdder(
                        parameters=[
                            structlog.processors.CallsiteParameter.FUNC_NAME,
                            structlog.processors.CallsiteParameter.LINENO,
                            structlog.processors.CallsiteParameter.PATHNAME,
                        ]
                    ),
                    callsite_ecs_fields,
                    error_ecs_fields,
                    contextvars_injector,
                    namespace_ecs_fields,
                    mask_sensitive_data,
                    ecs_validator,
                ],
            },
        },
        "handlers": {
            "console": {
                "level": handler_level,
                "filters": handler_filters,
                "class": "logging.StreamHandler",
                "formatter": "structlog_formatter",
            },
        },
        "loggers": {
            "django.request": {
                "level": "ERROR",
                "propagate": True,
            },
            "py.warnings": {
                "level": "WARNING",
                "propagate": True,
            },
        },
        "root": {
            "handlers": ["console"],
            "level": root_level,
        },
    }

    # Merge custom/preset loggers
    if loggers:
        config["loggers"].update(loggers)

    install_maskers_in_config(config)

    return config


class ChainIntegration(Protocol):
    """
    An object that installs itself into the native processor chain.

    ecsctx core stays vendor-neutral: it only folds integrations over the
    default chain. Each integration owns its placement rule and validation
    (implementations live under ``ecsctx.contrib.*``).
    """

    def install(self, processors: list) -> list: ...


def default_processors() -> list:
    """The standard native-chain processors, in execution order."""
    return [
        structlog.contextvars.merge_contextvars,
        contextvars_injector,
        structlog.processors.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.CallsiteParameterAdder(
            parameters=[
                structlog.processors.CallsiteParameter.FUNC_NAME,
                structlog.processors.CallsiteParameter.LINENO,
                structlog.processors.CallsiteParameter.PATHNAME,
            ]
        ),
        callsite_ecs_fields,
        error_ecs_fields,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.ExceptionRenderer(),
        structlog.processors.format_exc_info,
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
    ]


def configure_structlog(integrations: list[ChainIntegration] | None = None):
    """
    Configure structlog with standard processors.

    Call this in settings.py after LOGGING is set up:
        configure_structlog()

    Args:
        integrations: ChainIntegration objects, each applied to the default
            chain via ``install(processors) -> list``. Default: none, chain
            unchanged. Example:
                configure_structlog(integrations=[SentryIntegration()])
    """
    processors = default_processors()
    for integration in integrations or ():
        processors = integration.install(processors)

    structlog.configure(
        processors=processors,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def setup_logging(
    capture_warnings: bool = True,
    integrations: list[ChainIntegration] | None = None,
):
    """
    Complete logging setup helper.

    Call after setting LOGGING in settings.py:
        LOGGING = get_logging_config()
        setup_logging()

    Args:
        capture_warnings: Route Python warnings through logging (default: True)
        integrations: See configure_structlog()
    """
    # NB: do NOT bridge ECSCTX_MASK_EXEMPT_PATHS from Django settings here.
    # setup_logging() is documented to be called from settings.py, i.e. while the
    # settings module is still importing. Reading django.conf.settings at that
    # point forces an early settings._setup(), which caches a *partial* settings
    # object (everything defined after the setup_logging() call is lost) and
    # breaks the whole app. The exemptions are bridged lazily at log time instead
    # (contextvars_injector -> _auto_configure_masking), when settings are ready.
    configure_structlog(integrations=integrations)
    if capture_warnings:
        logging.captureWarnings(True)
