"""
Pre-built Django LOGGING configuration for plug-and-play setup.

Usage in settings.py:
    from logctx.contrib.django.logging import get_logging_config, setup_logging
    LOGGING = get_logging_config()
    setup_logging()

    # With RQ task queue:
    from logctx.contrib.django.logging import get_logging_config, setup_logging, RQ_LOGGERS
    LOGGING = get_logging_config(loggers=RQ_LOGGERS)
    setup_logging()

    # With Celery:
    from logctx.contrib.django.logging import get_logging_config, setup_logging, CELERY_LOGGERS
    LOGGING = get_logging_config(loggers=CELERY_LOGGERS)
    setup_logging()

    # Custom loggers:
    LOGGING = get_logging_config(loggers={
        "myapp": {"level": "DEBUG", "propagate": True},
        **RQ_LOGGERS,
    })
"""

import logging

import structlog

from logctx import ECSFormatter, ecs_validator, mask_sensitive_data, namespace_ecs_fields
from logctx.contrib.django.processors import contextvars_injector


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
        loggers: Additional logger configurations to merge (use presets like RQ_LOGGERS, CELERY_LOGGERS)

    Returns:
        Complete LOGGING dict ready to use in Django settings.

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

    return config


def configure_structlog():
    """
    Configure structlog with standard processors.

    Call this in settings.py after LOGGING is set up:
        configure_structlog()
    """
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def setup_logging(capture_warnings: bool = True):
    """
    Complete logging setup helper.

    Call after setting LOGGING in settings.py:
        LOGGING = get_logging_config()
        setup_logging()

    Args:
        capture_warnings: Route Python warnings through logging (default: True)
    """
    configure_structlog()
    if capture_warnings:
        logging.captureWarnings(True)