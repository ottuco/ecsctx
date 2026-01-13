"""
Logging utilities and backward-compatible logger instance.

Context injection is handled by:
1. LoggingContextMiddleware binds request_id, user_id, ip
2. Processor (contextvars_injector) injects context into log events

Usage:
    # New code (recommended):
    import structlog
    logger = structlog.get_logger(__name__)

    # Existing code (still works):
    from logctx.structlog.loggers import ottu_logger
    ottu_logger.info("message", key=value)

    # For Entity access:
    from logctx.enums import Entity
    # or
    from logctx.structlog.loggers import entities
"""

import structlog

from logctx.enums import Entity

# Module-level entities for backward compatibility
# Allows: from logctx.structlog.loggers import entities
#         entities.PG.value
entities = Entity

# Create a logger instance
_logger = structlog.get_logger("ottu")


class _LoggerProxy:
    """
    Proxy that adds .entities attribute to a structlog logger.

    This maintains backward compatibility for code using:
        ottu_logger.entities.PG.value
    """

    def __init__(self, logger):
        self._logger = logger
        self.entities = Entity

    def __getattr__(self, name):
        return getattr(self._logger, name)


# Global logger instance for backward compatibility
ottu_logger = _LoggerProxy(_logger)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """
    Get a structlog logger.

    This is the recommended way to get a logger:
        from logctx.structlog.loggers import get_logger
        logger = get_logger(__name__)
    """
    return structlog.get_logger(name)