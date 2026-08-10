"""
In-chain Sentry event capture for the native structlog pipeline.

sentry-sdk's stdlib LoggingIntegration hooks logging.Logger.callHandlers and
reads the raw pre-formatter ``record.msg`` — for structlog records that is the
whole event dict, so events arrive as an unreadable dict repr and top-level
``payload`` / ``args`` / ``kwargs`` / ``headers`` reach Sentry unmasked (the
formatter masks a shallow copy). SentryIntegration replaces that path: it runs
inside the chain, on masked data, while ``exc_info`` is still present.

Usage in settings.py (requires the ``ecsctx[sentry]`` extra):
    from ecsctx.contrib.sentry import SentryIntegration
    setup_logging(integrations=[SentryIntegration()])

REQUIRED in the consuming project: disable sentry-sdk's stdlib paths with
``LoggingIntegration(level=None, event_level=None)`` — otherwise the raw
pre-formatter record still ships alongside the masked one. Both are needed:
``event_level`` stops the duplicate event, ``level`` stops the breadcrumb that
carries the same unmasked dict. This integration supplies both, masked. Native
exception capture via DjangoIntegration etc. is unaffected.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable

try:
    from structlog_sentry import SentryProcessor
except ImportError as exc:
    raise ImportError(
        "ecsctx.contrib.sentry requires structlog-sentry — "
        "install the ecsctx[sentry] extra"
    ) from exc

from ecsctx import error_ecs_fields, mask_sensitive_data

# LoggingContextMiddleware.process_exception logs every unhandled exception so
# it reaches the log pipeline. Sentry already receives that same exception
# natively (DjangoIntegration hooks got_request_exception), so capturing the log
# call as well files two issues for one 500 — a readable duplicate is still a
# duplicate. Ignored by default; pass ignore_loggers explicitly to override.
DEFAULT_IGNORE_LOGGERS: tuple[str, ...] = ("ecsctx.contrib.django.middleware",)


class SentryIntegration:
    """
    Masked Sentry events from inside the native chain.

    install() inserts mask_sensitive_data + SentryProcessor as an adjacent
    pair directly before error_ecs_fields: that is the last spot where
    exc_info is still present (error_ecs_fields pops it, so this is what
    attaches a real exception to the Sentry event) and the event is already
    context/callsite-enriched. Masking first means Sentry never receives
    unmasked containers; the formatter-stage masking re-runs later and is
    idempotent.

    Args:
        event_level: Minimum level that becomes a Sentry event (default:
            ERROR). Lower levels are recorded as breadcrumbs only.
        level: Minimum level recorded as a Sentry breadcrumb (default: INFO).
            Breadcrumbs are attached to whatever event ships next.
        ignore_loggers: Logger names whose events and breadcrumbs are dropped.
            Default: DEFAULT_IGNORE_LOGGERS. Pass an empty iterable to capture
            everything.
    """

    def __init__(
        self,
        event_level: int = logging.ERROR,
        level: int = logging.INFO,
        ignore_loggers: Iterable[str] | None = None,
    ):
        self.event_level = event_level
        self.level = level
        self.ignore_loggers = (
            DEFAULT_IGNORE_LOGGERS
            if ignore_loggers is None
            else tuple(ignore_loggers)
        )

    def install(self, processors: list) -> list:
        if any(isinstance(p, SentryProcessor) for p in processors):
            raise ValueError(
                "SentryIntegration is already installed in this chain — "
                "installing twice would send every event to Sentry twice"
            )
        procs = list(processors)
        try:
            idx = procs.index(error_ecs_fields)
        except ValueError:
            raise ValueError(
                "SentryIntegration needs a chain containing "
                "ecsctx.error_ecs_fields — Sentry capture must run while "
                "exc_info is still present"
            ) from None
        procs[idx:idx] = [
            mask_sensitive_data,
            SentryProcessor(
                event_level=self.event_level,
                level=self.level,
                ignore_loggers=self.ignore_loggers,
            ),
        ]
        return procs
