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

REQUIRED in the consuming project: disable sentry-sdk's stdlib event path with
``LoggingIntegration(event_level=None)`` — otherwise the raw pre-formatter
record still ships alongside the masked one (breadcrumbs keep working; native
exception capture via DjangoIntegration etc. is unaffected).
"""

from __future__ import annotations

import logging

try:
    from structlog_sentry import SentryProcessor
except ImportError as exc:
    raise ImportError(
        "ecsctx.contrib.sentry requires structlog-sentry — "
        "install the ecsctx[sentry] extra"
    ) from exc

from ecsctx import error_ecs_fields, mask_sensitive_data


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
    """

    def __init__(self, event_level: int = logging.ERROR):
        self.event_level = event_level

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
            SentryProcessor(event_level=self.event_level),
        ]
        return procs
