"""Attach MaskPIIFilter to handlers that ecsctx did not build itself.

get_logging_config() puts the filter in every handler it builds via
dictConfig — that is the default path and needs no consumer code. This
module is the explicit escape hatch for handlers ecsctx never configured:
third-party handlers, hand-built ones, or a logging setup that predates
this feature.

Deliberately does NOT patch logging.Handler or anything else in the
standard library — install_maskers() only sweeps handlers that exist at
the moment it is called. Call it late in settings, after dictConfig/logging
setup has run, so it sees everything. A handler created after the call is
not covered by this layer; it is still covered by the structlog processor
(ecsctx.processors.mask_sensitive_data) when the handler uses ecsctx's
formatter, and reported by the Django system check when it does not.
"""

from __future__ import annotations

import logging

from ecsctx.masking.filters import MaskPIIFilter

_enabled = False


def _has_masker(handler: logging.Handler) -> bool:
    return any(isinstance(f, MaskPIIFilter) for f in handler.filters)


def _iter_handlers():
    seen: set[int] = set()
    for handler in logging.root.handlers:
        if id(handler) not in seen:
            seen.add(id(handler))
            yield handler
    for logger in list(logging.Logger.manager.loggerDict.values()):
        if isinstance(logger, logging.PlaceHolder):
            continue
        for handler in logger.handlers:
            if id(handler) not in seen:
                seen.add(id(handler))
                yield handler


def install_maskers() -> None:
    """Attach a MaskPIIFilter to every handler that exists right now.

    Idempotent — never adds a second filter to a handler that already has
    one, so it is safe to call again after adding more handlers.
    """
    flt = MaskPIIFilter()
    for handler in _iter_handlers():
        if not _has_masker(handler):
            handler.addFilter(flt)
    global _enabled
    _enabled = True


def uninstall_maskers() -> None:
    """Remove any MaskPIIFilter from every handler that has one."""
    for handler in _iter_handlers():
        for flt in [f for f in handler.filters if isinstance(f, MaskPIIFilter)]:
            handler.removeFilter(flt)
    global _enabled
    _enabled = False
