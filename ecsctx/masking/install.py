"""Attach MaskPIIFilter to handlers — both dict-configured and live ones.

install_maskers_in_config() takes the LOGGING config dict (the one
get_logging_config() returns, before dictConfig() runs on it) and injects
the filter definition into it: adds "mask_pii_filter" to filters and
references it from every handler whose formatter does not already run
mask_sensitive_data — a handler whose formatter masks would only be masked
twice. Call it before dictConfig() so the handlers dictConfig builds carry
the filter from the start.

install_maskers_on_handlers() sweeps any handler that already exists as a
live object right now (third-party handlers, hand-built ones, or a logging
setup that predates this feature), skipping the same formatter-masked ones
— the explicit escape hatch for handlers ecsctx never configured. Deliberately does NOT patch logging.Handler or
anything else in the standard library — only handlers that exist at the
moment it is called are covered. A handler created after the call and
outside the LOGGING dict is not covered by this layer; it is still covered
by the structlog processor (ecsctx.processors.mask_sensitive_data) when the
handler uses ecsctx's formatter, and reported by the Django system check
when it does not.

install_maskers() is the full install: it calls both of the above.

uninstall_maskers_in_config(), uninstall_maskers_on_handlers(), and
uninstall_maskers() are the reverse of each.
"""

from __future__ import annotations

import logging

from ecsctx.masking.filters import MaskPIIFilter


def _has_masker(handler: logging.Handler) -> bool:
    return any(isinstance(f, MaskPIIFilter) for f in handler.filters)


def _masks(processors) -> bool:
    # Imported here: ecsctx.processors imports this package.
    from ecsctx.processors import mask_sensitive_data

    return any(p is mask_sensitive_data for p in processors or ())


def formatter_config_masks(formatter_config: dict) -> bool:
    """True if a LOGGING formatter entry runs mask_sensitive_data itself —
    structlog's ProcessorFormatter with it in `processors`, which every
    record (structlog or stdlib) passes through."""
    return _masks(formatter_config.get("processors"))


def formatter_masks(formatter: logging.Formatter | None) -> bool:
    """The live-object counterpart of formatter_config_masks."""
    return _masks(getattr(formatter, "processors", None))


def masking_formatter_names(logging_config: dict) -> set[str]:
    return {
        name
        for name, formatter_config in logging_config.get("formatters", {}).items()
        if isinstance(formatter_config, dict) and formatter_config_masks(formatter_config)
    }


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


def install_maskers_in_config(logging_config: dict) -> None:
    """Wire "mask_pii_filter" into logging_config's filters and reference
    it from every handler whose formatter does not already mask. Idempotent
    — never adds it twice to the same handler.

    A handler formatted by a ProcessorFormatter that runs
    mask_sensitive_data is left without the filter: its formatter masks every
    record, and a second pass would only cost CPU.
    """
    filters = logging_config.setdefault("filters", {})
    filters["mask_pii_filter"] = {"()": "ecsctx.masking.filters.MaskPIIFilter"}
    masked_by_formatter = masking_formatter_names(logging_config)
    for handler_config in logging_config.get("handlers", {}).values():
        if handler_config.get("formatter") in masked_by_formatter:
            continue
        handler_filters = handler_config.setdefault("filters", [])
        if "mask_pii_filter" not in handler_filters:
            handler_filters.append("mask_pii_filter")


def install_maskers_on_handlers() -> None:
    """Attach a MaskPIIFilter to every live handler that exists right now.

    Idempotent — never adds a second filter to a handler that already has
    one.
    """
    flt = MaskPIIFilter()
    for handler in _iter_handlers():
        if not _has_masker(handler) and not formatter_masks(handler.formatter):
            handler.addFilter(flt)


def install_maskers(logging_config: dict) -> None:
    """Full install: wire the filter into logging_config and sweep every
    live handler that exists right now."""
    install_maskers_in_config(logging_config)
    install_maskers_on_handlers()


def uninstall_maskers_in_config(logging_config: dict) -> None:
    """Remove "mask_pii_filter" from logging_config's filters and from
    every handler that references it."""
    logging_config.get("filters", {}).pop("mask_pii_filter", None)
    for handler_config in logging_config.get("handlers", {}).values():
        handler_filters = handler_config.get("filters", [])
        if "mask_pii_filter" in handler_filters:
            handler_filters.remove("mask_pii_filter")


def uninstall_maskers_on_handlers() -> None:
    """Remove any MaskPIIFilter from every live handler that has one."""
    for handler in _iter_handlers():
        for flt in [f for f in handler.filters if isinstance(f, MaskPIIFilter)]:
            handler.removeFilter(flt)


def uninstall_maskers(logging_config: dict) -> None:
    """Full uninstall: remove the filter from logging_config and from
    every live handler that has one."""
    uninstall_maskers_in_config(logging_config)
    uninstall_maskers_on_handlers()
