"""Tests for ecsctx.masking.install: install_maskers()/uninstall_maskers()
and their config-dict / live-handler variants."""

import logging

import pytest

from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.install import (
    _has_masker,
    install_maskers,
    install_maskers_in_config,
    install_maskers_on_handlers,
    uninstall_maskers,
    uninstall_maskers_in_config,
    uninstall_maskers_on_handlers,
)


@pytest.fixture
def logging_state():
    """Snapshot and restore process-wide logging state.

    install_maskers_on_handlers() / uninstall_maskers_on_handlers() touch
    *every* live handler in the process, not just the one a test made — and
    logging is a module-level singleton nothing resets between tests. So any
    test that calls them must put the handlers, the loggers, and their filter
    lists back the way it found them.
    """
    manager = logging.Logger.manager
    known_names = set(manager.loggerDict)
    loggers = [logging.root] + [
        lg for lg in manager.loggerDict.values() if isinstance(lg, logging.Logger)
    ]
    saved_handlers = [(lg, list(lg.handlers)) for lg in loggers]
    saved_filters = {}
    for lg in loggers:
        for handler in lg.handlers:
            saved_filters.setdefault(id(handler), (handler, list(handler.filters)))

    yield

    for name in list(manager.loggerDict):
        if name not in known_names:
            del manager.loggerDict[name]
    for logger, handlers in saved_handlers:
        logger.handlers = list(handlers)
    for handler, filters in saved_filters.values():
        handler.filters = list(filters)


def _count_maskers(handler):
    return sum(1 for f in handler.filters if isinstance(f, MaskPIIFilter))


class TestInstallMaskersInConfig:
    def test_adds_filter_definition(self):
        cfg = {"filters": {}, "handlers": {"console": {"class": "logging.StreamHandler", "filters": []}}}
        install_maskers_in_config(cfg)
        assert cfg["filters"]["mask_pii_filter"] == {"()": "ecsctx.masking.filters.MaskPIIFilter"}

    def test_references_filter_from_every_handler(self):
        cfg = {
            "filters": {},
            "handlers": {
                "console": {"class": "logging.StreamHandler", "filters": []},
                "file": {"class": "logging.FileHandler", "filters": ["other"]},
            },
        }
        install_maskers_in_config(cfg)
        assert "mask_pii_filter" in cfg["handlers"]["console"]["filters"]
        assert cfg["handlers"]["file"]["filters"] == ["other", "mask_pii_filter"]

    def test_idempotent_does_not_add_twice(self):
        cfg = {"filters": {}, "handlers": {"console": {"class": "logging.StreamHandler", "filters": []}}}
        install_maskers_in_config(cfg)
        install_maskers_in_config(cfg)
        assert cfg["handlers"]["console"]["filters"].count("mask_pii_filter") == 1

    def test_creates_missing_filters_key(self):
        """A handler config without its own 'filters' list gets one."""
        cfg = {"handlers": {"console": {"class": "logging.StreamHandler"}}}
        install_maskers_in_config(cfg)
        assert cfg["handlers"]["console"]["filters"] == ["mask_pii_filter"]


class TestUninstallMaskersInConfig:
    def test_removes_filter_definition_and_references(self):
        cfg = {"filters": {}, "handlers": {"console": {"class": "logging.StreamHandler", "filters": []}}}
        install_maskers_in_config(cfg)
        uninstall_maskers_in_config(cfg)
        assert "mask_pii_filter" not in cfg["filters"]
        assert "mask_pii_filter" not in cfg["handlers"]["console"]["filters"]

    def test_noop_on_config_without_masker(self):
        cfg = {"filters": {}, "handlers": {"console": {"class": "logging.StreamHandler", "filters": []}}}
        uninstall_maskers_in_config(cfg)  # must not raise
        assert cfg["filters"] == {}

    def test_noop_on_handler_without_filters_key(self):
        """A handler config that never declared 'filters' is left untouched —
        uninstall must not raise, and must not invent an empty list."""
        cfg = {"filters": {}, "handlers": {"console": {"class": "logging.StreamHandler"}}}
        uninstall_maskers_in_config(cfg)
        assert cfg["handlers"]["console"] == {"class": "logging.StreamHandler"}

    def test_leaves_other_filters_in_place(self):
        cfg = {"filters": {}, "handlers": {"console": {"class": "logging.StreamHandler", "filters": ["other"]}}}
        install_maskers_in_config(cfg)
        uninstall_maskers_in_config(cfg)
        assert cfg["handlers"]["console"]["filters"] == ["other"]


class TestInstallMaskersOnHandlers:
    def _handler(self):
        h = logging.StreamHandler()
        logging.getLogger("ecsctx-install-test").addHandler(h)
        return h

    def test_attaches_masker_to_live_handler(self, logging_state):
        h = self._handler()
        assert not _has_masker(h)
        install_maskers_on_handlers()
        assert _has_masker(h)

    def test_idempotent_does_not_double_attach(self, logging_state):
        h = self._handler()
        install_maskers_on_handlers()
        install_maskers_on_handlers()
        assert _count_maskers(h) == 1

    def test_uninstall_removes_from_live_handler(self, logging_state):
        h = self._handler()
        install_maskers_on_handlers()
        assert _has_masker(h)
        uninstall_maskers_on_handlers()
        assert not _has_masker(h)

    def test_does_not_touch_a_handler_created_afterward(self, logging_state):
        """install_maskers_on_handlers() deliberately does not patch the
        stdlib — only handlers that exist at call time are covered."""
        install_maskers_on_handlers()
        h = self._handler()
        assert not _has_masker(h)


class TestIterHandlers:
    def test_handler_shared_by_several_loggers_is_swept_once(self, logging_state):
        """One handler attached to multiple loggers (and root) must not
        collect a stack of duplicate filters."""
        handler = logging.StreamHandler()
        logging.getLogger("ecsctx-dedup-a").addHandler(handler)
        logging.getLogger("ecsctx-dedup-b").addHandler(handler)
        install_maskers_on_handlers()
        assert _count_maskers(handler) == 1

    def test_root_handler_is_swept(self, logging_state):
        """Root's handlers are the ones logging.basicConfig() sets up, so
        they are the most likely to exist in a real app."""
        handler = logging.StreamHandler()
        logging.root.addHandler(handler)
        install_maskers_on_handlers()
        assert _has_masker(handler)
        uninstall_maskers_on_handlers()
        assert not _has_masker(handler)

    def test_root_handler_shared_with_a_named_logger_is_swept_once(self, logging_state):
        handler = logging.StreamHandler()
        logging.root.addHandler(handler)
        logging.getLogger("ecsctx-root-dedup").addHandler(handler)
        install_maskers_on_handlers()
        assert _count_maskers(handler) == 1

    def test_skips_placeholder_loggers(self, logging_state):
        """A dotted logger name leaves a logging.PlaceHolder behind for each
        missing ancestor. PlaceHolder has no .handlers, so _iter_handlers()
        must skip it rather than blow up."""
        logging.getLogger("ecsctx-ph-parent.child")
        assert isinstance(
            logging.Logger.manager.loggerDict["ecsctx-ph-parent"], logging.PlaceHolder
        )
        install_maskers_on_handlers()  # must not raise


class TestFullInstallUninstall:
    def test_install_maskers_covers_config_and_live_handlers(self, logging_state):
        h = logging.StreamHandler()
        logging.getLogger("ecsctx-install-test-full").addHandler(h)
        cfg = {"filters": {}, "handlers": {"console": {"class": "logging.StreamHandler", "filters": []}}}
        install_maskers(cfg)
        assert "mask_pii_filter" in cfg["filters"]
        assert cfg["handlers"]["console"]["filters"] == ["mask_pii_filter"]
        assert _has_masker(h)

    def test_uninstall_maskers_covers_config_and_live_handlers(self, logging_state):
        h = logging.StreamHandler()
        logging.getLogger("ecsctx-install-test-full2").addHandler(h)
        cfg = {"filters": {}, "handlers": {"console": {"class": "logging.StreamHandler", "filters": []}}}
        install_maskers(cfg)
        uninstall_maskers(cfg)
        assert "mask_pii_filter" not in cfg["filters"]
        assert cfg["handlers"]["console"]["filters"] == []
        assert not _has_masker(h)
