"""Tests for ecsctx.masking.install: install_maskers()/uninstall_maskers()
and their config-dict / live-handler variants."""

import logging

from ecsctx.masking.filters import MaskPIIFilter
from ecsctx.masking.install import (
    install_maskers,
    install_maskers_in_config,
    install_maskers_on_handlers,
    uninstall_maskers,
    uninstall_maskers_in_config,
    uninstall_maskers_on_handlers,
)


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
        assert cfg["handlers"]["console"]["filters"] == ["mask_pii_filter"]
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
        assert cfg["filters"] == {}
        assert cfg["handlers"]["console"]["filters"] == []

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
        assert _count_maskers(h) == 0
        install_maskers_on_handlers()
        assert _count_maskers(h) == 1

    def test_idempotent_does_not_double_attach(self, logging_state):
        h = self._handler()
        install_maskers_on_handlers()
        install_maskers_on_handlers()
        assert _count_maskers(h) == 1

    def test_uninstall_removes_from_live_handler(self, logging_state):
        h = self._handler()
        install_maskers_on_handlers()
        assert _count_maskers(h) == 1
        uninstall_maskers_on_handlers()
        assert h.filters == []

    def test_does_not_touch_a_handler_created_afterward(self, logging_state):
        """install_maskers_on_handlers() deliberately does not patch the
        stdlib — only handlers that exist at call time are covered."""
        install_maskers_on_handlers()
        h = self._handler()
        assert h.filters == []


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
        assert _count_maskers(handler) == 1
        uninstall_maskers_on_handlers()
        assert handler.filters == []

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
        handler = logging.StreamHandler()
        logging.getLogger("ecsctx-ph-parent.child").addHandler(handler)
        assert isinstance(
            logging.Logger.manager.loggerDict["ecsctx-ph-parent"], logging.PlaceHolder
        )
        install_maskers_on_handlers()
        assert _count_maskers(handler) == 1


class TestFullInstallUninstall:
    def test_install_maskers_covers_config_and_live_handlers(self, logging_state):
        h = logging.StreamHandler()
        logging.getLogger("ecsctx-install-test-full").addHandler(h)
        cfg = {"filters": {}, "handlers": {"console": {"class": "logging.StreamHandler", "filters": []}}}
        install_maskers(cfg)
        assert cfg["filters"] == {
            "mask_pii_filter": {"()": "ecsctx.masking.filters.MaskPIIFilter"}
        }
        assert cfg["handlers"]["console"]["filters"] == ["mask_pii_filter"]
        assert _count_maskers(h) == 1

    def test_uninstall_maskers_covers_config_and_live_handlers(self, logging_state):
        h = logging.StreamHandler()
        logging.getLogger("ecsctx-install-test-full2").addHandler(h)
        cfg = {"filters": {}, "handlers": {"console": {"class": "logging.StreamHandler", "filters": []}}}
        install_maskers(cfg)
        uninstall_maskers(cfg)
        assert cfg["filters"] == {}
        assert cfg["handlers"]["console"]["filters"] == []
        assert _count_maskers(h) == 0
