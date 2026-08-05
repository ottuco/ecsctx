"""Tests for ecsctx.formatters.ECSFormatter."""

import json

from ecsctx.formatters import ECSFormatter


class TestLogLevelNormalization:
    """structlog's logger.exception() hands the method name ("exception") to
    ecs-logging as the level; ECS has no such level, so Kibana filters on
    log.level:error miss those documents unless the formatter normalizes it."""

    def test_exception_method_name_becomes_error(self):
        out = ECSFormatter()(None, "exception", {"event": "boom"})
        doc = json.loads(out)
        assert doc["log.level"] == "error"

    def test_nested_level_shape_is_normalized(self):
        doc = ECSFormatter().format_to_ecs({"log": {"level": "exception"}})
        assert doc["log"]["level"] == "error"

    def test_flat_level_shape_is_normalized(self):
        doc = ECSFormatter().format_to_ecs({"log.level": "exception"})
        assert doc["log.level"] == "error"

    def test_other_levels_untouched(self):
        for level in ("debug", "info", "warning", "error", "critical"):
            out = ECSFormatter()(None, level, {"event": "boom"})
            doc = json.loads(out)
            assert doc["log.level"] == level


class TestExceptionLevelEndToEnd:
    """Full get_logging_config() + setup_logging() pipeline: .exception() calls
    must ship log.level "error" in the final JSON, alongside the stack trace."""

    def _formatted(self, emit, capsys):
        import logging.config

        import structlog

        from ecsctx.contrib.django import get_logging_config, setup_logging

        cfg = get_logging_config(use_cid_filter=False)
        cfg["loggers"] = {}
        logging.config.dictConfig(cfg)
        setup_logging()
        try:
            emit()
        finally:
            structlog.reset_defaults()

        lines = [ln for ln in capsys.readouterr().err.splitlines() if ln.strip()]
        return json.loads(lines[-1])

    def test_native_structlog_exception_ships_error_level(self, capsys):
        import structlog

        def emit():
            try:
                raise ValueError("boom")
            except ValueError:
                structlog.get_logger("x").exception("boom")

        doc = self._formatted(emit, capsys)
        assert doc["log.level"] == "error"
        assert doc["error"]["stack_trace"].startswith("Traceback")

    def test_foreign_stdlib_exception_ships_error_level(self, capsys):
        import logging

        def emit():
            try:
                raise ValueError("boom")
            except ValueError:
                logging.getLogger("y").exception("boom")

        doc = self._formatted(emit, capsys)
        assert doc["log.level"] == "error"
        assert doc["error"]["stack_trace"].startswith("Traceback")
