"""Tests for ecsctx.contrib.django.logging."""

import django.conf

from ecsctx.contrib.django.logging import setup_logging


class TestSetupLoggingSettingsSafety:
    def test_setup_logging_does_not_read_django_settings(self, monkeypatch):
        """setup_logging() must not touch django.conf.settings.

        It is documented to run from settings.py (while the settings module is
        still importing). Reading settings then forces an early settings._setup()
        that caches a *partial* settings object — everything defined after the
        setup_logging() call is silently dropped, breaking the whole app. The
        masking-exemption bridge must stay lazy (log time), never eager here.
        """
        seen = []
        real_getattr = django.conf.LazySettings.__getattr__

        def spy(self, name):
            seen.append(name)
            return real_getattr(self, name)

        monkeypatch.setattr(django.conf.LazySettings, "__getattr__", spy)

        setup_logging(capture_warnings=False)

        assert "ECSCTX_MASK_EXEMPT_PATHS" not in seen


class TestAttributionEndToEnd:
    """Full get_logging_config() + configure_structlog() pipeline through the
    real formatter — guards the chain ordering (callsite keys must be reshaped
    into log.* before namespace_ecs_fields sweeps them into extra)."""

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
        import json

        lines = [ln for ln in capsys.readouterr().err.splitlines() if ln.strip()]
        return json.loads(lines[-1])

    def test_native_call_carries_logger_and_origin(self, capsys):
        import structlog

        doc = self._formatted(
            lambda: structlog.get_logger("core.gateway.knetv3.views.KnetV3ResponseView").info(
                "attribution e2e"
            ),
            capsys,
        )
        assert doc["log"]["logger"] == "core.gateway.knetv3.views.KnetV3ResponseView"
        assert doc["log"]["origin"]["function"]
        assert doc["log"]["origin"]["file"]["name"].endswith(".py")
        assert isinstance(doc["log"]["origin"]["file"]["line"], int)
        assert "extra" not in doc

    def test_foreign_record_carries_logger_and_origin(self, capsys):
        import logging

        doc = self._formatted(
            lambda: logging.getLogger("some.stdlib.ForeignLogger").info("foreign e2e"),
            capsys,
        )
        assert doc["log"]["logger"] == "some.stdlib.ForeignLogger"
        assert doc["log"]["origin"]["file"]["name"]
        assert "extra" not in doc


class TestUnhandled500EndToEnd:
    """The original #158750 report: a django.request record with exc_info must
    ship a full ECS error object through the REAL config — not a stringified
    extra.exc_info."""

    def test_django_request_500_ships_error_object(self, capsys):
        import json
        import logging.config
        import sys as _sys

        import structlog

        from ecsctx.contrib.django import get_logging_config, setup_logging

        cfg = get_logging_config(use_cid_filter=False)
        cfg["loggers"] = {}
        logging.config.dictConfig(cfg)
        setup_logging()
        try:
            try:
                raise FileNotFoundError(2, "No such file or directory")
            except FileNotFoundError:
                logging.getLogger("django.request").error(
                    "Internal Server Error: /api/checkout/", exc_info=_sys.exc_info()
                )
        finally:
            structlog.reset_defaults()

        lines = [ln for ln in capsys.readouterr().err.splitlines() if ln.strip()]
        doc = json.loads(lines[-1])
        assert doc["error"]["type"] == "FileNotFoundError"
        assert doc["error"]["message"] == "[Errno 2] No such file or directory"
        assert doc["error"]["stack_trace"].startswith("Traceback")
        assert doc["log"]["logger"] == "django.request"
        assert "extra" not in doc
