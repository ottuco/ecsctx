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
