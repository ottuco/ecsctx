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
