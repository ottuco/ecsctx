"""Tests for ecsctx.contrib.django.processors."""

from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.test import override_settings

from ecsctx.contrib.django.processors import (
    _auto_configure_masking,
    _get_django_user_model,
    _is_django_user,
    _reset_masking_settings_flag,
    _serialize_django_user,
    contextvars_injector,
)
from ecsctx.pii import configure_pii
from ecsctx.processors import _safe_dump_and_mask, masking_is_configured

User = get_user_model()


class TestGetDjangoUserModel:
    def test_returns_user_model(self):
        model = _get_django_user_model()
        assert model is User


class TestIsDjangoUser:
    @pytest.mark.django_db
    def test_detects_user_instance(self):
        user = User(pk=1, username="test")
        assert _is_django_user(user) is True

    def test_rejects_non_user(self):
        assert _is_django_user("not a user") is False
        assert _is_django_user(None) is False
        assert _is_django_user(42) is False


class TestSerializeDjangoUser:
    @pytest.mark.django_db
    def test_serializes_user_fields(self):
        user = User(
            pk=7,
            username="alice",
            email="alice@example.com",
            first_name="Alice",
            last_name="Smith",
        )
        result = _serialize_django_user(user)
        assert result == {
            "id": "7",
            "username": "alice",
            "email": "alice@example.com",
            "first_name": "Alice",
            "last_name": "Smith",
        }

    @pytest.mark.django_db
    def test_user_without_pk(self):
        user = User(username="nopk")
        result = _serialize_django_user(user)
        assert result["id"] is None

    def test_non_user_passthrough(self):
        obj = {"id": "123"}
        assert _serialize_django_user(obj) is obj


class TestContextvarsInjectorUserSerialization:
    @pytest.mark.django_db
    def test_serializes_user_in_event_dict(self):
        user = User(pk=5, username="bob")
        event_dict = {"event": "test", "user": user}
        result = contextvars_injector(None, None, event_dict)
        assert isinstance(result["user"], dict)
        assert result["user"]["id"] == "5"
        assert result["user"]["username"] == "bob"

    def test_non_user_value_unchanged(self):
        event_dict = {"event": "test", "user": {"id": "manual"}}
        result = contextvars_injector(None, None, event_dict)
        assert result["user"] == {"id": "manual"}


class TestLazyImport:
    def test_no_module_level_auth_import(self):
        """Regression: importing processors must not trigger AppRegistryNotReady."""
        import importlib

        import ecsctx.contrib.django.processors as mod

        # Re-import should not fail — if auth models were imported at module
        # level, this would raise AppRegistryNotReady in some configurations.
        importlib.reload(mod)


class TestMaskingSettingsBridge:
    @pytest.fixture(autouse=True)
    def _reset_flag(self):
        _reset_masking_settings_flag()
        yield
        _reset_masking_settings_flag()

    @override_settings(ECSCTX_MASK_EXEMPT_PATHS=["payment_methods[*].name"])
    def test_setting_applied_via_auto_configure(self, token_keyset_path):
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        _auto_configure_masking()
        assert masking_is_configured()
        out = _safe_dump_and_mask(
            {"payment_methods": [{"name": "KNET"}], "customer": {"name": "John"}}
        )
        assert out["payment_methods"][0]["name"] == "KNET"
        assert out["customer"]["name"].startswith("ptok:v1:")

    @override_settings(ECSCTX_MASK_EXEMPT_PATHS=["payment_methods[*].name"])
    def test_setting_applied_via_processor_first_call(self, token_keyset_path):
        # A real log record through the Django contextvars_injector must
        # trigger the settings bridge — no setup_logging() required.
        configure_pii(token_keyset_path=token_keyset_path, env="test")
        contextvars_injector(None, None, {"event": "hello"})
        assert masking_is_configured()
        out = _safe_dump_and_mask({"payment_methods": [{"name": "KNET"}]})
        assert out["payment_methods"][0]["name"] == "KNET"

    def test_absent_setting_is_noop(self):
        _auto_configure_masking()
        assert not masking_is_configured()

    @override_settings(ECSCTX_MASK_EXEMPT_PATHS=["customer.name"])
    def test_explicit_configure_beats_setting(self, token_keyset_path):
        from ecsctx.processors import configure_masking

        configure_pii(token_keyset_path=token_keyset_path, env="test")
        configure_masking(exempt_paths=[])  # explicit empty wins over the setting
        _auto_configure_masking()
        out = _safe_dump_and_mask({"customer": {"name": "John"}})
        assert out["customer"]["name"].startswith("ptok:v1:")

    def test_retries_when_settings_not_ready(self, token_keyset_path):
        """Regression for the original bug: if settings access raises (e.g.
        called during settings.py import, before Django is configured), the
        bridge must NOT burn its one-shot flag — it retries at real log time."""
        configure_pii(token_keyset_path=token_keyset_path, env="test")

        class _NotReady:
            def __getattr__(self, name):
                raise RuntimeError("Requested setting, but settings are not configured.")

        # First call: settings not ready -> no-op, flag NOT burned.
        with patch("django.conf.settings", _NotReady()):
            _auto_configure_masking()
        assert not masking_is_configured()

        # Later call: settings now available -> exemption is applied.
        with override_settings(ECSCTX_MASK_EXEMPT_PATHS=["payment_methods[*].name"]):
            _auto_configure_masking()
        assert masking_is_configured()
        out = _safe_dump_and_mask({"payment_methods": [{"name": "KNET"}]})
        assert out["payment_methods"][0]["name"] == "KNET"
