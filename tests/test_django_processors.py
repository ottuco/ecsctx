"""Tests for ecsctx.contrib.django.processors."""

import pytest
from django.contrib.auth import get_user_model

from ecsctx.contrib.django.processors import (
    _get_django_user_model,
    _is_django_user,
    _serialize_django_user,
    contextvars_injector,
)

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
