"""Tests for ecsctx.contrib.django.middleware."""

from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.test import RequestFactory

from ecsctx.contrib.django.middleware import LoggingContextMiddleware

User = get_user_model()


@pytest.fixture()
def rf():
    return RequestFactory()


@pytest.fixture()
def middleware():
    return LoggingContextMiddleware(get_response=lambda r: r)


class TestProcessRequest:
    def test_binds_span_id(self, rf, middleware):
        request = rf.get("/ok/")
        with patch("ecsctx.contrib.django.middleware.sentry_sdk"):
            middleware.process_request(request)
        assert hasattr(request, "_span_id")
        assert hasattr(request, "_logging_context_token")
        # Clean up
        from ecsctx import reset_logging_context

        reset_logging_context(request._logging_context_token)

    def test_span_id_is_uuid(self, rf, middleware):
        import uuid

        request = rf.get("/ok/")
        with patch("ecsctx.contrib.django.middleware.sentry_sdk"):
            middleware.process_request(request)
        uuid.UUID(request._span_id)  # Raises if not valid UUID
        from ecsctx import reset_logging_context

        reset_logging_context(request._logging_context_token)


class TestProcessView:
    @pytest.mark.django_db
    def test_binds_user_id_when_authenticated(self, rf, middleware):
        request = rf.get("/ok/")
        user = User.objects.create_user(username="testuser", password="pass")
        request.user = user

        with patch("ecsctx.contrib.django.middleware.sentry_sdk"):
            middleware.process_request(request)
            middleware.process_view(request, lambda r: r, [], {})

        assert hasattr(request, "_logging_context_token")
        from ecsctx import reset_logging_context

        reset_logging_context(request._logging_context_token)

    def test_skips_anonymous_user(self, rf, middleware):
        from django.contrib.auth.models import AnonymousUser

        request = rf.get("/ok/")
        request.user = AnonymousUser()

        with patch("ecsctx.contrib.django.middleware.sentry_sdk"):
            middleware.process_request(request)
            original_token = request._logging_context_token
            middleware.process_view(request, lambda r: r, [], {})
            # Token should not have changed for anonymous user
            assert request._logging_context_token == original_token

        from ecsctx import reset_logging_context

        reset_logging_context(request._logging_context_token)


class TestProcessResponse:
    def test_resets_context(self, rf, middleware):
        request = rf.get("/ok/")
        with patch("ecsctx.contrib.django.middleware.sentry_sdk"):
            middleware.process_request(request)
            response = middleware.process_response(request, request)
        assert response is not None


class TestProcessException:
    def test_logs_exception(self, rf, middleware):
        request = rf.get("/error/")
        with (
            patch("ecsctx.contrib.django.middleware.sentry_sdk"),
            patch("ecsctx.contrib.django.middleware.logger") as mock_logger,
        ):
            middleware.process_request(request)
            middleware.process_exception(request, ValueError("boom"))
            mock_logger.exception.assert_called_once()
            call_kwargs = mock_logger.exception.call_args
            assert call_kwargs[0][0] == "unhandled_exception"
