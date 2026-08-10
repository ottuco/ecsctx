"""Tests for ecsctx.contrib.django.middleware."""

from unittest.mock import patch

import pytest
import structlog
from django.contrib.auth import get_user_model
from django.test import RequestFactory

from ecsctx import bind_logging_context, reset_logging_context
from ecsctx.context import _logging_context
from ecsctx.contrib.django.middleware import LoggingContextMiddleware
from ecsctx.contrib.django.processors import contextvars_injector

User = get_user_model()


@pytest.fixture()
def rf():
    return RequestFactory()


@pytest.fixture()
def middleware():
    return LoggingContextMiddleware(get_response=lambda r: r)


@pytest.fixture()
def clean_logging_state():
    """Start and leave with both context stores empty, whatever ran before."""
    structlog.contextvars.clear_contextvars()
    _logging_context.set(None)
    yield
    structlog.contextvars.clear_contextvars()
    _logging_context.set(None)


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


class TestStructlogContextvarsCleared:
    """process_request must start each request from a clean structlog slate.

    Stale structlog bindings outlive their request wherever the execution
    context is long-lived: WSGI sync workers reuse one context across requests
    (request N's session_id/customer show up on request N+1), and under ASGI
    anything bound outside a request task is inherited by every request task
    via the copied base context. Without a boundary clear those stale values
    (merge_contextvars runs before contextvars_injector, first writer wins)
    even beat a freshly bound ecsctx context.
    """

    def test_process_request_clears_stale_structlog_contextvars(
        self, rf, middleware, clean_logging_state
    ):
        structlog.contextvars.bind_contextvars(
            session_id="request-n-session", customer={"email": "tok_abc"}
        )
        request = rf.get("/ok/")

        with patch("ecsctx.contrib.django.middleware.sentry_sdk"):
            middleware.process_request(request)

        assert structlog.contextvars.get_contextvars() == {}
        reset_logging_context(request._logging_context_token)

    def test_stale_structlog_session_id_loses_to_fresh_ecsctx_context(
        self, rf, middleware, clean_logging_state
    ):
        # Request N: an audited save bound session_id onto structlog
        # contextvars and nothing reset it.
        structlog.contextvars.bind_contextvars(session_id="request-n-session")

        # Request N+1 begins: middleware runs, then the app binds the real
        # session id onto the ecsctx store (what OttuLoggingContextMiddleware
        # does in process_view).
        request = rf.get("/ok/")
        with patch("ecsctx.contrib.django.middleware.sentry_sdk"):
            middleware.process_request(request)
        token = bind_logging_context(session_id="request-n-plus-1-session")

        try:
            event_dict = structlog.contextvars.merge_contextvars(None, "info", {})
            event_dict = contextvars_injector(None, "info", event_dict)
            assert event_dict["session_id"] == "request-n-plus-1-session"
        finally:
            reset_logging_context(token)
            reset_logging_context(request._logging_context_token)


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
