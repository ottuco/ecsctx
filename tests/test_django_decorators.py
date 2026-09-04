"""Tests for ecsctx.contrib.django.decorators.api_logging."""

from unittest.mock import patch

from django.contrib.auth.models import AnonymousUser
from rest_framework.exceptions import Throttled, ValidationError
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory, force_authenticate
from rest_framework.views import APIView

from ecsctx.contrib.django.decorators import _log_user, api_logging


class _StubUser:
    def __init__(self, pk, username, authenticated=True):
        self.pk = pk
        self._username = username
        self.is_authenticated = authenticated

    def get_username(self):
        return self._username


class TestLogUser:
    def test_none_user(self):
        assert _log_user(None) is None

    def test_anonymous_user(self):
        assert _log_user(AnonymousUser()) is None

    def test_unauthenticated_stub(self):
        assert _log_user(_StubUser(1, "x", authenticated=False)) is None

    def test_id_and_name(self):
        assert _log_user(_StubUser(7, "saif")) == {"id": "7", "name": "saif"}

    def test_uuid_pk_is_stringified(self):
        uid = "4e540889-d724-49d3-8edc-b8bf2a212b42"
        assert _log_user(_StubUser(uid, "kc")) == {"id": uid, "name": "kc"}

    def test_blank_name_is_omitted(self):
        assert _log_user(_StubUser(3, "")) == {"id": "3"}


@api_logging
class _PingView(APIView):
    permission_classes = []

    def get(self, request):
        return Response({"ok": True})


def _info_user_payloads(mock_logger):
    return [call.kwargs.get("user") for call in mock_logger.info.call_args_list]


class TestApiLoggingUser:
    def test_authenticated_user_logged_inbound_and_outbound(self):
        request = APIRequestFactory().get("/ping/")
        force_authenticate(request, user=_StubUser(7, "saif"))

        with patch("ecsctx.contrib.django.decorators.logger") as mock_logger:
            _PingView.as_view()(request)

        # INBOUND (initial) and OUTBOUND (dispatch) each carry the user block.
        assert _info_user_payloads(mock_logger) == [
            {"id": "7", "name": "saif"},
            {"id": "7", "name": "saif"},
        ]

    def test_anonymous_request_has_no_user_block(self):
        request = APIRequestFactory().get("/ping/")

        with patch("ecsctx.contrib.django.decorators.logger") as mock_logger:
            _PingView.as_view()(request)

        assert _info_user_payloads(mock_logger) == [None, None]


@api_logging
class _ThrottledView(APIView):
    permission_classes = []

    def get(self, request):
        raise Throttled(wait=30)


@api_logging
class _InvalidView(APIView):
    permission_classes = []

    def get(self, request):
        raise ValidationError({"amount": ["required"]})


@api_logging
class _BrokenView(APIView):
    permission_classes = []

    def get(self, request):
        raise RuntimeError("kaboom")


def _events(mock_logger):
    """(level, event.action) per line, in the order they were emitted.

    `method_calls` rather than per-level `call_args_list`, because the two lines
    can land on different levels and only this preserves their order.
    """
    return [
        (name, kwargs["ecs_event"]["action"])
        for name, _args, kwargs in mock_logger.method_calls
        if "ecs_event" in kwargs
    ]


def _closing(mock_logger):
    lines = [k for _n, _a, k in mock_logger.method_calls if "ecs_event" in k]
    assert len(lines) == 2, f"expected a request and a response line, got {len(lines)}"
    return lines[-1]["ecs_event"]


class TestBoundaryActions:
    """The decorator is applied to 81 views, so naming its two lines moves
    event.action coverage further than any other single edit (#159494)."""

    def test_both_lines_name_themselves(self):
        request = APIRequestFactory().get("/ping/")
        with patch("ecsctx.contrib.django.decorators.logger") as mock_logger:
            _PingView.as_view()(request)
        assert _events(mock_logger) == [
            ("info", "api.request_received"),
            ("info", "api.response_sent"),
        ]

    def test_the_response_carries_a_duration_in_nanoseconds(self):
        request = APIRequestFactory().get("/ping/")
        with patch("ecsctx.contrib.django.decorators.logger") as mock_logger:
            _PingView.as_view()(request)
        # ECS event.duration is nanoseconds; a millisecond value would be off
        # by six orders of magnitude and still look plausible.
        assert _closing(mock_logger)["duration"] > 0

    def test_the_request_line_carries_no_duration(self):
        request = APIRequestFactory().get("/ping/")
        with patch("ecsctx.contrib.django.decorators.logger") as mock_logger:
            _PingView.as_view()(request)
        assert "duration" not in mock_logger.info.call_args_list[0].kwargs["ecs_event"]

    def test_a_successful_response_reports_success(self):
        request = APIRequestFactory().get("/ping/")
        with patch("ecsctx.contrib.django.decorators.logger") as mock_logger:
            _PingView.as_view()(request)
        assert _closing(mock_logger)["outcome"] == "success"


class TestRejections:
    """A throttled or invalid request was refused at the boundary — the view
    never ran — so calling it a response the view sent loses that."""

    def test_throttling_is_a_rejection_with_a_bounded_reason(self):
        request = APIRequestFactory().get("/ping/")
        with patch("ecsctx.contrib.django.decorators.logger") as mock_logger:
            _ThrottledView.as_view()(request)
        event = _closing(mock_logger)
        assert event["action"] == "api.request_rejected"
        assert event["reason"] == "throttled"
        assert event["outcome"] == "failure"

    def test_validation_failure_is_a_rejection(self):
        request = APIRequestFactory().get("/ping/")
        with patch("ecsctx.contrib.django.decorators.logger") as mock_logger:
            _InvalidView.as_view()(request)
        event = _closing(mock_logger)
        assert event["action"] == "api.request_rejected"
        assert event["reason"] == "validation_failed"

    def test_a_rejection_is_typed_denied_not_access(self):
        # The type is what separates a refusal from an ordinary reply in a
        # query that does not know the status codes.
        request = APIRequestFactory().get("/ping/")
        with patch("ecsctx.contrib.django.decorators.logger") as mock_logger:
            _ThrottledView.as_view()(request)
        assert _closing(mock_logger)["type"] == ["denied"]

    def test_a_server_error_is_still_a_response_not_a_rejection(self):
        # A crash is the view failing, not the boundary refusing.
        request = APIRequestFactory().get("/ping/")
        with patch("ecsctx.contrib.django.decorators.logger") as mock_logger:
            try:
                _BrokenView.as_view()(request)
            except RuntimeError:
                pass
        event = _closing(mock_logger)
        assert event["action"] == "api.response_sent"
        assert event["outcome"] == "failure"

    def test_a_rejection_still_carries_its_duration(self):
        request = APIRequestFactory().get("/ping/")
        with patch("ecsctx.contrib.django.decorators.logger") as mock_logger:
            _ThrottledView.as_view()(request)
        assert _closing(mock_logger)["duration"] > 0


class TestRegistration:
    def test_the_api_domain_is_not_claimed_on_import(self):
        # Auto-claiming `api` would take the prefix from a service that wants
        # to own it, and nothing in the decorator needs the registry.
        from ecsctx.events import registry

        registry.reset()
        import ecsctx.contrib.django.decorators  # noqa: F401

        assert registry.domains() == ()

    def test_register_http_events_claims_it_when_asked(self):
        from ecsctx.events import registry
        from ecsctx.events.http import register_http_events

        registry.reset()
        try:
            register_http_events()
            assert registry.resolve("api.request_rejected") is not None
        finally:
            registry.reset()
