"""Tests for ecsctx.contrib.django.decorators.api_logging."""

import json
from unittest.mock import patch

import pytest
from django.contrib.auth.models import AnonymousUser
from django.urls import path, re_path
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed, Throttled, ValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.renderers import BrowsableAPIRenderer, JSONRenderer
from rest_framework.response import Response
from rest_framework.test import APIClient, APIRequestFactory, force_authenticate
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
    def test_authenticated_user_logged_on_both_boundary_lines(self):
        request = APIRequestFactory().get("/ping/")
        force_authenticate(request, user=_StubUser(7, "saif"))

        with patch("ecsctx.contrib.django.decorators.logger") as mock_logger:
            _PingView.as_view()(request)

        # The request-received (initial) and response-sent (dispatch) lines each
        # carry the user block.
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


class TestErrorTypeOnRejections:
    def test_a_refusal_is_not_an_error_condition(self):
        """A throttled request is the system working as designed. Setting
        error.type for it would put successful rate limiting into every
        "count the errors" dashboard."""
        request = APIRequestFactory().get("/ping/")
        with patch("ecsctx.contrib.django.decorators.logger") as mock_logger:
            _ThrottledView.as_view()(request)
        closing = [k for _n, _a, k in mock_logger.method_calls if "ecs_event" in k][-1]
        assert "error" not in closing
        # The bounded reason carries the same fact, from a vocabulary we own.
        assert closing["ecs_event"]["reason"] == "throttled"

    def test_a_genuine_crash_still_reports_error_type(self):
        request = APIRequestFactory().get("/ping/")
        with patch("ecsctx.contrib.django.decorators.logger") as mock_logger:
            try:
                _BrokenView.as_view()(request)
            except RuntimeError:
                pass
        closing = [k for _n, _a, k in mock_logger.method_calls if "ecs_event" in k][-1]
        assert closing["error"] == {"type": "RuntimeError"}


REFUSAL = "Token issuer is not an allowed Keycloak realm."


class _RefusingAuth(BaseAuthentication):
    def authenticate(self, request):
        raise AuthenticationFailed(REFUSAL)

    def authenticate_header(self, request):
        return 'Bearer realm="api"'


class _CrashingAuth(BaseAuthentication):
    def authenticate(self, request):
        raise RuntimeError("authenticator crashed")


class _RefusedView(APIView):
    authentication_classes = [_RefusingAuth]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"ok": True})


class _CrashedView(_RefusedView):
    authentication_classes = [_CrashingAuth]


class _NegotiatingRefusedView(_RefusedView):
    renderer_classes = [BrowsableAPIRenderer, JSONRenderer]


class _OpenRefusedView(_RefusedView):
    permission_classes = [AllowAny]


def _outcome(view, **headers):
    response = view.as_view()(APIRequestFactory().get("/ping/", **headers))
    return (
        response.status_code,
        response.data,
        response.accepted_media_type,
        response.get("WWW-Authenticate"),
    )


class TestAuthenticationRefusal:
    """Logging must not change how a request is answered: a refused token gets
    the authenticator's reason, not DRF's generic NotAuthenticated, and DRF
    keeps its own order of content negotiation, versioning and authentication
    (#162363). Each case compares the view with and without the decorator."""

    @pytest.mark.parametrize(
        ("view", "headers", "expected"),
        [
            pytest.param(
                _RefusedView,
                {},
                (401, {"detail": REFUSAL}, "application/json", 'Bearer realm="api"'),
                id="refused-token",
            ),
            pytest.param(
                _NegotiatingRefusedView,
                {"HTTP_ACCEPT": "application/json"},
                (401, {"detail": REFUSAL}, "application/json", 'Bearer realm="api"'),
                id="accept-header-still-picks-the-renderer",
            ),
            pytest.param(
                _RefusedView,
                {"HTTP_ACCEPT": "application/xml"},
                (
                    406,
                    {"detail": 'Could not satisfy the request Accept header.'},
                    "application/json",
                    None,
                ),
                id="unacceptable-accept-answers-406-before-401",
            ),
            pytest.param(
                _OpenRefusedView,
                {},
                (401, {"detail": REFUSAL}, "application/json", 'Bearer realm="api"'),
                # An open view used to serve a refused credential as anonymous;
                # undecorated DRF refuses it, and so does the decorated view now.
                id="open-view-refuses-a-bad-credential",
            ),
        ],
    )
    def test_a_decorated_view_answers_as_an_undecorated_one(self, view, headers, expected):
        assert _outcome(view, **headers) == expected
        assert _outcome(api_logging(view), **headers) == expected

    def test_the_refused_request_is_logged_once_without_a_user(self):
        request = APIRequestFactory().get("/ping/")
        with patch("ecsctx.contrib.django.decorators.logger") as mock_logger:
            api_logging(_RefusedView).as_view()(request)

        received = [
            call
            for call in mock_logger.info.call_args_list
            if call.kwargs["ecs_event"]["action"] == "api.request_received"
        ]
        assert [(c.args, "user" in c.kwargs) for c in received] == [
            (("api request received: %s %s", "GET", "/ping/"), False)
        ]
        warning = mock_logger.warning.call_args
        assert warning.args == ("api response sent: %s %s (%s)", "GET", "/ping/", 401)
        assert warning.kwargs["http"]["response"]["status_code"] == 401
        assert warning.kwargs["http"]["response"]["body"] == {"detail": REFUSAL}

    def test_an_authenticator_crash_is_the_same_with_and_without_the_decorator(self):
        for view in (_CrashedView, api_logging(_CrashedView)):
            with pytest.raises(RuntimeError, match="authenticator crashed"):
                _outcome(view)


@api_logging
class _CardView(APIView):
    permission_classes = []

    def delete(self, request, **kwargs):
        return Response(status=204)


# The urlconf the routed tests below run under (pytest.mark.urls). A saved
# card's delete route carries the card token as a path segment, as ottu_pg's
# `/v1/pbl/card/token/<str:token>/` and Connect's `/pbl/v2/card/<token>` do.
urlpatterns = [
    path("v1/cards/<str:token>/", _CardView.as_view()),
    path("v1/payments/<uuid:uid>/", _CardView.as_view()),
    path("v1/accounts/<str:acct>/tokens/<str:token>/", _CardView.as_view()),
    path("v1/keys/<str:api_key>/tokens/<str:token>/", _CardView.as_view()),
    re_path(r"^v1/receipts/(?P<token>[^/.]+)\.pdf$", _CardView.as_view()),
]

# An MPGS token is sixteen digits; a CyberSource instrument id is hex that no
# content rule recognises.
CARD_TOKENS = pytest.mark.parametrize(
    "token", ["9584184138614802", "E4B1C1F4F2B35BD6E05341588E0A4F4F"], ids=["mpgs", "cybersource"]
)


def _api_lines(output):
    docs = [json.loads(line) for line in output.splitlines() if line.strip()]
    return [doc for doc in docs if doc.get("event", {}).get("action", "").startswith("api.")]


@pytest.mark.urls(__name__)
class TestRouteNotPath:
    """Both lines name the route the request matched, not its path. The path
    put whatever the URL carries into the message -- a card token, a payment
    id -- so no two lines grouped, and a token is a credential."""

    @CARD_TOKENS
    def test_both_messages_name_the_route(self, rendered, token):
        output = rendered(lambda: APIClient().delete(f"/v1/cards/{token}/"))
        assert [line["message"] for line in _api_lines(output)] == [
            "api request received: DELETE /v1/cards/<str:token>/",
            "api response sent: DELETE /v1/cards/<str:token>/ (204)",
        ]

    @CARD_TOKENS
    def test_the_token_is_nowhere_in_the_rendered_lines(self, rendered, token):
        output = rendered(lambda: APIClient().delete(f"/v1/cards/{token}/"))
        assert token not in output
        # url.path keeps the path, the segment masked as a `token` body field is.
        assert [line["url"]["path"] for line in _api_lines(output)] == [
            "/v1/cards/[SECRET-MASKED]/",
            "/v1/cards/[SECRET-MASKED]/",
        ]

    def test_a_parameter_the_engine_leaves_alone_stays_in_the_path(self, rendered):
        uid = "4e540889-d724-49d3-8edc-b8bf2a212b42"
        output = rendered(lambda: APIClient().delete(f"/v1/payments/{uid}/"))
        lines = _api_lines(output)
        assert [line["message"] for line in lines] == [
            "api request received: DELETE /v1/payments/<uuid:uid>/",
            "api response sent: DELETE /v1/payments/<uuid:uid>/ (204)",
        ]
        assert [line["url"]["path"] for line in lines] == [
            f"/v1/payments/{uid}/",
            f"/v1/payments/{uid}/",
        ]

    def test_a_view_called_without_url_resolution_names_its_path(self, rendered):
        request = APIRequestFactory().get("/ping/")
        output = rendered(lambda: _PingView.as_view()(request))
        assert [line["message"] for line in _api_lines(output)] == [
            "api request received: GET /ping/",
            "api response sent: GET /ping/ (200)",
        ]


@pytest.mark.urls(__name__)
class TestMaskedSegments:
    """url.path masks the segments a classified parameter fills. Replacing its
    value anywhere in the path also hit segments that merely contain it."""

    def test_a_segment_that_contains_the_token_stays_readable(self, rendered):
        output = rendered(lambda: APIClient().delete("/v1/accounts/1234/tokens/23/"))
        assert [line["url"]["path"] for line in _api_lines(output)] == [
            "/v1/accounts/1234/tokens/[SECRET-MASKED]/",
            "/v1/accounts/1234/tokens/[SECRET-MASKED]/",
        ]

    def test_a_token_that_starts_with_another_credential_is_masked_whole(self, rendered):
        output = rendered(lambda: APIClient().delete("/v1/keys/7c1e/tokens/7c1e9a0b/"))
        assert [line["url"]["path"] for line in _api_lines(output)] == [
            "/v1/keys/[SECRET-MASKED]/tokens/[SECRET-MASKED]/",
            "/v1/keys/[SECRET-MASKED]/tokens/[SECRET-MASKED]/",
        ]

    def test_a_token_that_shares_its_segment_is_still_masked(self, rendered):
        token = "E4B1C1F4F2B35BD6E05341588E0A4F4F"
        output = rendered(lambda: APIClient().delete(f"/v1/receipts/{token}.pdf"))
        assert token not in output
        assert [line["url"]["path"] for line in _api_lines(output)] == [
            "/v1/receipts/[SECRET-MASKED].pdf",
            "/v1/receipts/[SECRET-MASKED].pdf",
        ]


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
