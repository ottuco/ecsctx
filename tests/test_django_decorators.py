"""Tests for ecsctx.contrib.django.decorators.api_logging."""

from unittest.mock import patch

from django.contrib.auth.models import AnonymousUser
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
