"""Outcomes and reasons are objects a call site imports, not strings it types.

A string is always valid Python, so `reason="tiemout"` only fails when that
line runs — usually on the failure path, the one least often exercised. A
member is a name the editor completes and a linter can see; the document still
carries the plain value, so nothing changes in the index.
"""

import json

import pytest

from ecsctx.contrib.ottu import ALL_DOMAINS, yaml_render
from ecsctx.contrib.ottu.auth import (
    AUTH_REQUEST_REJECTED,
    AUTH_TOKEN_ISSUED,
    AUTH_TOKEN_REVOKED,
    AuthRejection,
    TokenIssueFailure,
    TokenRevocation,
)
from ecsctx.contrib.ottu.net import OUTBOUND_FAILURE_REASONS, OutboundFailure
from ecsctx.contrib.ottu.pg import PG_PAYLOAD_DECRYPTED, PG_REQUEST_FAILED
from ecsctx.contrib.ottu.webhook import WebhookFailure
from ecsctx.events import ECS_OUTCOMES, EventSpec, Outcome, Reason
from ecsctx.events.http import HTTP_EVENTS


class Refusal(Reason):
    THROTTLED = "throttled"
    TIMEOUT = "timeout"


class OtherRefusal(Reason):
    TIMEOUT = "timeout"


REFUSED = EventSpec(action="api.request_refused", terminal=True, reasons=Refusal)


class TestOutcome:
    def test_the_members_are_the_ecs_closed_set(self):
        assert {o.value for o in Outcome} == set(ECS_OUTCOMES) == {"success", "failure", "unknown"}

    def test_a_member_reads_as_its_value(self):
        assert str(Outcome.FAILURE) == "failure"
        assert f"{Outcome.FAILURE}" == "failure"

    def test_the_payload_carries_a_plain_string(self):
        outcome = REFUSED.ecs(outcome=Outcome.FAILURE)["outcome"]
        assert outcome == "failure"
        assert type(outcome) is str

    def test_a_plain_string_is_still_accepted(self):
        assert REFUSED.ecs(outcome="success")["outcome"] == "success"

    def test_a_value_outside_the_set_still_raises(self):
        with pytest.raises(ValueError, match="event.outcome"):
            REFUSED.ecs(outcome="failed")


class TestReason:
    def test_a_reason_class_declares_the_set(self):
        assert REFUSED.reasons == (Refusal.THROTTLED, Refusal.TIMEOUT)

    def test_the_same_class_declares_an_equal_spec(self):
        assert EventSpec(action="api.request_refused", terminal=True, reasons=Refusal) == REFUSED

    def test_the_payload_carries_a_plain_string(self):
        reason = REFUSED.ecs(outcome=Outcome.FAILURE, reason=Refusal.TIMEOUT)["reason"]
        assert reason == "timeout"
        assert type(reason) is str

    def test_the_rendered_document_is_unchanged(self):
        payload = REFUSED.ecs(outcome=Outcome.FAILURE, reason=Refusal.THROTTLED)
        assert json.loads(json.dumps(payload))["reason"] == "throttled"
        assert json.loads(json.dumps(payload))["outcome"] == "failure"

    def test_a_declared_plain_string_is_still_accepted(self):
        assert REFUSED.ecs(outcome="failure", reason="throttled")["reason"] == "throttled"

    def test_an_undeclared_string_still_raises(self):
        with pytest.raises(ValueError, match="not a declared reason"):
            REFUSED.ecs(outcome="failure", reason="tiemout")

    def test_a_member_of_another_set_is_rejected_even_with_the_same_value(self):
        # The check an object makes possible and a string cannot: the value
        # matches, the meaning belongs to a different event.
        with pytest.raises(ValueError, match="not a declared reason"):
            REFUSED.ecs(outcome="failure", reason=OtherRefusal.TIMEOUT)

    def test_a_tuple_of_strings_still_declares_reasons(self):
        spec = EventSpec(action="api.request_refused", reasons=("throttled",))
        assert spec.ecs(reason="throttled")["reason"] == "throttled"


def _catalogue():
    for specs in ALL_DOMAINS.values():
        yield from specs
    yield from HTTP_EVENTS


class TestCatalogueReasons:
    @pytest.mark.parametrize("spec", [s for s in _catalogue() if s.reasons], ids=str)
    def test_every_reason_set_is_one_reason_class(self, spec):
        assert all(isinstance(r, Reason) for r in spec.reasons)
        assert len({type(r) for r in spec.reasons}) == 1

    def test_events_that_require_a_reason_but_declare_no_set_are_pinned(self):
        # These require `event.reason` (ticket #159487) but no service logs one
        # yet, so there are no values to declare. They take no reason until the
        # first service that needs one adds the `Reason` class here. Pinned so
        # the list only shrinks: a new event that requires a reason declares
        # its set.
        pending = {
            s.action for s in _catalogue() if "event.reason" in s.required and not s.reasons
        }
        assert pending == {
            "auth.identity_sync_failed",
            "auth.session_check_skipped",
            "auth.session_terminated",
            "card.token_lookup_failed",
            "card.tokenization_skipped",
            "payment.duplicate_suppressed",
            "payment.state_change_skipped",
            "pg.credentials_unavailable",
            "pg.signature_verification_skipped",
        }

    def test_both_request_failed_events_share_the_outbound_set(self):
        assert PG_REQUEST_FAILED.reasons == tuple(OutboundFailure)
        assert OUTBOUND_FAILURE_REASONS == tuple(OutboundFailure)

    def test_a_catalogue_member_logs_its_value(self):
        payload = PG_REQUEST_FAILED.ecs(outcome=Outcome.FAILURE, reason=OutboundFailure.TIMEOUT)
        assert payload["reason"] == "timeout"
        assert type(payload["reason"]) is str

    def test_a_reason_from_the_wrong_catalogue_set_is_rejected(self):
        with pytest.raises(ValueError, match="not a declared reason"):
            PG_REQUEST_FAILED.ecs(outcome="failure", reason=WebhookFailure.TIMEOUT)

    def test_the_rendered_catalogue_lists_plain_values(self):
        rendered = yaml_render.render({"pg": [PG_REQUEST_FAILED]})
        assert (
            "reasons: [http_client_error, http_server_error, timeout, connection_error, "
            "invalid_json, request_error, unexpected_error]"
        ) in rendered


class TestAuthReasons:
    """Reasons Connect logs on shared auth events (its login refusals, its
    token revocations, its failed token requests), declared here so every
    service uses the same values."""

    @pytest.mark.parametrize("reason", ["ACCOUNT_LOCKED", "INVALID_CREDENTIALS"])
    def test_a_login_refusal_is_an_auth_rejection(self, reason):
        payload = AUTH_REQUEST_REJECTED.ecs(
            outcome=Outcome.FAILURE, reason=getattr(AuthRejection, reason)
        )
        assert payload["reason"] == reason.lower()

    def test_a_revoked_token_says_why(self):
        payload = AUTH_TOKEN_REVOKED.ecs(
            outcome=Outcome.SUCCESS, reason=TokenRevocation.USER_DEACTIVATED
        )
        assert payload["reason"] == "user_deactivated"

    @pytest.mark.parametrize("reason", ["CONNECTION_FAILED", "REJECTED"])
    def test_a_token_this_service_could_not_get_says_why(self, reason):
        payload = AUTH_TOKEN_ISSUED.ecs(
            outcome=Outcome.FAILURE, reason=getattr(TokenIssueFailure, reason)
        )
        assert payload["reason"] == reason.lower()


class TestPayloadDecryption:
    """KNET-family PSPs (KPay, Benefit, OmanNet, Rajhi) encrypt what they send
    back. Connect and ottu_pg both decrypt it, so the event is shared."""

    def test_a_payload_that_would_not_decrypt_is_a_failure_at_error(self):
        payload = PG_PAYLOAD_DECRYPTED.ecs(outcome=Outcome.FAILURE)
        assert payload["action"] == "pg.payload_decrypted"
        assert payload["outcome"] == "failure"
        assert PG_PAYLOAD_DECRYPTED.level_on_failure == "error"
