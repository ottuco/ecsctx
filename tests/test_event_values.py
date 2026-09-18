"""Outcomes and reasons are objects a call site imports, not strings it types.

A string is always valid Python, so `reason="tiemout"` only fails when that
line runs — usually on the failure path, the one least often exercised. A
member is a name the editor completes and a linter can see; the document still
carries the plain value, so nothing changes in the index.
"""

import json

import pytest

from ecsctx.contrib.ottu import ALL_DOMAINS, yaml_render
from ecsctx.contrib.ottu.net import OUTBOUND_FAILURE_REASONS, OutboundFailure
from ecsctx.contrib.ottu.pg import PG_REQUEST_FAILED
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
