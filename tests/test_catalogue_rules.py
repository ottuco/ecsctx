"""One Ottu vocabulary: the naming rules, and where they are enforced.

Services are built by different teams, and a name is only shared if nothing
lets a second spelling in: `payment.created` in one service and
`payment.inited` in another split every dashboard that counts payments. The
catalogue is checked here; a service's own events are checked by
`register_ottu()` when it starts, so a bad name fails that service's tests
rather than waiting for a reviewer to notice.
"""

from pathlib import Path

import pytest

from ecsctx.contrib.ottu import ALL_DOMAINS, register_ottu, render_docs, rules
from ecsctx.contrib.ottu.pg import PG_REQUEST_SENT
from ecsctx.events import EventSpec, Reason, register_domain, registry
from ecsctx.events.http import ApiRejection

DOCS = Path(__file__).resolve().parent.parent / "docs" / "events.md"


@pytest.fixture(autouse=True)
def _clean_registry():
    registry.reset()
    yield
    registry.reset()


def _spec(action, description="Logged when the test says so."):
    return EventSpec(action=action, description=description)


def _catalogue():
    for specs in ALL_DOMAINS.values():
        yield from specs


class TestNamingRules:
    def test_a_well_formed_event_passes(self):
        assert rules.check(_spec("wallet.balance_debited")) == []

    def test_an_event_may_name_only_its_domain(self):
        # `task.started`, `cache.read`: the domain is the subject.
        assert rules.check(_spec("task.started")) == []

    @pytest.mark.parametrize(
        ("action", "canonical"),
        [
            ("payment.session_inited", "created"),
            ("payment.session_initiated", "created"),
            ("notify.message_queued", "enqueued"),
            ("task.finished", "completed"),
            ("pg.request_errored", "failed"),
            ("payment.charge_canceled", "cancelled"),
        ],
    )
    def test_a_synonym_names_the_word_to_use(self, action, canonical):
        [problem] = rules.check(_spec(action))
        assert repr(canonical) in problem

    def test_the_last_word_must_be_a_known_verb(self):
        [problem] = rules.check(_spec("pg.vendor_result"))
        assert "'result'" in problem
        assert "VERBS" in problem

    def test_a_failure_is_the_outcome_not_the_name(self):
        problems = rules.check(_spec("checkout.session_not_found"))
        assert any("negation" in p for p in problems)

    @pytest.mark.parametrize(
        "action", ["Payment.created", "payment.Session_created", "payment session.created", "payment"]
    )
    def test_the_shape_is_lower_snake_case_under_a_domain(self, action):
        [problem] = rules.check(_spec(action))
        assert "<domain>.<subject>_<verb>" in problem

    def test_the_word_lists_agree(self):
        # A word both allowed and rejected would pass or fail depending on
        # which check ran first; every replacement must itself be allowed.
        assert rules.VERBS.isdisjoint(rules.SYNONYMS)
        assert set(rules.SYNONYMS.values()) <= rules.VERBS

    def test_every_event_says_when_to_log_it(self):
        [problem] = rules.check(_spec("wallet.balance_debited", description="  "))
        assert "description" in problem


class TestTheCatalogue:
    @pytest.mark.parametrize("spec", list(_catalogue()), ids=str)
    def test_every_shared_event_follows_the_rules(self, spec):
        assert rules.check(spec) == []

    def test_the_header_gate_refusals_are_api_rejections(self):
        # Connect's header gate refuses a request before any view runs — the
        # same thing `api.request_rejected` names, so it is not a second action.
        assert ApiRejection.MISSING_HEADER.value == "missing_header"
        assert ApiRejection.INVALID_HEADER.value == "invalid_header"


class TestReservedDomains:
    @pytest.mark.parametrize(
        "prefix", ["file", "host", "network", "process", "source", "destination", "client", "server"]
    )
    def test_a_domain_cannot_be_an_ecs_field_set(self, prefix):
        # `file.stored` as an action reads, in every query, like the `file.*`
        # fields a document already carries.
        with pytest.raises(ValueError, match="ECS field-set name"):
            register_domain(prefix, [_spec(f"{prefix}.thing_stored")])


class TestLocalEvents:
    def test_a_well_named_local_event_registers(self):
        debited = _spec("wallet.balance_debited")
        register_ottu(local={"wallet": (debited,)})
        assert registry.resolve("wallet.balance_debited") is debited

    def test_a_local_event_under_a_shared_domain_registers(self):
        built = _spec("pg.payload_built")
        register_ottu(local={"pg": (built,)})
        assert registry.resolve("pg.payload_built") is built

    def test_a_badly_named_local_event_fails_the_service_at_startup(self):
        with pytest.raises(rules.EventRuleError) as caught:
            register_ottu(
                local={
                    "notify": (_spec("notify.message_queued"),),
                    "sdk": (_spec("sdk.payment_flow_undefined", description=""),),
                }
            )
        message = str(caught.value)
        assert "notify.message_queued" in message
        assert "sdk.payment_flow_undefined" in message
        assert "description" in message
        assert not registry.is_frozen()

    def test_a_local_event_cannot_redefine_a_shared_one(self):
        clone = EventSpec(action=PG_REQUEST_SENT.action, description=PG_REQUEST_SENT.description)
        with pytest.raises(ValueError):
            register_ottu(local={"pg": (clone,)})

    def test_a_local_reason_set_is_its_own_class(self):
        class SweepFailure(Reason):
            RECOVERY_RAISED = "recovery_raised"

        swept = EventSpec(
            action="wallet.sweep_completed",
            terminal=True,
            reasons=SweepFailure,
            description="The nightly sweep of expired reservations finished.",
        )
        register_ottu(local={"wallet": (swept,)})
        assert swept.ecs(outcome="failure", reason=SweepFailure.RECOVERY_RAISED)["reason"] == (
            "recovery_raised"
        )


class TestReferencePage:
    def test_the_committed_page_matches_the_catalogue(self):
        # Regenerate with: python -m ecsctx.contrib.ottu.render_docs
        assert DOCS.read_text() == render_docs.render()

    def test_every_event_is_on_the_page_with_its_import(self):
        page = render_docs.render()
        for spec in _catalogue():
            assert f"`{spec.action}`" in page
        assert "from ecsctx.contrib.ottu.pg import PG_REQUEST_FAILED" in page

    def test_reasons_are_listed_under_their_class(self):
        page = render_docs.render()
        assert "`OutboundFailure`" in page
        assert "`http_client_error`" in page
