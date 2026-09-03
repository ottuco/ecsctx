"""The log-contract processor (#159491).

The defect these exist for is silent: `ecs_event="payment.started"` looks right
at every call site and lands in `event.original` — ECS's field for the raw
unparsed message — so `event.action` is absent and the line disappears from
every dashboard filtering on it.
"""

import pytest

from ecsctx.events import EventSpec, register_domain, registry
from ecsctx.events.validator import (
    FAILURE_BELOW_WARNING,
    MISSING_OUTCOME,
    STRING_ACTION,
    UNBOUNDED_LABEL,
    UNKNOWN_ACTION,
    EventContractError,
    configure_event_contract,
    event_contract,
    get_mode,
    reset_event_contract,
)
from ecsctx.processors import namespace_ecs_fields

STARTED = EventSpec(action="payment.started", category=("api",), type=("start",))
SUCCEEDED = EventSpec(
    action="payment.succeeded", terminal=True, category=("api",), type=("end",)
)


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("ECSCTX_EVENT_CONTRACT", raising=False)
    registry.reset()
    reset_event_contract()
    yield
    registry.reset()
    reset_event_contract()


def contract(event_dict, level="info"):
    return event_contract(None, level, event_dict)


class TestTheFootgunItself:
    def test_a_string_ecs_event_reaches_event_original_without_the_processor(self):
        # The behaviour being defended against, asserted so the fix has a
        # documented reason to exist rather than an asserted one.
        out = namespace_ecs_fields(None, "info", {"ecs_event": "payment.started"})
        assert out["event.original"] == "payment.started"
        assert "event.action" not in out

    def test_the_processor_coerces_it_to_the_dict_form(self):
        out = contract({"ecs_event": "payment.started"})
        assert out["ecs_event"] == {"action": "payment.started"}

    def test_and_then_it_lands_on_event_action(self):
        # The two processors composed, in the order the chain runs them.
        out = namespace_ecs_fields(
            None, "info", contract({"ecs_event": "payment.started"})
        )
        assert out["event.action"] == "payment.started"
        assert "event.original" not in out

    def test_the_repair_is_recorded_rather_than_hidden(self):
        assert contract({"ecs_event": "payment.started"})["labels"]["log_contract"] == (
            STRING_ACTION
        )

    def test_a_correct_call_is_left_alone(self):
        original = {"ecs_event": {"action": "payment.started"}, "labels": {"a": "b"}}
        assert contract(dict(original)) == original


class TestUnknownAction:
    def test_an_unregistered_action_is_flagged_once_frozen(self):
        register_domain("payment", [STARTED])
        registry.freeze()
        out = contract({"ecs_event": {"action": "payment.invented"}})
        assert out["labels"]["log_contract"] == UNKNOWN_ACTION

    def test_nothing_is_flagged_before_the_registry_is_frozen(self):
        # A domain that has not registered yet would otherwise make all of its
        # own events look unknown — a startup race reported as a breach.
        register_domain("payment", [STARTED])
        out = contract({"ecs_event": {"action": "payment.invented"}})
        assert "labels" not in out

    def test_a_consumer_with_no_registry_is_not_nagged(self):
        # ecsctx is public; a service that does not use the registry must not
        # have every one of its log lines stamped as a violation.
        out = contract({"ecs_event": {"action": "anything.at_all"}})
        assert "labels" not in out


class TestOutcome:
    def test_a_terminal_event_without_an_outcome_is_flagged_and_repaired(self):
        register_domain("payment", [SUCCEEDED])
        registry.freeze()
        out = contract({"ecs_event": {"action": "payment.succeeded"}})
        assert out["labels"]["log_contract"] == MISSING_OUTCOME
        # "unknown" is a real ECS outcome, and the honest one: the call did not
        # say, and this processor cannot know.
        assert out["ecs_event"]["outcome"] == "unknown"

    def test_a_terminal_event_with_an_outcome_passes(self):
        register_domain("payment", [SUCCEEDED])
        registry.freeze()
        out = contract(
            {"ecs_event": {"action": "payment.succeeded", "outcome": "success"}}
        )
        assert "labels" not in out

    def test_a_failure_logged_at_info_is_flagged(self):
        # Both audited payment journeys were 100% log.level=info while carrying
        # webhook delivery failures, so severity filtering found nothing.
        out = contract(
            {"ecs_event": {"action": "x.y", "outcome": "failure"}}, level="info"
        )
        assert out["labels"]["log_contract"] == FAILURE_BELOW_WARNING

    def test_a_failure_logged_at_error_is_fine(self):
        out = contract(
            {"ecs_event": {"action": "x.y", "outcome": "failure"}}, level="error"
        )
        assert "labels" not in out

    def test_the_level_is_not_repaired_because_it_cannot_be(self):
        # The level was decided before the chain ran; the stamp is the only
        # honest response.
        out = contract(
            {"ecs_event": {"action": "x.y", "outcome": "failure"}}, level="info"
        )
        assert out["ecs_event"]["outcome"] == "failure"


class TestLabels:
    def test_a_structured_label_is_flagged_and_stringified(self):
        out = contract({"labels": {"ids": [1, 2]}})
        assert out["labels"]["ids"] == "[1, 2]"
        assert out["labels"]["log_contract"] == UNBOUNDED_LABEL

    def test_scalar_labels_are_untouched(self):
        out = contract({"labels": {"a": "x", "b": 2, "c": 1.5, "d": True, "e": None}})
        assert "log_contract" not in out["labels"]

    def test_a_non_dict_labels_value_does_not_crash_the_chain(self):
        out = contract({"labels": "not-a-dict", "ecs_event": "payment.started"})
        # The stamp needs somewhere to live, so labels is replaced rather than
        # the line being lost.
        assert out["labels"]["log_contract"] == STRING_ACTION


class TestModes:
    def test_repair_is_the_default(self):
        # A logging library that takes a service down over a malformed log line
        # has chosen the wrong failure.
        assert get_mode() == "repair"

    def test_strict_raises_instead_of_repairing(self):
        configure_event_contract(mode="strict")
        with pytest.raises(EventContractError, match=STRING_ACTION):
            contract({"ecs_event": "payment.started"})

    def test_strict_leaves_a_correct_call_alone(self):
        configure_event_contract(mode="strict")
        assert contract({"ecs_event": {"action": "payment.started"}}) == {
            "ecs_event": {"action": "payment.started"}
        }

    def test_the_mode_comes_from_the_environment(self, monkeypatch):
        monkeypatch.setenv("ECSCTX_EVENT_CONTRACT", "strict")
        assert get_mode() == "strict"

    def test_an_explicit_call_beats_the_environment(self, monkeypatch):
        monkeypatch.setenv("ECSCTX_EVENT_CONTRACT", "strict")
        configure_event_contract(mode="repair")
        assert get_mode() == "repair"

    def test_an_unknown_mode_warns_and_falls_back_to_repair(self, monkeypatch):
        monkeypatch.setenv("ECSCTX_EVENT_CONTRACT", "paranoid")
        with pytest.warns(RuntimeWarning, match="paranoid"):
            assert get_mode() == "repair"

    def test_configure_rejects_an_unknown_mode_outright(self):
        with pytest.raises(ValueError, match="not a mode"):
            configure_event_contract(mode="paranoid")


class TestMultipleViolations:
    def test_they_are_summarised_as_one_aggregatable_keyword(self):
        # labels.* must stay a flat scalar — a list here would be dropped by
        # the index template and warned about by ecs_validator.
        register_domain("payment", [SUCCEEDED])
        registry.freeze()
        out = contract({"ecs_event": "payment.succeeded", "labels": {"ids": [1]}})
        assert out["labels"]["log_contract"] == ",".join(
            sorted({STRING_ACTION, MISSING_OUTCOME, UNBOUNDED_LABEL})
        )
        assert isinstance(out["labels"]["log_contract"], str)


class TestTheDoublePassOnStdlibRecords:
    """A stdlib record runs the processor twice — once in `foreign_pre_chain`,
    once in the shared `processors` list. That is a property of
    ProcessorFormatter, not of this processor, but it must not cost the record
    the violations found on the first pass."""

    def test_the_stamp_survives_the_second_pass_intact(self):
        record = {
            "event": "Payment started",
            "ecs_event": "payment.started",
            "labels": {"ids": [1, 2]},
        }
        record = contract(record)
        expected = f"{STRING_ACTION},{UNBOUNDED_LABEL}"
        assert record["labels"]["log_contract"] == expected

        record = namespace_ecs_fields(None, "info", record)
        assert "ecs_event" not in record

        # Nothing left to find: the ecs_event-derived codes cannot re-fire
        # because the key is gone, and the labels are scalars now. The
        # processor only ever writes the stamp when it finds violations, so
        # finding none leaves the first pass's verdict standing.
        record = contract(record)
        assert record["labels"]["log_contract"] == expected


class TestChainWiring:
    def test_it_runs_before_namespace_ecs_fields_in_both_chains(self):
        # Ordering is the whole point: namespace_ecs_fields is what turns a
        # string ecs_event into event.original, so running after it would leave
        # nothing to repair.
        from ecsctx.contrib.django.logging import get_logging_config

        formatter = get_logging_config()["formatters"]["structlog_formatter"]
        for key in ("processors", "foreign_pre_chain"):
            names = [getattr(p, "__name__", type(p).__name__) for p in formatter[key]]
            assert names.index("event_contract") < names.index(
                "namespace_ecs_fields"
            ), key
