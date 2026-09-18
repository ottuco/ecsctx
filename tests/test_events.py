"""The event mechanism (#159490).

These assert the rules rather than spot-check entries, because the value of a
registry is that it cannot drift: production carried 34 hand-rolled names in
Connect and ~163 in Ottu PG precisely because nothing rejected any of them.
"""

import importlib
import warnings

import pytest

import ecsctx.events
from ecsctx.events import (
    EventSpec,
    RegistryFrozenError,
    register_aliases,
    register_domain,
    registry,
    resolve,
)

REQUEST_SENT = EventSpec(
    action="pg.request_sent",
    category=("network",),
    type=("connection",),
)
RESPONSE_RECEIVED = EventSpec(
    action="pg.response_received",
    terminal=True,
    category=("network",),
    type=("connection",),
)
REFUSED = EventSpec(
    action="pg.refused",
    level="warning",
    terminal=True,
    type=("denied",),
    reasons=("timeout", "declined"),
)


@pytest.fixture(autouse=True)
def _clean_registry():
    """The registry is process-global."""
    registry.reset()
    yield
    registry.reset()


class TestSpec:
    def test_ecs_payload_matches_the_connect_contract(self):
        # Pinned against utils/log_events.py's own test so the two stay swappable
        # rather than drifting into two shapes for one field.
        assert RESPONSE_RECEIVED.ecs(outcome="failure") == {
            "action": "pg.response_received",
            "kind": "event",
            "category": ["network"],
            "type": ["connection"],
            "outcome": "failure",
        }

    def test_terminal_event_refuses_to_build_without_an_outcome(self):
        with pytest.raises(ValueError, match="terminal"):
            RESPONSE_RECEIVED.ecs()

    def test_non_terminal_event_needs_no_outcome(self):
        assert REQUEST_SENT.ecs() == {
            "action": "pg.request_sent",
            "kind": "event",
            "category": ["network"],
            "type": ["connection"],
        }

    def test_outcome_must_be_an_ecs_value(self):
        with pytest.raises(ValueError, match=r"event\.outcome"):
            REQUEST_SENT.ecs(outcome="ok")

    def test_declared_reasons_bound_the_reason(self):
        assert REFUSED.ecs(outcome="failure", reason="timeout")["reason"] == "timeout"
        with pytest.raises(ValueError, match="declared reason"):
            REFUSED.ecs(outcome="failure", reason="tiemout")

    def test_undeclared_reasons_stay_permissive(self):
        # Most events have not declared theirs; the check must not block sites
        # that predate the mechanism.
        assert REQUEST_SENT.ecs(reason="anything")["reason"] == "anything"

    def test_duration_is_nanoseconds_and_rides_inside_the_payload(self):
        # structlog takes the message as a positional arg named `event`, so a
        # bare event={"duration": ...} kwarg raises TypeError at call time.
        assert REQUEST_SENT.ecs(duration_ns=1_500_000)["duration"] == 1_500_000
        with pytest.raises(ValueError, match="duration_ns"):
            REQUEST_SENT.ecs(duration_ns=-1)

    def test_domain_is_the_prefix(self):
        assert REQUEST_SENT.domain == "pg"

    def test_stringifies_to_its_action(self):
        assert f"{REQUEST_SENT}" == "pg.request_sent"

    def test_is_immutable(self):
        with pytest.raises((AttributeError, TypeError)):
            REQUEST_SENT.action = "pg.something_else"


class TestFailureLevel:
    """Connect's LogEvent kept only the success level, so a taxonomy that said
    'info on success, error on failure' lost half its meaning to the generator."""

    def test_terminal_events_default_to_error_on_failure(self):
        assert RESPONSE_RECEIVED.level == "info"
        assert RESPONSE_RECEIVED.level_on_failure == "error"

    def test_non_terminal_events_keep_their_level(self):
        assert REQUEST_SENT.level_on_failure == "info"

    def test_an_explicit_failure_level_wins(self):
        spec = EventSpec(action="pg.x", terminal=True, failure_level="warning")
        assert spec.level_on_failure == "warning"


class TestRegistry:
    def test_a_registered_event_resolves_by_name(self):
        register_domain("pg", [REQUEST_SENT])
        assert resolve("pg.request_sent") is REQUEST_SENT

    def test_an_unknown_name_resolves_to_none(self):
        assert resolve("pg.never_declared") is None

    def test_a_spec_resolves_to_itself(self):
        assert resolve(REQUEST_SENT) is REQUEST_SENT

    def test_a_prefix_cannot_be_claimed_twice(self):
        register_domain("pg", [REQUEST_SENT])
        with pytest.raises(ValueError, match="already registered"):
            register_domain("pg", [RESPONSE_RECEIVED])

    def test_an_identical_re_register_is_tolerated(self):
        # Django can import an AppConfig module twice under autoreload.
        register_domain("pg", [REQUEST_SENT])
        register_domain("pg", [REQUEST_SENT])
        assert registry.domains() == ("pg",)

    @pytest.mark.parametrize("prefix", ["log", "event", "service", "trace", "error"])
    def test_ecs_field_set_names_are_reserved(self, prefix):
        # `log.written` is indistinguishable from the log.* field set in a query.
        spec = EventSpec(action=f"{prefix}.written")
        with pytest.raises(ValueError, match="ECS field-set name"):
            register_domain(prefix, [spec])

    @pytest.mark.parametrize("prefix", ["PG", "pg.sub", "pg-x", "2pg", ""])
    def test_a_prefix_must_be_a_bare_lowercase_identifier(self, prefix):
        with pytest.raises(ValueError, match="lowercase identifier"):
            register_domain(prefix, [])

    def test_the_same_action_cannot_be_declared_twice_in_one_domain(self):
        # A copy-pasted EventSpec used to leave the last one winning in the
        # action index while the domain kept both, so resolve() and all_events()
        # silently disagreed about what the action meant.
        other = EventSpec(action="pg.request_sent", level="warning")
        with pytest.raises(ValueError, match="declared twice"):
            register_domain("pg", [REQUEST_SENT, other])
        assert registry.domains() == ()

    def test_an_event_must_live_under_the_prefix_it_registers_with(self):
        with pytest.raises(ValueError, match="does not belong"):
            register_domain("wallet", [REQUEST_SENT])

    def test_freeze_closes_registration(self):
        registry.freeze()
        assert registry.is_frozen()
        with pytest.raises(RegistryFrozenError, match="frozen"):
            register_domain("pg", [REQUEST_SENT])

    def test_all_events_lists_what_was_registered(self):
        register_domain("pg", [REQUEST_SENT, RESPONSE_RECEIVED])
        assert set(registry.all_events()) == {REQUEST_SENT, RESPONSE_RECEIVED}


class TestAliases:
    def test_a_retired_name_resolves_to_its_replacement(self):
        register_domain("pg", [REQUEST_SENT])
        register_aliases({"PG_CALL": "pg.request_sent"})
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            assert resolve("PG_CALL") is REQUEST_SENT
        assert any(issubclass(w.category, DeprecationWarning) for w in caught)

    def test_an_alias_cannot_shadow_a_registered_event(self):
        register_domain("pg", [REQUEST_SENT])
        with pytest.raises(ValueError, match="registered event"):
            register_aliases({"pg.request_sent": "pg.response_received"})

    def test_an_alias_to_nothing_still_resolves_to_none(self):
        register_aliases({"PG_CALL": "pg.never_declared"})
        assert resolve("PG_CALL") is None


class TestOneWayToLog:
    @pytest.mark.parametrize(
        "name", ["emit", "emit_pair", "Call", "UnknownEventError", "route", "FIELD_PATHS"]
    )
    def test_the_events_package_has_no_logging_wrapper(self, name):
        # A service logs with its own logger and `ecs_event=SPEC.ecs(...)`. A
        # second way to log hid the level from the call site, placed fields by
        # kwarg name and took an event as a string.
        assert not hasattr(ecsctx.events, name)

    @pytest.mark.parametrize("module", ["ecsctx.events.emit", "ecsctx.events.fields"])
    def test_the_wrapper_modules_are_gone(self, module):
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module(module)
