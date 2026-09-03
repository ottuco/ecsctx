"""The event mechanism (#159490).

These assert the rules rather than spot-check entries, because the value of a
registry is that it cannot drift: production carried 34 hand-rolled names in
Connect and ~163 in Ottu PG precisely because nothing rejected any of them.
"""

import warnings

import pytest

from ecsctx.events import (
    EventSpec,
    RegistryFrozenError,
    UnknownEventError,
    emit,
    register_aliases,
    register_domain,
    registry,
    resolve,
    route,
)
from ecsctx.events import fields as field_table
from ecsctx.processors import (
    ROOT_ALLOWLIST,
    _reset_root_fields,
    configure_root_fields,
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


class Recorder:
    """Captures the call the way structlog would receive it."""

    def __init__(self):
        self.calls = []

    def __getattr__(self, level):
        def record(message, *args, **kwargs):
            self.calls.append((level, message, args, kwargs))

        return record

    @property
    def last(self):
        return self.calls[-1]


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


class TestRouting:
    def test_every_table_path_lands_under_an_allowlisted_root(self):
        # A path outside ROOT_ALLOWLIST would be swept into `extra` by
        # namespace_ecs_fields — correct at the call site, wrong in Elasticsearch.
        for name, path in field_table.FIELD_PATHS.items():
            assert path.partition(".")[0] in ROOT_ALLOWLIST, f"{name} -> {path}"

    def test_correlation_ids_stay_flat_at_root(self):
        assert route({"session_id": "abc", "merchant_id": "m1"}) == {
            "session_id": "abc",
            "merchant_id": "m1",
        }

    def test_two_http_kwargs_merge_into_one_object(self):
        assert route({"method": "POST", "status_code": 201}) == {
            "http": {"request": {"method": "POST"}, "response": {"status_code": 201}}
        }

    def test_an_unknown_scalar_becomes_an_aggregatable_label(self):
        assert route({"attempt": 3}) == {"labels": {"attempt": 3}}

    def test_an_unknown_structure_goes_to_extra(self):
        assert route({"blob": {"a": 1}}) == {"extra": {"blob": {"a": 1}}}

    def test_an_explicit_ecs_namespace_passes_through(self):
        # 44 existing call sites pass `http=` this way; routing it into `extra`
        # would be a regression dressed up as normalization.
        assert route({"http": {"response": {"status_code": 500}}}) == {
            "http": {"response": {"status_code": 500}}
        }

    def test_a_service_configured_root_namespace_also_passes_through(self):
        # configure_root_fields() is how Wallet, AutoPay et al. claim their own
        # root namespace, and reshape_log_event honours it dynamically. Reading
        # a frozen copy of the allowlist here would send wallet={...} to
        # extra.wallet while the rest of the chain treated wallet as root.
        try:
            configure_root_fields(extra_fields=["wallet"])
            assert route({"wallet": {"balance": 100}}) == {"wallet": {"balance": 100}}
        finally:
            _reset_root_fields()

    def test_an_unconfigured_namespace_still_goes_to_extra(self):
        # The passthrough follows the allowlist rather than waving through any
        # dict, so this must stay in extra once the configuration is gone.
        _reset_root_fields()
        assert route({"wallet": {"balance": 100}}) == {
            "extra": {"wallet": {"balance": 100}}
        }

    def test_an_explicit_namespace_merges_with_the_table_rather_than_replacing(self):
        assert route({"status_code": 200, "http": {"request": {"method": "GET"}}}) == {
            "http": {"response": {"status_code": 200}, "request": {"method": "GET"}}
        }

    def test_an_explicit_leaf_wins_over_the_table(self):
        routed = route({"status_code": 200, "http": {"response": {"status_code": 500}}})
        assert routed["http"]["response"]["status_code"] == 500


class TestEmit:
    def test_it_logs_at_the_specs_level_with_the_ecs_payload(self):
        log = Recorder()
        emit(log, REQUEST_SENT, "Calling gateway", pg_code="mpgs")
        level, message, _args, kwargs = log.last
        assert level == "info"
        assert message == "Calling gateway"
        assert kwargs["ecs_event"]["action"] == "pg.request_sent"
        assert kwargs["payment"] == {"pg_code": "mpgs"}

    def test_a_failure_outcome_raises_the_level(self):
        log = Recorder()
        emit(log, RESPONSE_RECEIVED, "PG failed", outcome="failure")
        assert log.last[0] == "error"

    def test_a_success_outcome_keeps_the_specs_level(self):
        log = Recorder()
        emit(log, RESPONSE_RECEIVED, "PG replied", outcome="success")
        assert log.last[0] == "info"

    def test_an_explicit_level_overrides_the_outcome(self):
        log = Recorder()
        emit(log, RESPONSE_RECEIVED, "PG failed", outcome="failure", level="warning")
        assert log.last[0] == "warning"

    def test_lazy_format_args_reach_the_logger_uncollapsed(self):
        # The house rule bans f-strings in log calls; an API that forced eager
        # formatting would defeat it silently.
        log = Recorder()
        emit(log, REQUEST_SENT, "took %s ms", 42)
        assert log.last[1:3] == ("took %s ms", (42,))

    def test_a_string_name_resolves_through_the_registry(self):
        register_domain("pg", [REQUEST_SENT])
        log = Recorder()
        emit(log, "pg.request_sent", "Calling gateway")
        assert log.last[3]["ecs_event"]["action"] == "pg.request_sent"

    def test_a_retired_string_name_resolves_through_the_alias_map(self):
        register_domain("pg", [REQUEST_SENT])
        register_aliases({"PG_CALL": "pg.request_sent"})
        log = Recorder()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            emit(log, "PG_CALL", "Calling gateway")
        assert log.last[3]["ecs_event"]["action"] == "pg.request_sent"

    def test_an_unregistered_name_raises_rather_than_inventing_a_value(self):
        log = Recorder()
        with pytest.raises(UnknownEventError, match="not a registered event"):
            emit(log, "pg.invented", "Whatever")
        assert log.calls == []

    def test_duration_and_reason_travel_in_the_ecs_payload(self):
        log = Recorder()
        emit(
            log,
            REFUSED,
            "Refused",
            outcome="failure",
            reason="timeout",
            duration_ns=1_000,
        )
        payload = log.last[3]["ecs_event"]
        assert payload["reason"] == "timeout"
        assert payload["duration"] == 1_000

    def test_a_terminal_event_without_an_outcome_still_refuses(self):
        log = Recorder()
        with pytest.raises(ValueError, match="terminal"):
            emit(log, RESPONSE_RECEIVED, "PG replied")
        assert log.calls == []
